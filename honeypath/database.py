"""SQLite storage: canary manifest, events, managed changes, SSH state.

Threading model
---------------
Python's sqlite3 connections are thread-bound.  Honeypath therefore does one
of two things and never anything in between:

* One-shot commands open a short-lived connection per operation
  (``with db.connection() as conn``).
* ``watch`` runs several watcher threads and routes *every* write through a
  single :class:`WriterQueue` thread that owns the only writing connection.

WAL plus a busy timeout keeps concurrent readers (``events``, ``doctor``)
from tripping over the writer.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
import shutil
import tempfile
import uuid
from urllib.parse import quote
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path("/var/lib/honeypath/events.sqlite3")
SCHEMA_VERSION = 4

MANAGED_BY = "honeypath"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DatabaseError(Exception):
    pass


_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS canaries (
        id INTEGER PRIMARY KEY,
        canary_id TEXT NOT NULL,
        path TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        profile TEXT NOT NULL,
        platform TEXT NOT NULL,
        intrusiveness TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_baseline_atime INTEGER,
        active INTEGER NOT NULL DEFAULT 1,
        managed_by TEXT NOT NULL DEFAULT 'honeypath',
        content_hash TEXT,
        managed_marker TEXT,
        file_dev INTEGER,
        file_ino INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        hostname TEXT NOT NULL,
        method TEXT NOT NULL,
        event_type TEXT NOT NULL,
        path TEXT NOT NULL,
        canary_id TEXT,
        kind TEXT,
        severity TEXT,
        message TEXT,
        process_info TEXT,
        pushover_sent INTEGER NOT NULL DEFAULT 0,
        pushover_error TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_path ON events(path)",
    """
    CREATE TABLE IF NOT EXISTS schema_metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ssh_installations (
        id INTEGER PRIMARY KEY,
        home TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        uid INTEGER NOT NULL,
        relocated_dir TEXT NOT NULL,
        backup_path TEXT,
        phase TEXT NOT NULL,
        activated_at TEXT,
        config_validation TEXT,
        source_hashes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        notes TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS managed_changes (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        home TEXT,
        change_type TEXT NOT NULL,
        target TEXT NOT NULL,
        previous_existed INTEGER,
        previous_value TEXT,
        new_value TEXT,
        content_hash TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        notes TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_managed_type ON managed_changes(change_type, active)",
    """
    CREATE TABLE IF NOT EXISTS windows_event_inbox (
        id INTEGER PRIMARY KEY,
        log_generation INTEGER NOT NULL,
        record_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        detail TEXT NOT NULL,
        process_info TEXT,
        observed_at REAL NOT NULL,
        event_id INTEGER,
        delivered INTEGER NOT NULL DEFAULT 0,
        UNIQUE(log_generation, record_id),
        FOREIGN KEY(event_id) REFERENCES events(id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_windows_inbox_pending "
    "ON windows_event_inbox(delivered, record_id)",
]


@dataclass
class CanaryRow:
    canary_id: str
    path: str
    kind: str
    severity: str
    profile: str
    platform: str
    intrusiveness: str
    last_baseline_atime: int | None
    active: int
    content_hash: str | None = None
    managed_marker: str | None = None
    file_dev: int | None = None
    file_ino: int | None = None
    managed_by: str = MANAGED_BY

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "CanaryRow":
        keys = set(row.keys())
        return cls(
            canary_id=row["canary_id"],
            path=row["path"],
            kind=row["kind"],
            severity=row["severity"],
            profile=row["profile"],
            platform=row["platform"],
            intrusiveness=row["intrusiveness"],
            last_baseline_atime=row["last_baseline_atime"],
            active=row["active"],
            content_hash=row["content_hash"] if "content_hash" in keys else None,
            managed_marker=row["managed_marker"] if "managed_marker" in keys else None,
            file_dev=row["file_dev"] if "file_dev" in keys else None,
            file_ino=row["file_ino"] if "file_ino" in keys else None,
            managed_by=row["managed_by"] if "managed_by" in keys else MANAGED_BY,
        )


class Database:
    def __init__(
        self,
        path: Path | str = DEFAULT_DB_PATH,
        *,
        read_only: bool = False,
        empty_state: bool = False,
        snapshot_owner=None,
        connection_path: Path | str | None = None,
    ):
        self.path = Path(path)
        self.read_only = read_only
        self.empty_state = empty_state
        self._snapshot_owner = snapshot_owner
        self._connection_path = Path(connection_path) if connection_path else self.path

    @classmethod
    def dry_run_snapshot(cls, path: Path | str) -> "Database":
        """Copy SQLite plus live WAL state into a private disposable directory."""
        original = Path(path)
        owner = tempfile.TemporaryDirectory(prefix="honeypath-dry-run-db-")
        destination = Path(owner.name) / original.name
        try:
            shutil.copy2(original, destination)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(original) + suffix)
                if sidecar.exists():
                    shutil.copy2(sidecar, Path(str(destination) + suffix))
        except Exception:
            owner.cleanup()
            raise
        return cls(
            original,
            read_only=True,
            snapshot_owner=owner,
            connection_path=destination,
        )

    def close(self) -> None:
        owner, self._snapshot_owner = self._snapshot_owner, None
        if owner is not None:
            owner.cleanup()

    def __del__(self):  # pragma: no cover - safety net for embedded callers
        try:
            self.close()
        except Exception:
            pass

    # -- connections -------------------------------------------------------

    def _open(self) -> sqlite3.Connection:
        if self.empty_state:
            conn = sqlite3.connect(":memory:", timeout=10.0)
        elif self.read_only and self._snapshot_owner is None:
            # immutable avoids creating a WAL shared-memory file during a
            # supposedly non-mutating dry run.  It is a point-in-time view.
            uri = f"file:{quote(str(self._connection_path))}?mode=ro&immutable=1"
            conn = sqlite3.connect(uri, timeout=10.0, uri=True)
        else:
            conn = sqlite3.connect(str(self._connection_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        if self.empty_state:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_metadata(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute("PRAGMA query_only=ON")
        elif self.read_only:
            conn.execute("PRAGMA query_only=ON")
        else:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def connection(self):
        conn = self._open()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -- schema ------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def writable(self) -> tuple[bool, str]:
        """Can we create/write the database here?  Returns (ok, detail)."""
        target = self.path
        if target.exists():
            return (os.access(target, os.W_OK), f"{target} exists")
        parent = target.parent
        if parent.exists():
            return (os.access(parent, os.W_OK), f"{parent} exists")
        probe = parent
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        return (
            os.access(probe, os.W_OK),
            f"would create {parent} (nearest existing: {probe})",
        )

    def initialize(self) -> None:
        if self.read_only or self.empty_state:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            current = conn.execute(
                "SELECT value FROM schema_metadata WHERE key='schema_version'"
            ).fetchone()
            if current is None:
                conn.execute(
                    "INSERT INTO schema_metadata(key, value) VALUES(?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
                conn.execute(
                    "INSERT INTO schema_metadata(key, value) VALUES(?, ?)",
                    ("install_id", str(uuid.uuid4())),
                )
                conn.execute(
                    "INSERT INTO schema_metadata(key, value) VALUES(?, ?)",
                    ("created_at", utc_now()),
                )
                conn.execute(
                    "INSERT INTO schema_metadata(key, value) VALUES(?, ?)",
                    (f"migration:{SCHEMA_VERSION}", utc_now()),
                )
            else:
                self._migrate(conn, int(current["value"]))

    def _migrate(self, conn: sqlite3.Connection, from_version: int) -> None:
        """Apply forward migrations.  Version 1 is the initial schema."""
        version = from_version
        while version < SCHEMA_VERSION:
            version += 1
            if version == 2:
                columns = {
                    row["name"] for row in conn.execute("PRAGMA table_info(canaries)")
                }
                for name, declaration in (
                    ("content_hash", "TEXT"),
                    ("managed_marker", "TEXT"),
                    ("file_dev", "INTEGER"),
                    ("file_ino", "INTEGER"),
                ):
                    if name not in columns:
                        conn.execute(
                            f"ALTER TABLE canaries ADD COLUMN {name} {declaration}"
                        )
            elif version == 3:
                # Version 3 keyed the durable inbox by EventRecordID alone.
                # Preserve that historical shape for databases migrating
                # through v3; v4 rebuilds it with a log-generation namespace.
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS windows_event_inbox (
                        record_id INTEGER PRIMARY KEY,
                        path TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        process_info TEXT,
                        observed_at REAL NOT NULL,
                        event_id INTEGER,
                        delivered INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY(event_id) REFERENCES events(id)
                    )
                    """)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_windows_inbox_pending "
                    "ON windows_event_inbox(delivered, record_id)"
                )
            elif version == 4:
                columns = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(windows_event_inbox)")
                }
                if "log_generation" not in columns:
                    conn.execute(
                        "ALTER TABLE windows_event_inbox "
                        "RENAME TO windows_event_inbox_v3"
                    )
                    conn.execute(_SCHEMA[-2])
                    conn.execute("""
                        INSERT INTO windows_event_inbox(
                            id,log_generation,record_id,path,detail,process_info,
                            observed_at,event_id,delivered)
                        SELECT record_id,0,record_id,path,detail,process_info,
                               observed_at,event_id,delivered
                          FROM windows_event_inbox_v3
                        """)
                    conn.execute("DROP TABLE windows_event_inbox_v3")
                    conn.execute(_SCHEMA[-1])
            conn.execute(
                "INSERT OR REPLACE INTO schema_metadata(key, value) VALUES(?, ?)",
                (f"migration:{version}", utc_now()),
            )
        if version != from_version:
            conn.execute(
                "UPDATE schema_metadata SET value=? WHERE key='schema_version'",
                (str(version),),
            )

    # -- metadata ----------------------------------------------------------

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT value FROM schema_metadata WHERE key=?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO schema_metadata(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def stage_windows_record(
        self,
        *,
        checkpoint_key: str,
        log_generation: int,
        record_id: int,
        hit: dict | None,
    ) -> None:
        """Durably stage a matching 4663 and advance its checkpoint atomically."""
        with self.connection() as conn:
            if hit is not None:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO windows_event_inbox(
                        log_generation,record_id,path,detail,process_info,
                        observed_at,delivered)
                    VALUES(?,?,?,?,?,?,0)
                    """,
                    (
                        log_generation,
                        record_id,
                        hit["path"],
                        hit.get("detail", ""),
                        hit.get("process_info"),
                        float(hit.get("at", time.time())),
                    ),
                )
            conn.execute(
                "INSERT INTO schema_metadata(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (checkpoint_key, str(record_id)),
            )

    def rotate_windows_log(
        self, *, checkpoint_key: str, generation_key: str, checkpoint: int
    ) -> int:
        """Start a new Security-log ID namespace and rewind atomically."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT value FROM schema_metadata WHERE key=?", (generation_key,)
            ).fetchone()
            try:
                generation = int(row["value"]) + 1 if row else 1
            except (TypeError, ValueError):
                generation = 1
            for key, value in (
                (generation_key, str(generation)),
                (checkpoint_key, str(checkpoint)),
            ):
                conn.execute(
                    "INSERT INTO schema_metadata(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )
        return generation

    def pending_windows_records(self, *, limit: int = 1000) -> list[dict]:
        with self.connection() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM windows_event_inbox WHERE delivered=0 "
                    "ORDER BY id LIMIT ?",
                    (limit,),
                )
            ]

    def mute_until(self) -> float:
        raw = self.get_meta("mute_until_epoch")
        try:
            return float(raw) if raw else 0.0
        except ValueError:
            return 0.0

    def is_muted(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < self.mute_until()

    # -- canaries ----------------------------------------------------------

    def record_canary(
        self,
        *,
        canary_id: str,
        path: str,
        kind: str,
        severity: str,
        profile: str,
        platform: str,
        intrusiveness: str,
        baseline_atime: int | None,
        active: int = 1,
        content_hash: str | None = None,
        managed_marker: str | None = None,
        file_dev: int | None = None,
        file_ino: int | None = None,
        managed_by: str = MANAGED_BY,
    ) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO canaries(
                    canary_id, path, kind, severity, profile, platform,
                    intrusiveness, created_at, last_baseline_atime, active, managed_by,
                    content_hash, managed_marker, file_dev, file_ino)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(path) DO UPDATE SET
                    canary_id=excluded.canary_id,
                    kind=excluded.kind,
                    severity=excluded.severity,
                    profile=excluded.profile,
                    platform=excluded.platform,
                    intrusiveness=excluded.intrusiveness,
                    last_baseline_atime=excluded.last_baseline_atime,
                    active=excluded.active,
                    managed_by=excluded.managed_by,
                    content_hash=excluded.content_hash,
                    managed_marker=excluded.managed_marker,
                    file_dev=excluded.file_dev,
                    file_ino=excluded.file_ino
                """,
                (
                    canary_id,
                    path,
                    kind,
                    severity,
                    profile,
                    platform,
                    intrusiveness,
                    utc_now(),
                    baseline_atime,
                    active,
                    managed_by,
                    content_hash,
                    managed_marker,
                    file_dev,
                    file_ino,
                ),
            )

    def get_canaries(self, *, active_only: bool = True, platform: str | None = None):
        sql = "SELECT * FROM canaries"
        clauses, params = [], []
        if active_only:
            clauses.append("active=1")
        if platform:
            clauses.append("platform=?")
            params.append(platform)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY path"
        with self.connection() as conn:
            return [CanaryRow.from_row(r) for r in conn.execute(sql, params)]

    def get_canary_by_path(self, path: str) -> CanaryRow | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM canaries WHERE path=?", (path,)
            ).fetchone()
        return CanaryRow.from_row(row) if row else None

    def is_managed_canary(self, path: str) -> bool:
        """True only when this exact path is recorded as Honeypath-managed.

        Used as the first gate of ``--refresh-managed``: a path Honeypath did
        not create is never refreshable, whatever its contents look like.
        """
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM canaries WHERE path=?", (path,)
            ).fetchone()
        return bool(row) and row["managed_by"] == MANAGED_BY and bool(row["active"])

    def update_canary_identity(
        self,
        path: str,
        *,
        content_hash: str,
        managed_marker: str,
        file_dev: int | None,
        file_ino: int | None,
    ) -> None:
        with self.connection() as conn:
            cur = conn.execute(
                "UPDATE canaries SET content_hash=?, managed_marker=?, file_dev=?, file_ino=? "
                "WHERE path=? AND active=1 AND managed_by=?",
                (content_hash, managed_marker, file_dev, file_ino, path, MANAGED_BY),
            )
            if cur.rowcount != 1:
                raise DatabaseError(f"managed canary identity vanished for {path}")

    def update_baseline_atime(self, path: str, atime_ns: int) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE canaries SET last_baseline_atime=? WHERE path=?",
                (atime_ns, path),
            )

    def set_canaries_active(self, paths, active: int) -> int:
        if not paths:
            return 0
        with self.connection() as conn:
            cur = conn.executemany(
                "UPDATE canaries SET active=? WHERE path=?",
                [(active, p) for p in paths],
            )
            return cur.rowcount

    def deactivate_under(self, prefix: str) -> int:
        with self.connection() as conn:
            cur = conn.execute(
                "UPDATE canaries SET active=0 WHERE path LIKE ?", (prefix + "%",)
            )
            return cur.rowcount

    def has_ssh_canaries(self, home: Path | str) -> bool:
        """True when SSH-canary activation has registered canaries for a home."""
        prefix = str(Path(home) / ".ssh") + "/"
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM canaries WHERE active=1 AND path LIKE ?",
                (prefix + "%",),
            ).fetchone()
        return bool(row["n"])

    # -- events ------------------------------------------------------------

    def record_event(self, event: dict) -> int:
        with self.connection() as conn:
            return _insert_event(conn, event)

    def count_events(self) -> int:
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def recent_events(
        self,
        *,
        limit: int = 20,
        severity: str | None = None,
        path_substring: str | None = None,
    ):
        sql = "SELECT * FROM events"
        clauses, params = [], []
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if path_substring:
            clauses.append("path LIKE ?")
            params.append(f"%{path_substring}%")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connection() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    # -- managed changes ---------------------------------------------------

    def record_managed_change(
        self,
        *,
        change_type: str,
        target: str,
        home: str | None = None,
        previous_existed: bool | None = None,
        previous_value: str | None = None,
        new_value: str | None = None,
        content_hash: str | None = None,
        notes: str | None = None,
    ) -> int:
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO managed_changes(
                    created_at, home, change_type, target, previous_existed,
                    previous_value, new_value, content_hash, active, notes)
                VALUES(?,?,?,?,?,?,?,?,1,?)
                """,
                (
                    utc_now(),
                    home,
                    change_type,
                    target,
                    None if previous_existed is None else int(previous_existed),
                    previous_value,
                    new_value,
                    content_hash,
                    notes,
                ),
            )
            return int(cur.lastrowid or 0)

    def get_managed_changes(
        self,
        *,
        change_type: str | None = None,
        target: str | None = None,
        home: str | None = None,
        active_only: bool = True,
    ):
        sql = "SELECT * FROM managed_changes"
        clauses, params = [], []
        if active_only:
            clauses.append("active=1")
        if change_type:
            clauses.append("change_type=?")
            params.append(change_type)
        if target:
            clauses.append("target=?")
            params.append(target)
        if home:
            clauses.append("home=?")
            params.append(home)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        with self.connection() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def retire_managed_change(self, change_id: int) -> None:
        with self.connection() as conn:
            conn.execute("UPDATE managed_changes SET active=0 WHERE id=?", (change_id,))

    # -- ssh installations -------------------------------------------------

    def upsert_ssh_installation(
        self,
        *,
        home: str,
        username: str,
        uid: int,
        relocated_dir: str,
        phase: str,
        backup_path: str | None = None,
        activated_at: str | None = None,
        config_validation: str | None = None,
        source_hashes: dict | None = None,
        notes: str | None = None,
    ) -> None:
        payload = (
            json.dumps(source_hashes, sort_keys=True)
            if source_hashes is not None
            else None
        )
        now = utc_now()
        with self.connection() as conn:
            existing = conn.execute(
                "SELECT id, phase, backup_path FROM ssh_installations WHERE home=?",
                (home,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO ssh_installations(
                        home, username, uid, relocated_dir, backup_path, phase,
                        activated_at, config_validation, source_hashes,
                        created_at, updated_at, notes)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        home,
                        username,
                        uid,
                        relocated_dir,
                        backup_path,
                        phase,
                        activated_at,
                        config_validation,
                        payload,
                        now,
                        now,
                        notes,
                    ),
                )
            else:
                if existing["phase"] == "activated":
                    if backup_path is not None and existing["backup_path"] not in (
                        None,
                        backup_path,
                    ):
                        raise DatabaseError(
                            "refusing to replace the original SSH backup path for an "
                            "activated installation"
                        )
                    if phase not in ("activated", "restored"):
                        raise DatabaseError(
                            "refusing an invalid transition from activated SSH state"
                        )
                sets = [
                    "username=?",
                    "uid=?",
                    "relocated_dir=?",
                    "phase=?",
                    "updated_at=?",
                ]
                params: list = [username, uid, relocated_dir, phase, now]
                for column, value in (
                    ("backup_path", backup_path),
                    ("activated_at", activated_at),
                    ("config_validation", config_validation),
                    ("source_hashes", payload),
                    ("notes", notes),
                ):
                    if value is not None:
                        sets.append(f"{column}=?")
                        params.append(value)
                params.append(home)
                conn.execute(
                    f"UPDATE ssh_installations SET {', '.join(sets)} WHERE home=?",
                    params,
                )

    def finalize_ssh_activation(
        self,
        *,
        home: str,
        backup_path: str,
        activated_at: str,
        canaries: list[dict],
        authorized_change: dict | None = None,
    ) -> None:
        """Commit all Phase-2 manifest changes in one SQLite transaction."""
        now = utc_now()
        prefix = str(Path(home) / ".ssh") + "/%"
        with self.connection() as conn:
            installation = conn.execute(
                "SELECT phase, backup_path FROM ssh_installations WHERE home=?",
                (home,),
            ).fetchone()
            if installation is None or installation["phase"] != "prepared":
                raise DatabaseError(
                    "SSH activation can only be finalized from the prepared phase"
                )
            if installation["backup_path"]:
                raise DatabaseError(
                    "prepared installation unexpectedly has a backup path"
                )

            # A previous failed implementation may have left inactive/partial
            # rows.  They are never allowed to leak into this activation.
            conn.execute(
                "DELETE FROM canaries WHERE path LIKE ? AND managed_by=?",
                (prefix, MANAGED_BY),
            )
            for item in canaries:
                conn.execute(
                    """
                    INSERT INTO canaries(
                        canary_id,path,kind,severity,profile,platform,intrusiveness,
                        created_at,last_baseline_atime,active,managed_by,content_hash,
                        managed_marker,file_dev,file_ino)
                    VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)
                    """,
                    (
                        item["canary_id"],
                        item["path"],
                        item["kind"],
                        item["severity"],
                        item["profile"],
                        item["platform"],
                        item["intrusiveness"],
                        now,
                        item.get("baseline_atime"),
                        MANAGED_BY,
                        item["content_hash"],
                        item["managed_marker"],
                        item.get("file_dev"),
                        item.get("file_ino"),
                    ),
                )
            if authorized_change is not None:
                conn.execute(
                    """
                    INSERT INTO managed_changes(
                        created_at,home,change_type,target,previous_existed,
                        previous_value,new_value,content_hash,active,notes)
                    VALUES(?,?,?,?,?,?,?,?,1,?)
                    """,
                    (
                        now,
                        home,
                        "ssh-authorized-keys",
                        authorized_change["target"],
                        1,
                        None,
                        authorized_change["source"],
                        authorized_change.get("content_hash"),
                        "server-side state preserved across activation; NOT a canary",
                    ),
                )
            cur = conn.execute(
                """
                UPDATE ssh_installations
                   SET phase='activated', backup_path=?, activated_at=?, updated_at=?
                 WHERE home=? AND phase='prepared' AND backup_path IS NULL
                """,
                (backup_path, activated_at, now, home),
            )
            if cur.rowcount != 1:
                raise DatabaseError("SSH installation changed during activation")

    def get_ssh_installation(self, home: str | Path) -> dict | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM ssh_installations WHERE home=?", (str(home),)
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        if data.get("source_hashes"):
            try:
                data["source_hashes"] = json.loads(data["source_hashes"])
            except json.JSONDecodeError:
                data["source_hashes"] = {}
        else:
            data["source_hashes"] = {}
        return data


def _insert_event(conn: sqlite3.Connection, event: dict) -> int:
    cur = conn.execute(
        """
        INSERT INTO events(
            timestamp, hostname, method, event_type, path, canary_id, kind,
            severity, message, process_info, pushover_sent, pushover_error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            event.get("timestamp") or utc_now(),
            event.get("hostname", ""),
            event.get("method", ""),
            event.get("event_type", ""),
            event.get("path", ""),
            event.get("canary_id"),
            event.get("kind"),
            event.get("severity"),
            event.get("message"),
            event.get("process_info"),
            int(event.get("pushover_sent", 0)),
            event.get("pushover_error"),
        ),
    )
    return int(cur.lastrowid or 0)


class WriterQueue(threading.Thread):
    """Single writer thread owning the only writing connection.

    Watcher threads never touch sqlite directly; they hand callables here.
    """

    _STOP = object()

    def __init__(self, db: Database, name: str = "honeypath-writer"):
        super().__init__(name=name, daemon=False)
        self.db = db
        self._queue: queue.Queue = queue.Queue()
        self._started = threading.Event()
        self.errors: list[str] = []
        self._stop_lock = threading.Lock()
        self._stopped = False

    def run(self) -> None:  # pragma: no cover - exercised via integration
        conn = self.db._open()
        self._started.set()
        try:
            while True:
                item = self._queue.get()
                if item is self._STOP:
                    self._queue.task_done()
                    return
                func, result_box, done = item
                try:
                    value = func(conn)
                    conn.commit()
                    if result_box is not None:
                        result_box.append(("ok", value))
                except Exception as exc:  # keep the watcher alive
                    conn.rollback()
                    self.errors.append(str(exc))
                    if result_box is not None:
                        result_box.append(("error", exc))
                finally:
                    if done is not None:
                        done.set()
                    self._queue.task_done()
        finally:
            conn.close()

    def submit(self, func) -> None:
        if self._stopped:
            return
        self._queue.put((func, None, None))

    def submit_sync(self, func, timeout: float = 10.0):
        if self._stopped:
            raise DatabaseError("database writer is stopped")
        box: list = []
        done = threading.Event()
        self._queue.put((func, box, done))
        if not done.wait(timeout):
            raise DatabaseError("timed out waiting for the database writer")
        status, value = box[0]
        if status == "error":
            raise value
        return value

    def record_event(self, event: dict) -> None:
        self.submit(lambda conn: _insert_event(conn, event))

    def record_event_sync(self, event: dict) -> int:
        return self.submit_sync(lambda conn: _insert_event(conn, event))

    def record_windows_event_sync(
        self, event: dict, inbox_ids: list[int]
    ) -> int | None:
        """Insert one coalesced event and consume inbox rows in one transaction."""
        ids = sorted(set(int(value) for value in inbox_ids))
        if not ids:
            return self.record_event_sync(event)

        def write(conn):
            placeholders = ",".join("?" for _ in ids)
            pending = [
                int(row["id"])
                for row in conn.execute(
                    f"SELECT id FROM windows_event_inbox "
                    f"WHERE delivered=0 AND id IN ({placeholders})",
                    ids,
                )
            ]
            if not pending:
                return None
            event_id = _insert_event(conn, event)
            pending_marks = ",".join("?" for _ in pending)
            conn.execute(
                f"UPDATE windows_event_inbox SET delivered=1,event_id=? "
                f"WHERE delivered=0 AND id IN ({pending_marks})",
                (event_id, *pending),
            )
            return event_id

        return self.submit_sync(write)

    def update_event_delivery(
        self, event_id: int, sent: bool, error: str | None
    ) -> None:
        self.submit(
            lambda conn: conn.execute(
                "UPDATE events SET pushover_sent=?, pushover_error=? WHERE id=?",
                (int(sent), error, event_id),
            )
        )

    def update_baseline_atime(self, path: str, atime_ns: int) -> None:
        self.submit(
            lambda conn: conn.execute(
                "UPDATE canaries SET last_baseline_atime=? WHERE path=?",
                (atime_ns, path),
            )
        )

    def set_meta(self, key: str, value: str) -> None:
        self.submit(
            lambda conn: conn.execute(
                "INSERT INTO schema_metadata(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        )

    def stop(self, timeout: float = 5.0) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
            self._queue.put(self._STOP)
        self.join(timeout)

    def drain(self) -> None:
        """Wait until every write accepted so far has committed or failed."""
        self._queue.join()
