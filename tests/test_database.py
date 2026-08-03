"""Schema, concurrency and the writer queue (§6)."""

from __future__ import annotations

import sqlite3
import threading
import unittest

from .support import TempHomeCase

from honeypath.database import SCHEMA_VERSION, Database, WriterQueue  # noqa: E402


class SchemaTests(TempHomeCase):
    def test_tables_exist(self):
        with self.db.connection() as conn:
            names = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertTrue(
            {
                "canaries",
                "events",
                "schema_metadata",
                "ssh_installations",
                "managed_changes",
            }
            <= names
        )

    def test_wal_and_busy_timeout_are_set(self):
        with self.db.connection() as conn:
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        self.assertEqual(journal.lower(), "wal")
        self.assertEqual(timeout, 5000)

    def test_version_and_install_id_recorded(self):
        self.assertEqual(self.db.get_meta("schema_version"), str(SCHEMA_VERSION))
        self.assertTrue(self.db.get_meta("install_id"))
        self.assertTrue(self.db.get_meta(f"migration:{SCHEMA_VERSION}"))

    def test_initialize_is_idempotent(self):
        install_id = self.db.get_meta("install_id")
        self.db.initialize()
        self.db.initialize()
        self.assertEqual(self.db.get_meta("install_id"), install_id)

    def test_v3_windows_inbox_migrates_with_generation_namespace(self):
        path = self.root / "legacy.sqlite3"
        with sqlite3.connect(path) as conn:
            conn.execute(
                "CREATE TABLE schema_metadata(key TEXT PRIMARY KEY, value TEXT)"
            )
            conn.execute("INSERT INTO schema_metadata VALUES('schema_version', '3')")
            conn.execute("""
                CREATE TABLE windows_event_inbox (
                    record_id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    process_info TEXT,
                    observed_at REAL NOT NULL,
                    event_id INTEGER,
                    delivered INTEGER NOT NULL DEFAULT 0
                )
                """)
            conn.execute(
                "CREATE INDEX idx_windows_inbox_pending "
                "ON windows_event_inbox(delivered, record_id)"
            )
            conn.execute(
                "INSERT INTO windows_event_inbox VALUES(10,'/x','old',NULL,1,NULL,1)"
            )

        legacy = Database(path)
        legacy.initialize()
        with legacy.connection() as conn:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(windows_event_inbox)")
            }
            row = conn.execute("SELECT * FROM windows_event_inbox").fetchone()
        self.assertTrue({"id", "log_generation", "record_id"} <= columns)
        self.assertEqual(row["id"], 10)
        self.assertEqual(row["log_generation"], 0)
        self.assertEqual(row["record_id"], 10)
        self.assertEqual(row["delivered"], 1)

    def test_canary_path_is_unique_and_upserts(self):
        for kind in ("netrc", "netrc-updated"):
            self.db.record_canary(
                canary_id="k",
                path="/x/.netrc",
                kind=kind,
                severity="high",
                profile="linux-developer",
                platform="linux",
                intrusiveness="active-config",
                baseline_atime=1,
            )
        rows = self.db.get_canaries()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "netrc-updated")

    def test_writable_reports_a_missing_parent(self):
        db = Database(self.root / "nope" / "deeper" / "events.sqlite3")
        ok, detail = db.writable()
        self.assertTrue(ok)
        self.assertIn("would create", detail)


class ManagedChangeTests(TempHomeCase):
    def test_records_previous_value_and_unset_state(self):
        self.db.record_managed_change(
            change_type="git-core-sshcommand",
            target="core.sshCommand",
            previous_existed=False,
            new_value="/home/x/bin/ssh",
        )
        change = self.db.get_managed_changes(change_type="git-core-sshcommand")[0]
        self.assertEqual(change["previous_existed"], 0)
        self.assertIsNone(change["previous_value"])

        self.db.record_managed_change(
            change_type="git-core-sshcommand",
            target="core.sshCommand",
            previous_existed=True,
            previous_value="/usr/bin/ssh -o X=y",
            new_value="/home/x/bin/ssh",
        )
        changes = self.db.get_managed_changes(change_type="git-core-sshcommand")
        self.assertEqual(changes[0]["previous_value"], "/usr/bin/ssh -o X=y")

    def test_retire_hides_the_change(self):
        change_id = self.db.record_managed_change(
            change_type="ssh-wrapper", target="/home/x/bin/ssh"
        )
        self.db.retire_managed_change(change_id)
        self.assertEqual(self.db.get_managed_changes(change_type="ssh-wrapper"), [])
        self.assertEqual(
            len(
                self.db.get_managed_changes(
                    change_type="ssh-wrapper", active_only=False
                )
            ),
            1,
        )


class SSHInstallationTests(TempHomeCase):
    def test_upsert_preserves_unspecified_fields(self):
        self.db.upsert_ssh_installation(
            home="/home/x",
            username="x",
            uid=1000,
            relocated_dir="/home/x/relocated",
            phase="prepared",
            source_hashes={"config": "abc"},
        )
        self.db.upsert_ssh_installation(
            home="/home/x",
            username="x",
            uid=1000,
            relocated_dir="/home/x/relocated",
            phase="activated",
            backup_path="/home/x/backup",
        )
        row = self.db.get_ssh_installation("/home/x")
        assert row is not None
        self.assertEqual(row["phase"], "activated")
        self.assertEqual(row["backup_path"], "/home/x/backup")
        self.assertEqual(row["source_hashes"], {"config": "abc"})


class WriterQueueTests(TempHomeCase):
    def test_many_threads_never_share_a_connection(self):
        writer = WriterQueue(self.db)
        writer.start()
        errors: list[Exception] = []

        def worker(index: int):
            try:
                for n in range(20):
                    writer.record_event(
                        {
                            "hostname": "test",
                            "method": "inotify",
                            "event_type": "read",
                            "path": f"/x/{index}",
                            "message": str(n),
                        }
                    )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        writer._queue.join()
        writer.stop()

        self.assertEqual(errors, [])
        self.assertEqual(writer.errors, [])
        self.assertEqual(self.db.count_events(), 160)

    def test_submit_sync_returns_the_row_id(self):
        writer = WriterQueue(self.db)
        writer.start()
        try:
            event_id = writer.record_event_sync(
                {
                    "hostname": "test",
                    "method": "atime",
                    "event_type": "read",
                    "path": "/x/a",
                }
            )
            self.assertGreater(event_id, 0)
            writer.update_event_delivery(event_id, True, None)
            writer._queue.join()
        finally:
            writer.stop()
        row = self.db.recent_events(limit=1)[0]
        self.assertEqual(row["pushover_sent"], 1)

    def test_a_failing_write_does_not_kill_the_writer(self):
        writer = WriterQueue(self.db)
        writer.start()
        try:
            with self.assertRaises(sqlite3.OperationalError):
                writer.submit_sync(lambda conn: conn.execute("SELECT * FROM nope"))
            event_id = writer.record_event_sync(
                {
                    "hostname": "test",
                    "method": "atime",
                    "event_type": "read",
                    "path": "/x/a",
                }
            )
            self.assertGreater(event_id, 0)
        finally:
            writer.stop()

    def test_concurrent_reader_while_writing(self):
        writer = WriterQueue(self.db)
        writer.start()
        try:
            for n in range(50):
                writer.record_event(
                    {
                        "hostname": "test",
                        "method": "atime",
                        "event_type": "read",
                        "path": f"/x/{n}",
                    }
                )
            # A separate short-lived read connection must not be blocked out.
            self.db.recent_events(limit=5)
            writer._queue.join()
        finally:
            writer.stop()
        self.assertEqual(self.db.count_events(), 50)


class EventQueryTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        for path, severity in (
            ("/home/x/.ssh/id_rsa", "critical"),
            ("/home/x/.netrc", "high"),
            ("/home/x/.npmrc", "high"),
        ):
            self.db.record_event(
                {
                    "hostname": "h",
                    "method": "inotify",
                    "event_type": "read",
                    "path": path,
                    "severity": severity,
                    "kind": "k",
                }
            )

    def test_limit(self):
        self.assertEqual(len(self.db.recent_events(limit=2)), 2)

    def test_severity_filter(self):
        rows = self.db.recent_events(limit=10, severity="critical")
        self.assertEqual(len(rows), 1)

    def test_path_substring_filter(self):
        rows = self.db.recent_events(limit=10, path_substring="ssh")
        self.assertEqual(len(rows), 1)
        self.assertIn(".ssh", rows[0]["path"])


if __name__ == "__main__":
    unittest.main()
