"""Command-line interface and command implementations."""

from __future__ import annotations

import argparse
import getpass
import grp
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import VERSION, alerts as alerts_mod
from . import catalog as catalog_mod
from . import eventlog
from . import safe_write
from . import ssh_canary, windows_audit
from .database import DEFAULT_DB_PATH, Database
from .monitor import (
    DEFAULT_COOLDOWN,
    DEFAULT_DEDUP_WINDOW,
    DEFAULT_POLL_INTERVAL,
    InotifyWatcher,
    Monitor,
)
from .platform_detect import (
    OS_MACOS,
    OS_WSL,
    detect_platform_context,
    fsutil_disablelastaccess,
    interop_available,
    inotifywait_path,
    is_windows_filesystem,
    mount_for,
    read_mounts,
    wsl_signals,
)
from .target_user import TargetUserError, resolve_target_user

SSH_GATE_MESSAGE = (
    "SSH canaries skipped: setup-ssh-canary --activate has not been completed"
)

SYSTEMD_UNIT_PATH = Path("/etc/systemd/system/honeypath.service")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def make_confirm(assume_yes: bool, log=print):
    def confirm(prompt: str) -> bool:
        if assume_yes:
            log(f"{prompt} [--yes]")
            return True
        if not sys.stdin.isatty():
            log(f"{prompt} [no tty; assuming no]")
            return False
        try:
            answer = input(f"{prompt} [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            log("")
            return False
        return answer in ("y", "yes")

    return confirm


def heading(text: str) -> None:
    print(f"\n{text}")
    print("-" * len(text))


@dataclass
class Context:
    args: argparse.Namespace
    target: object
    platform: object
    db: Database
    confirm: object
    log_path: Path | None = None

    def open_event_log(self):
        """Open the operations log, or a no-op log for dry runs.

        Never raises: a log that cannot be opened reports ``error`` and
        swallows writes, so a logging problem cannot stop monitoring.
        """
        if self.dry_run:
            return eventlog.NullEventLog()
        return eventlog.open_log(self.log_path, version=VERSION)

    @property
    def dry_run(self) -> bool:
        # `--dry-run` is accepted before or after the sub-command.
        return bool(_merged(self.args, "dry_run", False))

    @property
    def force(self) -> bool:
        return bool(_merged(self.args, "force", False))


def _merged(args: argparse.Namespace, name: str, default=None):
    """Top-level and sub-command copies of an option; the sub-command wins."""
    sub = getattr(args, name, None)
    top = getattr(args, f"top_{name}", None)
    if sub not in (None, False):
        return sub
    if top not in (None, False):
        return top
    return default


def build_context(args: argparse.Namespace, *, initialize_db: bool = True) -> Context:
    target = resolve_target_user(
        _merged(args, "user"), allow_root=bool(_merged(args, "allow_root", False))
    )
    windows_home = _merged(args, "windows_home")
    platform = detect_platform_context(
        target,
        windows_home=Path(windows_home) if windows_home else None,
        include_crypto=bool(getattr(args, "include_crypto", False)),
    )
    db_path = Path(_merged(args, "db", DEFAULT_DB_PATH))
    dry_run = bool(_merged(args, "dry_run", False))
    if dry_run:
        # Existing state is copied with its WAL/SHM into a private disposable
        # snapshot.  A missing database uses an in-memory empty manifest.  The
        # real database, parent and sidecars are never created or modified.
        db = (
            Database.dry_run_snapshot(db_path)
            if db_path.exists()
            else Database(db_path, empty_state=True)
        )
    else:
        db = Database(db_path)
    if initialize_db and not dry_run:
        try:
            db.initialize()
        except (OSError, Exception) as exc:  # sqlite3.OperationalError et al.
            raise SystemExit(
                f"cannot open the Honeypath database at {db.path}: {exc}\n"
                "Run under sudo, or pass --db <path> to use a different location."
            )
    return Context(
        args=args,
        target=target,
        platform=platform,
        db=db,
        confirm=make_confirm(bool(_merged(args, "yes", False))),
        log_path=resolve_log_path(args, db_path),
    )


def resolve_log_path(args: argparse.Namespace, db_path: Path) -> Path | None:
    """Where the human-readable log goes; ``None`` means logging is off.

    The log lives beside the database, so the documented default is
    ``/var/lib/honeypath/honeypath.log`` and a custom ``--db`` keeps the two
    halves of the record — the queryable one and the readable one — together.
    """
    if bool(_merged(args, "no_log_file", False)):
        return None
    explicit = _merged(args, "log_file")
    if explicit:
        return Path(explicit).expanduser()
    return eventlog.default_log_path(db_path)


def home_root_for(ctx: Context, platform_name: str) -> Path | None:
    if platform_name == catalog_mod.PLATFORM_WINDOWS:
        return ctx.platform.windows_home
    return ctx.target.home


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


@dataclass
class PlanItem:
    entry: catalog_mod.CanaryEntry
    path: Path
    action: str  # create | refresh | skip | watch-only
    reason: str


def refresh_is_permitted(
    ctx: Context, path: Path, root: Path, entry: catalog_mod.CanaryEntry | None = None
) -> tuple[bool, str]:
    """Decide whether ``--refresh-managed`` may replace ``path``.

    All five conditions must hold, and each is checked independently:

    1. the exact path is recorded in SQLite as Honeypath-managed;
    2. the path on disk is a regular file — never a symlink, directory, FIFO,
       socket or device node;
    3. its contents carry the Honeypath marker;
    4. the resolved destination is still inside the approved home root, with
       no symlinked parent component;
    5. consequently, a credential file Honeypath did not write can never be
       selected.

    Returns ``(permitted, reason)``; ``reason`` explains a refusal.
    """
    try:
        info = safe_write.stat_nofollow(path, root=root)
    except FileNotFoundError:
        return False, "not present (nothing to refresh)"
    except OSError as exc:
        return False, f"cannot inspect: {exc}"
    if stat.S_ISLNK(info.st_mode):
        return False, "refused: path is a symlink"
    if not stat.S_ISREG(info.st_mode):
        return False, "refused: path is not a regular file"

    row = ctx.db.get_canary_by_path(str(path))
    if row is None or not row.active or row.managed_by != "honeypath":
        return False, "refused: not recorded as a Honeypath-managed canary"
    if not row.content_hash or not row.managed_marker:
        return False, (
            "refused: legacy row has no exact managed identity; recreate or "
            "verify it through a dedicated adoption workflow"
        )
    expected_id = entry.key if entry is not None else row.canary_id
    if (
        row.canary_id != expected_id
        or row.managed_marker != catalog_mod.managed_marker(expected_id)
    ):
        return False, "refused: managed marker does not match the expected canary ID"
    try:
        current_hash = safe_write.sha256_anchored(path, root=root)
    except (OSError, safe_write.SafeWriteError) as exc:
        return False, f"refused: {exc}"
    if current_hash != row.content_hash:
        return False, "refused: exact content hash changed since Honeypath wrote it"
    return True, ""


def build_plan(ctx: Context) -> tuple[list[PlanItem], list[str], list[str]]:
    """Returns (items, profiles, notes)."""
    args = ctx.args
    raw_profiles: list[str] = []
    for chunk in getattr(args, "profiles", ["auto"]) or ["auto"]:
        raw_profiles.extend(part for part in chunk.split(",") if part.strip())

    profiles, warnings = catalog_mod.expand_profile_names(
        raw_profiles,
        os_name=ctx.platform.os_name,
        has_windows_home=bool(ctx.platform.windows_homes),
        include_crypto=bool(getattr(args, "include_crypto", False)),
        include_noisy=bool(getattr(args, "include_noisy", False)),
        default_profiles=ctx.platform.default_profiles,
    )
    notes = list(warnings)

    include_active = bool(getattr(args, "include_active_config", False))
    refresh_managed = bool(getattr(args, "refresh_managed", False))

    excluded_active = catalog_mod.active_config_entries(profiles)
    if excluded_active and not include_active:
        notes.append(catalog_mod.ACTIVE_CONFIG_EXCLUDED_NOTE)

    canarytoken = None
    token_file = getattr(args, "canarytoken_aws_file", None)
    if token_file:
        canarytoken = ssh_canary.load_canarytoken_aws(Path(token_file))
        notes.append(
            f"Canarytokens AWS material from {token_file} will replace the default "
            "fake content in .aws/credentials canaries"
        )
        if not refresh_managed:
            notes.append(
                "Existing .aws/credentials canaries are left alone; pass "
                "--refresh-managed to update ones Honeypath created."
            )
    ctx.canarytoken = canarytoken  # type: ignore[attr-defined]

    items: list[PlanItem] = []
    ssh_gate_reported = False
    for entry in catalog_mod.entries_for_profiles(
        profiles, include_active_config=include_active
    ):
        root = home_root_for(ctx, entry.platform)
        if root is None:
            notes.append(f"{entry.relative_path}: skipped (no Windows home detected)")
            continue

        if entry.ssh_gated and not ctx.db.has_ssh_canaries(root):
            if not ssh_gate_reported:
                notes.append(SSH_GATE_MESSAGE)
                ssh_gate_reported = True
            continue

        for path in catalog_mod.expand_entry_paths(entry, root):
            if not entry.creatable:
                try:
                    watch_info = safe_write.stat_nofollow(path, root=root)
                    present = stat.S_ISREG(watch_info.st_mode)
                    replacement = "" if present else " (not a regular file)"
                except (OSError, safe_write.SafeWriteError):
                    present = False
                    replacement = ""
                items.append(
                    PlanItem(
                        entry,
                        path,
                        "watch-only" if present else "skip",
                        (
                            "watch/report only — Honeypath never creates browser data"
                            if present
                            else f"watch/report only target not present{replacement}"
                        ),
                    )
                )
                continue

            # An existing path is ALWAYS skipped.  There is no flag that makes
            # ordinary create-canaries overwrite a file it did not write;
            # --refresh-managed is the single narrow exception and it verifies
            # Honeypath ownership first.
            exists = path.is_symlink() or path.exists()
            if not exists:
                items.append(PlanItem(entry, path, "create", ""))
            elif refresh_managed:
                permitted, reason = refresh_is_permitted(ctx, path, root, entry)
                if permitted:
                    items.append(
                        PlanItem(
                            entry,
                            path,
                            "refresh",
                            "verified Honeypath-managed canary",
                        )
                    )
                else:
                    items.append(
                        PlanItem(
                            entry,
                            path,
                            "skip",
                            f"{reason} (--refresh-managed declined)",
                        )
                    )
            else:
                items.append(PlanItem(entry, path, "skip", "file already exists"))
    return items, profiles, notes


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


def _describe_volume(label: str, path: Path, mounts) -> list[str]:
    lines = []
    mount = mount_for(path, mounts)
    fstype = mount.fstype if mount else "unknown"
    lines.append(f"{label} ({path}, {fstype}):")
    if not path.exists():
        lines.append("  path does not exist")
        return lines

    inotify = inotifywait_path()
    windows_fs = is_windows_filesystem(mount)
    if windows_fs:
        lines.append(
            "  Linux-side reads via inotify: "
            + (
                "best-effort (9p/drvfs can miss WSL file-access events)"
                if inotify
                else "UNAVAILABLE (install inotify-tools)"
            )
        )
        lines.append(
            "  Windows-side reads via inotify: NOT detected "
            "(use setup-windows-audit)"
        )
    elif inotify:
        lines.append("  inotify access events: available")
    else:
        lines.append("  inotify access events: UNAVAILABLE (install inotify-tools)")

    if windows_fs:
        value, error = fsutil_disablelastaccess()
        detail = value if value else f"unavailable ({error})"
        lines.append(
            "  atime: unavailable/unreliable; re-arming disabled "
            f"(fsutil disablelastaccess = {detail})"
        )
    elif mount is None:
        lines.append("  atime: unknown mount options")
    else:
        policy = mount.atime_policy
        if "noatime" in policy:
            lines.append("  atime: noatime (atime detection will NOT work)")
        elif "strictatime" in policy:
            lines.append("  atime: strictatime (reliable)")
        else:
            lines.append(f"  atime: {policy} (limited; re-arming enabled)")
    return lines


def windows_read_test(windows_home: Path, log=print) -> None:
    """Prove (or disprove) that WSL sees a genuine Windows-side read."""
    from .platform_detect import run_powershell, to_windows_path

    inotify = inotifywait_path()
    if not inotify:
        log("  cannot run the test: inotifywait is not installed")
        return
    probe = windows_home / f".honeypath-readtest-{int(time.time())}"
    try:
        probe.write_text("honeypath windows read test\n")
    except OSError as exc:
        log(f"  cannot create {probe}: {exc}")
        return

    win_path = to_windows_path(probe)
    if not win_path:
        log("  wslpath could not convert the probe path; skipping")
        probe.unlink(missing_ok=True)
        return

    observed: list[str] = []

    def watch():
        try:
            proc = subprocess.run(
                [
                    inotify,
                    "-q",
                    "-e",
                    "access",
                    "-e",
                    "open",
                    "-t",
                    "12",
                    "--format",
                    "%e",
                    str(probe),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.stdout.strip():
                observed.append(proc.stdout.strip())
        except OSError as exc:
            observed.append(f"error: {exc}")

    thread = threading.Thread(target=watch, daemon=False)
    thread.start()
    time.sleep(1.5)
    log(f"  reading {win_path} from Windows via powershell.exe ...")
    result = run_powershell(
        f"Get-Content -LiteralPath '{win_path}' > $null; 'done'", timeout=30
    )
    thread.join(timeout=35)
    probe.unlink(missing_ok=True)

    if not result.ok:
        log(
            f"  the Windows-side read did not run: {result.error or result.stderr.strip()}"
        )
        return
    if observed:
        log(f"  RESULT: the WSL watcher DID observe the Windows read ({observed[0]})")
    else:
        log("  RESULT: the WSL watcher did NOT observe the Windows read.")
        log("          This is the expected outcome — run setup-windows-audit for")
        log("          Windows-side detection with process attribution.")


def log_file_status(ctx: Context) -> list[str]:
    """Describe the operations log without creating or opening it."""
    path = ctx.log_path
    if path is None:
        return ["  logging: DISABLED (--no-log-file)"]
    lines = [f"  path:       {path}"]
    try:
        info = path.stat()
    except FileNotFoundError:
        parent = path.parent
        writable = parent.is_dir() and os.access(parent, os.W_OK)
        lines.append("  present:    no (created when `watch` next starts)")
        lines.append(
            f"  writable:   {'yes' if writable else 'NO'} "
            f"({parent}{'' if parent.is_dir() else ' does not exist'})"
        )
        return lines
    except OSError as exc:
        lines.append(f"  present:    cannot inspect: {exc}")
        return lines
    lines.append(
        f"  present:    yes, {info.st_size} bytes, mode {oct(info.st_mode & 0o777)}"
        + ("  (WORLD-READABLE)" if info.st_mode & 0o004 else "")
    )
    lines.append(f"  writable:   {'yes' if os.access(path, os.W_OK) else 'NO'}")
    rotated = sorted(
        p.name for p in path.parent.glob(path.name + ".*") if p.name != path.name
    )
    if rotated:
        lines.append(f"  rotated:    {', '.join(rotated)}")
    return lines


def cmd_doctor(ctx: Context) -> int:
    args = ctx.args
    heading("Environment")
    print(f"Honeypath version:   {VERSION}")
    print(f"Detected OS:         {ctx.platform.os_name}")
    print(f"WSL:                 {'yes' if ctx.platform.os_name == OS_WSL else 'no'}")
    signals = wsl_signals()
    if signals:
        print(f"  WSL signals:       {', '.join(signals)}")
    print(f"Target user:         {ctx.target.describe()}")
    print(f"Running as:          uid {os.geteuid()}")
    print(f"Linux/macOS home:    {ctx.target.home}")
    if ctx.platform.windows_homes:
        for index, home in enumerate(ctx.platform.windows_homes):
            marker = " (selected)" if index == 0 else ""
            print(f"Windows home:        {home}{marker}")
    elif ctx.platform.os_name == OS_WSL:
        print("Windows home:        not detected")
    print(f"Default profiles:    {', '.join(ctx.platform.default_profiles) or 'none'}")
    for note in ctx.platform.notes:
        print(f"  note: {note}")

    heading("Tooling")
    inotify = inotifywait_path()
    print(
        f"inotifywait:         {inotify or 'NOT INSTALLED (apt install inotify-tools)'}"
    )
    print(
        f"ssh binary:          {ssh_canary.SSH_BINARY} "
        f"({'present' if Path(ssh_canary.SSH_BINARY).exists() else 'MISSING'})"
    )
    print(f"git:                 {shutil.which('git') or 'not found'}")

    heading("Alerting")
    for status in alerts_mod.credential_status():
        print(f"  {status.describe()}")
    pushover = alerts_mod.Pushover()
    print(f"  Pushover configured: {'yes' if pushover.configured() else 'no'}")
    if not pushover.configured():
        print("  setup: sudo python3 honeypath.py configure-alerts")
    muted_until = ctx.db.mute_until()
    if ctx.db.is_muted():
        remaining = int(muted_until - time.time())
        print(f"  Alerts MUTED for another {remaining // 60}m {remaining % 60}s")
    else:
        print("  Alerts: not muted")

    heading("Database")
    ok, detail = ctx.db.writable()
    print(f"  path:       {ctx.db.path}")
    print(f"  writable:   {'yes' if ok else 'NO'} ({detail})")
    canaries = ctx.db.get_canaries()
    print(f"  canaries recorded (active): {len(canaries)}")
    print(f"  events recorded: {ctx.db.count_events()}")

    heading("Log file")
    for line in log_file_status(ctx):
        print(line)

    heading("Per-filesystem monitoring")
    mounts = read_mounts()
    for line in _describe_volume("Linux home", ctx.target.home, mounts):
        print(line)
    for home in ctx.platform.windows_homes:
        for line in _describe_volume("Windows home", home, mounts):
            print(line)
    if ctx.platform.os_name == OS_MACOS:
        print("macOS home:")
        print(
            "  event-based read monitoring: unavailable "
            "(FSEvents does not report reads)"
        )
        print("  atime polling: best-effort, may be ineffective")

    heading("SSH state")
    state = ssh_canary.ssh_state(ctx.db, ctx.target)
    print(f"  ~/.ssh exists:            {state['ssh_dir_exists']}")
    if state["ssh_dir_is_symlink"]:
        print("  ~/.ssh is a SYMLINK:      activation blocker (see setup-ssh-canary)")
    print(f"  ~/.ssh is a canary:       {state['ssh_dir_is_canary']}")
    print(
        f"  relocated dir exists:     {state['relocated_dir_exists']} "
        f"({state['relocated_dir']})"
    )
    print(f"  relocated config exists:  {state['relocated_config_exists']}")
    for wrapper in state["wrappers"]:
        print(f"  {wrapper.describe()}")
    print(
        f"  which ssh:                {ssh_canary.which_ssh(ctx.target) or 'not found'}"
    )
    print(
        f"  git core.sshCommand:      "
        f"{ssh_canary.git_ssh_command(ctx.target) or '<unset>'}"
    )
    installation = state["installation"]
    print(
        f"  activation phase:         "
        f"{installation['phase'] if installation else 'not started'}"
    )
    if installation and installation.get("backup_path"):
        print(f"  backup path:              {installation['backup_path']}")
    direct = ssh_canary.direct_ssh_status(ctx.db, ctx.target)
    print(
        f"  direct /usr/bin/ssh use:  "
        f"{'supported' if direct['supported'] else 'UNSUPPORTED'}"
    )
    if not direct["supported"]:
        print(f"    {direct['reason']}")

    if state["authorized_keys"]:
        print()
        for line in ssh_canary.authorized_keys_warning(ctx.target.home):
            print(line)

    if ctx.platform.os_name == OS_WSL:
        heading("Windows-side auditing")
        status = windows_audit.collect_status(ctx.db, ctx.platform.windows_home)
        print(f"  interop available:        {status.interop}")
        if status.interop:
            print(f"  elevated:                 {status.elevated}")
            print(
                f"  audit policy:             "
                f"{status.audit_policy or status.audit_policy_error}"
            )
            print(
                f"  Security log readable:    {status.security_log_readable} "
                f"{status.security_log_error or ''}".rstrip()
            )
            print(f"  scheduled task:           {status.scheduled_task or 'unknown'}")
            print(
                f"  fsutil disablelastaccess: "
                f"{status.fsutil_value or status.fsutil_error}"
            )
            if status.sacl_paths:
                for path, win_path, present in status.sacl_paths:
                    print(
                        f"  SACL {'OK ' if present else 'MISSING'} {path} -> {win_path}"
                    )
            else:
                print("  SACLs:                    none recorded")
        for note in status.notes:
            print(f"  note: {note}")

        if getattr(args, "windows_read_test", False):
            heading("Windows-side read test")
            if ctx.dry_run:
                print(
                    "  [dry-run] skipped write-based reliability test; no probe file created"
                )
            elif not ctx.platform.windows_home:
                print("  no Windows home detected; skipping")
            elif ctx.confirm(
                f"Create a temporary file in {ctx.platform.windows_home}, read it from "
                "Windows, and report whether WSL saw it?"
            ):
                windows_read_test(ctx.platform.windows_home)
            else:
                print("  skipped")
        elif ctx.platform.windows_home:
            print("\n  Tip: `doctor --windows-read-test` runs a genuine Windows-side")
            print("       read and reports whether the WSL watcher observed it.")

    return 0


# --------------------------------------------------------------------------
# plan / create-canaries
# --------------------------------------------------------------------------


def _print_plan(ctx: Context, items, profiles, notes) -> None:
    heading("Platform")
    print(f"  OS:            {ctx.platform.os_name}")
    print(f"  Target user:   {ctx.target.describe()}")
    print(f"  Linux home:    {ctx.target.home}")
    for home in ctx.platform.windows_homes:
        print(f"  Windows home:  {home}")
    print(f"  Profiles:      {', '.join(profiles) or 'none'}")

    creates = [i for i in items if i.action == "create"]
    refreshes = [i for i in items if i.action == "refresh"]
    skips = [i for i in items if i.action == "skip"]
    watch_only = [i for i in items if i.action == "watch-only"]

    heading(f"Canaries to create ({len(creates)})")
    active_config = []
    for item in sorted(creates, key=lambda i: str(i.path)):
        flag = ""
        if item.entry.is_active_config:
            flag = "  [active-config]"
            active_config.append(item)
        print(f"  {item.path}{flag}")
        print(
            f"      kind={item.entry.kind} severity={item.entry.severity} "
            f"profile={item.entry.profile} category={item.entry.category}"
        )
    if not creates:
        print("  (none)")

    if refreshes:
        heading(f"Managed canaries to refresh ({len(refreshes)})")
        print("  Verified as Honeypath-managed: recorded in the database, a regular")
        print("  file, carrying the Honeypath marker, inside the approved home root.")
        for item in sorted(refreshes, key=lambda i: str(i.path)):
            print(f"    {item.path}")

    if active_config:
        heading(f"Active-config canaries ({len(active_config)})")
        for line in catalog_mod.ACTIVE_CONFIG_WARNING:
            print(f"  {line}")
        print("  Every host referenced is under the reserved .invalid TLD, so")
        print("  nothing real is ever contacted. Expect legitimate access to raise")
        print("  alerts — that is useful signal, not a bug.")
        for item in active_config:
            print(f"    {item.path}")

    # Report what the default profile deliberately left out.
    excluded = [
        e
        for e in catalog_mod.active_config_entries(profiles)
        if not any(i.entry.key == e.key for i in creates + refreshes)
    ]
    if excluded:
        heading(f"Active-config canaries EXCLUDED ({len(excluded)})")
        print(f"  {catalog_mod.ACTIVE_CONFIG_EXCLUDED_NOTE}")
        print("  These occupy a default authentication path, token cache, current")
        print("  context or sole configuration file, so enabling them may change")
        print("  how a legitimate tool behaves:")
        for entry in sorted(excluded, key=lambda e: (e.platform, e.relative_path)):
            print(f"    {entry.platform}: {entry.relative_path}")

    if watch_only:
        heading(f"Watch/report-only targets present ({len(watch_only)})")
        print("  Honeypath never creates browser databases; these are watched only.")
        for item in watch_only:
            print(f"    {item.path}")

    heading(f"Skipped ({len(skips)})")
    for item in sorted(skips, key=lambda i: str(i.path)):
        print(f"  {item.path}: {item.reason}")
    if not skips:
        print("  (none)")

    if notes:
        heading("Notes")
        for note in notes:
            print(f"  {note}")

    heading("Available but not enabled")
    state = ssh_canary.ssh_state(ctx.db, ctx.target)
    installation = state["installation"]
    if not installation or installation.get("phase") != ssh_canary.PHASE_ACTIVATED:
        print("  SSH canary: available — run `setup-ssh-canary`, test, then")
        print("              `setup-ssh-canary --activate`")
    else:
        print("  SSH canary: active")
    if ctx.platform.os_name == OS_WSL:
        recorded = ctx.db.get_managed_changes(change_type=windows_audit.CHANGE_SACL)
        if recorded:
            print(f"  Windows auditing: active ({len(recorded)} SACLs recorded)")
        elif interop_available():
            print("  Windows auditing: available — run `setup-windows-audit` to detect")
            print("                    Windows-native reads of /mnt/c canaries")
        else:
            print("  Windows auditing: unavailable (WSL interop is disabled)")

    if state["authorized_keys"]:
        print()
        for line in ssh_canary.authorized_keys_warning(ctx.target.home):
            print(line)


FORCE_REJECTED_MESSAGE = (
    "error: --force is not accepted by this command.\n"
    "  create-canaries and plan must never overwrite an existing file: that file\n"
    "  may be your real AWS, Kubernetes, npm, Docker, Git or database credentials.\n"
    "  Existing paths are always skipped.\n"
    "  To update a canary Honeypath itself created, use --refresh-managed, which\n"
    "  replaces a path only after verifying its recorded exact hash, per-canary\n"
    "  managed identifier, regular-file type, and anchored containment."
)


def reject_force(ctx: Context) -> bool:
    """True when --force was supplied to a command that must never accept it."""
    return bool(_merged(ctx.args, "force", False))


def cmd_plan(ctx: Context) -> int:
    if reject_force(ctx):
        print(FORCE_REJECTED_MESSAGE, file=sys.stderr)
        return 2
    items, profiles, notes = build_plan(ctx)
    _print_plan(ctx, items, profiles, notes)
    return 0


def cmd_create_canaries(ctx: Context) -> int:
    if reject_force(ctx):
        print(FORCE_REJECTED_MESSAGE, file=sys.stderr)
        return 2
    items, profiles, notes = build_plan(ctx)

    if len(ctx.platform.windows_homes) > 1:
        print("Multiple Windows homes were detected:")
        for home in ctx.platform.windows_homes:
            print(f"  {home}")
        if not ctx.confirm(f"Use {ctx.platform.windows_homes[0]}?"):
            print("Aborted. Pass --windows-home <path> to choose explicitly.")
            return 1

    if not bool(getattr(ctx.args, "setup_compact", False)):
        _print_plan(ctx, items, profiles, notes)

    to_create = [i for i in items if i.action == "create"]
    to_refresh = [i for i in items if i.action == "refresh"]
    to_register = [i for i in items if i.action == "watch-only"]
    planned_skips = [i for i in items if i.action == "skip"]
    operations = to_create + to_refresh
    if not operations and not to_register:
        print("\nNothing to create, refresh, or register.")
        print(
            f"Created: 0\nRefreshed: 0\nRegistered watch-only: 0\nSkipped: {len(planned_skips)}"
        )
        return 0
    if ctx.dry_run:
        print("\n[dry-run] no files or database rows will be written.")
        print(f"Created: {len(to_create)} (planned)")
        print(f"Refreshed: {len(to_refresh)} (planned)")
        print(f"Registered watch-only: {len(to_register)} (planned)")
        print(f"Skipped: {len(planned_skips)}")
        return 0

    if any(i.entry.is_active_config for i in operations):
        heading("Active-config canaries are being created")
        for line in catalog_mod.ACTIVE_CONFIG_WARNING:
            print(f"  {line}")

    heading("Creating")
    canarytoken = getattr(ctx, "canarytoken", None)
    created_count = 0
    refreshed_count = 0
    registered_count = 0
    skipped_count = len(planned_skips)
    problems: list[str] = []

    for item in operations:
        best_effort = item.entry.platform == catalog_mod.PLATFORM_WINDOWS
        content = catalog_mod.render_content(item.entry, canarytoken=canarytoken)
        root = home_root_for(ctx, item.entry.platform) or ctx.target.home
        # `refresh_managed` is only ever True for an item the planner already
        # verified through refresh_is_permitted(); it is re-verified here so a
        # file that changed between plan and write is still refused.
        replace_managed = False
        if item.action == "refresh":
            permitted, reason = refresh_is_permitted(ctx, item.path, root, item.entry)
            if not permitted:
                print(f"  {reason}: {item.path}")
                skipped_count += 1
                continue
            replace_managed = True
        existing_row = (
            ctx.db.get_canary_by_path(str(item.path)) if replace_managed else None
        )
        outcome = catalog_mod.create_canary_file(
            item.path,
            content,
            item.entry.mode,
            ctx.target,
            replace_managed=replace_managed,
            best_effort=best_effort,
            root=root,
            expected_content_hash=existing_row.content_hash if existing_row else None,
        )
        if outcome.created:
            try:
                # Hash through one anchored descriptor, then capture metadata
                # from that same descriptor *after* the verification read.
                # Recording the pre-read atime makes our own verification look
                # like an attacker read on the first watch polling pass.
                verify_fd = safe_write.open_regular_nofollow(item.path, root=root)
                try:
                    disk_hash = safe_write.sha256_fd(verify_fd)
                    disk_info = os.fstat(verify_fd)
                finally:
                    os.close(verify_fd)
                baseline = disk_info.st_atime_ns
            except (OSError, safe_write.SafeWriteError) as exc:
                print(f"  failed verification after write: {item.path}: {exc}")
                skipped_count += 1
                continue
            expected_hash = catalog_mod.sha256_text(content)
            if disk_hash != expected_hash or not stat.S_ISREG(disk_info.st_mode):
                print(f"  failed exact identity verification after write: {item.path}")
                skipped_count += 1
                continue
            try:
                ctx.db.record_canary(
                    canary_id=item.entry.key,
                    path=str(item.path),
                    kind=item.entry.kind,
                    severity=item.entry.severity,
                    profile=item.entry.profile,
                    platform=item.entry.platform,
                    intrusiveness=item.entry.intrusiveness,
                    baseline_atime=baseline,
                    active=1,
                    content_hash=expected_hash,
                    managed_marker=catalog_mod.managed_marker(item.entry.key),
                    file_dev=disk_info.st_dev,
                    file_ino=disk_info.st_ino,
                )
            except Exception as exc:
                print(f"  database registration failed for {item.path}: {exc}")
                if item.action == "create":
                    try:
                        safe_write.unlink_regular_if_hash(
                            item.path,
                            root=root,
                            expected_sha256=expected_hash,
                            expected_dev=disk_info.st_dev,
                            expected_ino=disk_info.st_ino,
                        )
                        print(
                            "  removed the exact unregistered canary created by this run"
                        )
                    except Exception as cleanup_exc:
                        print(
                            "  FATAL: could not safely remove the unregistered canary: "
                            f"{cleanup_exc}"
                        )
                skipped_count += 1
                continue
            if item.action == "refresh":
                refreshed_count += 1
                print(f"  refreshed {item.path}")
            else:
                created_count += 1
                print(f"  created {item.path}")
        else:
            skipped_count += 1
            print(f"  {outcome.reason}: {item.path}")
        for problem in outcome.problems:
            problems.append(f"{item.path}: {problem}")

    # Registration is an independent operation set; it must run even when no
    # creatable files are pending.
    for item in to_register:
        root = home_root_for(ctx, item.entry.platform) or ctx.target.home
        try:
            info = safe_write.stat_nofollow(item.path, root=root)
            if not stat.S_ISREG(info.st_mode):
                raise safe_write.SafeWriteError("target is not a regular file")
            baseline = info.st_atime_ns
        except (OSError, safe_write.SafeWriteError) as exc:
            skipped_count += 1
            print(f"  skipped watch-only replacement {item.path}: {exc}")
            continue
        ctx.db.record_canary(
            canary_id=item.entry.key,
            path=str(item.path),
            kind=item.entry.kind,
            severity=item.entry.severity,
            profile=item.entry.profile,
            platform=item.entry.platform,
            intrusiveness=item.entry.intrusiveness,
            baseline_atime=baseline,
            active=1,
            content_hash=None,
            managed_marker=None,
            file_dev=info.st_dev,
            file_ino=info.st_ino,
            managed_by="watch-only",
        )
        registered_count += 1
        print(f"  registered for watching (not created): {item.path}")

    heading("Summary")
    print(f"  Created: {created_count}")
    print(f"  Refreshed: {refreshed_count}")
    print(f"  Registered watch-only: {registered_count}")
    print(f"  Skipped: {skipped_count}")
    if problems:
        heading("Ownership/permission warnings (expected on /mnt/c)")
        for problem in problems:
            print(f"  {problem}")
    return 0


# --------------------------------------------------------------------------
# watch
# --------------------------------------------------------------------------


def cmd_watch(ctx: Context) -> int:
    args = ctx.args
    canaries = ctx.db.get_canaries(active_only=True)

    if getattr(args, "watch_existing_catalog_paths", False):
        items, _, _ = build_plan(ctx)
        known = {c.path for c in canaries}
        from .database import CanaryRow

        for item in items:
            if str(item.path) in known:
                continue
            root = home_root_for(ctx, item.entry.platform) or ctx.target.home
            try:
                info = safe_write.stat_nofollow(item.path, root=root)
            except (OSError, safe_write.SafeWriteError):
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            canaries.append(
                CanaryRow(
                    canary_id=item.entry.key,
                    path=str(item.path),
                    kind=item.entry.kind,
                    severity=item.entry.severity,
                    profile=item.entry.profile,
                    platform=item.entry.platform,
                    intrusiveness=item.entry.intrusiveness,
                    last_baseline_atime=None,
                    active=1,
                )
            )

    if not canaries:
        print("No canaries are recorded. Run `create-canaries` first, or pass")
        print(
            "--watch-existing-catalog-paths to watch catalog paths that already exist."
        )
        return 1
    if ctx.dry_run:
        print(
            f"[dry-run] would watch {len(canaries)} recorded canary path(s); no threads, "
        )
        print(
            "database baselines, checkpoints, events, or alerts were started or changed."
        )
        return 0

    # Opened before anything else can go wrong, so the log records the reasons
    # a session was degraded — not just what it detected afterwards.
    event_log = ctx.open_event_log()
    if event_log.error:
        print(f"Note: the log file is unavailable ({event_log.error}).")
        print("      Detections are still recorded in SQLite and shown here.")
    elif event_log.path is not None:
        print(f"Logging to {event_log.path}")

    win_watcher = None
    if ctx.platform.os_name == OS_WSL:
        windows_canaries = [c for c in canaries if c.platform == "windows"]
        recorded_sacls = ctx.db.get_managed_changes(
            change_type=windows_audit.CHANGE_SACL
        )
        if windows_canaries and recorded_sacls and interop_available():
            win_watcher = windows_audit.WinAuditWatcher(
                ctx.db, windows_canaries, interval=float(args.win_audit_interval)
            )
        elif windows_canaries and not recorded_sacls:
            print("Note: Windows canaries are recorded but Windows auditing is not set")
            print("      up. Windows-native reads will go undetected — run")
            print("      `setup-windows-audit`.")
            event_log.warn(
                "Windows canaries are recorded but Windows auditing is "
                "not set up; Windows-native reads will go undetected"
            )

    if not InotifyWatcher.available():
        print("Note: inotifywait is not installed, so read detection falls back to")
        print(
            "      atime polling only. Install it with: sudo apt install inotify-tools"
        )
        event_log.warn(
            "inotifywait is not installed; read detection falls back to "
            "atime polling only"
        )

    pushover = alerts_mod.Pushover()
    if not pushover.configured():
        print("Note: Pushover is not configured. Detections will still be shown here")
        print("      and stored in SQLite, without repeated delivery-error messages.")
        print("      Configure alerts with: sudo python3 honeypath.py configure-alerts")
        event_log.warn(
            f"Pushover is not configured ({pushover.missing_reason()}); "
            "detections will be recorded but not delivered"
        )
    if ctx.db.is_muted():
        event_log.warn(
            "alerts are MUTED; detections will be recorded but not delivered"
        )

    monitor = Monitor(
        ctx.db,
        canaries,
        cooldown=float(args.cooldown),
        dedup_window=float(args.dedup_window),
        poll_interval=float(args.poll_interval),
        enable_inotify=not args.no_inotify,
        enable_atime=not args.no_atime,
        win_audit_watcher=win_watcher,
        rearm=not args.no_rearm,
        event_log=event_log,
    )

    stopping = threading.Event()

    def handle_signal(signum, _frame):
        print(f"\nreceived signal {signum}; shutting down")
        event_log.info(f"received signal {signum}; shutting down")
        stopping.set()
        monitor.stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print(
        f"Honeypath {VERSION} watching {len(canaries)} canaries "
        f"(cooldown {args.cooldown}s, dedup {args.dedup_window}s)"
    )
    event_log.info(
        f"watch started on {alerts_mod.hostname()} as uid {os.geteuid()}: "
        f"{len(canaries)} canaries, cooldown {args.cooldown}s, "
        f"dedup {args.dedup_window}s, poll {args.poll_interval}s"
    )
    monitor.start()
    time.sleep(0.3)
    for line in monitor.status_lines():
        print(line)
        event_log.info(f"watcher {line.strip()}")
    print("Ctrl-C to stop.\n")

    try:
        while not stopping.is_set():
            monitor.pump(0.5)
    except Exception as exc:
        # A crash in the pump loop is exactly the kind of thing nobody sees
        # under systemd unless it is written down.
        event_log.error_line(f"watch loop failed: {exc.__class__.__name__}: {exc}")
        raise
    finally:
        monitor.stop()
        counts = monitor.counts
        summary = (
            f"events logged: {counts['events']}, alerts sent: {counts['alerts']}, "
            f"cooldown-suppressed: {counts['suppressed']}, muted: {counts['muted']}"
        )
        print(f"\n{summary}")
        event_log.info(f"watch stopped — {summary}")
        event_log.close()
    return 0


# --------------------------------------------------------------------------
# mute / configure-alerts / test-alert / events / install-systemd
# --------------------------------------------------------------------------


def cmd_mute(ctx: Context) -> int:
    minutes = float(ctx.args.minutes)
    if ctx.dry_run:
        print(
            f"[dry-run] would {'un-mute' if minutes <= 0 else f'mute for {minutes:g} minutes'}; database unchanged."
        )
        return 0
    # A mute window is the first thing to check when someone asks why an alert
    # never arrived, so both edges of it are recorded.
    if minutes <= 0:
        ctx.db.set_meta("mute_until_epoch", "0")
        with ctx.open_event_log() as event_log:
            event_log.info("alerts un-muted")
        print("Alerts un-muted.")
        return 0
    until = time.time() + minutes * 60
    ctx.db.set_meta("mute_until_epoch", str(until))
    with ctx.open_event_log() as event_log:
        event_log.warn(
            f"alerts MUTED for {minutes:g} minutes (until "
            f"{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(until))}); "
            "events are still recorded"
        )
    print(
        f"Alerts muted for {minutes:g} minutes "
        f"(until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(until))})."
    )
    print("Events are still recorded in the database while muted.")
    return 0


def configure_alerts_interactive(ctx: Context, *, send_test: bool = True) -> int:
    """Prompt without echoing secrets, store them, and optionally test them."""
    if ctx.dry_run:
        print("[dry-run] would securely prompt for Pushover credentials and store")
        print(f"them in {alerts_mod.CONFIG_DIR}; no prompt, file, or request was made.")
        return 0
    if os.geteuid() != 0:
        print("Pushover setup writes protected files under /etc.")
        print("Re-run this command with sudo.")
        return 1
    if not sys.stdin.isatty():
        print("Pushover setup requires an interactive terminal so credentials can")
        print("be entered without echoing or placing them in shell history.")
        return 1

    print("Enter the Pushover application API token and your user/group key.")
    print("Input is hidden and the values are never printed or stored in SQLite.")
    try:
        token = getpass.getpass("Pushover application token: ")
        user_key = getpass.getpass("Pushover user/group key:  ")
    except (EOFError, KeyboardInterrupt):
        print("\nPushover setup cancelled.")
        return 130
    try:
        token_file, user_file = alerts_mod.store_credentials(
            token, user_key, group_gid=ctx.target.gid
        )
    except (OSError, ValueError, safe_write.SafeWriteError) as exc:
        print(f"Could not store Pushover credentials: {exc}")
        return 1

    group = target_group_name(ctx.target)
    print(f"Stored {token_file} and {user_file} as root:{group}, mode 0640.")
    if not send_test:
        return 0

    sent, error = alerts_mod.Pushover().send(
        f"HONEYPATH test alert from {alerts_mod.hostname()}\n"
        f"target user: {ctx.target.username}",
        title="Honeypath test",
    )
    if sent:
        print("Test alert sent successfully.")
        return 0
    print(f"Credentials were stored, but the test alert failed: {error}")
    print("Run `configure-alerts` again to replace them.")
    return 1


def cmd_configure_alerts(ctx: Context) -> int:
    return configure_alerts_interactive(
        ctx, send_test=not bool(getattr(ctx.args, "no_test", False))
    )


def cmd_setup(ctx: Context) -> int:
    """Guided first-run path covering the ordinary safe-default workflow."""
    heading("Honeypath guided setup")
    print(f"  Target user: {ctx.target.username}")
    print(f"  Linux home:  {ctx.target.home}")
    print(f"  Platform:    {ctx.platform.os_name}")
    if ctx.platform.windows_homes:
        print(f"  Windows home candidates: {len(ctx.platform.windows_homes)}")
        for home in ctx.platform.windows_homes:
            print(f"    {home}")
    print("  Existing credential paths are always skipped and never overwritten.")

    if not InotifyWatcher.available():
        print("\nRecommended dependency missing: inotify-tools")
        print("Install it after setup with: sudo apt install inotify-tools")
        print("Until then Honeypath uses less-reliable atime polling.")
    else:
        print("\nRead-event monitoring: inotify-tools is available.")

    pushover = alerts_mod.Pushover()
    if pushover.configured():
        print("Pushover alerts: already configured.")
    elif ctx.dry_run:
        print("Pushover alerts: not configured (dry-run will not prompt for secrets).")
    elif ctx.confirm("Configure optional Pushover phone alerts now?"):
        code = configure_alerts_interactive(ctx)
        if code != 0:
            print("Guided setup stopped before creating canaries.")
            return code
    else:
        print("Pushover skipped. Events will still be printed and stored locally.")

    if len(ctx.platform.windows_homes) > 1:
        selected = ctx.platform.windows_homes[0]
        if not ctx.confirm(f"Use {selected} as the Windows home?"):
            print("Setup stopped. Re-run with --windows-home <path> to choose another.")
            return 1
        # Keep the choice for the rest of this wizard and avoid asking twice.
        ctx.platform.windows_homes[:] = [selected]

    items, profiles, notes = build_plan(ctx)
    creates = [item for item in items if item.action == "create"]
    skips = [item for item in items if item.action == "skip"]
    heading("Safe-default canaries")
    print(f"  Profiles: {', '.join(profiles) or 'none'}")
    print(f"  New files: {len(creates)}")
    print(f"  Existing/unsupported paths skipped: {len(skips)}")
    print("  Active configuration and SSH canaries are not included in this step.")
    if ctx.confirm("Show the full file-by-file plan?"):
        _print_plan(ctx, items, profiles, notes)
    if ctx.dry_run:
        print("\n[dry-run] setup would next ask to create these canaries, prepare")
        print(
            "optional SSH Phase 1, and install the optional service; nothing changed."
        )
        return 0
    if not ctx.confirm(f"Create these {len(creates)} safe-default canaries?"):
        print("No canaries were created.")
        return 0

    ctx.args.setup_compact = True
    code = cmd_create_canaries(ctx)
    if code != 0:
        return code

    if ctx.platform.os_name == OS_WSL:
        windows_count = len(ctx.db.get_canaries(active_only=True, platform="windows"))
        if windows_count:
            heading("Windows-side detection")
            print(f"  {windows_count} Windows-home canaries were created.")
            if windows_audit.is_elevated():
                if ctx.confirm("Configure Windows Security auditing for them now?"):
                    code = windows_audit.setup_windows_audit(
                        ctx.db, dry_run=False, confirm=ctx.confirm
                    )
                    if code != 0:
                        print(
                            "Windows auditing was not enabled; Linux-side "
                            "monitoring remains usable."
                        )
            else:
                print(
                    "  WSL-side reads are monitored best-effort; DrvFS can miss access"
                )
                print("  events. Reliable Windows-home detection requires Windows")
                print("  administrator privileges; setup-windows-audit explains the")
                print("  elevated PowerShell/WSL command when you are ready.")

    heading("SSH canary (optional, two phases)")
    print("  Phase 1 copies your SSH client state to Honeypath-managed storage and")
    print("  installs ssh/scp/sftp wrappers. It does not replace ~/.ssh yet.")
    print("  You test the wrappers first and activate the canary in a later command.")
    if ctx.confirm("Prepare SSH canary Phase 1 now?"):
        code = cmd_setup_ssh_canary(ctx)
        if code != 0:
            print("Guided setup stopped; the SSH canary was not prepared.")
            return code
    else:
        print(
            "  SSH canary skipped; run "
            "`sudo python3 honeypath.py setup-ssh-canary` later."
        )

    heading("Run continuously")
    if shutil.which("systemctl") and Path("/run/systemd/system").exists():
        if ctx.confirm("Install, enable, and start the Honeypath systemd service?"):
            ctx.args.enable = True
            code = cmd_install_systemd(ctx)
            if code != 0:
                return code
            print("\nGuided setup complete; Honeypath is running as a service.")
            return 0
    else:
        print("  systemd is not active in this WSL distribution.")

    print("Guided setup complete. Start monitoring with:")
    print("  sudo python3 honeypath.py watch")
    return 0


def cmd_test_alert(ctx: Context) -> int:
    if ctx.dry_run:
        print("[dry-run] would send a Pushover test message; no network request made.")
        return 0
    pushover = alerts_mod.Pushover()
    reason = pushover.missing_reason()
    if reason:
        print(f"Pushover is not configured: {reason}")
        print("Run `sudo python3 honeypath.py configure-alerts` for secure prompts.")
        return 1
    message = (
        f"HONEYPATH test alert from {alerts_mod.hostname()}\n"
        f"target user: {ctx.target.username}"
    )
    sent, error = pushover.send(message, title="Honeypath test")
    # The whole point of a test alert is to answer "does delivery work?" later,
    # so its outcome belongs in the same log as real deliveries.
    with ctx.open_event_log() as event_log:
        if sent:
            event_log.info("test alert delivered via Pushover")
            print("Test alert sent.")
            return 0
        event_log.error_line(f"test alert delivery FAILED: {error}")
    print(f"Test alert failed: {error}")
    return 1


def cmd_events(ctx: Context) -> int:
    rows = ctx.db.recent_events(
        limit=int(ctx.args.limit),
        severity=ctx.args.severity,
        path_substring=ctx.args.path_substring,
    )
    if not rows:
        print("No matching events.")
        return 0
    for row in reversed(rows):
        delivery = (
            "sent" if row["pushover_sent"] else (row["pushover_error"] or "not sent")
        )
        print(
            f"{row['timestamp']}  {row['event_type'].upper():9} "
            f"{row['severity'] or '-':8} {row['method']:22} {row['path']}"
        )
        if row["process_info"]:
            print(f"    process: {row['process_info']}")
        print(f"    kind={row['kind'] or '-'}  alert={delivery}")
    print(f"\n{len(rows)} event(s).")
    return 0


# The unit runs as the TARGET USER, never as root.
#
# Honeypath's code lives in a checkout the target user can write.  A root
# service executing that checkout would be a privilege-escalation path: the
# user — or same-user malware — edits a .py file and waits for the next
# restart to get root.  Running as the target user removes the escalation
# entirely: the service can only reach what that user could already reach,
# which is exactly the set of files it needs (their canaries, their home,
# their Windows-mounted home under WSL).
#
# StateDirectory=honeypath makes systemd create and chown
# /var/lib/honeypath to the service user before the process starts, so the
# database and the honeypath.log beside it live at their documented paths
# without any root-owned directory or manual chown.
SYSTEMD_TEMPLATE = """\
[Unit]
Description=Honeypath credential canary monitor
Documentation=https://github.com/honeypath
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Honeypath runs UNPRIVILEGED, as the user whose canaries it watches.
# It must never run as root out of a user-writable checkout: that would let
# anyone who can edit {entry_dir} obtain root at the next restart.
User={user}
Group={group}
ExecStart={python} {entry} --user {user} --db {db}{log_option} watch
Restart=on-failure
RestartSec=10

{state}
# Hardening.  Deliberately NOT set: ProtectHome / PrivateUsers / ProtectSystem=strict,
# any of which would stop Honeypath reading the very canaries it exists to watch,
# and ReadOnlyPaths over /mnt, which would break Windows-home monitoring on WSL.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"""

# systemd creates and chowns the state directory to the service user before
# the process starts, so the database lives at its documented path with no
# root-owned directory and no manual chown.
STATE_DIRECTORY_BLOCK = """\
# systemd creates /var/lib/honeypath owned by the service user before start.
StateDirectory=honeypath
StateDirectoryMode=0700
"""

SYSTEMD_STATE_DIR = Path("/var/lib/honeypath")


def systemd_unit_text(ctx: Context) -> str:
    entry = Path(sys.argv[0]).resolve()
    db_dir = ctx.db.path.parent
    # The log defaults to the database directory, so the common case needs no
    # option and no extra write grant; only an explicit choice is carried into
    # the unit, where the service would otherwise not know about it.
    log_option = ""
    log_dir = None
    if bool(_merged(ctx.args, "no_log_file", False)):
        log_option = " --no-log-file"
    elif _merged(ctx.args, "log_file"):
        log_path = Path(_merged(ctx.args, "log_file")).expanduser()
        log_option = f" --log-file {log_path}"
        if log_path.parent != db_dir:
            log_dir = log_path.parent
    if db_dir == SYSTEMD_STATE_DIR and log_dir is None:
        state = STATE_DIRECTORY_BLOCK
    else:
        # A non-default --db or --log-file still needs an explicit write grant,
        # and the directory must already exist and be writable by the service
        # user.
        grants = [db_dir] if db_dir != SYSTEMD_STATE_DIR else []
        if log_dir is not None:
            grants.append(log_dir)
        listed = " and ".join(str(g) for g in grants)
        state = (
            f"# Non-default database or log location; {listed} must already\n"
            f"# exist and be writable by the service user.\n"
            f"StateDirectory=honeypath\n"
            f"StateDirectoryMode=0700\n"
        ) + "".join(f"ReadWritePaths={grant}\n" for grant in grants)
    return SYSTEMD_TEMPLATE.format(
        python=sys.executable,
        entry=entry,
        entry_dir=entry.parent,
        user=ctx.target.username,
        group=target_group_name(ctx.target),
        db=ctx.db.path,
        db_dir=db_dir,
        log_option=log_option,
        state=state,
    )


def target_group_name(target) -> str:
    """The target user's primary group name (falling back to the gid)."""
    try:
        return grp.getgrgid(target.gid).gr_name
    except (KeyError, OverflowError):  # pragma: no cover - host group db
        return str(target.gid)


def _credential_permission_lines(user: str, group: str) -> list[str]:
    """How to let the service user read the Pushover files without world access."""
    return [
        "The service runs as a non-root user, so it must be able to read the",
        "Pushover credentials without those files becoming world-readable.",
        "Use ONE of these ownership models:",
        "",
        f"  root-owned, group-readable by {group} (recommended):",
        f"    sudo chown root:{group} {alerts_mod.TOKEN_FILE} {alerts_mod.USER_FILE}",
        f"    sudo chmod 0640 {alerts_mod.TOKEN_FILE} {alerts_mod.USER_FILE}",
        f"    sudo chmod 0750 {alerts_mod.CONFIG_DIR}",
        "",
        f"  or owned outright by {user}:",
        f"    sudo chown {user}:{group} {alerts_mod.TOKEN_FILE} {alerts_mod.USER_FILE}",
        f"    sudo chmod 0600 {alerts_mod.TOKEN_FILE} {alerts_mod.USER_FILE}",
        "",
        "Never chmod these files 0644. `doctor` flags a world-readable credential.",
    ]


def _pushover_service_access(ctx: Context) -> tuple[bool, bool]:
    """Return ``(configured, readable_by_service_user)`` without exposing secrets.

    The generated unit runs as the target user.  Check the actual directory and
    file metadata so setup can distinguish an already-correct configuration
    from one that genuinely needs the permission recipe below.
    """
    if not alerts_mod.Pushover().configured():
        return False, False

    def allowed(info, owner_bit: int, group_bit: int, other_bit: int) -> bool:
        if info.st_uid == ctx.target.uid:
            return bool(info.st_mode & owner_bit)
        if info.st_gid == ctx.target.gid:
            return bool(info.st_mode & group_bit)
        return bool(info.st_mode & other_bit)

    try:
        config_info = alerts_mod.CONFIG_DIR.lstat()
        file_infos = [
            path.lstat() for path in (alerts_mod.TOKEN_FILE, alerts_mod.USER_FILE)
        ]
    except OSError:
        return True, False

    if not stat.S_ISDIR(config_info.st_mode) or not allowed(
        config_info, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH
    ):
        return True, False
    for info in file_infos:
        if not stat.S_ISREG(info.st_mode):
            return True, False
        if info.st_mode & stat.S_IROTH:
            return True, False
        if not allowed(info, stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH):
            return True, False
    return True, True


def cmd_install_systemd(ctx: Context) -> int:
    entry = Path(sys.argv[0]).resolve()
    group = target_group_name(ctx.target)
    unit = systemd_unit_text(ctx)
    compact = bool(getattr(ctx.args, "setup_compact", False))
    pushover_configured, pushover_ready = _pushover_service_access(ctx)

    if compact:
        heading("Installing systemd service")
        print(f"  Service account:  {ctx.target.username} (unprivileged)")
        print(f"  Unit:             {SYSTEMD_UNIT_PATH}")
        print(f"  Event database:   {ctx.db.path}")
        print(f"  Log file:         {ctx.log_path or 'disabled (--no-log-file)'}")
    else:
        # Everything the operator needs to check BEFORE the unit is written.
        heading("Service privilege model")
        print(f"  User=                 {ctx.target.username}")
        print(f"  Group=                {group}")
        print(f"  Python:               {sys.executable}")
        print(f"  Executable:           {entry}")
        print(f"  Executable directory: {entry.parent}")
        print(f"  Database:             {ctx.db.path}")
        print(f"  Log file:             {ctx.log_path or 'disabled (--no-log-file)'}")
        print(f"  StateDirectory:       honeypath -> {SYSTEMD_STATE_DIR} (mode 0700)")
        print(f"  Unit path:            {SYSTEMD_UNIT_PATH}")
        print()
        print("  Honeypath runs UNPRIVILEGED as the target user. The service never")
        print("  executes this user-writable checkout as root, which would let anyone")
        print(f"  able to edit {entry.parent}")
        print("  gain root at the next service restart.")
        print()
        print("  Note: the checkout stays writable by the target user. That is safe")
        print("  ONLY because the service also runs as that same user, so editing it")
        print("  grants no privilege the user did not already have.")

    if ctx.dry_run and not compact:
        heading("Pushover credential permissions")
        for line in _credential_permission_lines(ctx.target.username, group):
            print(f"  {line}")
    elif not pushover_configured:
        print("  Pushover alerts:  not configured (events will still be logged)")
    elif pushover_ready:
        print(f"  Pushover alerts:  ready for service user {ctx.target.username}")
    else:
        heading("Pushover credential permissions need attention")
        for line in _credential_permission_lines(ctx.target.username, group):
            print(f"  {line}")

    if not compact:
        heading("Unit file")
        print(unit)

    if ctx.dry_run:
        print(f"[dry-run] would write {SYSTEMD_UNIT_PATH}")
        return 0
    try:
        SYSTEMD_UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            previous_unit_hash = safe_write.sha256_anchored(
                SYSTEMD_UNIT_PATH, root=SYSTEMD_UNIT_PATH.parent
            )
        except FileNotFoundError:
            previous_unit_hash = None
        safe_write.atomic_write(
            SYSTEMD_UNIT_PATH,
            unit,
            mode=0o644,
            root=SYSTEMD_UNIT_PATH.parent,
            uid=0,
            gid=0,
            fsync_data=True,
            replace=previous_unit_hash is not None,
            expected_sha256=previous_unit_hash,
        )
    except (OSError, safe_write.SafeWriteError) as exc:
        print(f"cannot write {SYSTEMD_UNIT_PATH}: {exc}")
        return 1
    print(f"  Wrote unit:       {SYSTEMD_UNIT_PATH}")

    if getattr(ctx.args, "enable", False):
        for command in (
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", "honeypath.service"],
        ):
            proc = subprocess.run(command, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
                print(f"  Failed: {' '.join(command)}: {detail}")
                return 1
        print("  Service:          enabled and running")
        print("\nOptional inspection:")
        print("  systemctl status honeypath.service")
        print("  sudo journalctl -u honeypath -f")
    else:
        print("\nService installed but not started. To enable it now:")
        print("  sudo systemctl daemon-reload")
        print("  sudo systemctl enable --now honeypath.service")
    return 0


# --------------------------------------------------------------------------
# SSH commands
# --------------------------------------------------------------------------


def cmd_setup_ssh_canary(ctx: Context) -> int:
    args = ctx.args
    target = ctx.target
    home = target.home
    source = home / ".ssh"
    destination = ssh_canary.relocated_dir(home)

    # This guard deliberately precedes inventory, hashing, copying, config
    # regeneration, and wrapper changes.  An activated canary directory is
    # never a migration source, including under --force.
    existing_installation = ctx.db.get_ssh_installation(str(home))
    existing_phase = (
        existing_installation.get("phase") if existing_installation else None
    )
    filesystem_canary = ssh_canary.looks_like_canary_dir(source)
    if existing_phase == ssh_canary.PHASE_ACTIVATED and filesystem_canary:
        backup = existing_installation.get("backup_path")
        print("SSH canary is already activated; activation is permanently single-shot.")
        print("--force cannot resynchronise or reactivate an activated installation.")
        print(f"Original recorded backup: {backup}")
        return 0
    if existing_phase == ssh_canary.PHASE_ACTIVATED and not filesystem_canary:
        print("BLOCKED: database/filesystem mismatch: SQLite says activated but ~/.ssh")
        print(
            "is not the Honeypath canary directory. Do not use --force or activate again."
        )
        print(
            f"Recover with `ssh-status` / `restore-ssh-canary` and backup: "
            f"{existing_installation.get('backup_path')}"
        )
        return 1
    if filesystem_canary and existing_phase != ssh_canary.PHASE_ACTIVATED:
        print("BLOCKED: ~/.ssh looks activated but SQLite does not. This may be an")
        print("interrupted older activation. Do not use --force; restore the original")
        print("backup manually, then repeat Phase 1.")
        return 1

    if args.activate:
        return _activate_ssh_canary(ctx)

    heading("Plan")
    print(ssh_canary.CONFIRM_PROMPT)
    print(f"\n  target user:     {target.describe()}")
    print(f"  source:          {source}")
    print(f"  relocated dir:   {destination}")
    print(
        f"  wrappers:        {', '.join(str(ssh_canary.wrapper_dir(home) / n) for n in ssh_canary.SSH_BINARIES)}"
    )
    print(
        f"  agent forwarding: {'ALLOWED (--allow-agent-forwarding)' if args.allow_agent_forwarding else 'disabled'}"
    )

    warnings = ssh_canary.authorized_keys_warning(home)
    if warnings:
        print()
        for line in warnings:
            print(line)

    if not ctx.dry_run and not ctx.confirm("Continue?"):
        print("Aborted.")
        return 1

    heading("Phase 1: copying SSH client state")
    inventory = ssh_canary.inventory_ssh_dir(
        source, allow_unsafe_symlinks=args.allow_unsafe_symlinks
    )
    if inventory.refused:
        print("  refused (not copied):")
        for item in inventory.refused:
            print(f"    {item}")
    if not inventory.entries:
        print(f"  {source} contains no regular files to copy")
    installation = ctx.db.get_ssh_installation(str(home)) or {}
    plan = ssh_canary.plan_copy(
        inventory, destination, previous_hashes=installation.get("source_hashes", {})
    )
    print(
        f"  to copy: {len(plan.to_copy)}, unchanged: {len(plan.unchanged)}, "
        f"conflicts: {len(plan.conflicts)}"
    )
    try:
        copy_warnings = ssh_canary.copy_inventory(
            source,
            destination,
            inventory,
            plan,
            target,
            force=ctx.force,
            dry_run=ctx.dry_run,
        )
    except ssh_canary.SSHCanaryError as exc:
        print(f"\nFAILED: {exc}")
        return 1
    for warning in copy_warnings:
        print(f"  WARNING: {warning}")

    if not ctx.dry_run:
        ssh_canary.known_hosts_seed(target)

    heading("Phase 1: building the relocated config")
    baseline_ok, baseline_lines, baseline_error = ssh_canary.ssh_dash_g(
        "github.com", target=target
    )
    if not baseline_ok:
        print(f"  note: could not capture a baseline `ssh -G`: {baseline_error}")
    result = ssh_canary.prepare_relocated_config(
        ctx.db,
        target,
        allow_agent_forwarding=args.allow_agent_forwarding,
        force_managed_identities=args.force_managed_identities,
        force=ctx.force,
        dry_run=ctx.dry_run,
        baseline=baseline_lines if baseline_ok else None,
    )
    for warning in result.warnings:
        print(f"  WARNING: {warning}")
    if result.blockers:
        heading("Activation blockers")
        for blocker in result.blockers:
            print(f"  {blocker}")
        print("\nPhase 1 stopped. Resolve the blockers above and re-run.")
        return 1

    heading("Phase 1: installing wrappers")
    problems = ssh_canary.install_wrappers(
        ctx.db, target, force=ctx.force, dry_run=ctx.dry_run
    )
    if problems:
        for problem in problems:
            print(f"  {problem}")
        return 1

    heading("PATH")
    if ssh_canary.path_contains_wrapper_dir(target):
        print(f"  {ssh_canary.wrapper_dir(home)} is already in PATH")
    else:
        print(f"  {ssh_canary.wrapper_dir(home)} is NOT in PATH")
        for rc_name in (".zshrc", ".bashrc"):
            rc_file = home / rc_name
            if not rc_file.exists() and rc_name == ".bashrc":
                continue
            if ctx.confirm(f"Add a Honeypath-managed PATH block to {rc_file}?"):
                ssh_canary.install_rc_block(
                    ctx.db, target, rc_file, dry_run=ctx.dry_run
                )

    heading("Git")
    if args.skip_git:
        print("  skipped (--skip-git)")
    else:
        ssh_canary.set_git_ssh_command(
            ctx.db, target, force=ctx.force, dry_run=ctx.dry_run, confirm=ctx.confirm
        )

    if args.canarytoken_aws_file:
        heading("Canarytokens")
        print(f"  AWS material will be spliced into .aws/credentials canaries from")
        print(
            f"  {args.canarytoken_aws_file} on the next "
            "`create-canaries --refresh-managed` run."
        )

    if not ctx.dry_run:
        ctx.db.upsert_ssh_installation(
            home=str(home),
            username=target.username,
            uid=target.uid,
            relocated_dir=str(destination),
            phase=ssh_canary.PHASE_PREPARED,
            source_hashes={
                **installation.get("source_hashes", {}),
                **inventory.hashes(),
            },
            config_validation=result.validation_status,
        )

    heading("Phase 1 complete — test before activating")
    print("Run these and confirm they behave as expected. None of them needs to")
    print("reach a real host: example.invalid never resolves, so a DNS failure is a")
    print("PASS. What they verify is which binary and which config got selected.\n")
    for command in ssh_canary.PHASE1_TEST_COMMANDS:
        print(f"  {command}")
    print()
    for line in ssh_canary.PHASE1_TEST_NOTES:
        print(f"  {line}")

    heading("What activation will break, on purpose")
    for line in ssh_canary.DIRECT_SSH_WARNING:
        print(f"  {line}" if line else "")

    print("\nWhen you are satisfied (days later is fine), run:")
    print("  sudo python3 honeypath.py setup-ssh-canary --activate")
    print("\nNothing under ~/.ssh has been changed yet.")
    return 0


def _activate_ssh_canary(ctx: Context) -> int:
    args = ctx.args
    target = ctx.target
    home = target.home
    source = home / ".ssh"
    destination = ssh_canary.relocated_dir(home)

    installation = ctx.db.get_ssh_installation(str(home))
    if not installation:
        print("Phase 1 has not been run for this home. Run `setup-ssh-canary` first.")
        return 1
    phase = installation.get("phase")
    filesystem_canary = ssh_canary.looks_like_canary_dir(source)
    if phase == ssh_canary.PHASE_ACTIVATED and filesystem_canary:
        print("SSH canary is already activated; no files or metadata were changed.")
        print(f"Original recorded backup: {installation.get('backup_path')}")
        return 0
    if phase == ssh_canary.PHASE_ACTIVATED or filesystem_canary:
        print("BLOCKED: database and ~/.ssh disagree about activation state.")
        print("Do not use --force. Run `ssh-status` and recover from the recorded")
        print(f"backup: {installation.get('backup_path')}")
        return 1
    if phase != ssh_canary.PHASE_PREPARED:
        print(f"BLOCKED: expected Phase 1 state 'prepared', found {phase!r}.")
        return 1
    if installation.get("backup_path"):
        print("BLOCKED: this installation already has an original activation backup;")
        print("activation is permanently single-shot and --force cannot repeat it.")
        return 1

    heading("Phase 2: activation")
    print(f"  target user:   {target.describe()}")
    print(f"  ~/.ssh:        {source}")
    print(f"  relocated dir: {destination}")

    if source.is_symlink():
        print("\nBLOCKED: ~/.ssh is a symlink. Honeypath will not rename it.")
        return 1

    heading("Wrappers")
    for status in ssh_canary.wrapper_statuses(home):
        print(f"  {status.describe()}")
        if not status.exists or not status.ours:
            print(
                "\nBLOCKED: install the Honeypath wrappers first (`setup-ssh-canary`)."
            )
            return 1

    warnings = ssh_canary.authorized_keys_warning(home)
    if warnings:
        print()
        for line in warnings:
            print(line)

    print()
    print("Activation will:")
    print(
        f"  1. rename {source} to a timestamped backup under "
        f"{ssh_canary.backup_root(home)}"
    )
    print(f"  2. create a fresh {source} (0700) containing canaries")
    print("  3. the canary ~/.ssh/config is DELIBERATELY INVALID so that any program")
    print("     still calling /usr/bin/ssh directly fails loudly instead of silently")
    print("     being handed fake keys")
    if not args.no_authorized_keys:
        print("  4. copy authorized_keys back into the new ~/.ssh (not a canary)")
    print("\nYour original ~/.ssh will NOT be deleted.")

    heading("Read this before continuing")
    for line in ssh_canary.DIRECT_SSH_WARNING:
        print(f"  {line}" if line else "")

    heading("Pre-activation checklist")
    print("Run these now and confirm each behaves as described. None of them needs")
    print("to reach a real host — example.invalid never resolves, and a DNS failure")
    print("is a PASS. What matters is which binary and which config got selected.\n")
    for command in ssh_canary.PHASE1_TEST_COMMANDS:
        print(f"  {command}")
    print()
    for line in ssh_canary.PHASE1_TEST_NOTES:
        print(f"  {line}")

    if not ctx.dry_run and not ctx.confirm("Activate the SSH canary now?"):
        print("Aborted.")
        return 1

    # The checklist may take minutes or days.  Only after confirmation do we
    # take the authoritative inventory, synchronize every byte, rebuild the
    # generated config, and proceed immediately to the rename.
    heading("Final just-in-time SSH synchronization")
    inventory = ssh_canary.inventory_ssh_dir(
        source, allow_unsafe_symlinks=args.allow_unsafe_symlinks
    )
    if inventory.refused:
        print("BLOCKED: current ~/.ssh contains entries that cannot be migrated:")
        for item in inventory.refused:
            print(f"  {item}")
        return 1
    previous = installation.get("source_hashes", {})
    plan = ssh_canary.plan_copy(
        inventory, destination, previous_hashes=previous, root=home
    )
    if plan.conflicts and not ctx.force:
        print("BLOCKED: relocated files have independent edits:")
        for rel in plan.conflicts:
            print(f"  {destination / rel}")
        print("Resolve them, or use --force for this Phase-1 conflict only.")
        return 1
    try:
        for warning in ssh_canary.copy_inventory(
            source,
            destination,
            inventory,
            plan,
            target,
            force=ctx.force,
            dry_run=ctx.dry_run,
            strict=not ctx.dry_run,
        ):
            print(f"  WARNING: {warning}")
        if not ctx.dry_run:
            ssh_canary.verify_relocated_inventory(inventory, destination, root=home)
    except ssh_canary.SSHCanaryError as exc:
        print(f"FAILED: {exc}")
        return 1

    heading("Final relocated-config rebuild and validation")
    baseline_ok, baseline_lines, _ = ssh_canary.ssh_dash_g("github.com", target=target)
    result = ssh_canary.prepare_relocated_config(
        ctx.db,
        target,
        allow_agent_forwarding=args.allow_agent_forwarding,
        force_managed_identities=args.force_managed_identities,
        force=ctx.force,
        dry_run=ctx.dry_run,
        baseline=baseline_lines if baseline_ok else None,
    )
    for warning in result.warnings:
        print(f"  WARNING: {warning}")
    if result.blockers or result.validation_status == "failed":
        for blocker in result.blockers:
            print(f"  {blocker}")
        print("BLOCKED: the final relocated config did not validate.")
        return 1

    heading("Activating")
    ok, backup = ssh_canary.activate(
        ctx.db,
        target,
        keep_authorized_keys=not args.no_authorized_keys,
        force=ctx.force,
        dry_run=ctx.dry_run,
        expected_inventory=inventory,
    )
    if not ok:
        return 3 if backup is not None else 1

    heading("Done")
    print(f"  BACKUP OF YOUR ORIGINAL ~/.ssh: {backup}")
    print("  Backups are never deleted by Honeypath.")
    print("\nVerify now:")
    for command in ssh_canary.PHASE1_TEST_COMMANDS:
        print(f"  {command}")
    print("\nTo undo everything:  sudo python3 honeypath.py restore-ssh-canary")
    return 0


def cmd_restore_ssh_canary(ctx: Context) -> int:
    target = ctx.target
    home = target.home
    ssh_dir = home / ".ssh"
    installation = ctx.db.get_ssh_installation(str(home))

    heading("Wrappers")
    ssh_canary.remove_wrappers(ctx.db, target, dry_run=ctx.dry_run)

    heading("~/.ssh")
    backup = (
        Path(installation["backup_path"])
        if installation and installation.get("backup_path")
        else None
    )
    backup_unsafe = False
    if backup is not None:
        try:
            backup_info = safe_write.stat_nofollow(backup, root=home)
            backup_unsafe = not stat.S_ISDIR(backup_info.st_mode)
        except FileNotFoundError:
            backup_info = None
        except (OSError, safe_write.SafeWriteError):
            backup_info = None
            backup_unsafe = True
    else:
        backup_info = None
    if backup is not None and backup_unsafe:
        print(f"  recorded backup {backup} is a symlink, non-directory, or unsafe")
        print("  refusing automatic restoration; inspect it and recover manually")
        backup = None
    elif backup is not None and backup_info is None:
        # The recorded backup was moved or renamed by hand.  Fall back to the
        # most recent backup still on disk rather than giving up; Honeypath
        # never deletes backups, so an older one is usually still there.
        print(f"  recorded backup {backup} no longer exists")
        fallback = ssh_canary.latest_valid_backup(home)
        if fallback is not None:
            print(f"  falling back to the most recent valid backup: {fallback}")
            backup = fallback
        else:
            backup = None
            print("  no other backup found; leaving ~/.ssh alone")
    elif backup is None:
        fallback = ssh_canary.latest_valid_backup(home)
        if fallback is not None:
            print(f"  no backup recorded; most recent valid backup on disk: {fallback}")
            backup = fallback
    if backup is None:
        print("  no recorded backup; leaving ~/.ssh alone")
    else:
        can_replace = (
            not ssh_dir.exists()
            or ssh_canary.looks_like_canary_dir(ssh_dir)
            or ctx.force
        )
        if not can_replace:
            print(f"  {ssh_dir} does not look like a Honeypath canary directory;")
            print("  refusing to overwrite it (use --force if you are sure).")
            print(f"  Your backup is at: {backup}")
        elif ctx.confirm(f"Restore {backup} to {ssh_dir}?"):
            if ctx.dry_run:
                print(f"  [dry-run] move {ssh_dir} aside and restore {backup}")
            else:
                aside = None
                if ssh_dir.exists():
                    aside = (
                        home / f".ssh.honeypath-canary-{ssh_canary.timestamp_slug()}"
                    )
                    try:
                        safe_write.rename_noreplace(ssh_dir, aside, root=home)
                        print(f"  moved the canary directory to {aside}")
                    except (OSError, safe_write.SafeWriteError) as exc:
                        print(f"  could not move {ssh_dir}: {exc}")
                        return 1
                try:
                    safe_write.rename_noreplace(backup, ssh_dir, root=home)
                    print(f"  restored {backup} -> {ssh_dir}")
                except (OSError, safe_write.SafeWriteError) as exc:
                    print(f"  could not restore backup: {exc}")
                    if aside is not None:
                        safe_write.rename_noreplace(aside, ssh_dir, root=home)
                    return 1
                ctx.db.deactivate_under(str(ssh_dir) + "/")

    heading("Git")
    ssh_canary.restore_git_ssh_command(ctx.db, target, dry_run=ctx.dry_run)

    heading("Shell rc files")
    if ctx.confirm("Remove the Honeypath PATH block from your rc files?"):
        ssh_canary.remove_rc_blocks(ctx.db, target, dry_run=ctx.dry_run)
    else:
        print("  left in place")

    if not ctx.dry_run:
        deactivated = ctx.db.deactivate_under(str(ssh_dir) + "/")
        ctx.db.upsert_ssh_installation(
            home=str(home),
            username=target.username,
            uid=target.uid,
            relocated_dir=str(ssh_canary.relocated_dir(home)),
            phase=ssh_canary.PHASE_RESTORED,
        )
        heading("Database")
        print(
            f"  deactivated {deactivated} SSH canary row(s); "
            "create-canaries is gated again"
        )

    heading("Kept")
    print(f"  relocated SSH state: {ssh_canary.relocated_dir(home)} (not removed)")
    print(f"  backups:             {ssh_canary.backup_root(home)} (never deleted)")
    for path in ssh_canary.list_backups(home):
        print(f"    {path}")
    return 0


def cmd_ssh_status(ctx: Context) -> int:
    target = ctx.target
    state = ssh_canary.ssh_state(ctx.db, target)

    heading("SSH canary status")
    print(f"  target user:            {target.describe()}")
    print(f"  ~/.ssh exists:          {state['ssh_dir_exists']}")
    print(f"  ~/.ssh is a symlink:    {state['ssh_dir_is_symlink']}")
    if state["ssh_dir_exists"]:
        keys = [p.name for p in sorted((target.home / ".ssh").glob("*"))]
        print(f"  ~/.ssh contents:        {', '.join(keys) or '(empty)'}")
    print(f"  ~/.ssh holds canaries:  {state['ssh_dir_is_canary']}")
    print(
        f"  relocated dir:          {state['relocated_dir']} "
        f"({'present' if state['relocated_dir_exists'] else 'absent'})"
    )
    print(
        f"  relocated config:       {state['relocated_config']} "
        f"({'present' if state['relocated_config_exists'] else 'absent'})"
    )
    if state["relocated_dir_exists"]:
        keys = ssh_canary.discover_identity_files(state["relocated_dir"])
        print(f"  relocated keys:         {', '.join(k.name for k in keys) or 'none'}")

    heading("Wrappers and PATH")
    for wrapper in state["wrappers"]:
        print(f"  {wrapper.describe()}")
    print(f"  which ssh:              {ssh_canary.which_ssh(target) or 'not found'}")
    print(f"  ~/bin in current PATH:  {ssh_canary.path_contains_wrapper_dir(target)}")

    heading("Git")
    current = ssh_canary.git_ssh_command(target)
    recorded = ctx.db.get_managed_changes(
        change_type=ssh_canary.CHANGE_GIT_SSH, home=str(target.home)
    )
    print(f"  core.sshCommand (now):      {current or '<unset>'}")
    if recorded:
        change = recorded[0]
        print(f"  core.sshCommand (recorded): {change['new_value']}")
        print(
            f"  previous value:             "
            f"{change['previous_value'] if change['previous_existed'] else '<unset>'}"
        )
    else:
        print("  core.sshCommand (recorded): none")

    installation = state["installation"]
    heading("Installation")
    if installation:
        print(f"  phase:              {installation['phase']}")
        print(f"  activated at:       {installation.get('activated_at') or '-'}")
        print(f"  backup path:        {installation.get('backup_path') or '-'}")
        print(f"  config validation:  {installation.get('config_validation') or '-'}")
    else:
        print("  not started")

    backups = ssh_canary.list_backups(target.home)
    print(f"  backups on disk:    {len(backups)} (Honeypath never deletes them)")
    for path in backups:
        print(f"    {path}")

    heading("Direct /usr/bin/ssh use (bypassing the wrappers)")
    direct = ssh_canary.direct_ssh_status(ctx.db, target)
    print(f"  supported: {'yes' if direct['supported'] else 'NO'}")
    print(f"  {direct['reason']}")
    for line in direct["lines"]:
        print(f"  {line}" if line else "")

    heading("Recent SSH canary events")
    rows = ctx.db.recent_events(
        limit=int(getattr(ctx.args, "limit", 10)), path_substring=".ssh"
    )
    if not rows:
        print("  none")
    for row in reversed(rows):
        print(
            f"  {row['timestamp']}  {row['event_type']:9} {row['method']:20} {row['path']}"
        )
    return 0


# --------------------------------------------------------------------------
# Windows auditing
# --------------------------------------------------------------------------


def cmd_setup_windows_audit(ctx: Context) -> int:
    if ctx.platform.os_name != OS_WSL:
        print("setup-windows-audit only applies under WSL.")
        return 1

    if getattr(ctx.args, "restore", False):
        heading("Restore Windows audit state")
        windows_audit.remove_windows_sacls(ctx.db, dry_run=ctx.dry_run)
        windows_audit.restore_windows_audit_policy(ctx.db, dry_run=ctx.dry_run)
        windows_audit.remove_windows_watcher(ctx.db, dry_run=ctx.dry_run)
        return 0

    code = windows_audit.setup_windows_audit(
        ctx.db, dry_run=ctx.dry_run, confirm=ctx.confirm
    )
    if code != 0:
        return code

    if getattr(ctx.args, "install_windows_watcher", False):
        heading("Optional Windows-resident watcher")
        home = ctx.platform.windows_home
        if home is None:
            print("  no Windows home detected; skipping")
            return code
        token_path, user_path = alerts_mod.TOKEN_FILE, alerts_mod.USER_FILE
        try:
            token = token_path.read_text().strip()
            user_key = user_path.read_text().strip()
        except OSError as exc:
            print(f"  cannot read Pushover credentials: {exc}")
            return 1
        if not ctx.confirm(
            "Write a PowerShell watcher (containing your Pushover credentials) into "
            f"{home}\\.honeypath and register it as a logon scheduled task?"
        ):
            print("  skipped")
            return code
        code = windows_audit.install_windows_watcher(
            ctx.db, home, token=token, user_key=user_key, dry_run=ctx.dry_run
        )
    return code


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser, *, allow_force: bool = True) -> None:
    parser.add_argument("--user", help="target user (defaults to SUDO_USER, then you)")
    parser.add_argument(
        "--allow-root", action="store_true", help="permit operating on root's home"
    )
    parser.add_argument("--db", help=f"database path (default {DEFAULT_DB_PATH})")
    parser.add_argument(
        "--log-file",
        help=f"human-readable log path (default: {eventlog.LOG_NAME} "
        f"beside the database, i.e. {eventlog.DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--no-log-file", action="store_true", help="do not write the human-readable log"
    )
    parser.add_argument("--windows-home", help="explicit Windows home under /mnt")
    parser.add_argument("--yes", action="store_true", help="assume yes to prompts")
    parser.add_argument(
        "--dry-run", action="store_true", help="show what would happen; change nothing"
    )
    if allow_force:
        # Only narrowly scoped operations accept --force: replacing a foreign
        # ~/bin/ssh wrapper, resolving a relocated-SSH copy conflict, and
        # restoring over a ~/.ssh that no longer looks Honeypath-managed.
        # create-canaries and plan deliberately do NOT (see FORCE_REJECTED_MESSAGE).
        parser.add_argument(
            "--force",
            action="store_true",
            help="resolve conflicts in SSH wrapper/copy/restore "
            "operations; never permits overwriting a canary "
            "target",
        )


def _add_profile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profiles",
        action="append",
        default=None,
        help="profiles to use (repeatable or comma-separated); " "default: auto",
    )
    parser.add_argument(
        "--include-crypto", action="store_true", help="include crypto-wallet canaries"
    )
    parser.add_argument(
        "--include-noisy",
        action="store_true",
        help="include browser-noisy watch targets",
    )
    parser.add_argument(
        "--include-active-config",
        action="store_true",
        help="also include behaviour-changing active-config "
        "canaries (gcloud ADC, Azure token cache, kubeconfig, "
        "dbt profiles, gh hosts, doctl, huggingface token). "
        "These occupy default authentication paths and MAY "
        "AFFECT LEGITIMATE TOOLS",
    )
    parser.add_argument(
        "--canarytoken-aws-file",
        help="file holding user-supplied Canarytokens AWS key material "
        "to splice into .aws/credentials canaries",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypath.py",
        description="Honeypath — defensive credential-canary monitor "
        "(detection, not prevention).",
    )
    parser.add_argument("--version", action="version", version=f"honeypath {VERSION}")
    # Top-level copies, so `honeypath.py --user alan plan` works too.
    parser.add_argument("--user", dest="top_user", help=argparse.SUPPRESS)
    parser.add_argument(
        "--allow-root",
        dest="top_allow_root",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--db", dest="top_db", help=argparse.SUPPRESS)
    parser.add_argument("--log-file", dest="top_log_file", help=argparse.SUPPRESS)
    parser.add_argument(
        "--no-log-file",
        dest="top_no_log_file",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--windows-home", dest="top_windows_home", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--yes", dest="top_yes", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--dry-run", dest="top_dry_run", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--force", dest="top_force", action="store_true", help=argparse.SUPPRESS
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    setup = sub.add_parser(
        "setup", help="guided first-run setup (alerts, canaries, and service)"
    )
    _add_common(setup, allow_force=False)
    _add_profile_options(setup)
    setup.set_defaults(
        handler=cmd_setup,
        activate=False,
        allow_agent_forwarding=False,
        allow_unsafe_symlinks=False,
        force_managed_identities=False,
        no_authorized_keys=False,
        skip_git=False,
    )

    doctor = sub.add_parser(
        "doctor", help="report the environment and monitoring capability"
    )
    _add_common(doctor, allow_force=False)
    doctor.add_argument(
        "--windows-read-test",
        action="store_true",
        help="offer a genuine Windows-side read test (WSL only)",
    )
    doctor.set_defaults(handler=cmd_doctor)

    # plan and create-canaries do not accept --force: they must never be able
    # to overwrite a real credential file.
    plan = sub.add_parser("plan", help="show what create-canaries would do")
    _add_common(plan, allow_force=False)
    _add_profile_options(plan)
    plan.add_argument(
        "--refresh-managed",
        action="store_true",
        help="show which existing canaries could be safely refreshed",
    )
    plan.set_defaults(handler=cmd_plan)

    create = sub.add_parser(
        "create-canaries",
        help="create the canary files (never overwrites an existing path)",
        description="Create canary files. An existing path is ALWAYS skipped — "
        "there is no --force. Use --refresh-managed to update a "
        "canary Honeypath itself created and still owns.",
    )
    _add_common(create, allow_force=False)
    _add_profile_options(create)
    create.add_argument(
        "--refresh-managed",
        action="store_true",
        help="replace an existing canary ONLY when it is recorded "
        "as active Honeypath-managed and its exact content hash "
        "and per-canary identifier still match inside the approved "
        "home root. Use this to update an AWS canary with "
        "Canarytokens material",
    )
    create.set_defaults(handler=cmd_create_canaries)

    watch = sub.add_parser("watch", help="watch the canaries and alert on access")
    _add_common(watch, allow_force=False)
    _add_profile_options(watch)
    watch.add_argument(
        "--watch-existing-catalog-paths",
        action="store_true",
        help="also watch catalog paths that exist but were not created " "by Honeypath",
    )
    watch.add_argument(
        "--cooldown",
        default=DEFAULT_COOLDOWN,
        type=float,
        help="seconds between alerts for the same path",
    )
    watch.add_argument(
        "--dedup-window",
        default=DEFAULT_DEDUP_WINDOW,
        type=float,
        help="seconds over which one logical read is collapsed",
    )
    watch.add_argument(
        "--poll-interval",
        default=DEFAULT_POLL_INTERVAL,
        type=float,
        help="atime polling interval in seconds",
    )
    watch.add_argument(
        "--win-audit-interval",
        default=60.0,
        type=float,
        help="Security-log polling interval in seconds",
    )
    watch.add_argument("--no-inotify", action="store_true")
    watch.add_argument("--no-atime", action="store_true")
    watch.add_argument(
        "--no-rearm",
        action="store_true",
        help="do not bump canary mtimes to re-arm relatime",
    )
    watch.set_defaults(handler=cmd_watch)

    mute = sub.add_parser(
        "mute", help="suppress alerts for a while (events still logged)"
    )
    _add_common(mute, allow_force=False)
    mute.add_argument(
        "--minutes", default=60, type=float, help="minutes to mute; 0 un-mutes"
    )
    mute.set_defaults(handler=cmd_mute)

    configure_alerts = sub.add_parser(
        "configure-alerts", help="securely prompt for and test Pushover credentials"
    )
    _add_common(configure_alerts, allow_force=False)
    configure_alerts.add_argument(
        "--no-test",
        action="store_true",
        help="store credentials without sending a test alert",
    )
    configure_alerts.set_defaults(handler=cmd_configure_alerts)

    test_alert = sub.add_parser("test-alert", help="send a Pushover test message")
    _add_common(test_alert, allow_force=False)
    test_alert.set_defaults(handler=cmd_test_alert)

    events = sub.add_parser("events", help="show recent events")
    _add_common(events, allow_force=False)
    events.add_argument("--limit", default=20, type=int)
    events.add_argument("--severity")
    events.add_argument("--path-substring")
    events.set_defaults(handler=cmd_events)

    systemd = sub.add_parser("install-systemd", help="write the systemd unit")
    _add_common(systemd, allow_force=False)
    systemd.add_argument(
        "--enable",
        action="store_true",
        help="also daemon-reload, enable and start the service",
    )
    systemd.set_defaults(handler=cmd_install_systemd)

    setup_ssh = sub.add_parser(
        "setup-ssh-canary",
        help="relocate real SSH state (phase 1) / activate (phase 2)",
    )
    _add_common(setup_ssh)
    setup_ssh.add_argument(
        "--activate",
        action="store_true",
        help="single-shot phase 2: transactionally back up ~/.ssh "
        "and replace it with canaries; --force cannot repeat it",
    )
    setup_ssh.add_argument(
        "--allow-agent-forwarding",
        action="store_true",
        help="do not disable ForwardAgent in the relocated config",
    )
    setup_ssh.add_argument(
        "--allow-unsafe-symlinks",
        action="store_true",
        help="report legacy symlink intent; anchored migration never "
        "follows SSH source symlinks",
    )
    setup_ssh.add_argument(
        "--force-managed-identities",
        action="store_true",
        help="add relocated keys as defaults even when your config "
        "already declares IdentityFile entries",
    )
    setup_ssh.add_argument(
        "--no-authorized-keys",
        action="store_true",
        help="do not copy authorized_keys into the new ~/.ssh",
    )
    setup_ssh.add_argument(
        "--skip-git", action="store_true", help="do not touch git core.sshCommand"
    )
    setup_ssh.add_argument(
        "--canarytoken-aws-file", help="user-supplied Canarytokens AWS key material"
    )
    setup_ssh.set_defaults(handler=cmd_setup_ssh_canary)

    restore = sub.add_parser("restore-ssh-canary", help="undo the SSH canary setup")
    _add_common(restore)
    restore.set_defaults(handler=cmd_restore_ssh_canary)

    status = sub.add_parser("ssh-status", help="report SSH canary state")
    _add_common(status, allow_force=False)
    status.add_argument("--limit", default=10, type=int)
    status.set_defaults(handler=cmd_ssh_status)

    winaudit = sub.add_parser(
        "setup-windows-audit", help="enable Windows SACL auditing for Windows canaries"
    )
    _add_common(winaudit, allow_force=False)
    winaudit.add_argument(
        "--install-windows-watcher",
        action="store_true",
        help="also install the optional Windows-resident watcher",
    )
    winaudit.add_argument(
        "--restore",
        action="store_true",
        help="restore exact recorded SACLs and remove the optional "
        "Windows watcher; conflicts are refused",
    )
    winaudit.set_defaults(handler=cmd_setup_windows_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 1
    try:
        ctx = build_context(args)
    except TargetUserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if _merged(args, "force", False) and args.command not in {
        "setup-ssh-canary",
        "restore-ssh-canary",
        "plan",
        "create-canaries",
    }:
        print(
            "error: --force is only valid for SSH setup/restore workflows",
            file=sys.stderr,
        )
        return 2

    try:
        return int(args.handler(ctx) or 0)
    except ssh_canary.SSHCanaryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    finally:
        ctx.db.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
