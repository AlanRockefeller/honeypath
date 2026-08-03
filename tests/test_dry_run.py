"""Dry-run state must be a read-only view, never a lighter mutation mode."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import cli, windows_audit
from honeypath.platform_detect import PlatformContext


def snapshot(root: Path) -> dict[str, tuple[str, str]]:
    result = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            result[rel] = ("symlink", str(path.readlink()))
        elif path.is_dir():
            result[rel] = ("dir", "")
        else:
            result[rel] = ("file", hashlib.sha256(path.read_bytes()).hexdigest())
    return result


class DryRunDatabaseTests(TempHomeCase):
    def platform(self):
        return PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )

    def test_missing_database_and_parent_are_never_created(self):
        missing = self.root / "missing-parent" / "events.sqlite3"
        args = namespace(db=str(missing), dry_run=True)
        with mock.patch.object(
            cli, "resolve_target_user", return_value=self.target
        ), mock.patch.object(
            cli, "detect_platform_context", return_value=self.platform()
        ):
            ctx = cli.build_context(args)
        self.assertTrue(ctx.db.empty_state)
        self.assertEqual(ctx.db.get_canaries(), [])
        self.assertFalse(missing.parent.exists())

    def test_existing_database_is_immutable_and_creates_no_sidecars(self):
        before = snapshot(self.root)
        args = namespace(db=str(self.db.path), dry_run=True)
        with mock.patch.object(
            cli, "resolve_target_user", return_value=self.target
        ), mock.patch.object(
            cli, "detect_platform_context", return_value=self.platform()
        ):
            ctx = cli.build_context(args)
        self.assertTrue(ctx.db.read_only)
        ctx.db.get_canaries()
        ctx.db.get_managed_changes()
        self.assertEqual(snapshot(self.root), before)
        ctx.db.close()

    def test_existing_database_snapshot_includes_uncheckpointed_wal(self):
        conn = sqlite3.connect(self.db.path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "INSERT OR REPLACE INTO schema_metadata(key,value) VALUES(?,?)",
                ("wal_only_value", "visible"),
            )
            conn.commit()
            args = namespace(db=str(self.db.path), dry_run=True)
            with mock.patch.object(
                cli, "resolve_target_user", return_value=self.target
            ), mock.patch.object(
                cli, "detect_platform_context", return_value=self.platform()
            ):
                ctx = cli.build_context(args)
            try:
                self.assertEqual(ctx.db.get_meta("wal_only_value"), "visible")
            finally:
                ctx.db.close()
        finally:
            conn.close()

    def test_mutating_commands_are_non_mutating_in_dry_run(self):
        platform = self.platform()
        before = snapshot(self.root)
        context = cli.Context(
            args=namespace(
                dry_run=True,
                profiles=["linux-developer"],
                minutes=10,
                enable=True,
            ),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )
        with self.quiet():
            self.assertEqual(cli.cmd_create_canaries(context), 0)
            self.assertEqual(cli.cmd_mute(context), 0)
            with mock.patch("honeypath.alerts.Pushover.send") as send:
                self.assertEqual(cli.cmd_test_alert(context), 0)
                send.assert_not_called()
            unit = self.root / "systemd" / "honeypath.service"
            with mock.patch.object(cli, "SYSTEMD_UNIT_PATH", unit):
                self.assertEqual(cli.cmd_install_systemd(context), 0)
        self.assertEqual(snapshot(self.root), before)

    def test_windows_audit_dry_run_invokes_no_mutating_command(self):
        self.db.record_canary(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/test/.npmrc",
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="low",
            baseline_atime=None,
        )
        before = snapshot(self.root)
        with mock.patch.object(
            windows_audit, "interop_available", return_value=True
        ), mock.patch.object(
            windows_audit, "is_elevated", return_value=True
        ), mock.patch.object(
            windows_audit, "enable_audit_policy"
        ) as policy, mock.patch.object(
            windows_audit, "capture_and_apply_audit_rule"
        ) as sacl:
            self.assertEqual(
                windows_audit.setup_windows_audit(self.db, dry_run=True, log=self.log),
                0,
            )
        policy.assert_not_called()
        sacl.assert_not_called()
        self.assertEqual(snapshot(self.root), before)


if __name__ == "__main__":
    import unittest

    unittest.main()
