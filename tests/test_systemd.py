"""systemd privilege boundary (§1).

The generated unit must never define a root service that executes Honeypath
out of a user-writable checkout: the target user (or same-user malware) could
edit a .py file and wait for the next restart to obtain root.
"""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import cli  # noqa: E402
from honeypath.database import Database  # noqa: E402
from honeypath.platform_detect import PlatformContext  # noqa: E402
from honeypath.target_user import TargetUserContext  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKED_IN_UNIT = REPO_ROOT / "systemd" / "honeypath.service"


def directives(unit: str) -> dict[str, list[str]]:
    """Parse `Key=value` lines, ignoring comments and section headers."""
    found: dict[str, list[str]] = {}
    for line in unit.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key.strip(), []).append(value.strip())
    return found


class UnitSafetyChecks:
    """Assertions applied to both the generated and the checked-in unit."""

    def assert_unit_is_safe(self, unit: str, *, expect_user: str | None = None):
        parsed = directives(unit)

        # 1. It must run as a named, non-root user and group.
        self.assertIn("User", parsed, "unit does not set User=")
        self.assertIn("Group", parsed, "unit does not set Group=")
        user = parsed["User"][0]
        group = parsed["Group"][0]
        self.assertTrue(user, "User= is empty")
        self.assertTrue(group, "Group= is empty")
        self.assertNotEqual(user, "root", "the service must not run as root")
        self.assertNotEqual(user, "0")
        self.assertNotEqual(group, "root")
        self.assertNotEqual(group, "0")
        if expect_user is not None:
            self.assertEqual(user, expect_user)

        # 2. There must be exactly one ExecStart and it must not re-elevate.
        self.assertEqual(len(parsed.get("ExecStart", [])), 1)
        exec_start = parsed["ExecStart"][0]
        for escalator in ("sudo", "su ", "pkexec", "setpriv", "runuser"):
            self.assertNotIn(
                escalator, exec_start, f"ExecStart re-elevates via {escalator!r}"
            )

        # 3. Privilege-raising directives must be absent.
        self.assertNotIn("PermissionsStartOnly", parsed)
        # Defaulting these lookups would let a unit that omits the directive
        # entirely pass the check it exists to enforce.
        self.assertIn("NoNewPrivileges", parsed)
        self.assertEqual(parsed["NoNewPrivileges"][0], "yes")
        for forbidden in ("AmbientCapabilities", "CapabilityBoundingSet", "SecureBits"):
            self.assertNotIn(
                forbidden,
                parsed,
                f"{forbidden} grants capabilities to a service "
                "running user-writable code",
            )

        # 4. Hardening that would break Honeypath must NOT be present.
        self.assertNotIn(
            "ProtectHome", parsed, "ProtectHome would hide the canaries being watched"
        )
        self.assertIn("ProtectSystem", parsed)
        self.assertEqual(
            parsed["ProtectSystem"][0],
            "full",
            "ProtectSystem=strict would break the state directory",
        )

        # 5. State directory management.
        self.assertIn("StateDirectory", parsed)
        self.assertEqual(parsed["StateDirectory"][0], "honeypath")
        self.assertIn("StateDirectoryMode", parsed)
        self.assertEqual(parsed["StateDirectoryMode"][0], "0700")


class GeneratedUnitTests(TempHomeCase, UnitSafetyChecks):
    def make_context(self, **kwargs):
        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        return cli.Context(
            args=namespace(enable=False, **kwargs),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def test_generated_unit_is_safe(self):
        unit = cli.systemd_unit_text(self.make_context())
        self.assert_unit_is_safe(unit, expect_user=self.target.username)

    def test_generated_unit_names_the_target_user_and_group(self):
        unit = cli.systemd_unit_text(self.make_context())
        parsed = directives(unit)
        self.assertEqual(parsed["User"][0], self.target.username)
        self.assertEqual(parsed["Group"][0], cli.target_group_name(self.target))

    def test_generated_unit_does_not_run_a_root_service_from_the_checkout(self):
        """The core §1 regression: root + user-writable ExecStart is banned."""
        unit = cli.systemd_unit_text(self.make_context())
        parsed = directives(unit)
        exec_start = parsed["ExecStart"][0]
        # The unit executes this very checkout...
        self.assertIn(str(Path(cli.sys.argv[0]).resolve()), exec_start)
        # ...so it must not be running as root.
        self.assertNotEqual(parsed["User"][0], "root")

    def test_default_database_uses_state_directory_without_readwritepaths(self):
        ctx = self.make_context()
        ctx.db.path = cli.SYSTEMD_STATE_DIR / "events.sqlite3"
        unit = cli.systemd_unit_text(ctx)
        parsed = directives(unit)
        self.assertEqual(parsed["StateDirectory"][0], "honeypath")
        self.assertNotIn("ReadWritePaths", parsed)

    def test_non_default_database_gets_an_explicit_write_grant(self):
        ctx = self.make_context()
        unit = cli.systemd_unit_text(ctx)
        parsed = directives(unit)
        self.assertIn("ReadWritePaths", parsed)
        self.assertEqual(parsed["ReadWritePaths"][0], str(ctx.db.path.parent))

    def test_the_default_log_location_needs_no_option_in_the_unit(self):
        # The log follows the database directory, so the service finds it
        # without being told; a stray option here would be one more thing to
        # keep in sync.
        ctx = self.make_context()
        exec_start = directives(cli.systemd_unit_text(ctx))["ExecStart"][0]
        self.assertNotIn("--log-file", exec_start)
        self.assertNotIn("--no-log-file", exec_start)

    def test_an_explicit_log_file_is_carried_into_the_unit_with_a_write_grant(self):
        log_path = self.root / "logs" / "honeypath.log"
        ctx = self.make_context(log_file=str(log_path))
        unit = cli.systemd_unit_text(ctx)
        parsed = directives(unit)
        self.assertIn(f'--log-file "{log_path}"', parsed["ExecStart"][0])
        self.assertIn(str(log_path.parent), parsed["ReadWritePaths"])

    def test_disabled_logging_is_carried_into_the_unit(self):
        ctx = self.make_context(no_log_file=True)
        exec_start = directives(cli.systemd_unit_text(ctx))["ExecStart"][0]
        self.assertIn("--no-log-file", exec_start)

    def test_install_systemd_reports_the_privilege_model_before_writing(self):
        import contextlib
        import io

        ctx = self.make_context(dry_run=True)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.cmd_install_systemd(ctx)
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn(f"User=                 {self.target.username}", output)
        self.assertIn(
            f"Group=                {cli.target_group_name(self.target)}", output
        )
        self.assertIn(str(cli.sys.executable), output)
        self.assertIn(str(ctx.db.path), output)
        self.assertIn("Pushover credential permissions", output)
        self.assertIn("0640", output)
        self.assertIn("[dry-run]", output)

    def test_dry_run_writes_nothing(self):
        import contextlib
        import io

        recorded: list = []
        original = cli.safe_write.atomic_write

        def spy(*args, **kwargs):
            recorded.append(args)
            return original(*args, **kwargs)

        cli.safe_write.atomic_write = spy
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.cmd_install_systemd(self.make_context(dry_run=True))
        finally:
            cli.safe_write.atomic_write = original
        self.assertEqual(recorded, [])

    def test_credential_permission_advice_never_suggests_world_readable(self):
        lines = cli._credential_permission_lines("alan", "alan")
        text = "\n".join(lines)
        self.assertIn("0640", text)
        self.assertIn("0600", text)
        for bad in ("0644", "0666", "a+r", "o+r"):
            self.assertNotIn(f"chmod {bad}", text)

    def test_guided_enable_reports_completed_work_not_manual_next_steps(self):
        import contextlib
        import io

        ctx = self.make_context(setup_compact=True)
        ctx.args.enable = True
        unit_path = self.root / "honeypath.service"
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        buffer = io.StringIO()
        with (
            mock.patch.object(cli, "SYSTEMD_UNIT_PATH", unit_path),
            mock.patch.object(cli.subprocess, "run", return_value=completed) as run,
            contextlib.redirect_stdout(buffer),
        ):
            code = cli.cmd_install_systemd(ctx)

        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 2)
        output = buffer.getvalue()
        self.assertIn("enabled and running", output)
        self.assertIn("Optional inspection", output)
        self.assertNotIn("Next steps", output)
        self.assertNotIn("sudo systemctl daemon-reload", output)
        self.assertNotIn("sudo systemctl enable", output)
        self.assertNotIn("Unit file\n", output)

    def test_enable_failure_is_reported_to_guided_setup(self):
        import contextlib
        import io

        ctx = self.make_context(setup_compact=True)
        ctx.args.enable = True
        unit_path = self.root / "honeypath.service"
        failed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="permission denied"
        )
        buffer = io.StringIO()
        with (
            mock.patch.object(cli, "SYSTEMD_UNIT_PATH", unit_path),
            mock.patch.object(cli.subprocess, "run", return_value=failed),
            contextlib.redirect_stdout(buffer),
        ):
            code = cli.cmd_install_systemd(ctx)

        self.assertEqual(code, 1)
        self.assertIn(
            "Failed: systemctl daemon-reload: permission denied", buffer.getvalue()
        )


class ServiceStateOwnershipTests(TempHomeCase):
    """A root-owned database is unusable by the unprivileged unit (§ ownership).

    ``ReadWritePaths=`` only relaxes systemd's filesystem sandbox.  Whatever a
    privileged setup run creates still has to change hands, or the service
    cannot open its own SQLite file.
    """

    def privileged(self):
        """Pretend to be root without needing to be root."""
        return mock.patch.object(cli, "can_change_ownership", return_value=True)

    def recorder(self):
        return mock.patch.object(
            cli.target_user_mod, "apply_ownership", return_value=[]
        )

    def test_a_created_custom_database_is_handed_to_the_service_user(self):
        db_path = self.root / "state" / "custom" / "events.sqlite3"
        db = Database(db_path)
        db.initialize()
        with self.privileged(), self.recorder() as chown:
            cli.adopt_state_ownership(db, self.target)
        owned = {call.args[0] for call in chown.call_args_list}
        self.assertIn(db_path, owned)
        # Both directories this run had to create, not just the leaf.
        self.assertIn(db_path.parent, owned)
        self.assertIn(db_path.parent.parent, owned)
        for call in chown.call_args_list:
            self.assertIs(call.args[1], self.target)

    def test_wal_sidecars_change_hands_with_the_database(self):
        db_path = self.root / "state" / "events.sqlite3"
        db = Database(db_path)
        db.initialize()
        Path(f"{db_path}-wal").write_text("")
        with self.privileged(), self.recorder() as chown:
            cli.adopt_state_ownership(db, self.target)
        owned = {call.args[0] for call in chown.call_args_list}
        self.assertIn(Path(f"{db_path}-wal"), owned)
        # -shm does not exist, so it is not chowned into existence.
        self.assertNotIn(Path(f"{db_path}-shm"), owned)

    def test_a_pre_existing_directory_keeps_the_ownership_the_admin_gave_it(self):
        existing = self.root / "already-there"
        existing.mkdir()
        db = Database(existing / "events.sqlite3")
        db.initialize()
        with self.privileged(), self.recorder() as chown:
            cli.adopt_state_ownership(db, self.target)
        owned = {call.args[0] for call in chown.call_args_list}
        self.assertNotIn(existing, owned)
        self.assertIn(db.path, owned)

    def test_a_pre_existing_database_is_left_alone(self):
        db = Database(self.root / "events.sqlite3")
        db.initialize()
        second = Database(db.path)
        second.initialize()
        with self.privileged(), self.recorder() as chown:
            cli.adopt_state_ownership(second, self.target)
        self.assertEqual(chown.call_args_list, [])

    def test_nothing_is_chowned_when_the_process_is_not_privileged(self):
        db = Database(self.root / "state" / "events.sqlite3")
        db.initialize()
        with (
            mock.patch.object(cli, "can_change_ownership", return_value=False),
            self.recorder() as chown,
        ):
            cli.adopt_state_ownership(db, self.target)
        self.assertEqual(chown.call_args_list, [])

    def test_a_root_target_needs_no_transfer(self):
        db = Database(self.root / "state" / "events.sqlite3")
        db.initialize()
        root_target = TargetUserContext(
            username="root", uid=0, gid=0, home=Path("/root")
        )
        with self.privileged(), self.recorder() as chown:
            cli.adopt_state_ownership(db, root_target)
        self.assertEqual(chown.call_args_list, [])


class ServiceStateAccessTests(TempHomeCase):
    def other_user(self) -> TargetUserContext:
        """A service account that owns neither the database nor its directory."""
        return TargetUserContext(
            username="svc",
            uid=os.getuid() + 4242,
            gid=os.getgid() + 4242,
            home=self.home,
        )

    def test_an_owned_writable_database_reports_no_problem(self):
        self.assertIsNone(cli.service_state_access(self.db, self.target))

    def test_a_database_owned_by_another_user_is_reported(self):
        # The directory has to be usable by svc, or the check stops there and
        # the database file is never reached.
        os.chmod(self.db.path.parent, 0o733)
        os.chmod(self.db.path, 0o600)
        problem = cli.service_state_access(self.db, self.other_user())
        self.assertIsNotNone(problem)
        self.assertIn(str(self.db.path), problem)
        self.assertIn("not writable by svc", problem)

    def test_an_unwritable_directory_is_reported(self):
        directory = self.root / "locked"
        directory.mkdir(mode=0o700)
        db = Database(directory / "events.sqlite3")
        db.initialize()
        problem = cli.service_state_access(db, self.other_user())
        self.assertIsNotNone(problem)
        self.assertIn(str(directory), problem)

    def enable_service(self, db: Database, *, state_dir=None):
        """Run `install-systemd --enable` against ``db``; returns (code, output)."""
        import contextlib
        import io

        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        ctx = cli.Context(
            args=namespace(enable=True),
            target=self.other_user(),
            platform=platform,
            db=db,
            confirm=lambda _prompt: True,
        )
        patches = [
            mock.patch.object(
                cli, "SYSTEMD_UNIT_PATH", self.root / "honeypath.service"
            ),
            mock.patch.object(
                cli.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
        ]
        if state_dir is not None:
            patches.append(mock.patch.object(cli, "SYSTEMD_STATE_DIR", state_dir))
        buffer = io.StringIO()
        with contextlib.ExitStack() as stack:
            run = [stack.enter_context(p) for p in patches][1]
            stack.enter_context(contextlib.redirect_stdout(buffer))
            code = cli.cmd_install_systemd(ctx)
        return code, buffer.getvalue(), run

    def test_install_systemd_refuses_to_enable_an_unusable_database(self):
        directory = self.root / "locked"
        directory.mkdir(mode=0o700)
        db = Database(directory / "events.sqlite3")
        db.initialize()

        code, output, run = self.enable_service(db)

        self.assertEqual(code, 1)
        run.assert_not_called()
        self.assertIn("Not enabling", output)
        self.assertIn("sudo chown", output)

    def test_the_systemd_state_directory_is_left_to_systemd(self):
        """StateDirectory= sets ownership at start, so do not second-guess it."""
        directory = self.root / "state"
        directory.mkdir(mode=0o700)
        db = Database(directory / "events.sqlite3")
        db.initialize()

        code, output, run = self.enable_service(db, state_dir=directory)

        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 2)
        self.assertNotIn("Not enabling", output)


class CheckedInUnitTests(unittest.TestCase, UnitSafetyChecks):
    """The example unit shipped in the repository must be safe by default."""

    def setUp(self):
        self.unit = CHECKED_IN_UNIT.read_text()

    def test_checked_in_unit_exists(self):
        self.assertTrue(CHECKED_IN_UNIT.is_file())

    def test_checked_in_unit_is_safe(self):
        self.assert_unit_is_safe(self.unit)

    def test_checked_in_unit_has_no_root_user_directive(self):
        self.assertNotRegex(self.unit, r"(?mi)^\s*User\s*=\s*root\s*$")
        self.assertNotRegex(self.unit, r"(?mi)^\s*Group\s*=\s*root\s*$")

    def test_checked_in_unit_documents_the_placeholder(self):
        """The example is a template; it must say so rather than look ready."""
        self.assertRegex(self.unit, r"(?i)install-systemd")


if __name__ == "__main__":
    unittest.main()
