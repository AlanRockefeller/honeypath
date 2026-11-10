"""Native Linux Audit rules and one-command installer."""

from __future__ import annotations

import contextlib
import io
import subprocess
from pathlib import Path
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import cli, linux_audit  # noqa: E402
from honeypath.database import CanaryRow  # noqa: E402
from honeypath.platform_detect import PlatformContext  # noqa: E402


def canary(path: str, *, platform: str = "linux", active: int = 1) -> CanaryRow:
    return CanaryRow(
        canary_id="linux.test",
        path=path,
        kind="test_credentials",
        severity="high",
        profile="linux-developer",
        platform=platform,
        intrusiveness="low",
        last_baseline_atime=None,
        active=active,
    )


class LinuxAuditRuleTests(TempHomeCase):
    def test_x86_rules_cover_native_and_compat_processes(self):
        text = linux_audit.rules_text(
            [canary("/home/test/.aws/credentials")], machine="x86_64"
        )
        self.assertTrue(text.startswith(linux_audit.MANAGED_MARKER))
        self.assertIn("arch=b64", text)
        self.assertIn("arch=b32", text)
        self.assertIn("-F perm=r", text)
        self.assertIn("-F key=honeypath-read", text)

    def test_only_active_linux_canaries_are_rendered(self):
        text = linux_audit.rules_text(
            [
                canary("/home/test/active"),
                canary("/home/test/inactive", active=0),
                canary("/mnt/c/Users/test/windows", platform="windows"),
            ],
            machine="aarch64",
        )
        self.assertIn("/home/test/active", text)
        self.assertNotIn("inactive", text)
        self.assertNotIn("/mnt/c", text)
        self.assertNotIn("arch=b32", text)

    def test_unsafe_rule_path_is_refused(self):
        with self.assertRaises(ValueError):
            linux_audit.rules_text([canary("/home/test/a path")])

    def test_dry_run_neither_writes_nor_loads_rules(self):
        rules = self.root / "70-honeypath.rules"
        with mock.patch.object(linux_audit.subprocess, "run") as run:
            ok, detail = linux_audit.install_rules(
                [canary("/home/test/.npmrc")],
                rules_path=rules,
                dry_run=True,
            )
        self.assertTrue(ok)
        self.assertIn("[dry-run]", detail)
        self.assertFalse(rules.exists())
        run.assert_not_called()

    def test_unmanaged_rule_file_is_never_overwritten(self):
        rules = self.write("70-honeypath.rules", "# operator-owned\n")
        with mock.patch.object(linux_audit.os, "geteuid", return_value=0):
            ok, detail = linux_audit.install_rules(
                [canary("/home/test/.npmrc")], rules_path=rules
            )
        self.assertFalse(ok)
        self.assertIn("unmanaged", detail)
        self.assertEqual(rules.read_text(), "# operator-owned\n")

    def test_loaded_rules_are_verified_in_the_kernel(self):
        target = canary("/home/test/.npmrc")
        listing = "\n".join(
            f"-a always,exit -F arch={arch} -F path={target.path} "
            f"-F perm=r -F key={linux_audit.AUDIT_KEY}"
            for arch in ("b64", "b32")
        )
        completed = [
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
        ]
        with (
            mock.patch.object(linux_audit.os, "geteuid", return_value=0),
            mock.patch.object(linux_audit, "command_available", return_value=True),
            mock.patch.object(linux_audit.safe_write, "atomic_write") as write,
            mock.patch.object(
                linux_audit.subprocess, "run", side_effect=completed
            ) as run,
        ):
            ok, detail = linux_audit.install_rules(
                [target], rules_path=self.root / "70-honeypath.rules"
            )
        self.assertTrue(ok, detail)
        write.assert_called_once()
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["augenrules", "--check"], ["augenrules", "--load"], ["auditctl", "-l"]],
        )

    def test_immutable_or_unloaded_rules_are_reported(self):
        completed = [
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            # augenrules exits zero when Audit is immutable, even if changed.
            subprocess.CompletedProcess([], 0, stdout="immutable", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="No rules", stderr=""),
        ]
        with (
            mock.patch.object(linux_audit.os, "geteuid", return_value=0),
            mock.patch.object(linux_audit, "command_available", return_value=True),
            mock.patch.object(linux_audit.safe_write, "atomic_write"),
            mock.patch.object(linux_audit.subprocess, "run", side_effect=completed),
        ):
            ok, detail = linux_audit.install_rules(
                [canary("/home/test/.npmrc")],
                rules_path=self.root / "70-honeypath.rules",
            )
        self.assertFalse(ok)
        self.assertIn("not active", detail)


class LinuxInstallCommandTests(TempHomeCase):
    def context(self, *, dry_run: bool = False):
        return cli.Context(
            args=namespace(dry_run=dry_run),
            target=self.target,
            platform=PlatformContext(
                os_name="linux",
                home=self.home,
                default_profiles=["linux-developer"],
            ),
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def test_install_orchestrates_audit_canaries_rules_and_service(self):
        ctx = self.context()
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with (
            mock.patch.object(cli.os, "geteuid", return_value=0),
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(
                cli.linux_audit,
                "service_state",
                return_value=(True, True, "auditd active and enabled"),
            ),
            mock.patch.object(cli.alerts_mod.Pushover, "configured", return_value=True),
            mock.patch.object(cli, "cmd_create_canaries", return_value=0) as create,
            mock.patch.object(
                ctx.db,
                "get_canaries",
                return_value=[canary(str(self.home / ".npmrc"))],
            ),
            mock.patch.object(
                cli.linux_audit,
                "install_rules",
                return_value=(True, "rules installed"),
            ) as rules,
            mock.patch.object(cli, "SYSTEMD_UNIT_PATH", self.root / "honeypath.service"),
            mock.patch.object(cli.subprocess, "run", return_value=completed),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = cli.cmd_install_linux(ctx)
        self.assertEqual(code, 0)
        create.assert_called_once_with(ctx)
        rules.assert_called_once()
        self.assertTrue(ctx.args.enable)

    def test_inactive_audit_is_enabled_before_canary_creation(self):
        ctx = self.context()
        order: list[str] = []
        with (
            mock.patch.object(cli.os, "geteuid", return_value=0),
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(
                cli.linux_audit,
                "service_state",
                return_value=(False, False, "inactive"),
            ),
            mock.patch.object(
                cli.linux_audit,
                "enable_service",
                side_effect=lambda **_kwargs: (order.append("audit") or True, "enabled"),
            ),
            mock.patch.object(cli.alerts_mod.Pushover, "configured", return_value=True),
            mock.patch.object(
                cli,
                "cmd_create_canaries",
                side_effect=lambda _ctx: order.append("canaries") or 1,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = cli.cmd_install_linux(ctx)
        self.assertEqual(code, 1)
        self.assertEqual(order, ["audit", "canaries"])

    def test_non_linux_host_is_refused(self):
        ctx = self.context()
        ctx.platform.os_name = "wsl"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_install_linux(ctx), 1)
