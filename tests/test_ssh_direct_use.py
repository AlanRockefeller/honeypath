"""The deliberately invalid canary ~/.ssh/config, and rollback (§6).

Keeping ~/.ssh/config unparseable is a deliberate trade-off: a program that
bypasses the wrappers fails loudly rather than being silently handed canary
keys. These tests pin the parts of that trade-off that must stay true, and
the disclosure that must accompany it.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from .support import TempHomeCase, namespace

from honeypath import catalog, cli, ssh_canary  # noqa: E402
from honeypath.platform_detect import PlatformContext  # noqa: E402


class WrapperConfigTests(TempHomeCase):
    """The wrappers must ALWAYS supply the relocated config."""

    def test_every_wrapper_passes_the_relocated_config(self):
        for name, binary in ssh_canary.SSH_BINARIES.items():
            content = ssh_canary.wrapper_content(binary)
            self.assertIn(f'-F "$HOME/{ssh_canary.RELOCATED_REL}/config"', content)
            self.assertIn(f"exec {binary}", content)
            self.assertIn('"$@"', content)

    def test_wrapper_covers_ssh_scp_and_sftp(self):
        self.assertEqual(set(ssh_canary.SSH_BINARIES), {"ssh", "scp", "sftp"})

    def test_installed_wrappers_all_reference_the_relocated_config(self):
        problems = ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.assertEqual(problems, [])
        for name in ssh_canary.SSH_BINARIES:
            path = ssh_canary.wrapper_dir(self.home) / name
            text = path.read_text()
            self.assertIn(f"{ssh_canary.RELOCATED_REL}/config", text)
            # No wrapper may fall back to the canary directory.
            self.assertNotIn("/.ssh/config", text)

    def test_wrapper_never_points_at_the_canary_directory(self):
        for binary in ssh_canary.SSH_BINARIES.values():
            content = ssh_canary.wrapper_content(binary)
            self.assertNotIn("$HOME/.ssh", content)
            self.assertNotIn("~/.ssh", content)


class RelocatedConfigTests(TempHomeCase):
    """The generated config must never read a canary path."""

    def build(self, user_config: str) -> str:
        destination = ssh_canary.relocated_dir(self.home)
        rewritten = ssh_canary.rewrite_user_config(user_config, self.home, destination)
        managed, _ = ssh_canary.build_managed_block(
            identity_files=[destination / "id_ed25519"],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        return ssh_canary.assemble_relocated_config(
            rewritten.text, managed, system_config=Path("/nonexistent")
        )

    def assert_no_canary_paths(self, text: str):
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self.assertNotIn("~/.ssh/", stripped, line)
            self.assertNotIn("$HOME/.ssh/", stripped, line)
            self.assertNotIn(f"{self.home}/.ssh/", stripped, line)
            self.assertNotIn("%d/.ssh/", stripped, line)

    def test_managed_block_reads_no_canary_path(self):
        self.assert_no_canary_paths(self.build(""))

    def test_rewritten_user_config_reads_no_canary_path(self):
        config = (
            "Host example\n"
            "    IdentityFile ~/.ssh/id_ed25519\n"
            "    UserKnownHostsFile ~/.ssh/known_hosts\n"
            "    CertificateFile $HOME/.ssh/id_ed25519-cert.pub\n"
            f"    ControlPath {self.home}/.ssh/cm-%r@%h:%p\n"
            "    Include conf.d/*\n"
        )
        assembled = self.build(config)
        self.assert_no_canary_paths(assembled)
        self.assertIn(ssh_canary.RELOCATED_REL, assembled)

    def test_known_hosts_points_into_the_relocated_tree(self):
        assembled = self.build("")
        self.assertIn(
            f"UserKnownHostsFile {ssh_canary.relocated_tilde()}/known_hosts",
            assembled,
        )

    def test_identityfile_points_into_the_relocated_tree(self):
        assembled = self.build("")
        self.assertIn(
            f"IdentityFile {ssh_canary.relocated_tilde()}/id_ed25519", assembled
        )


class DirectSshStatusTests(TempHomeCase):
    """Direct /usr/bin/ssh use must be REPORTED as unsupported after activation."""

    def activate_state(self, *, canary_config: bool = True):
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        entry = next(e for e in catalog.CATALOG if e.key == "linux.ssh.config")
        (ssh_dir / "config").write_text(
            entry.content if canary_config else "Host *\n    Compression yes\n"
        )
        self.db.upsert_ssh_installation(
            home=str(self.home),
            username=self.target.username,
            uid=self.target.uid,
            relocated_dir=str(ssh_canary.relocated_dir(self.home)),
            phase=ssh_canary.PHASE_ACTIVATED,
        )

    def test_supported_before_activation(self):
        status = ssh_canary.direct_ssh_status(self.db, self.target)
        self.assertTrue(status["supported"])
        self.assertFalse(status["activated"])

    def test_unsupported_after_activation(self):
        self.activate_state()
        status = ssh_canary.direct_ssh_status(self.db, self.target)
        self.assertTrue(status["activated"])
        self.assertFalse(status["supported"])
        self.assertIn("UNSUPPORTED", status["reason"])
        self.assertTrue(status["lines"])

    def test_supported_again_once_explicitly_reconfigured(self):
        """Replacing the canary config is the documented explicit opt-in."""
        self.activate_state(canary_config=False)
        status = ssh_canary.direct_ssh_status(self.db, self.target)
        self.assertTrue(status["activated"])
        self.assertTrue(status["supported"])
        self.assertIn("explicitly reconfigured", status["reason"])

    def test_the_warning_names_the_bypassed_wrappers(self):
        text = "\n".join(ssh_canary.DIRECT_SSH_WARNING)
        for wrapper in ("~/bin/ssh", "~/bin/scp", "~/bin/sftp"):
            self.assertIn(wrapper, text)
        self.assertIn("parse error", text)
        self.assertIn("UNSUPPORTED", text)

    def test_ssh_status_reports_the_unsupported_state(self):
        self.activate_state()
        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        ctx = cli.Context(
            args=namespace(limit=5),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _p: True,
        )
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            cli.cmd_ssh_status(ctx)
        output = buffer.getvalue()
        self.assertIn("Direct /usr/bin/ssh use", output)
        self.assertIn("supported: NO", output)


class ChecklistTests(unittest.TestCase):
    """§6: the pre-activation checklist must cover the representative tools."""

    def test_checklist_contains_the_required_commands(self):
        commands = "\n".join(ssh_canary.PHASE1_TEST_COMMANDS)
        for required in (
            "~/bin/ssh -G github.com",
            "~/bin/ssh -T git@github.com",
            "~/bin/scp -v /dev/null example.invalid:/tmp/",
            "~/bin/sftp -v example.invalid",
            "git config --global core.sshCommand",
            "which ssh",
            "ssh -G github.com",
            "rsync --version",
        ):
            self.assertIn(required, commands)

    def test_checklist_does_not_require_a_successful_connection(self):
        notes = "\n".join(ssh_canary.PHASE1_TEST_NOTES)
        self.assertIn("example.invalid", notes)
        self.assertIn("never resolves", notes)

    def test_checklist_only_contacts_reserved_hosts_or_github(self):
        """No command may target an arbitrary third-party host."""
        for command in ssh_canary.PHASE1_TEST_COMMANDS:
            for token in command.split():
                if "." not in token or token.startswith(("-", "~", "/")):
                    continue
                host = token.split(":", 1)[0].split("@")[-1]
                if host in ("github.com", "core.sshCommand"):
                    continue
                self.assertTrue(
                    host.endswith(".invalid") or "/" in token,
                    f"{command!r} references {host!r}",
                )


class RollbackBackupTests(TempHomeCase):
    """Rollback must find the most recent valid backup and delete none."""

    def make_backup(self, slug: str, marker: str) -> Path:
        path = ssh_canary.backup_root(self.home) / f"ssh-{slug}"
        path.mkdir(parents=True)
        (path / "id_ed25519").write_text(marker)
        return path

    def test_list_backups_is_chronological(self):
        first = self.make_backup("20240101-000000", "first")
        second = self.make_backup("20240202-000000", "second")
        third = self.make_backup("20240303-000000", "third")
        self.assertEqual(ssh_canary.list_backups(self.home), [first, second, third])

    def test_latest_valid_backup_picks_the_newest(self):
        self.make_backup("20240101-000000", "old")
        newest = self.make_backup("20240303-000000", "new")
        self.assertEqual(ssh_canary.latest_valid_backup(self.home), newest)

    def test_exdev_fallback_backups_are_found_too(self):
        under_root = self.make_backup("20240101-000000", "normal")
        fallback = self.home / ".ssh.honeypath-backup.20240505-000000"
        fallback.mkdir()
        found = ssh_canary.list_backups(self.home)
        self.assertIn(under_root, found)
        self.assertIn(fallback, found)
        self.assertEqual(ssh_canary.latest_valid_backup(self.home), fallback)

    def test_a_newer_backup_root_entry_beats_an_older_exdev_fallback(self):
        # Regression: the two locations use different name prefixes, so
        # ordering by whole name put every fallback last no matter its age.
        fallback = self.home / ".ssh.honeypath-backup.20240101-000000"
        fallback.mkdir()
        newest = self.make_backup("20240505-000000", "newer")
        self.assertEqual(ssh_canary.list_backups(self.home), [fallback, newest])
        self.assertEqual(ssh_canary.latest_valid_backup(self.home), newest)

    def test_a_symlinked_backup_is_not_treated_as_valid(self):
        real = self.make_backup("20240101-000000", "real")
        link = ssh_canary.backup_root(self.home) / "ssh-20240909-000000"
        link.symlink_to(self.root)
        self.assertEqual(ssh_canary.latest_valid_backup(self.home), real)

    def test_no_backups_returns_none(self):
        self.assertIsNone(ssh_canary.latest_valid_backup(self.home))

    def test_restore_uses_the_most_recent_backup_and_deletes_none(self):
        older = self.make_backup("20240101-000000", "OLDER")
        newest = self.make_backup("20240303-000000", "NEWEST")

        # An activated canary ~/.ssh, and a recorded backup that has since
        # been moved away by hand.
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir()
        entry = next(e for e in catalog.CATALOG if e.key == "linux.ssh.config")
        (ssh_dir / "config").write_text(entry.content)
        self.db.upsert_ssh_installation(
            home=str(self.home),
            username=self.target.username,
            uid=self.target.uid,
            relocated_dir=str(ssh_canary.relocated_dir(self.home)),
            phase=ssh_canary.PHASE_ACTIVATED,
            backup_path=str(self.home / "moved-away-by-hand"),
        )

        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        ctx = cli.Context(
            args=namespace(yes=True),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _p: True,
        )
        with self.quiet():
            code = cli.cmd_restore_ssh_canary(ctx)
        self.assertEqual(code, 0)

        # The newest backup was restored...
        self.assertEqual((ssh_dir / "id_ed25519").read_text(), "NEWEST")
        # ...the older one still exists, untouched...
        self.assertTrue(older.is_dir())
        self.assertEqual((older / "id_ed25519").read_text(), "OLDER")
        # ...and the backup root itself was not removed.
        self.assertTrue(ssh_canary.backup_root(self.home).is_dir())

    def test_restore_never_removes_the_backup_root(self):
        self.make_backup("20240101-000000", "only")
        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        ctx = cli.Context(
            args=namespace(yes=True),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _p: False,  # decline everything
        )
        with self.quiet():
            cli.cmd_restore_ssh_canary(ctx)
        self.assertTrue(ssh_canary.backup_root(self.home).is_dir())
        self.assertEqual(len(ssh_canary.list_backups(self.home)), 1)


if __name__ == "__main__":
    unittest.main()
