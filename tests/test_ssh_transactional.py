"""Adversarial single-shot and transactional SSH activation regressions."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import cli, safe_write, ssh_canary
from honeypath.catalog import CanaryCreateResult, ssh_entries
from honeypath.platform_detect import PlatformContext


class TransactionalActivationTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        (self.ssh / "id_rsa").write_text("REAL RSA")
        (self.ssh / "id_ed25519").write_text("REAL ED25519")
        (self.ssh / "config").write_text("Host work\n")
        self.destination = ssh_canary.relocated_dir(self.home)
        self.destination.mkdir(parents=True)
        (self.destination / "config").write_text("# relocated\n")
        (self.destination / "id_rsa").write_text("REAL RSA")
        (self.destination / "id_ed25519").write_text("REAL ED25519")
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.db.upsert_ssh_installation(
            home=str(self.home),
            username=self.target.username,
            uid=self.target.uid,
            relocated_dir=str(self.destination),
            phase=ssh_canary.PHASE_PREPARED,
            config_validation="ok",
        )

    def activate(self, **kwargs):
        with mock.patch.object(
            ssh_canary, "validate_relocated_config", return_value=("ok", [])
        ):
            return ssh_canary.activate(self.db, self.target, log=self.log, **kwargs)

    def assert_rolled_back(self):
        self.assertEqual((self.ssh / "id_rsa").read_text(), "REAL RSA")
        self.assertEqual((self.ssh / "id_ed25519").read_text(), "REAL ED25519")
        installation = self.db.get_ssh_installation(self.home)
        self.assertEqual(installation["phase"], ssh_canary.PHASE_PREPARED)
        self.assertIsNone(installation["backup_path"])
        self.assertFalse(self.db.has_ssh_canaries(self.home))

    def test_new_ssh_directory_creation_failure_rolls_back(self):
        with mock.patch.object(
            safe_write, "create_directory_exclusive", side_effect=OSError("mkdir full")
        ):
            ok, backup = self.activate()
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assert_rolled_back()

    def test_first_middle_and_last_canary_failure_roll_back(self):
        real = ssh_canary.create_canary_file
        for fail_index in (0, len(ssh_entries()) // 2, len(ssh_entries()) - 1):
            with self.subTest(fail_index=fail_index):
                calls = {"n": 0}

                # fail_index is bound per iteration: a late-binding closure
                # would make every subtest use the loop's final value.
                def injected(*args, _fail_index=fail_index, **kwargs):
                    index = calls["n"]
                    calls["n"] += 1
                    if index == _fail_index:
                        return CanaryCreateResult(args[0], False, "injected failure")
                    return real(*args, **kwargs)

                with mock.patch.object(
                    ssh_canary, "create_canary_file", side_effect=injected
                ):
                    ok, backup = self.activate()
                self.assertFalse(ok)
                self.assertIsNone(backup)
                self.assert_rolled_back()

    def test_disk_full_style_write_failure_rolls_back(self):
        with mock.patch.object(safe_write, "_write_all", side_effect=OSError("ENOSPC")):
            ok, _ = self.activate()
        self.assertFalse(ok)
        self.assert_rolled_back()

    def test_required_ownership_failure_rolls_back(self):
        ssh_canary.backup_root(self.home).mkdir(parents=True)
        with mock.patch("honeypath.safe_write.os.fchmod", side_effect=OSError("EPERM")):
            ok, _ = self.activate()
        self.assertFalse(ok)
        self.assert_rolled_back()

    def test_authorized_keys_failure_rolls_back(self):
        (self.ssh / "authorized_keys").write_text("ssh-ed25519 AAAA public\n")
        with mock.patch.object(
            safe_write, "atomic_copy", side_effect=OSError("copy failed")
        ):
            ok, _ = self.activate()
        self.assertFalse(ok)
        self.assert_rolled_back()
        self.assertTrue((self.ssh / "authorized_keys").exists())

    def test_database_failure_rolls_back_without_partial_rows(self):
        with mock.patch.object(
            self.db, "finalize_ssh_activation", side_effect=OSError("database full")
        ):
            ok, _ = self.activate()
        self.assertFalse(ok)
        self.assert_rolled_back()

    def test_post_commit_logging_failure_does_not_roll_back_filesystem(self):
        def failing_log(message):
            if "registered" in message:
                raise OSError("log sink failed")
            self.log(message)

        with mock.patch.object(
            ssh_canary, "validate_relocated_config", return_value=("ok", [])
        ), self.assertRaisesRegex(OSError, "log sink failed"):
            ssh_canary.activate(self.db, self.target, log=failing_log)

        installation = self.db.get_ssh_installation(self.home)
        self.assertEqual(installation["phase"], ssh_canary.PHASE_ACTIVATED)
        self.assertTrue(self.db.has_ssh_canaries(self.home))
        self.assertNotEqual((self.ssh / "id_rsa").read_text(), "REAL RSA")
        self.assertEqual(
            (Path(installation["backup_path"]) / "id_rsa").read_text(),
            "REAL RSA",
        )

    def test_rollback_rename_failure_returns_backup_location(self):
        real = safe_write.rename_noreplace
        calls = {"n": 0}

        def rename(source, destination, *, root):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("rollback rename failed")
            return real(source, destination, root=root)

        with mock.patch.object(
            safe_write, "rename_noreplace", side_effect=rename
        ), mock.patch.object(
            ssh_canary, "create_canary_file", side_effect=OSError("fail")
        ):
            ok, backup = self.activate()
        self.assertFalse(ok)
        self.assertIsNotNone(backup)
        self.assertTrue(backup.is_dir())
        self.assertIn("FATAL", self.logged())
        installation = self.db.get_ssh_installation(self.home)
        self.assertEqual(installation["phase"], ssh_canary.PHASE_PREPARED)

    def test_success_after_a_rolled_back_attempt(self):
        with mock.patch.object(
            ssh_canary, "create_canary_file", side_effect=OSError("once")
        ):
            ok, _ = self.activate()
        self.assertFalse(ok)
        self.assert_rolled_back()
        ok, backup = self.activate()
        self.assertTrue(ok)
        self.assertIsNotNone(backup)
        self.assertEqual(
            self.db.get_ssh_installation(self.home)["backup_path"], str(backup)
        )

    def test_stale_relocated_key_blocks_before_rename(self):
        (self.ssh / "id_rsa").write_text("CHANGED AFTER PHASE ONE")
        ok, backup = self.activate()
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assertTrue(self.ssh.is_dir())
        self.assertEqual((self.destination / "id_rsa").read_text(), "REAL RSA")
        self.assertIn("incomplete or stale", self.logged())

    def test_source_change_after_final_inventory_blocks_activation(self):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        (self.ssh / "known_hosts").write_text("late host key\n")
        ok, backup = self.activate(expected_inventory=inventory)
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assertTrue(self.ssh.is_dir())
        self.assertIn("changed during activation", self.logged())

    def test_copy_warning_is_fatal_in_strict_activation_sync(self):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        (self.destination / "id_rsa").write_text("OLD DESTINATION")
        plan = ssh_canary.plan_copy(
            inventory,
            self.destination,
            previous_hashes={
                "id_rsa": ssh_canary.sha256_text_bytes(b"OLD DESTINATION")
            },
            root=self.home,
        )
        with mock.patch.object(
            safe_write,
            "atomic_write",
            side_effect=safe_write.SafeWriteError("disk full"),
        ):
            with self.assertRaises(ssh_canary.SSHCanaryError):
                ssh_canary.copy_inventory(
                    self.ssh,
                    self.destination,
                    inventory,
                    plan,
                    self.target,
                    strict=True,
                )

    def test_backup_is_verified_before_canary_creation_and_rolls_back(self):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        real_rename = safe_write.rename_noreplace
        calls = 0

        def mutate_after_rename(source, destination, *, root):
            nonlocal calls
            calls += 1
            real_rename(source, destination, root=root)
            if calls == 1:
                (destination / "id_rsa").write_text("LATE CHANGE")

        with mock.patch.object(
            safe_write, "rename_noreplace", side_effect=mutate_after_rename
        ):
            ok, backup = self.activate(expected_inventory=inventory)
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assertEqual((self.ssh / "id_rsa").read_text(), "LATE CHANGE")
        self.assertFalse(self.db.has_ssh_canaries(self.home))

    def test_relocated_state_changed_during_rename_rolls_back(self):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        real_rename = safe_write.rename_noreplace
        calls = 0

        def mutate_relocated_after_rename(source, destination, *, root):
            nonlocal calls
            calls += 1
            real_rename(source, destination, root=root)
            if calls == 1:
                (self.destination / "id_ed25519").write_text("ATTACKER")

        with mock.patch.object(
            safe_write, "rename_noreplace", side_effect=mutate_relocated_after_rename
        ):
            ok, backup = self.activate(expected_inventory=inventory)
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assertEqual((self.ssh / "id_ed25519").read_text(), "REAL ED25519")
        self.assertFalse(self.db.has_ssh_canaries(self.home))

    def test_cli_reactivation_guard_runs_before_inventory_even_with_force(self):
        ok, backup = self.activate()
        self.assertTrue(ok)
        assert backup is not None
        real_hashes = {
            name: safe_write.sha256_anchored(self.destination / name, root=self.home)
            for name in ("id_rsa", "id_ed25519", "config")
        }
        (self.ssh / "id_rsa").write_text("FAKE RSA")
        (self.ssh / "id_ed25519").write_text("FAKE ED25519")
        with (self.ssh / "config").open("a") as handle:
            handle.write("\nIdentityFile /tmp/fake\n")
        # The unique canary marker remains, so activation is recognized.
        context = cli.Context(
            args=namespace(activate=True, force=True),
            target=self.target,
            platform=PlatformContext(os_name="linux", home=self.home),
            db=self.db,
            confirm=lambda _prompt: True,
        )
        with mock.patch.object(
            ssh_canary, "inventory_ssh_dir"
        ) as inventory, mock.patch.object(ssh_canary, "copy_inventory") as copy:
            with self.quiet():
                code = cli.cmd_setup_ssh_canary(context)
        self.assertEqual(code, 0)
        inventory.assert_not_called()
        copy.assert_not_called()
        self.assertEqual(
            self.db.get_ssh_installation(self.home)["backup_path"], str(backup)
        )
        self.assertEqual(
            real_hashes,
            {
                name: safe_write.sha256_anchored(
                    self.destination / name, root=self.home
                )
                for name in real_hashes
            },
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
