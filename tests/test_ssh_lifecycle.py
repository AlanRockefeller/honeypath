"""Copy rules, wrappers, activation and rollback (§8.1, §8.2, §8.5–§8.8)."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from .support import TempHomeCase

from honeypath import safe_write, ssh_canary  # noqa: E402
from honeypath.catalog import sha256_file, sha256_text  # noqa: E402


class InventoryTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)

    def test_regular_files_are_inventoried_with_hashes(self):
        (self.ssh / "id_rsa").write_text("KEY MATERIAL")
        (self.ssh / "config").write_text("Host x\n")
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertEqual(set(inventory.entries), {"id_rsa", "config"})
        self.assertEqual(
            inventory.entries["id_rsa"].sha256, sha256_text("KEY MATERIAL")
        )

    def test_subdirectories_are_walked(self):
        (self.ssh / "config.d").mkdir()
        (self.ssh / "config.d" / "work").write_text("Host work\n")
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertIn("config.d/work", inventory.entries)
        self.assertIn("config.d", inventory.directories)

    def test_fifo_is_refused(self):
        os.mkfifo(self.ssh / "pipe")
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertNotIn("pipe", inventory.entries)
        self.assertTrue(any("fifo" in r for r in inventory.refused))

    def test_socket_is_refused(self):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            self.skipTest("cannot create a unix socket here")
        try:
            sock.bind(str(self.ssh / "agent.sock"))
        except OSError:
            self.skipTest("cannot create a unix socket here")
        finally:
            sock.close()
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertNotIn("agent.sock", inventory.entries)
        self.assertTrue(any("socket" in r for r in inventory.refused))

    def test_symlink_outside_the_tree_is_refused(self):
        outside = self.root / "secret.txt"
        outside.write_text("elsewhere")
        (self.ssh / "linked").symlink_to(outside)
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertNotIn("linked", inventory.entries)
        self.assertTrue(any("linked" in r and "symlink" in r for r in inventory.refused))

    def test_symlink_inside_the_tree_is_also_refused(self):
        (self.ssh / "id_rsa").write_text("KEY")
        (self.ssh / "id_default").symlink_to(self.ssh / "id_rsa")
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertNotIn("id_default", inventory.entries)
        self.assertTrue(any("symlink" in r for r in inventory.refused))


class CopyTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        (self.ssh / "id_rsa").write_text("PRIVATE")
        os.chmod(self.ssh / "id_rsa", 0o600)
        (self.ssh / "id_rsa.pub").write_text("PUBLIC")
        self.destination = ssh_canary.relocated_dir(self.home)

    def copy(self, **kwargs):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        plan = ssh_canary.plan_copy(
            inventory, self.destination, previous_hashes=kwargs.pop("previous", {})
        )
        return (
            inventory,
            plan,
            ssh_canary.copy_inventory(
                self.ssh,
                self.destination,
                inventory,
                plan,
                self.target,
                log=self.log,
                **kwargs,
            ),
        )

    def test_copies_bytes_and_modes(self):
        self.copy()
        self.assertEqual((self.destination / "id_rsa").read_text(), "PRIVATE")
        self.assertEqual((self.destination / "id_rsa").stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            (self.destination / "id_rsa.pub").stat().st_mode & 0o777, 0o644
        )

    def test_original_is_left_untouched(self):
        self.copy()
        self.assertTrue((self.ssh / "id_rsa").exists())
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")

    def test_the_relocated_config_is_generated_not_copied(self):
        """Copying ~/.ssh/config over the generated one would defeat every
        path rewrite: prepare_relocated_config would see it as hand-edited."""
        (self.ssh / "config").write_text("Host w\n  IdentityFile ~/.ssh/id_rsa\n")
        _, plan, _ = self.copy()
        self.assertNotIn("config", plan.to_copy)
        self.assertIn("config", plan.generated)
        self.assertFalse((self.destination / "config").exists())

    def test_config_is_still_hashed_for_drift_detection(self):
        (self.ssh / "config").write_text("Host w\n")
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        self.assertIn("config", inventory.hashes())

    def test_second_run_is_a_no_op(self):
        self.copy()
        inventory, plan, _ = self.copy()
        self.assertEqual(plan.to_copy, [])
        self.assertIn("id_rsa", plan.unchanged)

    def test_conflicting_destination_refuses_without_force(self):
        self.destination.mkdir(parents=True)
        (self.destination / "id_rsa").write_text("SOMETHING ELSE")
        with self.assertRaises(ssh_canary.SSHCanaryError) as caught:
            self.copy()
        self.assertIn("--force", str(caught.exception))
        self.assertEqual((self.destination / "id_rsa").read_text(), "SOMETHING ELSE")

    def test_conflict_overwritten_with_force(self):
        self.destination.mkdir(parents=True)
        (self.destination / "id_rsa").write_text("SOMETHING ELSE")
        self.copy(force=True)
        self.assertEqual((self.destination / "id_rsa").read_text(), "PRIVATE")

    def test_refresh_when_destination_matches_last_copy(self):
        self.copy()
        (self.ssh / "id_rsa").write_text("ROTATED")
        previous = {
            "id_rsa": sha256_text("PRIVATE"),
            "id_rsa.pub": sha256_text("PUBLIC"),
        }
        _, plan, _ = self.copy(previous=previous)
        self.assertIn("id_rsa", plan.to_copy)
        self.assertEqual((self.destination / "id_rsa").read_text(), "ROTATED")

    def test_dry_run_writes_nothing(self):
        self.copy(dry_run=True)
        self.assertFalse(self.destination.exists())

    def test_source_parent_swap_after_inventory_cannot_change_copied_bytes(self):
        inventory = ssh_canary.inventory_ssh_dir(self.ssh)
        plan = ssh_canary.plan_copy(inventory, self.destination)
        original = self.home / ".ssh-original"
        self.ssh.rename(original)
        attacker = self.home / "attacker-ssh"
        attacker.mkdir()
        (attacker / "id_rsa").write_text("ATTACKER")
        self.ssh.symlink_to(attacker)
        ssh_canary.copy_inventory(
            self.ssh, self.destination, inventory, plan, self.target, log=self.log
        )
        self.assertEqual((self.destination / "id_rsa").read_text(), "PRIVATE")


class WrapperTests(TempHomeCase):
    def test_install_creates_all_three_with_mode_755(self):
        problems = ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.assertEqual(problems, [])
        for name, binary in ssh_canary.SSH_BINARIES.items():
            path = ssh_canary.wrapper_dir(self.home) / name
            self.assertTrue(path.exists())
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            content = path.read_text()
            self.assertIn(f"exec {binary} -F", content)
            self.assertIn(ssh_canary.WRAPPER_MARKER, content)

    def test_hashes_are_recorded(self):
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        changes = self.db.get_managed_changes(change_type=ssh_canary.CHANGE_WRAPPER)
        self.assertEqual(len(changes), 3)
        for change in changes:
            self.assertEqual(
                sha256_file(Path(change["target"])), change["content_hash"]
            )

    def test_foreign_file_is_refused(self):
        directory = ssh_canary.wrapper_dir(self.home)
        directory.mkdir(parents=True)
        foreign = directory / "ssh"
        foreign.write_text("#!/bin/sh\necho someone elses wrapper\n")
        problems = ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.assertEqual(len(problems), 1)
        self.assertIn("refusing to overwrite", problems[0])
        self.assertIn("someone elses wrapper", foreign.read_text())

    def test_force_replaces_a_foreign_file(self):
        directory = ssh_canary.wrapper_dir(self.home)
        directory.mkdir(parents=True)
        (directory / "ssh").write_text("#!/bin/sh\nfake\n")
        problems = ssh_canary.install_wrappers(
            self.db, self.target, force=True, log=self.log
        )
        self.assertEqual(problems, [])
        self.assertIn(ssh_canary.WRAPPER_MARKER, (directory / "ssh").read_text())

    def test_reinstall_is_idempotent(self):
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.assertEqual(
            len(self.db.get_managed_changes(change_type=ssh_canary.CHANGE_WRAPPER)), 3
        )

    def test_status_distinguishes_ours_from_foreign(self):
        directory = ssh_canary.wrapper_dir(self.home)
        directory.mkdir(parents=True)
        (directory / "scp").write_text("#!/bin/sh\nfake\n")
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        statuses = {s.name: s for s in ssh_canary.wrapper_statuses(self.home)}
        self.assertTrue(statuses["ssh"].ours)
        self.assertFalse(statuses["scp"].ours)

    def test_removal_leaves_modified_wrappers_alone(self):
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        path = ssh_canary.wrapper_dir(self.home) / "ssh"
        path.write_text("#!/bin/sh\nsomeone replaced this\n")
        ssh_canary.remove_wrappers(self.db, self.target, log=self.log)
        self.assertTrue(path.exists())
        self.assertFalse((ssh_canary.wrapper_dir(self.home) / "scp").exists())

    def test_removal_deletes_our_wrappers(self):
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        ssh_canary.remove_wrappers(self.db, self.target, log=self.log)
        for name in ssh_canary.SSH_BINARIES:
            self.assertFalse((ssh_canary.wrapper_dir(self.home) / name).exists())


class RcBlockTests(TempHomeCase):
    def test_install_and_remove(self):
        rc = self.home / ".zshrc"
        rc.write_text("export EDITOR=vim\n")
        ssh_canary.install_rc_block(self.db, self.target, rc, log=self.log)
        text = rc.read_text()
        self.assertIn(ssh_canary.RC_BEGIN, text)
        self.assertIn('export PATH="$HOME/bin:$PATH"', text)
        self.assertIn("export EDITOR=vim", text)

        ssh_canary.remove_rc_blocks(self.db, self.target, log=self.log)
        text = rc.read_text()
        self.assertNotIn(ssh_canary.RC_BEGIN, text)
        self.assertNotIn("$HOME/bin:$PATH", text)
        self.assertIn("export EDITOR=vim", text)

    def test_install_is_idempotent(self):
        rc = self.home / ".bashrc"
        rc.write_text("")
        ssh_canary.install_rc_block(self.db, self.target, rc, log=self.log)
        ssh_canary.install_rc_block(self.db, self.target, rc, log=self.log)
        self.assertEqual(rc.read_text().count(ssh_canary.RC_BEGIN), 1)


class GitConfigTests(TempHomeCase):
    """run_as_target sets HOME to the temp home, so --global stays sandboxed."""

    def setUp(self):
        super().setUp()
        if not shutil.which("git"):
            self.skipTest("git is not installed")

    def current(self):
        return ssh_canary.git_ssh_command(self.target)

    def test_sets_absolute_wrapper_path(self):
        ssh_canary.set_git_ssh_command(self.db, self.target, log=self.log)
        self.assertEqual(self.current(), str(ssh_canary.wrapper_dir(self.home) / "ssh"))
        # Not `ssh -F ...`: via PATH that could invoke the wrapper twice.
        self.assertNotIn(" -F ", self.current() or "")

    def test_restores_an_originally_unset_value_by_unsetting(self):
        ssh_canary.set_git_ssh_command(self.db, self.target, log=self.log)
        ssh_canary.restore_git_ssh_command(self.db, self.target, log=self.log)
        self.assertIsNone(self.current())

    def test_restores_the_exact_previous_value(self):
        subprocess.run(
            ["git", "config", "--global", "core.sshCommand", "/usr/bin/ssh -o Foo=bar"],
            env={**os.environ, "HOME": str(self.home)},
            check=True,
            capture_output=True,
        )
        ssh_canary.set_git_ssh_command(self.db, self.target, force=True, log=self.log)
        self.assertEqual(self.current(), str(ssh_canary.wrapper_dir(self.home) / "ssh"))
        ssh_canary.restore_git_ssh_command(self.db, self.target, log=self.log)
        self.assertEqual(self.current(), "/usr/bin/ssh -o Foo=bar")

    def test_refuses_to_replace_a_foreign_value_without_confirmation(self):
        subprocess.run(
            ["git", "config", "--global", "core.sshCommand", "/opt/custom/ssh"],
            env={**os.environ, "HOME": str(self.home)},
            check=True,
            capture_output=True,
        )
        ssh_canary.set_git_ssh_command(
            self.db, self.target, log=self.log, confirm=lambda _prompt: False
        )
        self.assertEqual(self.current(), "/opt/custom/ssh")

    def test_leaves_a_third_party_change_alone_on_restore(self):
        ssh_canary.set_git_ssh_command(self.db, self.target, log=self.log)
        subprocess.run(
            ["git", "config", "--global", "core.sshCommand", "/somewhere/else"],
            env={**os.environ, "HOME": str(self.home)},
            check=True,
            capture_output=True,
        )
        ssh_canary.restore_git_ssh_command(self.db, self.target, log=self.log)
        self.assertEqual(self.current(), "/somewhere/else")


class ActivationTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        (self.ssh / "id_rsa").write_text("PRIVATE")
        (self.ssh / "config").write_text("Host work\n  User alan\n")
        destination = ssh_canary.relocated_dir(self.home)
        destination.mkdir(parents=True)
        (destination / "config").write_text("# prepared relocated config\n")
        (destination / "id_rsa").write_text("PRIVATE")
        ssh_canary.install_wrappers(self.db, self.target, log=self.log)
        self.db.upsert_ssh_installation(
            home=str(self.home),
            username=self.target.username,
            uid=self.target.uid,
            relocated_dir=str(destination),
            phase=ssh_canary.PHASE_PREPARED,
            config_validation="ok",
        )
        self.log_lines.clear()

    def activate(self, **kwargs):
        with mock.patch.object(
            ssh_canary, "validate_relocated_config", return_value=("ok", [])
        ):
            return ssh_canary.activate(self.db, self.target, log=self.log, **kwargs)

    def test_symlinked_ssh_dir_blocks_activation(self):
        shutil.rmtree(self.ssh)
        real = self.home / "dotfiles" / "ssh"
        real.mkdir(parents=True)
        self.ssh.symlink_to(real)
        ok, backup = self.activate()
        self.assertFalse(ok)
        self.assertIsNone(backup)
        self.assertIn("symlink", self.logged())
        self.assertTrue(self.ssh.is_symlink())

    def test_backup_is_not_glob_findable_from_home(self):
        ok, backup = self.activate()
        self.assertTrue(ok)
        assert backup is not None
        self.assertTrue(str(backup).startswith(str(ssh_canary.backup_root(self.home))))
        self.assertEqual(list(self.home.glob(".ssh.*")), [])
        self.assertEqual((backup / "id_rsa").read_text(), "PRIVATE")

    def test_canaries_replace_the_directory(self):
        ok, _ = self.activate()
        self.assertTrue(ok)
        self.assertEqual(self.ssh.stat().st_mode & 0o777, 0o700)
        self.assertTrue((self.ssh / "id_rsa").exists())
        self.assertIn("HONEYPATH CANARY", (self.ssh / "id_rsa").read_text())
        self.assertIn("INTENTIONALLY INVALID", (self.ssh / "config").read_text())

    def test_canary_config_does_not_parse(self):
        if not Path(ssh_canary.SSH_BINARY).exists():
            self.skipTest("no system ssh")
        self.activate()
        proc = subprocess.run(
            [
                ssh_canary.SSH_BINARY,
                "-G",
                "-F",
                str(self.ssh / "config"),
                "example.invalid",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_canaries_are_registered_and_ungate_the_catalog(self):
        self.assertFalse(self.db.has_ssh_canaries(self.home))
        self.activate()
        self.assertTrue(self.db.has_ssh_canaries(self.home))
        paths = {c.path for c in self.db.get_canaries()}
        self.assertIn(str(self.ssh / "id_ed25519"), paths)

    def test_authorized_keys_is_preserved_and_not_a_canary(self):
        (self.ssh / "authorized_keys").write_text("ssh-ed25519 AAAA real-public-key\n")
        self.activate()
        restored = self.ssh / "authorized_keys"
        self.assertTrue(restored.exists())
        self.assertIn("real-public-key", restored.read_text())
        self.assertEqual(restored.stat().st_mode & 0o777, 0o600)
        paths = {c.path for c in self.db.get_canaries()}
        self.assertNotIn(str(restored), paths)

    def test_authorized_keys2_is_preserved_too(self):
        # Regression: authorized_keys2 is in GENERATED_FILES, so it is never
        # migrated to the relocated directory.  If activation does not restore
        # it as well, a configured authorized_keys2 is silently lost.
        (self.ssh / "authorized_keys").write_text("ssh-ed25519 AAAA primary\n")
        (self.ssh / "authorized_keys2").write_text("ssh-ed25519 AAAA secondary\n")
        self.activate()
        restored = self.ssh / "authorized_keys2"
        self.assertTrue(restored.exists())
        self.assertIn("secondary", restored.read_text())
        self.assertEqual(restored.stat().st_mode & 0o777, 0o600)
        paths = {c.path for c in self.db.get_canaries()}
        self.assertNotIn(str(restored), paths)

    def test_authorized_keys2_alone_is_preserved(self):
        (self.ssh / "authorized_keys2").write_text("ssh-ed25519 AAAA only-two\n")
        self.activate()
        self.assertIn("only-two", (self.ssh / "authorized_keys2").read_text())

    def test_authorized_keys_opt_out(self):
        (self.ssh / "authorized_keys").write_text("ssh-ed25519 AAAA key\n")
        self.activate(keep_authorized_keys=False)
        self.assertFalse((self.ssh / "authorized_keys").exists())

    def test_installation_state_records_the_backup(self):
        _, backup = self.activate()
        installation = self.db.get_ssh_installation(str(self.home))
        assert installation is not None
        self.assertEqual(installation["phase"], ssh_canary.PHASE_ACTIVATED)
        self.assertEqual(installation["backup_path"], str(backup))
        self.assertIsNotNone(installation["activated_at"])

    def test_reactivation_is_refused(self):
        self.activate()
        self.log_lines.clear()
        ok, _ = self.activate()
        self.assertFalse(ok)
        self.assertIn("already activated", self.logged())

    def test_dry_run_changes_nothing(self):
        ok, backup = self.activate(dry_run=True)
        self.assertTrue(ok)
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")
        assert backup is not None
        self.assertFalse(backup.exists())

    def test_exdev_falls_back_to_a_home_level_backup(self):
        real_rename = safe_write._renameat_noreplace
        state = {"first": True}

        def flaky_rename(src_fd, src, dst_fd, dst):
            if state["first"] and src == ".ssh":
                state["first"] = False
                raise OSError(18, "Invalid cross-device link")
            return real_rename(src_fd, src, dst_fd, dst)

        with mock.patch(
            "honeypath.safe_write._renameat_noreplace", side_effect=flaky_rename
        ):
            ok, backup = self.activate()
        self.assertTrue(ok)
        assert backup is not None
        self.assertTrue(backup.name.startswith(".ssh.honeypath-backup."))
        self.assertIn("EXDEV", self.logged())
        self.assertEqual((backup / "id_rsa").read_text(), "PRIVATE")

    def test_missing_ssh_dir_is_reported(self):
        shutil.rmtree(self.ssh)
        ok, _ = self.activate()
        self.assertFalse(ok)
        self.assertIn("does not exist", self.logged())

    def test_force_cannot_bypass_reactivation_guard_or_change_backup(self):
        ok, backup = self.activate()
        self.assertTrue(ok)
        assert backup is not None
        relocated_key = ssh_canary.relocated_dir(self.home) / "id_rsa"
        before = sha256_file(relocated_key)
        (self.ssh / "id_rsa").write_text("FAKE SECOND CANARY")
        ok2, _ = self.activate(force=True)
        self.assertFalse(ok2)
        self.assertEqual(sha256_file(relocated_key), before)
        installation = self.db.get_ssh_installation(self.home)
        self.assertEqual(installation["backup_path"], str(backup))


class DeactivationTests(TempHomeCase):
    def test_deactivate_under_regates_the_catalog(self):
        ssh_dir = self.home / ".ssh"
        self.db.record_canary(
            canary_id="linux.ssh.id_rsa",
            path=str(ssh_dir / "id_rsa"),
            kind="ssh_private_key",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="high",
            baseline_atime=None,
        )
        self.assertTrue(self.db.has_ssh_canaries(self.home))
        self.db.deactivate_under(str(ssh_dir) + "/")
        self.assertFalse(self.db.has_ssh_canaries(self.home))


if __name__ == "__main__":
    unittest.main()
