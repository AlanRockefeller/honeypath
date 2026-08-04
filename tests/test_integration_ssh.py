"""End-to-end SSH canary flow against the real OpenSSH client.

The unit tests check each piece in isolation; this one checks that the
relocated config OpenSSH actually parses resolves to the same settings as the
original, that the wrapper works, and that no canary path leaks back into the
resolved configuration.  It caught two real bugs during development:

* ``~/.ssh/config`` being *copied* to the relocated path, which made the
  hand-edit guard preserve it verbatim and silently skip every rewrite;
* ``UpdateHostKeys`` being turned off by OpenSSH as a side effect of moving
  ``known_hosts`` off its default path.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from .support import TempHomeCase

from honeypath import safe_write, ssh_canary  # noqa: E402

INTERESTING = {
    "user",
    "hostname",
    "identityfile",
    "userknownhostsfile",
    "controlpath",
    "serveraliveinterval",
    "identitiesonly",
    "forwardagent",
    "updatehostkeys",
}


@unittest.skipUnless(
    Path(ssh_canary.SSH_BINARY).exists() and shutil.which("ssh-keygen"),
    "needs the OpenSSH client",
)
class SshCanaryIntegrationTests(TempHomeCase):
    HOSTS = ("work", "team", "extra", "github.com")

    def setUp(self):
        super().setUp()
        self.system_config = self.root / "system-ssh-config"
        self.system_config.write_text("# isolated test system config\n")
        self._system_patch = mock.patch.object(
            ssh_canary, "SYSTEM_SSH_CONFIG", self.system_config
        )
        self._system_patch.start()
        self.addCleanup(self._system_patch.stop)
        self.ssh = self.home / ".ssh"
        (self.ssh / "config.d").mkdir(parents=True)
        os.chmod(self.ssh, 0o700)
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(self.ssh / "id_ed25519"),
                "-C",
                "integration",
            ],
            check=True,
            capture_output=True,
        )
        (self.ssh / "config").write_text(
            "Host work\n"
            "    HostName work.example.com\n"
            "    IdentityFile ~/.ssh/id_ed25519\n"
            "    UserKnownHostsFile ~/.ssh/known_hosts_work\n"
            "\n"
            "Include config.d/*.conf\n"  # relative: resolves against ~/.ssh
            "Include ~/.ssh/extra.conf\n"
            "\n"
            "Host *\n"
            "    ServerAliveInterval 60\n"
            "    ControlPath ~/.ssh/cm-%r@%h:%p\n"
        )
        (self.ssh / "config.d" / "team.conf").write_text(
            "Host team\n    HostName team.example.com\n    User teamer\n"
        )
        (self.ssh / "extra.conf").write_text("Host extra\n    User extrauser\n")
        (self.ssh / "known_hosts_work").touch()
        (self.ssh / "authorized_keys").write_text("ssh-ed25519 AAAAfake integration\n")

        # OpenSSH expands ~ and %d from the passwd entry, not $HOME, and
        # production compares against `ssh -G <host>` with no -F (which does
        # read the system config). Mirror both by building an explicit
        # baseline config that includes /etc/ssh/ssh_config.
        self.baseline_config = self.root / "baseline-config"
        text = (self.ssh / "config").read_text()
        if ssh_canary.SYSTEM_SSH_CONFIG.exists():
            text += f"\nInclude {ssh_canary.SYSTEM_SSH_CONFIG}\n"
        self.baseline_config.write_text(text)
        self.baselines = {}
        for host in self.HOSTS:
            code, lines, err = self.ssh_g(host, self.baseline_config)
            # An unchecked baseline that failed would be an empty option list,
            # and every later "nothing changed" comparison would pass vacuously.
            self.assertEqual(code, 0, f"baseline ssh -G {host} failed: {err}")
            self.assertTrue(lines, f"baseline ssh -G {host} produced no output")
            self.baselines[host] = lines

    def ssh_g(self, host, config):
        proc = subprocess.run(
            [ssh_canary.SSH_BINARY, "-G", "-F", str(config), host],
            capture_output=True,
            text=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        return proc.returncode, proc.stdout.splitlines(), (proc.stderr or "").strip()

    def phase_one(self):
        with self.quiet():
            inventory = ssh_canary.inventory_ssh_dir(self.ssh)
            destination = ssh_canary.relocated_dir(self.home)
            plan = ssh_canary.plan_copy(inventory, destination)
            ssh_canary.copy_inventory(
                self.ssh, destination, inventory, plan, self.target, log=self.log
            )
            result = ssh_canary.prepare_relocated_config(
                self.db,
                self.target,
                log=self.log,
                baseline=self.baselines["github.com"],
            )
            ssh_canary.install_wrappers(self.db, self.target, log=self.log)
            self.db.upsert_ssh_installation(
                home=str(self.home),
                username=self.target.username,
                uid=self.target.uid,
                relocated_dir=str(destination),
                phase=ssh_canary.PHASE_PREPARED,
                source_hashes=inventory.hashes(),
                config_validation=result.validation_status,
            )
        return result

    def test_phase_one_produces_an_equivalent_config(self):
        result = self.phase_one()
        self.assertTrue(result.ok)
        self.assertEqual(result.blockers, [])
        self.assertEqual(result.validation_status, "ok")

        config = ssh_canary.relocated_config(self.home)
        for host in self.HOSTS:
            code, lines, err = self.ssh_g(host, config)
            self.assertEqual(code, 0, f"{host}: {err}")
            self.assertEqual(
                ssh_canary.diff_ssh_g(self.baselines[host], lines),
                [],
                f"unexpected resolved differences for {host}",
            )

    def test_all_ssh_paths_were_rewritten(self):
        self.phase_one()
        text = ssh_canary.relocated_config(self.home).read_text()
        user_section, _, _ = ssh_canary.split_managed_block(text)
        self.assertNotIn("/.ssh/", user_section)
        self.assertIn(ssh_canary.RELOCATED_REL, user_section)
        # The relative include became an absolute relocated path.
        self.assertIn(
            f"Include {ssh_canary.relocated_dir(self.home)}/config.d/*.conf",
            user_section,
        )

    def test_after_activation_nothing_resolves_into_the_canary_directory(self):
        self.phase_one()
        with self.quiet():
            activated, backup = ssh_canary.activate(self.db, self.target, log=self.log)
        self.assertTrue(activated)

        config = ssh_canary.relocated_config(self.home)
        for host in self.HOSTS:
            code, lines, err = self.ssh_g(host, config)
            self.assertEqual(code, 0, f"{host}: {err}")
            for line in lines:
                self.assertNotIn(f"{self.home}/.ssh/", line, f"{host}: {line}")
            self.assertEqual(ssh_canary.diff_ssh_g(self.baselines[host], lines), [])

    def test_the_wrapper_resolves_the_real_config(self):
        self.phase_one()
        with self.quiet():
            ssh_canary.activate(self.db, self.target, log=self.log)
        proc = subprocess.run(
            [str(ssh_canary.wrapper_dir(self.home) / "ssh"), "-G", "work"],
            capture_output=True,
            text=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        resolved: dict[str, list[str]] = {}
        for line in proc.stdout.splitlines():
            key, _, value = line.partition(" ")
            if key in INTERESTING:
                resolved.setdefault(key, []).append(value)
        self.assertEqual(resolved["hostname"], ["work.example.com"])
        # The user's own key comes first; `none` only suppresses the built-ins.
        self.assertEqual(
            resolved["identityfile"],
            [f"~/{ssh_canary.RELOCATED_REL}/id_ed25519", "none"],
        )
        self.assertEqual(resolved["forwardagent"], ["no"])

    def test_the_canary_config_fails_loudly(self):
        self.phase_one()
        with self.quiet():
            ssh_canary.activate(self.db, self.target, log=self.log)
        code, _, err = self.ssh_g("work", self.ssh / "config")
        self.assertNotEqual(code, 0)
        self.assertIn("Bad configuration option", err)

    def test_reactivation_is_impossible_and_preserves_real_key_hashes_and_backup(self):
        self.phase_one()
        relocated_key = ssh_canary.relocated_dir(self.home) / "id_ed25519"
        before = safe_write.sha256_anchored(relocated_key, root=self.home)
        with self.quiet():
            activated, backup = ssh_canary.activate(self.db, self.target, log=self.log)
        self.assertTrue(activated)
        assert backup is not None
        (self.ssh / "id_ed25519").write_text("FAKE CANARY EDIT")
        with self.quiet():
            second, _ = ssh_canary.activate(
                self.db, self.target, force=True, log=self.log
            )
        self.assertFalse(second)
        self.assertEqual(
            safe_write.sha256_anchored(relocated_key, root=self.home), before
        )
        self.assertEqual(
            self.db.get_ssh_installation(self.home)["backup_path"], str(backup)
        )

    def test_failed_activation_restores_original_ssh(self):
        self.phase_one()
        original = (self.ssh / "id_ed25519").read_bytes()
        with mock.patch.object(
            ssh_canary,
            "create_canary_file",
            side_effect=RuntimeError("injected canary failure"),
        ):
            with self.quiet():
                activated, backup = ssh_canary.activate(
                    self.db, self.target, log=self.log
                )
        self.assertFalse(activated)
        self.assertIsNone(backup)
        self.assertEqual((self.ssh / "id_ed25519").read_bytes(), original)
        self.assertEqual(self.db.get_ssh_installation(self.home)["phase"], "prepared")


if __name__ == "__main__":
    unittest.main()
