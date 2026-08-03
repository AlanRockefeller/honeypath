"""Relocated-config construction (§8.3)."""

from __future__ import annotations

import unittest
from pathlib import Path

from .support import TempHomeCase

from honeypath import ssh_canary  # noqa: E402

HOME = Path("/home/tester")
DEST = HOME / ssh_canary.RELOCATED_REL
TILDE = "~/" + ssh_canary.RELOCATED_REL


def rewrite(text: str):
    return ssh_canary.rewrite_user_config(text, HOME, DEST)


class PathTokenTests(unittest.TestCase):
    def test_tilde_prefix(self):
        self.assertEqual(
            ssh_canary.rewrite_path_token("~/.ssh/id_rsa", HOME, DEST),
            f"{TILDE}/id_rsa",
        )

    def test_home_variable_prefix(self):
        self.assertEqual(
            ssh_canary.rewrite_path_token("$HOME/.ssh/id_rsa", HOME, DEST),
            f"$HOME/{ssh_canary.RELOCATED_REL}/id_rsa",
        )
        self.assertEqual(
            ssh_canary.rewrite_path_token("${HOME}/.ssh/known_hosts", HOME, DEST),
            f"${{HOME}}/{ssh_canary.RELOCATED_REL}/known_hosts",
        )

    def test_percent_d_prefix(self):
        self.assertEqual(
            ssh_canary.rewrite_path_token("%d/.ssh/id_ed25519", HOME, DEST),
            f"%d/{ssh_canary.RELOCATED_REL}/id_ed25519",
        )

    def test_absolute_home_prefix(self):
        self.assertEqual(
            ssh_canary.rewrite_path_token(
                "/home/tester/.ssh/config.d/work", HOME, DEST
            ),
            f"{DEST}/config.d/work",
        )

    def test_bare_directory_forms(self):
        self.assertEqual(ssh_canary.rewrite_path_token("~/.ssh", HOME, DEST), TILDE)
        self.assertEqual(
            ssh_canary.rewrite_path_token("%d/.ssh", HOME, DEST),
            f"%d/{ssh_canary.RELOCATED_REL}",
        )

    def test_unrelated_paths_are_untouched(self):
        for token in ("/etc/ssh/ssh_config", "~/keys/id_rsa", "none", "%h"):
            self.assertEqual(ssh_canary.rewrite_path_token(token, HOME, DEST), token)


class DirectiveRewriteTests(unittest.TestCase):
    def test_each_rewritten_directive(self):
        directives = [
            "IdentityFile",
            "CertificateFile",
            "UserKnownHostsFile",
            "GlobalKnownHostsFile",
            "ControlPath",
            "IdentityAgent",
            "RevokedHostKeys",
            "SecurityKeyProvider",
            "PKCS11Provider",
            "KnownHostsCommand",
        ]
        for directive in directives:
            result = rewrite(f"    {directive} ~/.ssh/thing\n")
            self.assertIn(f"{TILDE}/thing", result.text, directive)
            self.assertEqual(len(result.rewrites), 1, directive)
            self.assertEqual(result.blockers, [], directive)

    def test_equals_separator_is_preserved(self):
        result = rewrite("IdentityFile=~/.ssh/id_rsa\n")
        self.assertIn(f"IdentityFile={TILDE}/id_rsa", result.text)

    def test_quoted_arguments_stay_quoted(self):
        result = rewrite('IdentityFile "~/.ssh/my key"\n')
        self.assertIn(f'"{TILDE}/my key"', result.text)

    def test_comments_and_blank_lines_survive(self):
        source = "# a comment about ~/.ssh\n\nHost example\n"
        result = rewrite(source)
        self.assertEqual(result.text, source)
        self.assertEqual(result.blockers, [])

    def test_multiple_include_arguments(self):
        result = rewrite("Include ~/.ssh/a ~/.ssh/b\n")
        self.assertIn(f"{TILDE}/a {TILDE}/b", result.text)

    def test_declares_identity_flag(self):
        self.assertTrue(rewrite("IdentityFile ~/.ssh/id_rsa\n").declares_identity)
        self.assertFalse(rewrite("Host foo\n  User bar\n").declares_identity)


class RelativeIncludeTests(unittest.TestCase):
    """Fact 2: relative includes resolve against ~/.ssh, not the config's dir."""

    def test_relative_include_becomes_absolute_relocated(self):
        result = rewrite("Include config.d/*\n")
        self.assertIn(f"Include {DEST}/config.d/*", result.text)
        self.assertEqual(len(result.rewrites), 1)

    def test_relative_include_of_a_plain_file(self):
        result = rewrite("Include work_hosts\n")
        self.assertIn(f"Include {DEST}/work_hosts", result.text)

    def test_absolute_include_outside_ssh_is_untouched(self):
        result = rewrite("Include /etc/ssh/extra.conf\n")
        self.assertIn("Include /etc/ssh/extra.conf", result.text)
        self.assertEqual(result.rewrites, [])


class BlockerTests(unittest.TestCase):
    def test_proxycommand_referencing_ssh_blocks(self):
        result = rewrite("Host bastion\n  ProxyCommand ssh -i ~/.ssh/jump nc %h %p\n")
        self.assertEqual(len(result.blockers), 1)
        self.assertIn("ProxyCommand", result.blockers[0])
        # Report-only: the shell text itself is untouched.
        self.assertIn("~/.ssh/jump", result.text)

    def test_localcommand_referencing_ssh_blocks(self):
        result = rewrite("LocalCommand /bin/cat ~/.ssh/banner\n")
        self.assertEqual(len(result.blockers), 1)
        self.assertIn("LocalCommand", result.blockers[0])

    def test_match_exec_referencing_ssh_blocks(self):
        result = rewrite('Match exec "test -f ~/.ssh/flag"\n')
        self.assertEqual(len(result.blockers), 1)
        self.assertIn("Match exec", result.blockers[0])

    def test_match_exec_without_ssh_is_fine(self):
        result = rewrite('Match exec "test -f /tmp/flag"\n')
        self.assertEqual(result.blockers, [])

    def test_proxycommand_without_ssh_reference_is_fine(self):
        result = rewrite("ProxyCommand nc %h %p\n")
        self.assertEqual(result.blockers, [])

    def test_unknown_directive_with_ssh_path_blocks(self):
        result = rewrite("SomeFutureOption ~/.ssh/thing\n")
        self.assertEqual(len(result.blockers), 1)
        self.assertIn("SomeFutureOption", result.blockers[0])


class ManagedBlockTests(unittest.TestCase):
    def build(self, **kwargs):
        options = dict(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        options.update(kwargs)
        return ssh_canary.build_managed_block(**options)

    def test_identity_lines_for_discovered_keys(self):
        block, _ = self.build(identity_files=[DEST / "id_ed25519", DEST / "id_work"])
        self.assertIn(f"IdentityFile {TILDE}/id_ed25519", block)
        self.assertIn(f"IdentityFile {TILDE}/id_work", block)

    def test_no_default_keys_when_user_declares_identities(self):
        block, warnings = self.build(
            identity_files=[DEST / "id_ed25519"], declares_identity=True
        )
        # No relocated keys are added (they would accumulate and reorder), but
        # OpenSSH's built-in ~/.ssh/id_* fallback must still be suppressed or
        # uncovered hosts would be offered the canaries.
        self.assertNotIn("id_ed25519", block)
        self.assertIn("IdentityFile none", block)
        self.assertTrue(any("built-in" in w for w in warnings))

    def test_suppression_falls_back_when_none_is_rejected(self):
        block, warnings = self.build(
            identity_files=[DEST / "id_ed25519"],
            declares_identity=True,
            identityfile_none_ok=False,
        )
        self.assertNotIn("IdentityFile none", block)
        self.assertIn(f"IdentityFile {TILDE}/no-identity-configured", block)

    def test_force_managed_identities_is_offered_as_the_escape_hatch(self):
        _, warnings = self.build(
            identity_files=[DEST / "id_ed25519"], declares_identity=True
        )
        self.assertTrue(any("--force-managed-identities" in w for w in warnings))

    def test_updatehostkeys_is_restored(self):
        # Relocating known_hosts silently turns UpdateHostKeys off in OpenSSH.
        block, _ = self.build()
        self.assertIn("UpdateHostKeys yes", block)

    def test_custom_known_hosts_is_disclosed(self):
        _, warnings = self.build(declares_custom_known_hosts=True)
        self.assertTrue(any("UpdateHostKeys" in w for w in warnings))

    def test_identityfile_none_when_no_keys_exist(self):
        block, warnings = self.build()
        self.assertIn("IdentityFile none", block)
        self.assertTrue(any("IdentityFile none" in w for w in warnings))

    def test_fallback_when_none_is_rejected(self):
        block, warnings = self.build(identityfile_none_ok=False)
        self.assertNotIn("IdentityFile none", block)
        self.assertIn(f"IdentityFile {TILDE}/no-identity-configured", block)
        self.assertTrue(any("rejected" in w for w in warnings))

    def test_agent_forwarding_defaults_off(self):
        block, _ = self.build()
        self.assertIn("ForwardAgent no", block)
        block, _ = self.build(allow_agent_forwarding=True)
        self.assertIn("ForwardAgent yes", block)

    def test_block_contents(self):
        block, _ = self.build()
        self.assertTrue(block.startswith(ssh_canary.MANAGED_BEGIN))
        self.assertIn("Host *", block)
        self.assertIn("IdentitiesOnly yes", block)
        self.assertIn(f"UserKnownHostsFile {TILDE}/known_hosts", block)
        self.assertTrue(block.rstrip().endswith(ssh_canary.MANAGED_END))


class KnownHostsDetectionTests(unittest.TestCase):
    def test_default_known_hosts_is_not_custom(self):
        for token in (
            "~/.ssh/known_hosts",
            "%d/.ssh/known_hosts",
            "$HOME/.ssh/known_hosts",
            "/home/tester/.ssh/known_hosts",
        ):
            result = rewrite(f"UserKnownHostsFile {token}\n")
            self.assertFalse(result.declares_custom_known_hosts, token)

    def test_custom_known_hosts_is_detected(self):
        result = rewrite("UserKnownHostsFile ~/.ssh/known_hosts_work\n")
        self.assertTrue(result.declares_custom_known_hosts)

    def test_no_declaration_means_not_custom(self):
        self.assertFalse(rewrite("Host x\n  User y\n").declares_custom_known_hosts)


class AssemblyTests(unittest.TestCase):
    def test_managed_block_comes_after_user_content(self):
        block, _ = ssh_canary.build_managed_block(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        text = ssh_canary.assemble_relocated_config("Host work\n  User alan\n", block)
        self.assertLess(text.index("Host work"), text.index(ssh_canary.MANAGED_BEGIN))

    def test_system_include_is_last(self):
        block, _ = ssh_canary.build_managed_block(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        system = Path("/etc/ssh/ssh_config")
        text = ssh_canary.assemble_relocated_config(
            "Host work\n", block, system_config=system
        )
        if system.exists():
            self.assertIn(f"Include {system}", text)
            self.assertGreater(
                text.index(f"Include {system}"), text.index(ssh_canary.MANAGED_END)
            )

    def test_system_include_omitted_when_absent(self):
        block, _ = ssh_canary.build_managed_block(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        text = ssh_canary.assemble_relocated_config(
            "", block, system_config=Path("/nonexistent/ssh_config")
        )
        self.assertNotIn("Include /nonexistent", text)

    def test_split_managed_block_round_trip(self):
        block, _ = ssh_canary.build_managed_block(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        text = ssh_canary.assemble_relocated_config("Host work\n  User alan\n", block)
        user, managed, tail = ssh_canary.split_managed_block(text)
        self.assertIn("Host work", user)
        self.assertIn("IdentitiesOnly yes", managed)
        self.assertNotIn("Host work", managed)

    def test_regenerating_is_idempotent(self):
        block, _ = ssh_canary.build_managed_block(
            identity_files=[],
            declares_identity=False,
            identityfile_none_ok=True,
            allow_agent_forwarding=False,
        )
        first = ssh_canary.assemble_relocated_config("Host work\n", block)
        user, _, _ = ssh_canary.split_managed_block(first)
        second = ssh_canary.assemble_relocated_config(user, block)
        self.assertEqual(first, second)


class SshGDiffTests(unittest.TestCase):
    def test_expected_keys_are_ignored(self):
        before = ["identityfile ~/.ssh/id_rsa", "user alan", "port 22"]
        after = ["identityfile ~/other/id_rsa", "user alan", "port 22"]
        self.assertEqual(ssh_canary.diff_ssh_g(before, after), [])

    def test_unexpected_change_is_reported(self):
        before = ["user alan", "port 22"]
        after = ["user root", "port 22"]
        differences = ssh_canary.diff_ssh_g(before, after)
        self.assertEqual(len(differences), 1)
        self.assertIn("user", differences[0])


class IdentityDiscoveryTests(TempHomeCase):
    def test_finds_conventional_and_pub_paired_keys(self):
        directory = self.home / "real-ssh"
        directory.mkdir()
        for name in (
            "id_rsa",
            "id_rsa.pub",
            "id_work",
            "id_work.pub",
            "known_hosts",
            "config",
            "random.txt",
        ):
            (directory / name).write_text("x")
        found = {p.name for p in ssh_canary.discover_identity_files(directory)}
        self.assertEqual(found, {"id_rsa", "id_work"})

    def test_missing_directory_returns_empty(self):
        self.assertEqual(ssh_canary.discover_identity_files(self.home / "nope"), [])


class IdentityFileNoneProbeTests(unittest.TestCase):
    def test_probe_against_the_real_ssh(self):
        if not Path(ssh_canary.SSH_BINARY).exists():
            self.skipTest("no system ssh")
        # Whatever the answer, the probe must return a bool and not raise.
        self.assertIsInstance(ssh_canary.probe_identityfile_none(), bool)

    def test_probe_with_a_missing_binary_is_false(self):
        self.assertFalse(ssh_canary.probe_identityfile_none("/nonexistent/ssh"))


if __name__ == "__main__":
    unittest.main()
