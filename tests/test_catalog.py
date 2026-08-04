"""Catalog safety and creation semantics (§1, §5)."""

from __future__ import annotations

import json
import os
import re
import stat
import unittest
from pathlib import Path
from unittest import mock

from .support import TempHomeCase

from honeypath import catalog  # noqa: E402

# Hostnames that must never appear in canary content: a canary that points a
# real tool at a real endpoint is a liability, not a detector.
FORBIDDEN_SUBSTRINGS = [
    "amazonaws.com",
    "registry.npmjs.org",
    "pypi.org",
    "crates.io",
    "github.com",
    "gitlab.com",
    "googleapis.com",
    "docker.io",
    "hub.docker.com",
    "azure.com",
    "windows.net",
    "digitalocean.com",
    "huggingface.co",
    "terraform.io",
    "nuget.org",
    "rubygems.org",
    "packagist.org",
    "maven.org",
]

_URL_RE = re.compile(r"[a-z][a-z0-9+.\-]*://([^/\s\"']+)")


def _hosts_in(text: str) -> list[str]:
    hosts = []
    for raw in _URL_RE.findall(text):
        host = raw.rsplit("@", 1)[-1]
        host = host.split(":", 1)[0]
        hosts.append(host)
    return hosts


class ContentSafetyTests(unittest.TestCase):
    def test_every_url_host_is_invalid_tld(self):
        for entry in catalog.CATALOG:
            for host in _hosts_in(entry.content):
                self.assertTrue(
                    host.endswith(".invalid"),
                    f"{entry.key} references non-.invalid host {host!r}",
                )

    def test_no_real_service_hostnames(self):
        for entry in catalog.CATALOG:
            lowered = entry.content.lower()
            for forbidden in FORBIDDEN_SUBSTRINGS:
                self.assertNotIn(
                    forbidden, lowered, f"{entry.key} mentions {forbidden}"
                )

    def test_npmrc_cannot_reach_a_real_server(self):
        npmrc = next(e for e in catalog.CATALOG if e.key == "linux.npmrc")
        # A bare `registry=` line would repoint every npm install.
        self.assertNotRegex(npmrc.content, r"(?m)^registry=")

    def test_no_entry_claims_the_netrc_path(self):
        """git reads ~/.netrc on every HTTPS push; it cannot be a quiet canary."""
        for entry in catalog.CATALOG:
            self.assertNotEqual(entry.relative_path, ".netrc", entry.key)

    def test_my_cnf_does_not_define_a_client_group(self):
        entry = next(e for e in catalog.CATALOG if e.key == "linux.my.cnf")
        self.assertNotRegex(entry.content, r"(?m)^\[client\]")

    def test_private_key_canary_is_not_a_key(self):
        entry = next(e for e in catalog.CATALOG if e.key == "linux.ssh.id_ed25519")
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", entry.content)
        import base64

        blob = "".join(
            line for line in entry.content.splitlines() if not line.startswith("-----")
        )
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        self.assertIn(b"HONEYPATH CANARY KEY", decoded)
        self.assertNotIn(b"openssh-key-v1", decoded)

    def test_solana_canary_is_not_a_keypair_shaped_array(self):
        """§7: a 64-integer array reproduces the real keypair serialisation.

        The canary must be unmistakably not a keypair while still being
        attractive to a path-based stealer that grabs the file by name.
        """
        entry = next(e for e in catalog.CATALOG if e.key == "linux.solana.keypair")
        parsed = json.loads(entry.content)
        self.assertNotIsInstance(parsed, list)
        self.assertIsInstance(parsed, dict)
        self.assertIn("_honeypath", parsed)
        self.assertIn("HONEYPATH CANARY", parsed["_honeypath"])
        self.assertIn("NOT A SOLANA KEYPAIR", parsed["_honeypath"])
        self.assertIn("no private key material", parsed["warning"])

    def test_no_canary_serialises_as_a_64_integer_array(self):
        """No catalog entry may have the shape of a real ed25519 keypair."""
        for entry in catalog.CATALOG:
            if not entry.content.strip().startswith("["):
                continue
            try:
                parsed = json.loads(entry.content)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list) and len(parsed) == 64:
                self.assertFalse(
                    all(isinstance(v, int) for v in parsed),
                    f"{entry.key} is serialised as a 64-integer keypair array",
                )

    def test_every_creatable_canary_carries_the_marker(self):
        """--refresh-managed relies on this marker to identify its own files."""
        for entry in catalog.CATALOG:
            if not entry.creatable or not entry.content:
                continue
            self.assertTrue(
                catalog.content_has_marker(entry.content),
                f"{entry.key} content carries no Honeypath marker",
            )

    def test_electrum_seed_is_not_a_bip39_mnemonic(self):
        entry = next(e for e in catalog.CATALOG if e.key == "linux.electrum.wallet")
        seed = json.loads(entry.content)["seed"]
        self.assertIn("not a real seed phrase", seed)

    def test_ssh_canary_config_is_deliberately_invalid(self):
        entry = next(e for e in catalog.CATALOG if e.key == "linux.ssh.config")
        self.assertIn("INTENTIONALLY INVALID", entry.content)
        self.assertIn("HONEYPATH CANARY", entry.content)

    def test_json_canaries_parse(self):
        for entry in catalog.CATALOG:
            if entry.relative_path.endswith(".json") and entry.content:
                json.loads(entry.content)  # must not raise

    def test_browser_entries_are_never_created(self):
        for entry in catalog.CATALOG:
            if entry.base_profile == "browser-noisy":
                self.assertFalse(entry.creatable, entry.key)
                self.assertEqual(entry.content, "")


class ActiveConfigAuditTests(unittest.TestCase):
    """§4: behaviour-changing defaults must be opt-in, and the safe ones
    must genuinely be scoped."""

    def entry(self, key):
        return next(e for e in catalog.CATALOG if e.key == key)

    def test_every_entry_has_a_known_category(self):
        for entry in catalog.CATALOG:
            self.assertIn(entry.category, catalog.ALL_CATEGORIES, entry.key)

    def test_aws_template_has_no_default_profile(self):
        content = catalog.aws_credentials_content()
        self.assertNotRegex(content, r"(?m)^\s*\[default\]")
        self.assertIn(f"[{catalog.AWS_CANARY_PROFILE}]", content)

    def test_aws_template_with_canarytoken_has_no_default_profile(self):
        content = catalog.aws_credentials_content(
            {"aws_access_key_id": "AKIAX", "aws_secret_access_key": "y"}
        )
        self.assertNotRegex(content, r"(?m)^\s*\[default\]")
        self.assertIn(f"[{catalog.AWS_CANARY_PROFILE}]", content)

    def test_no_aws_entry_in_the_catalog_declares_a_default_profile(self):
        for entry in catalog.CATALOG:
            if entry.kind == "aws_credentials":
                self.assertNotRegex(entry.content, r"(?m)^\s*\[default\]", entry.key)

    def test_kubeconfig_sets_no_current_context(self):
        for entry in catalog.CATALOG:
            if entry.kind == "kubeconfig":
                self.assertNotRegex(
                    entry.content, r"(?m)^\s*current-context:", entry.key
                )

    def test_behaviour_changing_entries_are_active_config(self):
        must_be_active = {
            "linux.gcloud.adc",  # THE Application Default Credentials path
            "linux.azure.tokens",  # the Azure CLI token cache
            "linux.kube.config",  # kubectl's default kubeconfig
            "linux.dbt.profiles",  # dbt's sole configuration path
            "linux.gh.hosts",  # gh infers its default host from this
            "linux.huggingface.token",  # THE huggingface_hub token file
            "linux.doctl.config",  # doctl's sole config and default token
        }
        for key in must_be_active:
            self.assertEqual(self.entry(key).category, catalog.CATEGORY_ACTIVE, key)

    def test_scoped_entries_stay_enabled_by_default(self):
        must_be_safe = {
            "linux.aws.credentials",  # named profile, no [default]
            "linux.npmrc",  # scoped registry, no bare registry=
            "linux.pypirc",  # no [distutils] index-servers
            "linux.cargo.credentials",  # [registries.honeypath-canary]
            "linux.pgpass",  # host-keyed
            "linux.my.cnf",  # custom option group
            "linux.docker.config",  # auths keyed by registry
            "linux.terraformrc",  # credentials keyed by hostname
            "linux.gradle.properties",  # namespaced custom properties
        }
        for key in must_be_safe:
            self.assertEqual(self.entry(key).category, catalog.CATEGORY_SAFE, key)

    def test_pypirc_declares_no_index_servers(self):
        """`index-servers` redefines the set of servers twine knows about."""
        for entry in catalog.CATALOG:
            if entry.kind == "pypi_token":
                self.assertNotRegex(entry.content, r"(?m)^\s*index-servers", entry.key)
                self.assertNotRegex(entry.content, r"(?m)^\s*\[distutils\]", entry.key)

    def test_gradle_properties_sets_no_gradle_behaviour(self):
        entry = self.entry("linux.gradle.properties")
        self.assertNotIn("org.gradle.", entry.content)
        self.assertNotIn("systemProp.", entry.content)

    def test_gem_credentials_does_not_use_the_default_api_key(self):
        entry = self.entry("linux.gem.credentials")
        self.assertNotIn(":rubygems_api_key:", entry.content)

    def test_yarnrc_does_not_repoint_the_registry(self):
        entry = self.entry("linux.yarnrc")
        self.assertNotRegex(entry.content, r"(?m)^\s*npmRegistryServer")

    def test_crypto_and_watch_categories_are_consistent(self):
        for entry in catalog.CATALOG:
            if entry.base_profile == "crypto":
                self.assertEqual(entry.category, catalog.CATEGORY_CRYPTO, entry.key)
            if entry.base_profile == "browser-noisy":
                self.assertEqual(entry.category, catalog.CATEGORY_WATCH, entry.key)
            if entry.ssh_gated:
                self.assertEqual(entry.category, catalog.CATEGORY_SSH, entry.key)

    def test_entries_for_profiles_filters_active_config(self):
        profiles = ["linux-developer", "linux-supply-chain"]
        included = catalog.entries_for_profiles(profiles, include_active_config=True)
        excluded = catalog.entries_for_profiles(profiles, include_active_config=False)
        self.assertTrue(any(e.is_active_config for e in included))
        self.assertFalse(any(e.is_active_config for e in excluded))
        # Nothing else is lost.
        self.assertEqual(
            {e.key for e in included} - {e.key for e in excluded},
            {e.key for e in catalog.active_config_entries(profiles)},
        )


class CatalogStructureTests(unittest.TestCase):
    def test_ssh_entries_are_gated(self):
        for entry in catalog.CATALOG:
            if ".ssh" in Path(entry.relative_path).parts:
                self.assertTrue(entry.ssh_gated, entry.key)
        for entry in catalog.CATALOG:
            if entry.ssh_gated:
                self.assertIn(".ssh", Path(entry.relative_path).parts)

    def test_required_linux_developer_paths_present(self):
        required = {
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/config",
            ".aws/credentials",
            ".config/gcloud/application_default_credentials.json",
            ".azure/accessTokens.json",
            ".kube/config",
            ".docker/config.json",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials.toml",
            ".config/gh/hosts.yml",
            ".pgpass",
            ".my.cnf",
            ".dbt/profiles.yml",
            "honeypath-canary-project/.env",
        }
        present = {
            e.relative_path
            for e in catalog.CATALOG
            if e.platform == catalog.PLATFORM_LINUX
        }
        self.assertTrue(required <= present, required - present)

    def test_required_windows_paths_present(self):
        required = {
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/config",
            ".aws/credentials",
            ".git-credentials",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials.toml",
            ".kube/config",
            ".docker/config.json",
            ".dbt/profiles.yml",
            "AppData/Roaming/GitHub CLI/hosts.yml",
        }
        present = {
            e.relative_path
            for e in catalog.CATALOG
            if e.platform == catalog.PLATFORM_WINDOWS
        }
        self.assertTrue(required <= present, required - present)

    def test_macos_has_no_canary_project_but_has_gh_hosts(self):
        macos = {
            e.relative_path
            for e in catalog.CATALOG
            if e.platform == catalog.PLATFORM_MACOS
        }
        self.assertNotIn("honeypath-canary-project/.env", macos)
        self.assertIn("Library/Application Support/GitHub CLI/hosts.yml", macos)

    def test_paths_are_unique_per_platform(self):
        seen = set()
        for entry in catalog.CATALOG:
            key = (entry.platform, entry.relative_path)
            self.assertNotIn(key, seen, f"duplicate catalog path {key}")
            seen.add(key)


class ProfileExpansionTests(unittest.TestCase):
    def expand(self, names, **kwargs):
        options = dict(
            os_name="wsl",
            has_windows_home=True,
            default_profiles=[
                "linux-developer",
                "linux-supply-chain",
                "wsl-windows-developer",
                "wsl-windows-supply-chain",
            ],
        )
        options.update(kwargs)
        return catalog.expand_profile_names(names, **options)

    def test_auto_on_wsl_with_windows_home(self):
        profiles, _ = self.expand(["auto"])
        self.assertEqual(
            profiles,
            [
                "linux-developer",
                "linux-supply-chain",
                "wsl-windows-developer",
                "wsl-windows-supply-chain",
            ],
        )

    def test_crypto_requires_the_flag(self):
        profiles, warnings = self.expand(
            ["auto"], default_profiles=["linux-developer", "linux-crypto"]
        )
        self.assertNotIn("linux-crypto", profiles)
        self.assertTrue(any("include-crypto" in w for w in warnings))

        profiles, _ = self.expand(
            ["auto"],
            default_profiles=["linux-developer", "linux-crypto"],
            include_crypto=True,
        )
        self.assertIn("linux-crypto", profiles)

    def test_explicitly_named_crypto_profile_is_honoured(self):
        profiles, _ = self.expand(["linux-crypto"])
        self.assertEqual(profiles, ["linux-crypto"])

    def test_base_profile_expands_per_platform(self):
        profiles, _ = self.expand(["developer"])
        self.assertEqual(profiles, ["linux-developer", "wsl-windows-developer"])
        profiles, _ = self.expand(
            ["developer"], os_name="macos", has_windows_home=False
        )
        self.assertEqual(profiles, ["macos-developer"])

    def test_unknown_profile_warns(self):
        profiles, warnings = self.expand(["nope"])
        self.assertEqual(profiles, [])
        self.assertTrue(any("unknown profile" in w for w in warnings))

    def test_browser_noisy_excluded_by_default(self):
        profiles, warnings = self.expand(
            ["auto"], default_profiles=["linux-browser-noisy"]
        )
        self.assertEqual(profiles, [])
        self.assertTrue(any("include-noisy" in w for w in warnings))


class CreateCanaryFileTests(TempHomeCase):
    def test_creates_with_mode_and_content(self):
        path = self.home / ".aws" / "credentials"
        result = catalog.create_canary_file(path, "body\n", 0o600, self.target)
        self.assertTrue(result.created)
        self.assertEqual(path.read_text(), "body\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_never_overwrites_an_existing_file(self):
        path = self.write(".netrc", "REAL CREDENTIALS\n")
        result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertIn("already exists", result.reason)
        self.assertEqual(path.read_text(), "REAL CREDENTIALS\n")

    def test_create_canary_file_has_no_force_parameter(self):
        """§2: the only overwrite path is the verified replace_managed one."""
        import inspect

        signature = inspect.signature(catalog.create_canary_file)
        self.assertNotIn("force", signature.parameters)
        self.assertIn("replace_managed", signature.parameters)

    def test_replace_managed_replaces_a_regular_file(self):
        path = self.write(".netrc", "old honeypath canary\n")
        result = catalog.create_canary_file(
            path, "canary\n", 0o600, self.target, replace_managed=True
        )
        self.assertTrue(result.created)
        self.assertEqual(path.read_text(), "canary\n")

    def test_replace_managed_still_refuses_a_symlink(self):
        real = self.write("real.txt", "important\n")
        link = self.home / ".netrc"
        link.symlink_to(real)
        result = catalog.create_canary_file(
            link, "canary\n", 0o600, self.target, replace_managed=True
        )
        self.assertFalse(result.created)
        self.assertIn("symlink", result.reason)
        self.assertEqual(real.read_text(), "important\n")

    def test_replace_managed_still_refuses_a_fifo(self):
        path = self.home / ".pgpass"
        os.mkfifo(path)
        result = catalog.create_canary_file(
            path, "canary\n", 0o600, self.target, replace_managed=True
        )
        self.assertFalse(result.created)
        self.assertIn("not a regular file", result.reason)
        self.assertTrue(stat.S_ISFIFO(os.lstat(path).st_mode))

    def test_refuses_a_dangling_symlink(self):
        link = self.home / ".netrc"
        link.symlink_to(self.home / "does-not-exist")
        result = catalog.create_canary_file(link, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertIn("symlink", result.reason)
        # The symlink itself must survive untouched.
        self.assertTrue(link.is_symlink())

    def test_refuses_symlinks(self):
        real = self.write("real.txt", "important\n")
        link = self.home / ".netrc"
        link.symlink_to(real)
        result = catalog.create_canary_file(link, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertIn("symlink", result.reason)
        self.assertEqual(real.read_text(), "important\n")

    def test_refuses_directories(self):
        path = self.home / ".npmrc"
        path.mkdir()
        result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertIn("not a regular file", result.reason)

    def test_dry_run_changes_nothing(self):
        path = self.home / ".pgpass"
        result = catalog.create_canary_file(
            path, "canary\n", 0o600, self.target, dry_run=True
        )
        self.assertFalse(result.created)
        self.assertFalse(path.exists())

    def test_idempotent_second_run_skips(self):
        path = self.home / ".pypirc"
        first = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        second = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertTrue(first.created)
        self.assertFalse(second.created)

    def test_leaves_no_temp_file_behind(self):
        path = self.home / ".dbt" / "profiles.yml"
        catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        leftovers = [
            p
            for p in path.parent.iterdir()
            if p.name.startswith(".honeypath-tmp") or p.name.endswith(".honeypath-tmp")
        ]
        self.assertEqual(leftovers, [])

    def test_temp_file_name_is_not_predictable(self):
        """§3: the old adjacent `<name>.honeypath-tmp` was guessable.

        A pre-positioned symlink at the *old* predictable temporary path must
        not be followed, and must be left untouched.
        """
        outside = self.root / "outside.txt"
        outside.write_text("MUST NOT BE TOUCHED\n")
        path = self.home / ".aws" / "credentials"
        path.parent.mkdir(parents=True)
        trap = path.with_name(path.name + ".honeypath-tmp")
        trap.symlink_to(outside)

        result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertTrue(result.created)
        self.assertEqual(path.read_text(), "canary\n")
        # The trap was never opened, so the file it points at is unchanged.
        self.assertEqual(outside.read_text(), "MUST NOT BE TOUCHED\n")
        self.assertTrue(trap.is_symlink())


class PortableCreationTests(TempHomeCase):
    """Hosts without O_TMPFILE (macOS) must still be able to create canaries."""

    def no_unnamed_temporary(self):
        """Pretend this host is a kernel without O_TMPFILE, e.g. Darwin."""
        return mock.patch.object(
            catalog.safe_write, "supports_unnamed_temporary", return_value=False
        )

    def test_new_canary_is_created_without_otmpfile(self):
        path = self.home / ".aws" / "credentials"
        with self.no_unnamed_temporary():
            result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertTrue(result.created, result.reason)
        self.assertEqual(path.read_text(), "canary\n")
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)

    def test_the_portable_path_still_never_clobbers_an_existing_file(self):
        path = self.write(".netrc", "REAL CREDENTIALS\n")
        with self.no_unnamed_temporary():
            result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertEqual(path.read_text(), "REAL CREDENTIALS\n")

    def test_replacement_is_still_refused_without_the_linux_primitives(self):
        """A managed refresh needs compare-and-swap; O_EXCL cannot provide it."""
        path = self.write(".netrc", "old honeypath canary\n")
        with self.no_unnamed_temporary():
            result = catalog.create_canary_file(
                path, "canary\n", 0o600, self.target, replace_managed=True
            )
        self.assertFalse(result.created)
        self.assertEqual(path.read_text(), "old honeypath canary\n")

    def test_linux_hosts_do_not_silently_relax_to_the_portable_path(self):
        """On Linux a filesystem that cannot do O_TMPFILE is still refused."""
        if not catalog.safe_write.supports_unnamed_temporary():  # pragma: no cover
            self.skipTest("host has no O_TMPFILE support")
        path = self.home / ".pypirc"
        unavailable = catalog.safe_write.SafeWriteError("O_TMPFILE unsupported")
        with mock.patch.object(
            catalog.safe_write, "_open_unnamed_temporary", side_effect=unavailable
        ):
            result = catalog.create_canary_file(path, "canary\n", 0o600, self.target)
        self.assertFalse(result.created)
        self.assertFalse(path.exists())


class CanarytokenSpliceTests(unittest.TestCase):
    def test_default_content_is_fake(self):
        content = catalog.aws_credentials_content()
        self.assertIn("AKIAHONEYPATHCANARY0", content)

    def test_splice_replaces_the_keys(self):
        content = catalog.aws_credentials_content(
            {
                "aws_access_key_id": "AKIAOPERATORSUPPLIED",
                "aws_secret_access_key": "s3cr3t",
            }
        )
        self.assertIn("AKIAOPERATORSUPPLIED", content)
        self.assertNotIn("AKIAHONEYPATHCANARY0", content)

    def test_render_content_only_splices_aws_entries(self):
        token = {"aws_access_key_id": "AKIAX", "aws_secret_access_key": "y"}
        aws = next(e for e in catalog.CATALOG if e.key == "linux.aws.credentials")
        npm = next(e for e in catalog.CATALOG if e.key == "linux.npmrc")
        self.assertIn("AKIAX", catalog.render_content(aws, canarytoken=token))
        self.assertEqual(catalog.render_content(npm, canarytoken=token), npm.content)


if __name__ == "__main__":
    unittest.main()
