"""Plan construction and the .ssh activation gate (§5.3, §7.2, §7.3)."""

from __future__ import annotations

import os
import queue
import threading
import unittest
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import (  # noqa: E402
    catalog,
    cli,
    monitor as monitor_mod,
    safe_write,
)
from honeypath.platform_detect import PlatformContext  # noqa: E402


class PlanTests(TempHomeCase):
    def make_context(self, *, windows_home=None, os_name="linux", **kwargs):
        windows_homes = [windows_home] if windows_home else []
        platform = PlatformContext(
            os_name=os_name,
            home=self.home,
            windows_homes=windows_homes,
            default_profiles=(
                ["linux-developer", "linux-supply-chain"]
                + (
                    ["wsl-windows-developer", "wsl-windows-supply-chain"]
                    if windows_homes
                    else []
                )
            ),
        )
        return cli.Context(
            args=namespace(**kwargs),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def paths(self, items, action=None):
        return {str(i.path) for i in items if action is None or i.action == action}

    # -- the .ssh gate ----------------------------------------------------

    def test_no_ssh_paths_before_activation(self):
        items, _, notes = cli.build_plan(self.make_context())
        for path in self.paths(items):
            self.assertNotIn("/.ssh/", path)
        self.assertIn(cli.SSH_GATE_MESSAGE, notes)

    def test_gate_message_is_reported_once(self):
        _, _, notes = cli.build_plan(self.make_context())
        self.assertEqual(notes.count(cli.SSH_GATE_MESSAGE), 1)

    def test_ssh_paths_appear_after_activation_state_exists(self):
        self.db.record_canary(
            canary_id="linux.ssh.id_rsa",
            path=str(self.home / ".ssh" / "id_rsa"),
            kind="ssh_private_key",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="high",
            baseline_atime=None,
        )
        items, _, notes = cli.build_plan(self.make_context())
        planned = self.paths(items)
        self.assertTrue(any("/.ssh/" in p for p in planned))
        self.assertNotIn(cli.SSH_GATE_MESSAGE, notes)

    def test_gate_is_per_home(self):
        windows_home = self.root / "winhome"
        (windows_home / ".ssh").mkdir(parents=True)
        self.db.record_canary(
            canary_id="linux.ssh.id_rsa",
            path=str(self.home / ".ssh" / "id_rsa"),
            kind="ssh_private_key",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="high",
            baseline_atime=None,
        )
        ctx = self.make_context(windows_home=windows_home, os_name="wsl")
        items, _, _ = cli.build_plan(ctx)
        planned = self.paths(items)
        self.assertIn(str(self.home / ".ssh" / "id_rsa"), planned)
        self.assertNotIn(str(windows_home / ".ssh" / "id_rsa"), planned)

    # -- non-overwrite ----------------------------------------------------

    def test_existing_files_are_skipped_not_overwritten(self):
        self.write(".pgpass", "REAL\n")
        items, _, _ = cli.build_plan(self.make_context())
        skipped = [i for i in items if str(i.path).endswith("/.pgpass")]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0].action, "skip")
        self.assertIn("already exists", skipped[0].reason)

    def test_force_can_never_plan_an_overwrite(self):
        """§2: --force must not make create-canaries replace a real file."""
        self.write(".pgpass", "REAL\n")
        items, _, _ = cli.build_plan(self.make_context(force=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("already exists", entry.reason)

    def test_top_level_force_can_never_plan_an_overwrite(self):
        """An inherited top-level --force must not change the outcome either."""
        self.write(".pgpass", "REAL\n")
        items, _, _ = cli.build_plan(self.make_context(top_force=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")

    # -- active-config gating ---------------------------------------------

    def test_default_plan_excludes_behaviour_changing_defaults(self):
        """§4: no default authentication path is planned without opt-in."""
        items, _, notes = cli.build_plan(self.make_context())
        planned = self.paths(items)
        for relative in (
            ".config/gcloud/application_default_credentials.json",
            ".azure/accessTokens.json",
            ".kube/config",
            ".dbt/profiles.yml",
            ".config/gh/hosts.yml",
            ".huggingface/token",
            ".config/doctl/config.yaml",
        ):
            self.assertNotIn(str(self.home / relative), planned, relative)
        self.assertIn(catalog.ACTIVE_CONFIG_EXCLUDED_NOTE, notes)

    def test_default_plan_has_no_active_config_entries_at_all(self):
        items, _, _ = cli.build_plan(self.make_context())
        for item in items:
            self.assertFalse(
                item.entry.is_active_config,
                f"{item.entry.key} planned without --include-active-config",
            )

    def test_include_active_config_enables_them(self):
        items, _, notes = cli.build_plan(self.make_context(include_active_config=True))
        planned = self.paths(items, "create")
        self.assertIn(str(self.home / ".kube" / "config"), planned)
        self.assertIn(
            str(
                self.home
                / ".config"
                / "gcloud"
                / "application_default_credentials.json"
            ),
            planned,
        )
        self.assertNotIn(catalog.ACTIVE_CONFIG_EXCLUDED_NOTE, notes)

    def test_safe_scoped_canaries_remain_enabled_by_default(self):
        items, _, _ = cli.build_plan(self.make_context())
        planned = self.paths(items, "create")
        for relative in (
            ".npmrc",
            ".pypirc",
            ".pgpass",
            ".my.cnf",
            ".aws/credentials",
            ".docker/config.json",
        ):
            self.assertIn(str(self.home / relative), planned, relative)

    # -- --refresh-managed -------------------------------------------------

    def test_refresh_managed_refuses_an_untracked_file(self):
        """§2: a real credential file is never refreshable."""
        self.write(".pgpass", "real.example:5432:proddb:me:REAL\n")
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("not recorded as a Honeypath-managed canary", entry.reason)

    def test_refresh_managed_refuses_a_tracked_file_without_the_marker(self):
        """Recorded in SQLite is not enough; the content must match too."""
        path = self.write(".pgpass", "real.example:5432:proddb:me:REAL\n")
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(path),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
        )
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("exact managed identity", entry.reason)

    def test_refresh_managed_accepts_a_verified_managed_canary(self):
        path = self.write(
            ".pgpass",
            "# Honeypath canary file\ndb.x.invalid:5432:canarydb:canaryuser:fake\n",
        )
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(path),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
            content_hash=catalog.sha256_text(path.read_text()),
            managed_marker=catalog.managed_marker("linux.pgpass"),
        )
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "refresh")

    def test_refresh_refuses_edited_file_even_with_honeypath_header(self):
        original = (
            "# Honeypath canary file\ndb.x.invalid:5432:canarydb:canaryuser:fake\n"
        )
        path = self.write(".pgpass", original)
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(path),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
            content_hash=catalog.sha256_text(original),
            managed_marker=catalog.managed_marker("linux.pgpass"),
        )
        path.write_text(original + "real.example:5432:proddb:me:REAL\n")
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("exact content hash changed", entry.reason)

    def test_refresh_managed_refuses_a_symlink_even_when_tracked(self):
        outside = self.root / "real-secrets"
        outside.write_text("# honeypath\nREAL\n")
        link = self.home / ".pgpass"
        link.symlink_to(outside)
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(link),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
        )
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("symlink", entry.reason)
        self.assertEqual(outside.read_text(), "# honeypath\nREAL\n")

    def test_refresh_managed_refuses_a_directory_even_when_tracked(self):
        path = self.home / ".pgpass"
        path.mkdir()
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(path),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
        )
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("not a regular file", entry.reason)

    def test_refresh_managed_refuses_a_fifo_even_when_tracked(self):
        path = self.home / ".pgpass"
        os.mkfifo(path)
        self.db.record_canary(
            canary_id="linux.pgpass",
            path=str(path),
            kind="pgpass",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            baseline_atime=None,
        )
        items, _, _ = cli.build_plan(self.make_context(refresh_managed=True))
        entry = next(i for i in items if str(i.path).endswith("/.pgpass"))
        self.assertEqual(entry.action, "skip")
        self.assertIn("not a regular file", entry.reason)

    # -- platform scoping -------------------------------------------------

    def test_windows_entries_need_a_windows_home(self):
        items, profiles, _ = cli.build_plan(self.make_context(os_name="wsl"))
        self.assertNotIn("wsl-windows-developer", profiles)
        for path in self.paths(items):
            self.assertTrue(path.startswith(str(self.home)))

    def test_windows_entries_land_under_the_windows_home(self):
        windows_home = self.root / "winhome"
        windows_home.mkdir()
        ctx = self.make_context(windows_home=windows_home, os_name="wsl")
        items, profiles, _ = cli.build_plan(ctx)
        self.assertIn("wsl-windows-developer", profiles)
        self.assertIn(str(windows_home / ".npmrc"), self.paths(items, "create"))

    def test_nothing_is_planned_outside_the_target_homes(self):
        windows_home = self.root / "winhome"
        windows_home.mkdir()
        ctx = self.make_context(windows_home=windows_home, os_name="wsl")
        items, _, _ = cli.build_plan(ctx)
        for path in self.paths(items):
            self.assertTrue(
                path.startswith(str(self.home)) or path.startswith(str(windows_home)),
                path,
            )

    # -- profile flags ----------------------------------------------------

    def test_crypto_excluded_by_default(self):
        items, profiles, _ = cli.build_plan(self.make_context())
        self.assertNotIn("linux-crypto", profiles)
        self.assertFalse(any("electrum" in p.lower() for p in self.paths(items)))

    def test_crypto_included_with_the_flag(self):
        ctx = self.make_context(include_crypto=True, profiles=["linux-crypto"])
        items, profiles, _ = cli.build_plan(ctx)
        self.assertIn("linux-crypto", profiles)
        self.assertTrue(any("electrum" in p.lower() for p in self.paths(items)))

    def test_browser_targets_are_never_created(self):
        profile_dir = self.home / ".mozilla" / "firefox" / "abc.default"
        profile_dir.mkdir(parents=True)
        (profile_dir / "logins.json").write_text("{}")
        ctx = self.make_context(include_noisy=True, profiles=["linux-browser-noisy"])
        items, _, _ = cli.build_plan(ctx)
        actions = {i.action for i in items}
        self.assertNotIn("create", actions)
        self.assertIn("watch-only", actions)
        self.assertIn(str(profile_dir / "logins.json"), self.paths(items, "watch-only"))

    def test_comma_separated_profiles(self):
        ctx = self.make_context(profiles=["linux-developer,linux-supply-chain"])
        _, profiles, _ = cli.build_plan(ctx)
        self.assertEqual(profiles, ["linux-developer", "linux-supply-chain"])


class CreateCanariesTests(TempHomeCase):
    def make_context(self, **kwargs):
        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-developer"],
        )
        return cli.Context(
            args=namespace(profiles=["linux-developer"], **kwargs),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def make_browser_context(self, **kwargs):
        platform = PlatformContext(
            os_name="linux",
            home=self.home,
            windows_homes=[],
            default_profiles=["linux-browser-noisy"],
        )
        return cli.Context(
            args=namespace(
                profiles=["linux-browser-noisy"], include_noisy=True, **kwargs
            ),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def make_macos_context(self, **kwargs):
        platform = PlatformContext(
            os_name="macos",
            home=self.home,
            windows_homes=[],
            default_profiles=["macos-developer"],
        )
        return cli.Context(
            args=namespace(profiles=["macos-developer"], **kwargs),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def test_macos_canaries_are_created_without_otmpfile(self):
        """Darwin has no O_TMPFILE, and the workflow must still work there."""
        with mock.patch.object(
            safe_write, "supports_unnamed_temporary", return_value=False
        ):
            with self.quiet():
                code = cli.cmd_create_canaries(self.make_macos_context())
        self.assertEqual(code, 0)
        recorded = [row.path for row in self.db.get_canaries()]
        self.assertTrue(recorded, "no macOS canary was created")
        for path in recorded:
            self.assertTrue(
                os.path.isfile(path), f"{path} was recorded but not written"
            )

    def test_creates_and_records_canaries(self):
        with self.quiet():
            code = cli.cmd_create_canaries(self.make_context())
        self.assertEqual(code, 0)
        self.assertTrue((self.home / ".pgpass").exists())
        recorded = {c.path for c in self.db.get_canaries()}
        self.assertIn(str(self.home / ".pgpass"), recorded)
        row = self.db.get_canary_by_path(str(self.home / ".pgpass"))
        assert row is not None
        self.assertIsNotNone(row.last_baseline_atime)

    def test_a_failed_rollback_is_reported_and_exits_non_zero(self):
        """A path left neither written nor undone must not read as "skipped"."""
        fatal = safe_write.RollbackError("FATAL: rollback identity failed")
        with mock.patch.object(
            catalog, "create_canary_file", side_effect=fatal
        ), self.quiet():
            code = cli.cmd_create_canaries(self.make_context())
        self.assertEqual(code, 3)

    def test_verification_read_is_included_in_recorded_atime_baseline(self):
        """A create followed immediately by watch must start quietly."""
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        path = self.home / ".pgpass"
        row = self.db.get_canary_by_path(str(path))
        assert row is not None
        self.assertEqual(row.last_baseline_atime, os.stat(path).st_atime_ns)

        watcher = monitor_mod.AtimeWatcher(
            [row], queue.Queue(), threading.Event(), rearm=False, log=self.log
        )
        self.assertEqual(watcher.poll_once(), [])

    def answer_prompts(self, ctx, *, prepare_ssh: bool) -> None:
        """Answer cmd_setup's prompts; unknown prompts raise rather than default."""
        answers = {
            "Configure optional Pushover": False,
            "Show the full": False,
            "Create these": True,
            "Prepare SSH canary": prepare_ssh,
            "Install, enable": False,
        }
        ctx.confirm = lambda prompt: next(
            answer for prefix, answer in answers.items() if prompt.startswith(prefix)
        )

    def test_guided_setup_creates_safe_defaults_in_one_command(self):
        ctx = self.make_context()
        self.answer_prompts(ctx, prepare_ssh=False)
        with self.quiet():
            code = cli.cmd_setup(ctx)
        self.assertEqual(code, 0)
        self.assertTrue((self.home / ".pgpass").is_file())
        self.assertGreater(len(self.db.get_canaries(active_only=True)), 0)

    def test_guided_setup_is_exposed_as_a_command(self):
        parser = cli.build_parser()
        commands = parser._subparsers._group_actions[0].choices
        self.assertIn("setup", commands)
        self.assertIn("configure-alerts", commands)

    def test_guided_setup_offers_ssh_phase_one(self):
        ctx = self.make_context()
        self.answer_prompts(ctx, prepare_ssh=True)
        with mock.patch.object(
            cli, "cmd_setup_ssh_canary", return_value=0
        ) as setup_ssh:
            with self.quiet():
                code = cli.cmd_setup(ctx)

        self.assertEqual(code, 0)
        setup_ssh.assert_called_once_with(ctx)

    def setup_output(self, prepare_ssh: bool) -> str:
        import contextlib
        import io

        ctx = self.make_context()
        self.answer_prompts(ctx, prepare_ssh=prepare_ssh)
        buffer = io.StringIO()
        with mock.patch.object(cli, "cmd_setup_ssh_canary", return_value=0):
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(cli.cmd_setup(ctx), 0)
        return buffer.getvalue()

    def test_guided_setup_closes_the_loop_on_ssh_phase_one(self):
        """Phase 1 leaves a half-finished job; setup must say how to finish it."""
        output = self.setup_output(prepare_ssh=True)
        self.assertIn("prepared, not active", output)
        # What to test ...
        self.assertIn("~/bin/ssh -G github.com", output)
        self.assertIn("never into ~/.ssh", output)
        # ... and how to complete it, plus how to back out.
        self.assertIn("setup-ssh-canary --activate", output)
        self.assertIn("ssh-status", output)
        self.assertIn("restore-ssh-canary", output)

    def test_setup_stays_quiet_about_ssh_when_phase_one_was_declined(self):
        output = self.setup_output(prepare_ssh=False)
        self.assertNotIn("prepared, not active", output)
        self.assertNotIn("--activate", output)

    def test_never_creates_under_ssh(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        self.assertFalse((self.home / ".ssh").exists())
        for row in self.db.get_canaries():
            self.assertNotIn("/.ssh/", row.path)

    def test_is_idempotent(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        content = (self.home / ".pgpass").read_text()
        before = len(self.db.get_canaries())
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        self.assertEqual((self.home / ".pgpass").read_text(), content)
        self.assertEqual(len(self.db.get_canaries()), before)

    def test_does_not_clobber_a_real_file(self):
        self.write(".npmrc", "//registry.real.example/:_authToken=REAL\n")
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        self.assertIn("REAL", (self.home / ".npmrc").read_text())

    def test_force_is_rejected_outright(self):
        """§2: --force must not even be accepted by create-canaries."""
        real = "//registry.real.example/:_authToken=REAL\n"
        self.write(".npmrc", real)
        with self.quiet(stderr=True):
            code = cli.cmd_create_canaries(self.make_context(force=True))
        self.assertEqual(code, 2)
        self.assertEqual((self.home / ".npmrc").read_text(), real)

    def test_top_level_force_is_rejected_outright(self):
        real = "real.example:5432:proddb:me:REAL\n"
        self.write(".pgpass", real)
        with self.quiet(stderr=True):
            code = cli.cmd_create_canaries(self.make_context(top_force=True))
        self.assertEqual(code, 2)
        self.assertEqual((self.home / ".pgpass").read_text(), real)

    def test_plan_also_rejects_force(self):
        with self.quiet(stderr=True):
            self.assertEqual(cli.cmd_plan(self.make_context(force=True)), 2)

    def test_force_does_not_appear_in_create_canaries_help(self):
        parser = cli.build_parser()
        create = parser._subparsers._group_actions[0].choices["create-canaries"]
        options = {o for a in create._actions for o in a.option_strings}
        self.assertNotIn("--force", options)
        self.assertIn("--refresh-managed", options)
        self.assertIn("--include-active-config", options)

    def test_untracked_credential_file_survives_refresh_managed(self):
        """The whole point of §2, end to end."""
        real = "machine real.example login me password REALSECRET\n"
        self.write(".pgpass", real)
        with self.quiet():
            code = cli.cmd_create_canaries(self.make_context(refresh_managed=True))
        self.assertEqual(code, 0)
        self.assertEqual((self.home / ".pgpass").read_text(), real)

    def test_refresh_managed_updates_a_canary_with_canarytoken_material(self):
        """The supported replacement for the old `create-canaries --force`."""
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        credentials = self.home / ".aws" / "credentials"
        self.assertIn("AKIAHONEYPATHCANARY0", credentials.read_text())

        token_file = self.root / "canarytoken.txt"
        token_file.write_text(
            "aws_access_key_id = AKIAOPERATOR000\n"
            "aws_secret_access_key = operatorsecret\n"
        )
        with self.quiet():
            code = cli.cmd_create_canaries(
                self.make_context(
                    canarytoken_aws_file=str(token_file), refresh_managed=True
                )
            )
        self.assertEqual(code, 0)
        content = credentials.read_text()
        self.assertIn("AKIAOPERATOR000", content)
        self.assertNotIn("AKIAHONEYPATHCANARY0", content)
        # Still a named profile, never [default].
        self.assertNotRegex(content, r"(?m)^\s*\[default\]")

    def test_default_run_creates_no_active_config_files(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        for relative in (
            ".kube/config",
            ".dbt/profiles.yml",
            ".config/gcloud/application_default_credentials.json",
            ".azure/accessTokens.json",
            ".huggingface/token",
        ):
            self.assertFalse(
                (self.home / relative).exists(),
                f"{relative} created without --include-active-config",
            )

    def test_include_active_config_creates_them(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context(include_active_config=True))
        kubeconfig = self.home / ".kube" / "config"
        self.assertTrue(kubeconfig.exists())
        # No `current-context:` key, so kubectl selects nothing.
        self.assertNotRegex(kubeconfig.read_text(), r"(?m)^\s*current-context:")

    def test_dry_run_creates_nothing(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context(dry_run=True))
        self.assertFalse((self.home / ".pgpass").exists())
        self.assertEqual(self.db.get_canaries(), [])

    def test_database_failure_removes_exact_new_unregistered_canary(self):
        original = self.db.record_canary

        def fail_pgpass(**kwargs):
            if kwargs["path"].endswith("/.pgpass"):
                raise OSError("database full")
            return original(**kwargs)

        with mock.patch.object(self.db, "record_canary", side_effect=fail_pgpass):
            with self.quiet():
                cli.cmd_create_canaries(self.make_context())
        # Whichever entry fails to record, it must not remain unwatched.
        self.assertFalse((self.home / ".pgpass").exists())
        self.assertIsNone(self.db.get_canary_by_path(str(self.home / ".pgpass")))

    def failing_record_canary(self, suffix: str):
        """Make record_canary() fail for one path, as a full disk would."""
        original = self.db.record_canary

        def record(**kwargs):
            if kwargs["path"].endswith(suffix):
                raise OSError("database full")
            return original(**kwargs)

        return mock.patch.object(self.db, "record_canary", side_effect=record)

    def refresh_with_a_new_token(self, **kwargs):
        token_file = self.root / "canarytoken.txt"
        token_file.write_text(
            "aws_access_key_id = AKIAOPERATOR000\n"
            "aws_secret_access_key = operatorsecret\n"
        )
        context = self.make_context(
            canarytoken_aws_file=str(token_file), refresh_managed=True, **kwargs
        )
        with self.quiet():
            return cli.cmd_create_canaries(context)

    def test_refresh_that_cannot_be_recorded_restores_the_previous_file(self):
        """A refreshed file and its manifest row move together, or not at all."""
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        credentials = self.home / ".aws" / "credentials"
        before_content = credentials.read_text()
        before_inode = os.stat(credentials).st_ino
        before_row = self.db.get_canary_by_path(str(credentials))
        assert before_row is not None

        with self.failing_record_canary("/credentials"):
            self.refresh_with_a_new_token()

        # The exact previous inode is back, not merely equivalent content.
        self.assertEqual(credentials.read_text(), before_content)
        self.assertNotIn("AKIAOPERATOR000", credentials.read_text())
        self.assertEqual(os.stat(credentials).st_ino, before_inode)
        after_row = self.db.get_canary_by_path(str(credentials))
        assert after_row is not None
        self.assertEqual(after_row.content_hash, before_row.content_hash)
        self.assertEqual(after_row.file_ino, before_row.file_ino)

    def test_a_rolled_back_refresh_can_be_retried(self):
        """The bug this guards: a half-applied refresh poisons every later one."""
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        credentials = self.home / ".aws" / "credentials"

        with self.failing_record_canary("/credentials"):
            self.refresh_with_a_new_token()

        self.assertEqual(self.refresh_with_a_new_token(), 0)
        content = credentials.read_text()
        self.assertIn("AKIAOPERATOR000", content)
        row = self.db.get_canary_by_path(str(credentials))
        assert row is not None
        self.assertEqual(row.content_hash, catalog.sha256_text(content))
        self.assertEqual(row.file_ino, os.stat(credentials).st_ino)

    def test_a_rolled_back_refresh_does_not_look_like_tampering_to_watch(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        credentials = self.home / ".aws" / "credentials"

        with self.failing_record_canary("/credentials"):
            self.refresh_with_a_new_token()

        row = self.db.get_canary_by_path(str(credentials))
        assert row is not None
        info = os.stat(credentials)
        self.assertEqual(row.file_ino, info.st_ino)
        self.assertEqual(row.file_dev, info.st_dev)

    def test_a_rolled_back_refresh_leaves_no_staging_entry(self):
        with self.quiet():
            cli.cmd_create_canaries(self.make_context())
        credentials = self.home / ".aws" / "credentials"

        with self.failing_record_canary("/credentials"):
            self.refresh_with_a_new_token()

        leftovers = [
            p.name
            for p in credentials.parent.iterdir()
            if p.name.startswith(safe_write.TEMP_PREFIX)
        ]
        self.assertEqual(leftovers, [])

    def test_canarytoken_material_is_spliced(self):
        token_file = self.root / "canarytoken.txt"
        token_file.write_text(
            "aws_access_key_id = AKIAOPERATOR000\n"
            "aws_secret_access_key = operatorsecret\n"
        )
        with self.quiet():
            cli.cmd_create_canaries(
                self.make_context(canarytoken_aws_file=str(token_file))
            )
        content = (self.home / ".aws" / "credentials").read_text()
        self.assertIn("AKIAOPERATOR000", content)
        self.assertIn("operatorsecret", content)

    def test_browser_only_run_registers_existing_target(self):
        path = self.home / ".config/google-chrome/Default/Login Data"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"sqlite")
        with self.quiet():
            code = cli.cmd_create_canaries(self.make_browser_context())
        self.assertEqual(code, 0)
        row = self.db.get_canary_by_path(str(path))
        self.assertIsNotNone(row)
        self.assertEqual(row.managed_by, "watch-only")

    def test_multiple_firefox_profiles_register_and_reregister_idempotently(self):
        paths = []
        for name in ("one.default", "two.default-release"):
            path = self.home / ".mozilla/firefox" / name / "logins.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}")
            paths.append(path)
        with self.quiet():
            cli.cmd_create_canaries(self.make_browser_context())
            cli.cmd_create_canaries(self.make_browser_context())
        rows = {row.path for row in self.db.get_canaries()}
        self.assertTrue({str(path) for path in paths}.issubset(rows))
        self.assertEqual(len([p for p in rows if p.endswith("logins.json")]), 2)

    def test_watch_only_symlink_is_never_registered(self):
        target = self.root / "real-browser-db"
        target.write_bytes(b"sqlite")
        path = self.home / ".config/google-chrome/Default/Login Data"
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        with self.quiet():
            cli.cmd_create_canaries(self.make_browser_context())
        self.assertIsNone(self.db.get_canary_by_path(str(path)))

    def test_dry_run_lists_but_does_not_register_watch_only(self):
        path = self.home / ".config/google-chrome/Default/Login Data"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"sqlite")
        with self.quiet():
            cli.cmd_create_canaries(self.make_browser_context(dry_run=True))
        self.assertIsNone(self.db.get_canary_by_path(str(path)))


class CanarytokenParsingTests(TempHomeCase):
    def test_reads_credentials_style_file(self):
        from honeypath.ssh_canary import SSHCanaryError, load_canarytoken_aws

        path = self.root / "token"
        path.write_text(
            "[default]\naws_access_key_id=AKIA1\n" "aws_secret_access_key=shh\n"
        )
        parsed = load_canarytoken_aws(path)
        self.assertEqual(parsed["aws_access_key_id"], "AKIA1")

        path.write_text("nothing useful\n")
        with self.assertRaises(SSHCanaryError):
            load_canarytoken_aws(path)


if __name__ == "__main__":
    unittest.main()
