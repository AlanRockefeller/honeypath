"""Rollback behaviour (§8.8) and alert formatting (§10)."""

from __future__ import annotations

import os
import stat
import unittest
from unittest import mock

from .support import TempHomeCase, namespace

from honeypath import alerts as alerts_mod  # noqa: E402
from honeypath import cli, ssh_canary  # noqa: E402
from honeypath.platform_detect import PlatformContext  # noqa: E402


class RestoreTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        (self.ssh / "id_rsa").write_text("PRIVATE")
        (self.ssh / "config").write_text("Host work\n  User alan\n")

    def make_context(self, **kwargs):
        platform = PlatformContext(
            os_name="linux", home=self.home, windows_homes=[], default_profiles=[]
        )
        return cli.Context(
            args=namespace(**kwargs),
            target=self.target,
            platform=platform,
            db=self.db,
            confirm=lambda _prompt: True,
        )

    def activate(self):
        with self.quiet():
            destination = ssh_canary.relocated_dir(self.home)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "config").write_text("# prepared\n")
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
            with mock.patch.object(
                ssh_canary, "validate_relocated_config", return_value=("ok", [])
            ):
                return ssh_canary.activate(self.db, self.target, log=self.log)

    def test_full_round_trip(self):
        ok, backup = self.activate()
        self.assertTrue(ok)
        self.assertIn("HONEYPATH CANARY", (self.ssh / "id_rsa").read_text())

        with self.quiet():
            code = cli.cmd_restore_ssh_canary(self.make_context())
        self.assertEqual(code, 0)
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")
        self.assertEqual((self.ssh / "config").read_text(), "Host work\n  User alan\n")
        for name in ssh_canary.SSH_BINARIES:
            self.assertFalse((ssh_canary.wrapper_dir(self.home) / name).exists())

    def test_restore_regates_the_ssh_catalog(self):
        self.activate()
        self.assertTrue(self.db.has_ssh_canaries(self.home))
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context())
        self.assertFalse(self.db.has_ssh_canaries(self.home))

    def test_backups_are_never_deleted(self):
        _, backup = self.activate()
        assert backup is not None
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context())
        # The backup itself was renamed into place; the backup root survives.
        self.assertTrue(ssh_canary.backup_root(self.home).is_dir())

    def test_restore_prefers_original_recorded_backup_over_newer_directory(self):
        _, original = self.activate()
        assert original is not None
        newer = ssh_canary.backup_root(self.home) / "ssh-99991231-235959"
        newer.mkdir()
        (newer / "id_rsa").write_text("NOT THE ORIGINAL")
        with self.quiet():
            code = cli.cmd_restore_ssh_canary(self.make_context())
        self.assertEqual(code, 0)
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")
        self.assertTrue(newer.exists())

    def test_refuses_to_overwrite_a_non_honeypath_ssh_dir(self):
        self.activate()
        # The user rebuilt ~/.ssh by hand in the meantime.
        for child in self.ssh.iterdir():
            child.unlink()
        (self.ssh / "id_ed25519").write_text("A REAL KEY I MADE LATER")
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context())
        self.assertEqual(
            (self.ssh / "id_ed25519").read_text(), "A REAL KEY I MADE LATER"
        )
        self.assertFalse((self.ssh / "id_rsa").exists())

    def test_force_overwrites_a_non_honeypath_ssh_dir(self):
        self.activate()
        for child in self.ssh.iterdir():
            child.unlink()
        (self.ssh / "id_ed25519").write_text("LATER KEY")
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context(force=True))
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")

    def test_canary_directory_is_kept_aside_not_deleted(self):
        self.activate()
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context())
        kept = list(self.home.glob(".ssh.honeypath-canary-*"))
        self.assertEqual(len(kept), 1)
        self.assertIn("HONEYPATH CANARY", (kept[0] / "id_rsa").read_text())

    def test_dry_run_changes_nothing(self):
        self.activate()
        with self.quiet():
            cli.cmd_restore_ssh_canary(self.make_context(dry_run=True))
        self.assertIn("HONEYPATH CANARY", (self.ssh / "id_rsa").read_text())
        self.assertTrue((ssh_canary.wrapper_dir(self.home) / "ssh").exists())

    def test_restore_without_activation_is_harmless(self):
        with self.quiet():
            code = cli.cmd_restore_ssh_canary(self.make_context())
        self.assertEqual(code, 0)
        self.assertEqual((self.ssh / "id_rsa").read_text(), "PRIVATE")


class AlertFormatTests(unittest.TestCase):
    def test_two_line_form(self):
        body = alerts_mod.format_alert(
            {
                "severity": "critical",
                "kind": "ssh_private_key",
                "method": "inotify",
                "path": "/home/alan/.ssh/id_ed25519",
            }
        )
        self.assertEqual(
            body,
            "HONEYPATH critical ssh_private_key via inotify\n"
            "/home/alan/.ssh/id_ed25519",
        )

    def test_process_info_is_appended(self):
        body = alerts_mod.format_alert(
            {
                "severity": "critical",
                "kind": "ssh_private_key",
                "method": "win-audit",
                "path": "C:/x/id_rsa",
                "process_info": "C:\\evil.exe pid=42",
            }
        )
        self.assertTrue(body.endswith("C:\\evil.exe pid=42"))

    def test_priority_by_severity(self):
        self.assertEqual(alerts_mod.alert_priority("critical"), 1)
        self.assertEqual(alerts_mod.alert_priority("high"), 0)
        self.assertEqual(alerts_mod.alert_priority("medium"), -1)
        self.assertEqual(alerts_mod.alert_priority(None), 0)


class PushoverCredentialTests(TempHomeCase):
    def test_unconfigured_send_fails_without_leaking_paths_content(self):
        pushover = alerts_mod.Pushover(
            token_file=self.root / "no-token", user_file=self.root / "no-user"
        )
        self.assertFalse(pushover.configured())
        sent, error = pushover.send("hello")
        self.assertFalse(sent)
        self.assertIn("missing or empty", error or "")

    def test_status_reports_permissions_only(self):
        token = self.root / "pushover-token"
        token.write_text("SUPERSECRETTOKEN")
        os.chmod(token, 0o644)
        statuses = alerts_mod.credential_status()
        for status in statuses:
            self.assertNotIn("SUPERSECRET", status.describe())

    def test_world_readable_is_flagged(self):
        from honeypath.alerts import _status

        token = self.root / "pushover-token"
        token.write_text("x")
        os.chmod(token, 0o644)
        status = _status(token)
        self.assertTrue(status.world_readable)
        self.assertIn("WORLD-READABLE", status.describe())
        self.assertNotIn("x\n", status.describe())

    def test_secure_store_uses_group_readable_non_world_readable_files(self):
        config_dir = self.root / "etc-honeypath"
        with mock.patch.object(alerts_mod.os, "chown"):
            token, user = alerts_mod.store_credentials(
                "application-token",
                "user-key",
                group_gid=os.getgid(),
                config_dir=config_dir,
            )
        self.assertEqual(token.read_text(), "application-token\n")
        self.assertEqual(user.read_text(), "user-key\n")
        self.assertEqual(stat.S_IMODE(token.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(user.stat().st_mode), 0o640)
        self.assertFalse(token.stat().st_mode & stat.S_IROTH)


class PushoverSecretContainmentTests(TempHomeCase):
    """§5: the credentials go to api.pushover.net over HTTPS and nowhere else.

    In particular, no error string returned by ``send()`` may contain them —
    a leaked token would otherwise be persisted in ``events.pushover_error``
    and printed by ``honeypath.py events``.
    """

    TOKEN = "azGDORePK8gMaC0QOYAMyEEuzJnyUi"
    USER_KEY = "uQiRzpo4DXghDmr9QzzfQu27cmVRsG"

    def configured_pushover(self):
        token = self.root / "pushover-token"
        user = self.root / "pushover-user"
        token.write_text(self.TOKEN + "\n")
        user.write_text(self.USER_KEY + "\n")
        return alerts_mod.Pushover(token_file=token, user_file=user)

    def assert_clean(self, text: str):
        self.assertNotIn(self.TOKEN, text or "")
        self.assertNotIn(self.USER_KEY, text or "")

    def _send_with(self, opener):
        import urllib.request

        pushover = self.configured_pushover()
        original = urllib.request.urlopen
        urllib.request.urlopen = opener
        try:
            return pushover.send("HONEYPATH critical read")
        finally:
            urllib.request.urlopen = original

    def test_the_api_url_is_the_official_https_endpoint(self):
        self.assertTrue(alerts_mod.PUSHOVER_URL.startswith("https://"))
        self.assertEqual(
            alerts_mod.PUSHOVER_URL,
            "https://api.pushover.net/1/messages.json",
        )

    def test_http_error_body_cannot_leak_the_credentials(self):
        import io
        import urllib.error

        def opener(request, timeout=None):
            # A hostile or buggy server echoing the request back at us.
            body = io.BytesIO(
                f'{{"errors":["bad token {self.TOKEN} user {self.USER_KEY}"]}}'.encode()
            )
            raise urllib.error.HTTPError(
                alerts_mod.PUSHOVER_URL, 400, "Bad Request", {}, body
            )

        sent, error = self._send_with(opener)
        self.assertFalse(sent)
        self.assertIn("HTTP 400", error or "")
        self.assert_clean(error)

    def test_url_error_reason_cannot_leak_the_credentials(self):
        import urllib.error

        def opener(request, timeout=None):
            raise urllib.error.URLError(
                f"connection refused while sending {self.TOKEN}"
            )

        sent, error = self._send_with(opener)
        self.assertFalse(sent)
        self.assert_clean(error)

    def test_os_error_cannot_leak_the_credentials(self):
        def opener(request, timeout=None):
            raise OSError(f"broken pipe carrying {self.USER_KEY}")

        sent, error = self._send_with(opener)
        self.assertFalse(sent)
        self.assert_clean(error)

    def test_malformed_response_cannot_leak_the_credentials(self):
        class Response:
            def read(self):
                return b"<html>not json</html>"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        sent, error = self._send_with(lambda request, timeout=None: Response())
        self.assertFalse(sent)
        self.assert_clean(error)

    def test_api_error_list_is_reported_but_stays_clean(self):
        payload = (
            f'{{"status":0,"errors":["application token {self.TOKEN} is invalid"]}}'
        )

        class Response:
            def read(self):
                return payload.encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        sent, error = self._send_with(lambda request, timeout=None: Response())
        self.assertFalse(sent)
        self.assert_clean(error)

    def test_credentials_are_sent_only_to_the_official_endpoint(self):
        captured: dict = {}

        class Response:
            def read(self):
                return b'{"status":1}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(request, timeout=None):
            captured["url"] = request.full_url
            captured["body"] = request.data.decode()
            return Response()

        sent, error = self._send_with(opener)
        self.assertTrue(sent)
        self.assertIsNone(error)
        # They ARE transmitted — that is how Pushover authenticates the request.
        self.assertEqual(captured["url"], alerts_mod.PUSHOVER_URL)
        self.assertIn(self.TOKEN, captured["body"])
        self.assertIn(self.USER_KEY, captured["body"])

    def test_a_failed_alert_still_leaves_the_event_recorded(self):
        """Delivery failure must never lose the underlying detection."""
        event_id = self.db.record_event(
            {
                "hostname": "host",
                "method": "inotify",
                "event_type": "read",
                "path": str(self.home / ".netrc"),
                "severity": "critical",
                "pushover_sent": 0,
                "pushover_error": "HTTP 400",
            }
        )
        self.assertTrue(event_id)
        rows = self.db.recent_events(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pushover_sent"], 0)
        self.assertEqual(rows[0]["pushover_error"], "HTTP 400")
        self.assert_clean(rows[0]["pushover_error"])

    def test_no_credential_is_ever_written_into_the_database(self):
        pushover = self.configured_pushover()
        self.db.record_event(
            {
                "hostname": "host",
                "method": "inotify",
                "event_type": "read",
                "path": str(self.home / ".netrc"),
                "message": alerts_mod.format_alert(
                    {
                        "severity": "critical",
                        "kind": "netrc",
                        "method": "inotify",
                        "path": str(self.home / ".netrc"),
                    }
                ),
            }
        )
        self.db.set_meta("mute_until_epoch", "0")
        with self.db.connection() as conn:
            dumped = "\n".join(
                str(row)
                for table in (
                    "events",
                    "canaries",
                    "managed_changes",
                    "schema_metadata",
                )
                for row in conn.execute(f"SELECT * FROM {table}")
            )
        self.assertTrue(pushover.configured())
        self.assert_clean(dumped)

    def test_format_alert_never_includes_credentials(self):
        body = alerts_mod.format_alert(
            {
                "severity": "critical",
                "kind": "aws_credentials",
                "method": "inotify",
                "path": "/home/x/.aws/credentials",
            }
        )
        self.assert_clean(body)


if __name__ == "__main__":
    unittest.main()
