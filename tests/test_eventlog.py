"""The human-readable log at /var/lib/honeypath/honeypath.log.

Four properties matter and each is pinned here: one detection is one line
whatever an attacker puts in a filename, a logging failure never propagates,
the file cannot be redirected through a symlink, and no Pushover credential
can reach it.
"""

from __future__ import annotations

import os
import stat
import time
import unittest
from pathlib import Path

from .support import TempHomeCase, namespace

from honeypath import alerts as alerts_mod  # noqa: E402
from honeypath import cli  # noqa: E402
from honeypath import eventlog  # noqa: E402
from honeypath import monitor as monitor_mod  # noqa: E402
from honeypath.database import CanaryRow  # noqa: E402


def detection_event(**overrides) -> dict:
    event = {
        "timestamp": "2026-08-02 12:00:00",
        "hostname": "testhost",
        "method": "inotify+atime",
        "event_type": "read",
        "path": "/home/tester/.aws/credentials",
        "canary_id": "linux.aws",
        "kind": "aws-credentials",
        "severity": "critical",
        "message": "methods=inotify+atime | ACCESS,OPEN",
        "process_info": None,
        "pushover_sent": 0,
        "pushover_error": None,
    }
    event.update(overrides)
    return event


class LogFileBasicsTests(TempHomeCase):
    def open_log(self, name: str = "honeypath.log", **kwargs) -> eventlog.EventLog:
        log = eventlog.EventLog(self.root / name, version="9.9.9", **kwargs)
        self.addCleanup(log.close)
        return log

    def read(self, name: str = "honeypath.log") -> str:
        return (self.root / name).read_text()

    def test_the_file_is_created_private_with_a_header(self):
        log = self.open_log()
        self.assertTrue(log.enabled)
        self.assertIsNone(log.error)
        mode = stat.S_IMODE((self.root / "honeypath.log").stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertIn("honeypath 9.9.9 log started", self.read())
        self.assertIn("timestamps are UTC", self.read())

    def test_an_existing_log_is_appended_to_not_truncated(self):
        first = self.open_log()
        first.info("earlier line")
        first.close()
        second = self.open_log()
        second.info("later line")
        body = self.read()
        self.assertIn("earlier line", body)
        self.assertIn("later line", body)
        # One header only: reopening an existing log does not re-announce it.
        self.assertEqual(body.count("log started"), 1)

    def test_a_world_readable_log_is_tightened_on_open(self):
        path = self.root / "honeypath.log"
        path.write_text("")
        os.chmod(path, 0o644)
        self.open_log()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_every_line_carries_a_utc_timestamp_and_a_level(self):
        log = self.open_log()
        log.warn("inotifywait is not installed")
        line = [ln for ln in self.read().splitlines() if "inotifywait" in ln][0]
        self.assertRegex(line, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z  WARN   ")

    def test_default_path_follows_the_database_directory(self):
        self.assertEqual(
            eventlog.default_log_path(Path("/var/lib/honeypath/events.sqlite3")),
            Path("/var/lib/honeypath/honeypath.log"),
        )
        self.assertEqual(
            eventlog.default_log_path(self.root / "custom.sqlite3"),
            self.root / "honeypath.log",
        )
        self.assertEqual(eventlog.default_log_path(), eventlog.DEFAULT_LOG_PATH)


class DetectionLineTests(TempHomeCase):
    def log_and_read(self, event: dict, *, alerting: bool = True) -> str:
        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        log.detection(event, alerting=alerting)
        return (self.root / "honeypath.log").read_text()

    def test_an_alertable_detection_records_severity_kind_path_and_method(self):
        body = self.log_and_read(detection_event())
        line = [ln for ln in body.splitlines() if "READ" in ln][0]
        self.assertIn("ALERT", line)
        self.assertIn("severity=critical", line)
        self.assertIn("kind=aws-credentials", line)
        self.assertIn("path=/home/tester/.aws/credentials", line)
        self.assertIn("via=inotify+atime", line)

    def test_a_suppressed_detection_is_logged_with_its_reason(self):
        body = self.log_and_read(
            detection_event(pushover_error="suppressed: per-path cooldown"),
            alerting=False,
        )
        line = [ln for ln in body.splitlines() if "READ" in ln][0]
        self.assertIn("EVENT", line)
        self.assertNotIn("ALERT", line)
        self.assertIn("suppressed: per-path cooldown", line)

    def test_delivery_outcomes_are_recorded_at_the_right_level(self):
        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        event = detection_event()
        log.delivery(event, True, None)
        log.delivery(event, False, "HTTP 429")
        log.delivery(event, False, "pushover not configured")
        body = (self.root / "honeypath.log").read_text()
        self.assertIn(
            "INFO   alert delivered via Pushover for /home/tester/.aws/credentials",
            body,
        )
        self.assertIn(
            "ERROR  alert delivery FAILED for "
            "/home/tester/.aws/credentials: HTTP 429",
            body,
        )
        self.assertIn(
            "WARN   alert NOT sent for /home/tester/.aws/credentials: "
            "Pushover is not configured",
            body,
        )


class LogInjectionTests(TempHomeCase):
    """A canary path or a Windows process name is attacker-influenced text."""

    def test_newlines_in_process_attribution_cannot_forge_a_log_line(self):
        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        before = len((self.root / "honeypath.log").read_text().splitlines())
        log.detection(
            detection_event(
                process_info="C:\\evil.exe\n2026-01-01 00:00:00Z  INFO   all clear",
            )
        )
        lines = (self.root / "honeypath.log").read_text().splitlines()
        self.assertEqual(len(lines) - before, 1)
        self.assertIn("\\n", lines[-1])
        self.assertIn("C:\\evil.exe", lines[-1])

    def test_control_characters_are_escaped(self):
        self.assertEqual(eventlog.sanitize("a\nb"), "a\\nb")
        self.assertEqual(eventlog.sanitize("a\rb"), "a\\rb")
        self.assertEqual(eventlog.sanitize("a\tb"), "a\\tb")
        self.assertEqual(eventlog.sanitize("a\x7fb"), "a\\x7fb")
        self.assertEqual(eventlog.sanitize("a\x00b"), "a\\x00b")
        self.assertEqual(eventlog.sanitize("a\x1bb"), "a\\x1bb")
        self.assertEqual(
            eventlog.sanitize("plain /home/x/.ssh/id_rsa"), "plain /home/x/.ssh/id_rsa"
        )

    def test_an_absurdly_long_message_is_truncated(self):
        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        log.info("A" * 50_000)
        line = (self.root / "honeypath.log").read_text().splitlines()[-1]
        self.assertIn("[truncated]", line)
        self.assertLess(len(line), eventlog.MAX_MESSAGE_CHARS + 200)


class LogFailureTests(TempHomeCase):
    """Logging is best-effort: monitoring must survive a broken log."""

    def test_a_symlinked_log_path_is_refused_and_the_target_is_untouched(self):
        target = self.root / "sensitive"
        target.write_text("original\n")
        link = self.root / "honeypath.log"
        link.symlink_to(target)
        with self.quiet(stderr=True):
            log = eventlog.EventLog(link)
        self.addCleanup(log.close)
        self.assertFalse(log.enabled)
        self.assertIsNotNone(log.error)
        log.info("this must go nowhere")
        self.assertEqual(target.read_text(), "original\n")

    def test_a_directory_in_place_of_the_log_disables_logging_without_raising(self):
        (self.root / "honeypath.log").mkdir()
        with self.quiet(stderr=True):
            log = eventlog.EventLog(self.root / "honeypath.log")
        self.assertFalse(log.enabled)
        log.detection(detection_event())
        log.delivery(detection_event(), False, "HTTP 500")
        log.close()

    def test_an_unwritable_directory_disables_logging_without_raising(self):
        directory = self.root / "locked"
        directory.mkdir(mode=0o500)
        try:
            with self.quiet(stderr=True):
                log = eventlog.EventLog(directory / "honeypath.log")
            self.assertFalse(log.enabled)
            self.assertIsNotNone(log.error)
            log.info("dropped")
        finally:
            os.chmod(directory, 0o700)

    def test_a_write_failure_disables_further_writes_but_does_not_raise(self):
        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        os.close(log._fd)  # simulate the descriptor dying under us
        with self.quiet(stderr=True):
            log.info("this write fails")
            log.info("and so would this one")
        self.assertFalse(log.enabled)
        self.assertIsNotNone(log.error)

    def test_the_null_log_accepts_every_call(self):
        log = eventlog.NullEventLog()
        with log as opened:
            opened.info("x")
            opened.warn("x")
            opened.error_line("x")
            opened.write(eventlog.LEVEL_INFO, "x")
            opened.detection(detection_event())
            opened.delivery(detection_event(), True, None)
        self.assertFalse(log.enabled)


class RotationTests(TempHomeCase):
    def test_the_log_rotates_and_keeps_a_bounded_number_of_files(self):
        path = self.root / "honeypath.log"
        log = eventlog.EventLog(path, max_bytes=500, keep=2)
        self.addCleanup(log.close)
        for index in range(200):
            log.info(f"detection number {index} " + "x" * 60)
        self.assertTrue(path.exists())
        self.assertTrue((self.root / "honeypath.log.1").exists())
        self.assertTrue((self.root / "honeypath.log.2").exists())
        self.assertFalse((self.root / "honeypath.log.3").exists())
        # Rotation reopens a live descriptor: the newest line is in the log.
        self.assertIn("detection number 199", path.read_text())

    def test_rotation_moves_the_previous_generation_aside_intact(self):
        path = self.root / "honeypath.log"
        log = eventlog.EventLog(path, max_bytes=400, keep=3)
        self.addCleanup(log.close)
        log.info("FIRST-GENERATION-MARKER")
        while not (self.root / "honeypath.log.1").exists():
            log.info("filler " + "y" * 60)
        self.assertIn(
            "FIRST-GENERATION-MARKER", (self.root / "honeypath.log.1").read_text()
        )
        self.assertNotIn("FIRST-GENERATION-MARKER", path.read_text())
        # The reopened live file is usable again, header and all.
        log.info("AFTER-ROTATION-MARKER")
        self.assertIn("AFTER-ROTATION-MARKER", path.read_text())


class SecretContainmentTests(TempHomeCase):
    """No Pushover credential may reach the log, including via error text."""

    TOKEN = "azGDORePK8gMaC0QOYAMyEEuzJnyUi"
    USER_KEY = "uQiRzpo4DXghDmr9QzzfQu27cmVRsG"

    def test_a_delivery_error_echoing_the_token_is_logged_redacted(self):
        import urllib.error
        import urllib.request

        token = self.root / "pushover-token"
        user = self.root / "pushover-user"
        token.write_text(self.TOKEN + "\n")
        user.write_text(self.USER_KEY + "\n")
        pushover = alerts_mod.Pushover(token_file=token, user_file=user)

        def opener(request, timeout=None):
            raise urllib.error.URLError(
                f"refused while sending token={self.TOKEN} user={self.USER_KEY}"
            )

        original = urllib.request.urlopen
        urllib.request.urlopen = opener
        try:
            sent, error = pushover.send("HONEYPATH critical read")
        finally:
            urllib.request.urlopen = original

        log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(log.close)
        log.delivery(detection_event(), sent, error)
        body = (self.root / "honeypath.log").read_text()
        self.assertIn("alert delivery FAILED", body)
        self.assertNotIn(self.TOKEN, body)
        self.assertNotIn(self.USER_KEY, body)
        self.assertIn(alerts_mod.REDACTED, body)


class MonitorLoggingTests(TempHomeCase):
    """The watcher's detections, suppressions and failures all reach the log."""

    class FakePushover:
        def __init__(self, result=(True, None)):
            self.result = result
            self.sent = []

        def configured(self):
            return True

        def send(self, message, **kwargs):
            self.sent.append(message)
            return self.result

    def build(self, *, pushover=None, **kwargs):
        path = self.write("canary", "secret\n")
        row = CanaryRow(
            canary_id="linux.netrc",
            path=str(path),
            kind="netrc",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="active-config",
            last_baseline_atime=None,
            active=1,
        )
        self.event_log = eventlog.EventLog(self.root / "honeypath.log")
        self.addCleanup(self.event_log.close)
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=pushover or self.FakePushover(),
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
            dedup_window=0.0,
            event_log=self.event_log,
            **kwargs,
        )
        return monitor, path

    def body(self) -> str:
        return (self.root / "honeypath.log").read_text()

    def run_one_hit(self, monitor, path):
        monitor.start()
        try:
            monitor.hits.put(
                monitor_mod.RawHit(
                    path=str(path),
                    method="inotify",
                    event_type=monitor_mod.EVENT_READ,
                    at=time.time(),
                )
            )
            monitor.pump(0.4)
            time.sleep(0.4)
        finally:
            monitor.stop()

    def test_a_detection_and_its_delivery_are_both_logged(self):
        monitor, path = self.build()
        self.run_one_hit(monitor, path)
        body = self.body()
        self.assertIn("ALERT", body)
        self.assertIn("READ", body)
        self.assertIn(f"path={path}", body)
        self.assertIn("severity=critical", body)
        self.assertIn("alert delivered via Pushover", body)

    def test_a_failed_delivery_is_logged_as_an_error(self):
        monitor, path = self.build(
            pushover=self.FakePushover(result=(False, "HTTP 500"))
        )
        self.run_one_hit(monitor, path)
        self.assertIn("ERROR  alert delivery FAILED", self.body())
        self.assertIn("HTTP 500", self.body())

    def test_a_muted_detection_is_logged_as_an_unalerted_event(self):
        monitor, path = self.build()
        self.db.set_meta("mute_until_epoch", str(time.time() + 600))
        self.run_one_hit(monitor, path)
        body = self.body()
        self.assertIn("suppressed: alerts muted", body)
        self.assertIn("EVENT", body)
        self.assertNotIn("alert delivered", body)

    def test_watcher_failures_reach_the_log_as_warnings(self):
        monitor, _ = self.build()
        monitor._warn("[atime] could not re-arm /home/tester/.netrc: EPERM")
        self.assertIn("WARN   [atime] could not re-arm", self.body())
        self.assertIn("could not re-arm", self.logged())

    def test_a_monitor_without_a_log_still_dispatches(self):
        path = self.write("canary", "secret\n")
        row = CanaryRow(
            canary_id="linux.netrc",
            path=str(path),
            kind="netrc",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="active-config",
            last_baseline_atime=None,
            active=1,
        )
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=self.FakePushover(),
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
            dedup_window=0.0,
        )
        self.run_one_hit(monitor, path)
        self.assertEqual(len(self.db.recent_events(limit=10)), 1)


class LogPathResolutionTests(TempHomeCase):
    def test_the_log_sits_beside_the_database_by_default(self):
        args = namespace()
        self.assertEqual(
            cli.resolve_log_path(args, self.root / "events.sqlite3"),
            self.root / "honeypath.log",
        )

    def test_an_explicit_log_file_wins(self):
        args = namespace(log_file=str(self.root / "elsewhere.log"))
        self.assertEqual(
            cli.resolve_log_path(args, self.root / "events.sqlite3"),
            self.root / "elsewhere.log",
        )

    def test_no_log_file_disables_logging(self):
        args = namespace(no_log_file=True)
        self.assertIsNone(cli.resolve_log_path(args, self.root / "events.sqlite3"))

    def test_a_dry_run_context_never_opens_a_log(self):
        ctx = cli.Context(
            args=namespace(dry_run=True),
            target=self.target,
            platform=None,
            db=self.db,
            confirm=lambda *a, **k: True,
            log_path=self.root / "honeypath.log",
        )
        log = ctx.open_event_log()
        self.assertIsInstance(log, eventlog.NullEventLog)
        self.assertFalse((self.root / "honeypath.log").exists())

    def test_doctor_reports_the_log_file(self):
        ctx = cli.Context(
            args=namespace(),
            target=self.target,
            platform=None,
            db=self.db,
            confirm=lambda *a, **k: True,
            log_path=self.root / "honeypath.log",
        )
        lines = "\n".join(cli.log_file_status(ctx))
        self.assertIn(str(self.root / "honeypath.log"), lines)
        self.assertIn("created when `watch` next starts", lines)

        eventlog.EventLog(self.root / "honeypath.log").close()
        lines = "\n".join(cli.log_file_status(ctx))
        self.assertIn("present:    yes", lines)
        self.assertIn("mode 0o600", lines)

    def test_doctor_reports_disabled_logging(self):
        ctx = cli.Context(
            args=namespace(no_log_file=True),
            target=self.target,
            platform=None,
            db=self.db,
            confirm=lambda *a, **k: True,
            log_path=None,
        )
        self.assertIn("DISABLED", "\n".join(cli.log_file_status(ctx)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
