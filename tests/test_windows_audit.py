"""Windows SACL auditing: 4663 mapping and catch-up (§9)."""

from __future__ import annotations

import queue
import threading
import unittest
from unittest import mock

from .support import TempHomeCase

from honeypath import windows_audit  # noqa: E402
from honeypath.database import CanaryRow  # noqa: E402
from honeypath.monitor import EVENT_READ, METHOD_WIN_AUDIT, Monitor  # noqa: E402
from honeypath.platform_detect import InteropResult  # noqa: E402


class SilentPushover:
    """A Monitor without one of these reaches the operator's real phone."""

    def __init__(self):
        self.sent: list[str] = []

    def configured(self) -> bool:
        return False

    def missing_reason(self) -> str | None:
        return "test double"

    def send(self, message, *, title="Honeypath", timeout=15):
        self.sent.append(message)
        return False, "test double"


def canary(path: str) -> CanaryRow:
    return CanaryRow(
        canary_id="windows.ssh.id_rsa",
        path=path,
        kind="ssh_private_key",
        severity="critical",
        profile="wsl-windows-developer",
        platform="windows",
        intrusiveness="high",
        last_baseline_atime=None,
        active=1,
    )


class WinAuditWatcherTests(TempHomeCase):
    WSL_PATH = "/mnt/c/Users/alanr/.ssh/id_rsa"
    WIN_PATH = r"C:\Users\alanr\.ssh\id_rsa"

    def make_watcher(self, records):
        with mock.patch.object(
            windows_audit, "to_windows_path", return_value=self.WIN_PATH
        ):
            watcher = windows_audit.WinAuditWatcher(
                self.db,
                [canary(self.WSL_PATH)],
                sink=queue.Queue(),
                stop_event=threading.Event(),
                log=self.log,
            )
        watcher.fetch_records = lambda **kwargs: records
        return watcher

    def drain(self, watcher):
        out = []
        while True:
            try:
                out.append(watcher.sink.get_nowait())
            except queue.Empty:
                return out

    def record(self, record_id, object_name=None, process=r"C:\test.exe"):
        return {
            "RecordId": str(record_id),
            "TimeCreated": "2026-08-02T12:00:00.0000000Z",
            "ObjectName": object_name or self.WIN_PATH,
            "ProcessName": process,
            "ProcessId": "4242",
            "SubjectUser": "alanr",
            "AccessList": "%%4416",
        }

    def test_matching_record_becomes_a_read_hit_with_process_info(self):
        watcher = self.make_watcher([self.record(10)])
        self.assertEqual(watcher.poll_once(), 1)
        hits = self.drain(watcher)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].path, self.WSL_PATH)
        self.assertEqual(hits[0].method, METHOD_WIN_AUDIT)
        self.assertEqual(hits[0].event_type, EVENT_READ)
        self.assertIn("test.exe", hits[0].process_info)
        self.assertIn("pid=4242", hits[0].process_info)

    def test_path_matching_is_case_insensitive(self):
        watcher = self.make_watcher(
            [self.record(10, object_name=self.WIN_PATH.upper())]
        )
        self.assertEqual(watcher.poll_once(), 1)

    def test_unrelated_paths_are_ignored(self):
        watcher = self.make_watcher(
            [self.record(10, object_name=r"C:\Windows\notepad.exe")]
        )
        self.assertEqual(watcher.poll_once(), 0)
        self.assertEqual(self.drain(watcher), [])

    def test_already_seen_records_are_not_replayed(self):
        watcher = self.make_watcher([self.record(10), self.record(11)])
        self.assertEqual(watcher.poll_once(), 2)
        self.assertEqual(watcher.poll_once(), 0)

    def test_last_record_id_persists_for_catch_up(self):
        watcher = self.make_watcher([self.record(10), self.record(11)])
        watcher.poll_once()
        self.assertEqual(self.db.get_meta(windows_audit.LAST_RECORD_KEY), "11")
        # Model Monitor's atomic event/inbox commit for the first process.
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE windows_event_inbox SET delivered=1 WHERE record_id<=11"
            )

        # A fresh watcher (as after a reboot) resumes from the stored id and
        # replays only what it missed.
        later = self.make_watcher([self.record(11), self.record(12)])
        self.assertEqual(later.last_record_id, 11)
        self.assertEqual(later.poll_once(catch_up=True), 1)
        hits = self.drain(later)
        self.assertIn("catch-up", hits[0].detail)

    def test_crash_after_checkpoint_replays_durable_match(self):
        first = self.make_watcher([self.record(10)])
        self.assertEqual(first.poll_once(), 1)
        self.assertEqual(self.db.get_meta(windows_audit.LAST_RECORD_KEY), "10")
        # Discard the in-memory queue as a crash would.
        second = self.make_watcher([])
        second.fetch_records = lambda **kwargs: []
        self.assertEqual(second.poll_once(catch_up=True), 1)
        replay = self.drain(second)
        pending = self.db.pending_windows_records()
        self.assertEqual(pending[0]["record_id"], 10)
        self.assertEqual(replay[0].durable_record_ids, (pending[0]["id"],))
        self.assertEqual(replay[0].path, self.WSL_PATH)
        monitor = Monitor(
            self.db,
            [canary(self.WSL_PATH)],
            pushover=SilentPushover(),
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
        )
        monitor.start()
        monitor.hits.put(replay[0])
        monitor.stop()
        self.assertEqual(self.db.count_events(), 1)
        self.assertEqual(self.db.pending_windows_records(), [])
        third = self.make_watcher([])
        third.fetch_records = lambda **kwargs: []
        self.assertEqual(third.poll_once(catch_up=True), 0)

    def test_records_are_processed_in_id_order(self):
        watcher = self.make_watcher([self.record(12), self.record(10), self.record(11)])
        watcher.poll_once()
        hits = self.drain(watcher)
        self.assertEqual([h.detail.split()[-1] for h in hits], ["10", "11", "12"])

    def test_no_mapped_canaries_means_no_work(self):
        with mock.patch.object(windows_audit, "to_windows_path", return_value=None):
            watcher = windows_audit.WinAuditWatcher(
                self.db,
                [canary(self.WSL_PATH)],
                sink=queue.Queue(),
                stop_event=threading.Event(),
                log=self.log,
            )
        self.assertEqual(watcher.path_map, {})

    def test_pages_through_1200_unseen_records_oldest_first(self):
        watcher = self.make_watcher([])
        records = []
        for record_id in range(1, 1201):
            path = self.WIN_PATH if record_id in (1, 600, 1200) else r"C:\other"
            records.append(self.record(record_id, object_name=path))

        def page(*, checkpoint):
            unseen = [r for r in records if int(r["RecordId"]) > checkpoint]
            return {
                "OldestRecordId": "1",
                "NewestRecordId": "1200",
                "Events": unseen[: watcher.max_events],
            }

        watcher.fetch_records = page
        self.assertEqual(watcher.poll_once(catch_up=True), 3)
        self.assertEqual(watcher.last_record_id, 1200)
        hits = self.drain(watcher)
        self.assertEqual([int(h.detail.split()[2]) for h in hits], [1, 600, 1200])

    def test_inbox_backlog_deeper_than_max_events_is_fully_replayed(self):
        staging = self.make_watcher([])
        staging.max_events = 400
        staging.fetch_records = lambda **kwargs: {
            "OldestRecordId": "1",
            "NewestRecordId": "5",
            "Events": [self.record(rid) for rid in range(1, 6)],
        }
        staging.poll_once()
        self.drain(staging)

        # Rows stay pending until their alert is acknowledged, so a replay that
        # only ever reads the oldest window would stall at max_events.
        replay = self.make_watcher([])
        replay.max_events = 2
        replay.fetch_records = lambda **kwargs: {
            "OldestRecordId": "0",
            "NewestRecordId": "0",
            "Events": [],
        }
        self.assertEqual(replay.poll_once(catch_up=True), 5)
        hits = self.drain(replay)
        self.assertEqual([int(h.detail.split()[2]) for h in hits], [1, 2, 3, 4, 5])
        # A second pass must not re-emit anything still pending.
        self.assertEqual(replay.poll_once(), 0)

    def test_reports_security_log_rollover_gap(self):
        self.db.set_meta(windows_audit.LAST_RECORD_KEY, "100")
        watcher = self.make_watcher([])
        watcher.fetch_records = lambda **kwargs: {
            "OldestRecordId": "500",
            "NewestRecordId": "500",
            "Events": [],
        }
        watcher.poll_once(catch_up=True)
        self.assertIn("coverage gap", self.logged())
        self.assertEqual(watcher.last_record_id, 499)

    def test_reused_record_id_after_log_reset_is_staged_again(self):
        first = self.make_watcher(
            [
                self.record(10),
                self.record(20, object_name=r"C:\other"),
            ]
        )
        self.assertEqual(first.poll_once(), 1)
        old_hit = self.drain(first)[0]
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE windows_event_inbox SET delivered=1 WHERE id=?",
                old_hit.durable_record_ids,
            )

        second = self.make_watcher([])
        new_record = self.record(10)
        second.fetch_records = lambda **kwargs: {
            "OldestRecordId": "10",
            "NewestRecordId": "10",
            "Events": [new_record],
        }
        self.assertEqual(second.poll_once(), 1)
        new_hit = self.drain(second)[0]
        self.assertNotEqual(old_hit.durable_record_ids, new_hit.durable_record_ids)
        with self.db.connection() as conn:
            rows = list(
                conn.execute(
                    "SELECT log_generation,record_id,delivered "
                    "FROM windows_event_inbox ORDER BY id"
                )
            )
        self.assertEqual([tuple(row) for row in rows], [(0, 10, 1), (1, 10, 0)])


class PowerShellQuotingTests(unittest.TestCase):
    def test_single_quotes_are_escaped(self):
        self.assertEqual(
            windows_audit._ps_quote(r"C:\Users\o'brien\.ssh\id_rsa"),
            r"C:\Users\o''brien\.ssh\id_rsa",
        )

    def test_sacl_setup_uses_sid_and_captures_exact_sddl(self):
        captured = []
        result = InteropResult(
            True,
            stdout='{"Ok":true,"Before":"S:(AU;SA;FR;;;BA)",'
            '"After":"S:(AU;SA;FR;;;BA)(AU;SA;0x1;;;WD)","Error":""}',
        )
        with mock.patch.object(
            windows_audit,
            "run_powershell",
            side_effect=lambda script, **kwargs: captured.append(script) or result,
        ):
            ok, _, before, after = windows_audit.capture_and_apply_audit_rule(
                r"C:\canary"
            )
        self.assertTrue(ok)
        self.assertTrue(before.startswith("S:"))
        self.assertTrue(after.startswith("S:"))
        self.assertIn("S-1-1-0", captured[0])
        self.assertIn("GetSecurityDescriptorSddlForm", captured[0])
        self.assertNotIn("RemoveAuditRuleAll", captured[0])

    def test_restore_compares_expected_post_state_and_never_removes_all(self):
        captured = []
        with mock.patch.object(
            windows_audit,
            "run_powershell",
            side_effect=lambda script, **kwargs: captured.append(script)
            or InteropResult(
                True, stdout="CONFLICT: current SACL changed independently"
            ),
        ):
            ok, detail = windows_audit.restore_exact_sacl(
                r"C:\canary", "S:(AU;SA;FR;;;BA)", "S:(AU;SA;FR;;;WD)"
            )
        self.assertFalse(ok)
        self.assertIn("CONFLICT", detail)
        self.assertIn("-cne $expected", captured[0])
        self.assertNotIn("RemoveAuditRuleAll", captured[0])

    def test_conflict_is_reported_rather_than_exiting_nonzero(self):
        # `exit 3` would make PowerShell fail as a process, and the caller would
        # see a generic failure instead of the reason the SACL was left alone.
        captured = []
        with mock.patch.object(
            windows_audit,
            "run_powershell",
            side_effect=lambda script, **kwargs: captured.append(script)
            or InteropResult(False, error="powershell exited with 3"),
        ):
            ok, detail = windows_audit.restore_exact_sacl(
                r"C:\canary", "S:(AU;SA;FR;;;BA)", "S:(AU;SA;FR;;;WD)"
            )
        self.assertFalse(ok)
        self.assertIn("powershell exited with 3", detail)
        self.assertNotIn("exit 3", captured[0])

    def test_generated_watcher_pages_forward_and_queues_before_alerting(self):
        body = windows_audit.WATCHER_SCRIPT.format(
            task=windows_audit.TASK_NAME,
            paths="  'C:\\canary'",
            token="token",
            user="user",
        )
        self.assertIn("EventRecordID > $last", body)
        self.assertIn("-Oldest -MaxEvents 400", body)
        self.assertIn("Add-Content -Path $QueueFile", body)
        self.assertIn("$QueuedIds.ContainsKey($recordKey)", body)
        self.assertLess(
            body.index("Add-Content -Path $QueueFile"),
            body.index("Invoke-RestMethod"),
        )


class SetupGuardTests(TempHomeCase):
    def test_setup_without_interop_explains_itself(self):
        with mock.patch.object(windows_audit, "interop_available", return_value=False):
            code = windows_audit.setup_windows_audit(self.db, log=self.log)
        self.assertEqual(code, 2)
        self.assertIn("interop is unavailable", self.logged())

    def test_setup_without_windows_canaries_asks_for_create_canaries(self):
        with mock.patch.object(
            windows_audit, "interop_available", return_value=True
        ), mock.patch.object(windows_audit, "is_elevated", return_value=True):
            code = windows_audit.setup_windows_audit(self.db, log=self.log)
        self.assertEqual(code, 1)
        self.assertIn("create-canaries", self.logged())

    def record_windows_canary(self):
        self.db.record_canary(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/alanr/.npmrc",
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="active-config",
            baseline_atime=None,
        )

    def unelevated(self, distro: str | None = "Ubuntu-22.04"):
        return (
            mock.patch.object(windows_audit, "interop_available", return_value=True),
            mock.patch.object(windows_audit, "is_elevated", return_value=False),
            mock.patch.object(windows_audit, "wsl_distro_name", return_value=distro),
        )

    def test_unelevated_dry_run_still_shows_the_plan(self):
        self.record_windows_canary()
        interop, elevated, distro = self.unelevated()
        with interop, elevated, distro:
            code = windows_audit.setup_windows_audit(
                self.db, dry_run=True, log=self.log
            )
        self.assertEqual(code, 0)
        self.assertIn("not elevated", self.logged())
        self.assertIn("/mnt/c/Users/alanr/.npmrc", self.logged())

    def test_unelevated_setup_names_the_real_distribution(self):
        self.record_windows_canary()
        interop, elevated, distro = self.unelevated()
        with interop, elevated, distro, mock.patch.object(
            windows_audit, "audit_policy_state"
        ) as policy:
            code = windows_audit.setup_windows_audit(self.db, log=self.log)
        self.assertEqual(code, 1)
        # The old text told the operator to paste a *shell* variable into
        # PowerShell, where it expands to nothing and wsl.exe reports
        # WSL_E_DISTRO_NOT_FOUND.
        self.assertNotIn("$WSL_DISTRO_NAME", self.logged())
        self.assertIn("-d Ubuntu-22.04", self.logged())
        self.assertIn("auditpol", self.logged())
        policy.assert_not_called()

    def test_unelevated_setup_offers_to_request_uac(self):
        self.record_windows_canary()
        interop, elevated, distro = self.unelevated()
        with interop, elevated, distro, mock.patch.object(
            windows_audit, "relaunch_elevated", return_value=(True, "launched")
        ) as relaunch, mock.patch.object(
            windows_audit, "audit_policy_state"
        ) as policy:
            code = windows_audit.setup_windows_audit(
                self.db, log=self.log, confirm=lambda prompt: True
            )
        self.assertEqual(code, windows_audit.EXIT_HANDED_OFF)
        relaunch.assert_called_once()
        policy.assert_not_called()
        self.assertIn("elevated console", self.logged())

    def test_declined_uac_falls_back_to_manual_instructions(self):
        self.record_windows_canary()
        interop, elevated, distro = self.unelevated()
        with interop, elevated, distro, mock.patch.object(
            windows_audit, "relaunch_elevated", return_value=(False, "declined")
        ):
            code = windows_audit.setup_windows_audit(
                self.db, log=self.log, confirm=lambda prompt: True
            )
        self.assertEqual(code, 1)
        self.assertIn("Elevation failed: declined", self.logged())
        self.assertIn("ELEVATED PowerShell", self.logged())

    def test_unknown_distribution_says_how_to_find_it(self):
        self.record_windows_canary()
        interop, elevated, distro = self.unelevated(distro=None)
        with interop, elevated, distro:
            code = windows_audit.setup_windows_audit(
                self.db, log=self.log, confirm=lambda prompt: True
            )
        self.assertEqual(code, 1)
        self.assertIn("wsl.exe -l -q", self.logged())
        self.assertNotIn("$WSL_DISTRO_NAME", self.logged())


    def test_policy_failure_stops_before_any_sacl(self):
        self.db.record_canary(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/alanr/.npmrc",
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="low",
            baseline_atime=None,
        )
        with mock.patch.object(
            windows_audit, "interop_available", return_value=True
        ), mock.patch.object(
            windows_audit, "is_elevated", return_value=True
        ), mock.patch.object(
            windows_audit, "audit_policy_state", return_value=("Disabled", False, None)
        ), mock.patch.object(
            windows_audit, "enable_audit_policy", return_value=(False, "denied")
        ), mock.patch.object(
            windows_audit, "capture_and_apply_audit_rule"
        ) as apply:
            code = windows_audit.setup_windows_audit(self.db, log=self.log)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_unreadable_security_log_keeps_policy_restore_record(self):
        self.db.record_canary(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/alanr/.npmrc",
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="low",
            baseline_atime=None,
        )
        with mock.patch.object(
            windows_audit, "interop_available", return_value=True
        ), mock.patch.object(
            windows_audit, "is_elevated", return_value=True
        ), mock.patch.object(
            windows_audit,
            "audit_policy_state",
            side_effect=[("Disabled", False, None), ("Success", True, None)],
        ), mock.patch.object(
            windows_audit, "enable_audit_policy", return_value=(True, "enabled")
        ), mock.patch.object(
            windows_audit,
            "security_log_readable",
            return_value=(False, "access denied"),
        ), mock.patch.object(
            windows_audit, "capture_and_apply_audit_rule"
        ) as apply:
            code = windows_audit.setup_windows_audit(self.db, log=self.log)

        self.assertEqual(code, 1)
        apply.assert_not_called()
        changes = self.db.get_managed_changes(
            change_type=windows_audit.CHANGE_AUDIT_POLICY
        )
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["previous_existed"], 0)
        self.assertEqual(changes[0]["previous_value"], "Disabled")
        self.assertEqual(changes[0]["new_value"], "Success")


class WindowsWatcherInstallRollbackTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.windows_home = self.root / "windows-home"
        self.windows_home.mkdir()
        path = self.windows_home / ".npmrc"
        path.write_text("canary")
        self.db.record_canary(
            canary_id="windows.npmrc",
            path=str(path),
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="low",
            baseline_atime=None,
        )

    def script(self):
        return self.windows_home / ".honeypath" / "honeypath-watcher.ps1"

    def test_schtasks_failure_removes_plaintext_script(self):
        with mock.patch.object(
            windows_audit, "to_windows_path", return_value=r"C:\x"
        ), mock.patch.object(
            windows_audit,
            "run_interop",
            return_value=InteropResult(False, stderr="denied"),
        ):
            code = windows_audit.install_windows_watcher(
                self.db,
                self.windows_home,
                token="secret-token",
                user_key="secret-user",
                log=self.log,
            )
        self.assertEqual(code, 1)
        self.assertFalse(self.script().exists())

    def test_database_failure_deletes_task_and_plaintext_script(self):
        calls = []

        def interop(argv, **kwargs):
            calls.append(argv)
            return InteropResult(True)

        with mock.patch.object(
            windows_audit, "to_windows_path", return_value=r"C:\x"
        ), mock.patch.object(
            windows_audit, "run_interop", side_effect=interop
        ), mock.patch.object(
            self.db, "record_managed_change", side_effect=OSError("database full")
        ):
            code = windows_audit.install_windows_watcher(
                self.db,
                self.windows_home,
                token="secret-token",
                user_key="secret-user",
                log=self.log,
            )
        self.assertEqual(code, 1)
        self.assertTrue(any("/delete" in argv for argv in calls))
        self.assertFalse(self.script().exists())
        # The rollback path handles the credentials; a failure message that
        # echoed them would leave the secrets in the operator's log forever.
        logged = self.logged()
        self.assertNotIn("secret-token", logged)
        self.assertNotIn("secret-user", logged)

    def test_policy_prestate_capture_is_mandatory(self):
        self.db.record_canary(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/alanr/.npmrc",
            kind="npm_token",
            severity="high",
            profile="wsl-windows-developer",
            platform="windows",
            intrusiveness="low",
            baseline_atime=None,
        )
        with mock.patch.object(
            windows_audit, "interop_available", return_value=True
        ), mock.patch.object(
            windows_audit, "is_elevated", return_value=True
        ), mock.patch.object(
            windows_audit,
            "audit_policy_state",
            return_value=(None, None, "access denied"),
        ), mock.patch.object(
            windows_audit, "enable_audit_policy"
        ) as enable, mock.patch.object(
            windows_audit, "capture_and_apply_audit_rule"
        ) as apply:
            code = windows_audit.setup_windows_audit(self.db, log=self.log)
        self.assertEqual(code, 1)
        enable.assert_not_called()
        apply.assert_not_called()


class ElevationCommandTests(unittest.TestCase):
    def build(self):
        with mock.patch.object(
            windows_audit, "wsl_distro_name", return_value="Ubuntu-22.04"
        ), mock.patch.object(windows_audit.sys, "argv", ["/opt/hp/honeypath.py"]):
            built = windows_audit.elevation_command(extra=["--user", "alan"])
        assert built is not None
        return built

    def test_start_process_requests_elevation_for_this_distro(self):
        script, display = self.build()
        self.assertIn("-Verb RunAs", script)
        self.assertIn("'-d', 'Ubuntu-22.04'", script)
        self.assertIn("'-u', 'root'", script)
        # cmd.exe /k keeps the elevated console readable after the run.
        self.assertIn("'/k', 'wsl.exe'", script)
        self.assertIn("setup-windows-audit", script)
        self.assertIn("--user", script)
        self.assertTrue(display.startswith("wsl.exe -d Ubuntu-22.04"))

    def test_no_distribution_means_no_guessed_command(self):
        with mock.patch.object(windows_audit, "wsl_distro_name", return_value=None):
            self.assertIsNone(windows_audit.elevation_command())

    def test_a_quote_in_the_distro_name_cannot_break_out(self):
        with mock.patch.object(
            windows_audit, "wsl_distro_name", return_value="It's-A-Distro"
        ):
            built = windows_audit.elevation_command()
        assert built is not None
        self.assertIn("'It''s-A-Distro'", built[0])


if __name__ == "__main__":
    unittest.main()
