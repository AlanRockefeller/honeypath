"""Suppression of routine machine activity, without losing the events.

The scenario every test here is derived from: a WSL host whose NTFS
last-access updates are enabled, running Backblaze, Defender and the Windows
Search indexer.  Each profile-wide pass advanced the atime of all twelve
Windows canaries and produced twelve critical Pushover alerts, none of which
had a process name attached, roughly once an hour.

Every mechanism below governs *delivery only*.  The invariant asserted over and
over is that the event still reaches SQLite and the log file: a suppressed
alert must never become a missing record.
"""

from __future__ import annotations

import contextlib
import os
import queue
import subprocess
import sys
import threading
import time
import unittest

from .support import TempHomeCase

from honeypath import alerts as alerts_mod  # noqa: E402
from honeypath import monitor as monitor_mod  # noqa: E402
from honeypath import procscan  # noqa: E402
from honeypath import windows_audit  # noqa: E402
from honeypath.database import CanaryRow  # noqa: E402


def hit(path, method, event_type=monitor_mod.EVENT_READ, at=1000.0, **kwargs):
    return monitor_mod.RawHit(
        path=path, method=method, event_type=event_type, at=at, **kwargs
    )


@contextlib.contextmanager
def holding_open(path):
    """A separate process holding *path* open for the duration of the block."""
    reader = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time\n"
            "fh = open(sys.argv[1], 'rb')\n"
            "sys.stdout.write('ready\\n')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n",
            str(path),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert reader.stdout is not None
        reader.stdout.readline()  # the descriptor is open by the time this returns
        yield reader
    finally:
        reader.kill()
        reader.wait(timeout=5)


def event(path, severity="critical", **kwargs):
    base = {
        "path": path,
        "severity": severity,
        "kind": "aws_credentials",
        "method": "atime",
    }
    base.update(kwargs)
    return base


# --------------------------------------------------------------------------
# Windows atime is recorded, not delivered
# --------------------------------------------------------------------------


class WindowsAtimeModeTests(TempHomeCase):
    def make_watcher(self, paths, platform="windows", **kwargs):
        canaries = [
            CanaryRow(
                canary_id="k",
                path=str(p),
                kind="aws_credentials",
                severity="critical",
                profile="windows-developer",
                platform=platform,
                intrusiveness="high",
                last_baseline_atime=os.stat(p).st_atime_ns,
                active=1,
                file_dev=os.stat(p).st_dev,
                file_ino=os.stat(p).st_ino,
            )
            for p in paths
        ]
        return monitor_mod.AtimeWatcher(
            canaries, queue.Queue(), threading.Event(), log=self.log, **kwargs
        )

    def advance_atime(self, path):
        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns + 10_000_000_000, st.st_mtime_ns))

    def test_windows_read_is_advisory_by_default(self):
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher([path])
        watcher.poll_once()
        self.advance_atime(path)

        emitted = watcher.poll_once()
        self.assertEqual(len(emitted), 1)
        self.assertTrue(emitted[0].advisory)

    def test_linux_read_is_never_advisory(self):
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher([path], platform="linux")
        watcher.poll_once()
        self.advance_atime(path)

        emitted = watcher.poll_once()
        self.assertEqual(len(emitted), 1)
        self.assertFalse(emitted[0].advisory)

    def test_alert_mode_restores_delivery(self):
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher(
            [path], windows_atime=monitor_mod.WINDOWS_ATIME_ALERT
        )
        watcher.poll_once()
        self.advance_atime(path)

        emitted = watcher.poll_once()
        self.assertEqual(len(emitted), 1)
        self.assertFalse(emitted[0].advisory)

    def test_off_mode_emits_nothing_for_a_read(self):
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher([path], windows_atime=monitor_mod.WINDOWS_ATIME_OFF)
        watcher.poll_once()
        self.advance_atime(path)

        self.assertEqual(watcher.poll_once(), [])

    def test_off_mode_still_advances_the_baseline(self):
        """Otherwise flipping the mode back up replays every silenced read."""
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher([path], windows_atime=monitor_mod.WINDOWS_ATIME_OFF)
        watcher.poll_once()
        self.advance_atime(path)
        watcher.poll_once()

        self.assertEqual(watcher.baselines[str(path)], os.stat(path).st_atime_ns)

    def test_off_mode_still_reports_a_deleted_canary(self):
        """A scanner reads files.  It does not delete them."""
        path = self.write("credentials", "secret\n")
        watcher = self.make_watcher([path], windows_atime=monitor_mod.WINDOWS_ATIME_OFF)
        watcher.poll_once()
        path.unlink()

        emitted = watcher.poll_once()
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0].event_type, monitor_mod.EVENT_REMOVED)
        self.assertFalse(emitted[0].advisory)


class AdvisoryCoalescingTests(unittest.TestCase):
    def test_advisory_hits_alone_stay_advisory(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/mnt/c/x/.npmrc", "atime", at=1000.0, advisory=True))
        due = coalescer.due(now=1003.0)
        self.assertTrue(due[0].advisory)

    def test_one_attributable_method_promotes_the_whole_event(self):
        """atime cannot say who read the file.  SACL auditing can."""
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/mnt/c/x/.npmrc", "atime", at=1000.0, advisory=True))
        coalescer.add(
            hit(
                "/mnt/c/x/.npmrc",
                "win-audit",
                at=1000.5,
                process_info="C:\\evil.exe pid=9",
            )
        )
        due = coalescer.due(now=1003.0)
        self.assertEqual(len(due), 1)
        self.assertFalse(due[0].advisory)

    def test_promotion_holds_regardless_of_arrival_order(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/mnt/c/x/.npmrc", "win-audit", at=1000.0))
        coalescer.add(hit("/mnt/c/x/.npmrc", "atime", at=1000.5, advisory=True))
        self.assertFalse(coalescer.due(now=1003.0)[0].advisory)


# --------------------------------------------------------------------------
# Sweep aggregation
# --------------------------------------------------------------------------


class SweepAggregatorTests(unittest.TestCase):
    def make(self, **kwargs):
        kwargs.setdefault("window", 30.0)
        window = kwargs.pop("window")
        return monitor_mod.SweepAggregator(window, **kwargs)

    def test_the_first_alert_of_a_burst_goes_out_immediately(self):
        sweep = self.make()
        jobs = sweep.offer(1, event("/a"), now=1000.0)
        self.assertEqual(len(jobs), 1)
        self.assertIn("/a", jobs[0].body)

    def test_the_rest_of_the_burst_is_held(self):
        sweep = self.make()
        sweep.offer(1, event("/a"), now=1000.0)
        self.assertEqual(sweep.offer(2, event("/b"), now=1001.0), [])
        self.assertEqual(sweep.pending(), 1)

    def test_a_quiet_period_closes_the_burst(self):
        sweep = self.make(threshold=3)
        sweep.offer(1, event("/a"), now=1000.0)
        for index, path in enumerate(("/b", "/c", "/d"), start=2):
            sweep.offer(index, event(path), now=1000.0 + index)
        self.assertEqual(sweep.due(now=1010.0), [])

        jobs = sweep.due(now=1040.0)
        self.assertEqual(len(jobs), 1)
        self.assertIn("3 more canaries read", jobs[0].body)
        self.assertEqual(len(jobs[0].events), 3)

    def test_a_burst_spread_across_polls_stays_one_burst(self):
        """The real bursts spanned 44s across several 20s atime polls."""
        sweep = self.make(window=30.0, threshold=3)
        sweep.offer(1, event("/a"), now=1000.0)
        for index in range(2, 13):
            sweep.offer(index, event(f"/p{index}"), now=1000.0 + index * 4)
            self.assertEqual(sweep.due(now=1000.0 + index * 4), [])

        jobs = sweep.due(now=1200.0)
        self.assertEqual(len(jobs), 1)
        self.assertIn("11 more canaries read", jobs[0].body)

    def test_a_couple_of_stragglers_are_sent_individually(self):
        sweep = self.make(threshold=3)
        sweep.offer(1, event("/a"), now=1000.0)
        sweep.offer(2, event("/b"), now=1001.0)

        jobs = sweep.due(now=1040.0)
        self.assertEqual(len(jobs), 1)
        self.assertIn("/b", jobs[0].body)
        self.assertNotIn("more canaries read", jobs[0].body)

    def test_a_sweep_that_never_goes_quiet_still_reports(self):
        sweep = self.make(window=30.0, maximum=100.0, threshold=2)
        sweep.offer(1, event("/a"), now=1000.0)
        jobs = []
        for index in range(2, 40):
            jobs += sweep.offer(index, event(f"/p{index}"), now=1000.0 + index * 5)
        self.assertTrue(jobs)
        self.assertIn("more canaries read", jobs[0].body)

    def test_zero_window_disables_aggregation(self):
        sweep = self.make(window=0.0)
        for index in range(5):
            jobs = sweep.offer(index, event(f"/p{index}"), now=1000.0 + index)
            self.assertEqual(len(jobs), 1)
        self.assertEqual(sweep.pending(), 0)

    def test_flush_releases_everything_held(self):
        sweep = self.make(threshold=99)
        sweep.offer(1, event("/a"), now=1000.0)
        sweep.offer(2, event("/b"), now=1001.0)
        jobs = sweep.flush()
        self.assertEqual(sum(len(job.events) for job in jobs), 1)


class SweepAlertBodyTests(unittest.TestCase):
    def test_it_reports_count_and_worst_severity(self):
        body = alerts_mod.format_sweep_alert(
            [event("/a", "medium"), event("/b", "critical"), event("/c", "high")]
        )
        self.assertIn("3 more canaries read (critical)", body)
        self.assertIn("/b", body)

    def test_long_sweeps_are_truncated_for_pushovers_limit(self):
        events = [event(f"/path/number/{i}") for i in range(40)]
        body = alerts_mod.format_sweep_alert(events)
        self.assertIn("... and 30 more", body)
        self.assertLess(len(body), 1024)

    def test_processes_are_named_once_each(self):
        body = alerts_mod.format_sweep_alert(
            [
                event("/a", process_info="C:\\bzserv.exe pid=1"),
                event("/b", process_info="C:\\bzserv.exe pid=1"),
            ]
        )
        self.assertEqual(body.count("bzserv.exe"), 1)

    def test_an_unknown_severity_does_not_break_delivery(self):
        body = alerts_mod.format_sweep_alert([{"path": "/a", "severity": "banana"}])
        self.assertIn("unknown", body)


# --------------------------------------------------------------------------
# Windows process allowlist
# --------------------------------------------------------------------------


class ProcessAllowlistTests(unittest.TestCase):
    def test_it_matches_a_basename_pattern_against_a_full_image_path(self):
        allowlist = windows_audit.ProcessAllowlist(["bzserv.exe"])
        self.assertEqual(
            allowlist.matches("C:\\Program Files\\Backblaze\\bzserv.exe"),
            "bzserv.exe",
        )

    def test_it_tolerates_the_stored_process_info_form(self):
        allowlist = windows_audit.ProcessAllowlist(["bzserv.exe"])
        self.assertTrue(
            allowlist.matches(
                "C:\\Program Files\\Backblaze\\bzserv.exe pid=6248 user=x"
            )
        )

    def test_matching_is_case_insensitive(self):
        allowlist = windows_audit.ProcessAllowlist(["MsMpEng.exe"])
        self.assertTrue(allowlist.matches("c:\\windows\\msmpeng.exe"))

    def test_a_directory_glob_works(self):
        allowlist = windows_audit.ProcessAllowlist(["c:\\program files\\backblaze\\*"])
        self.assertTrue(
            allowlist.matches("C:\\Program Files\\Backblaze\\bztransmit.exe")
        )

    def test_unrelated_processes_do_not_match(self):
        allowlist = windows_audit.ProcessAllowlist(
            list(windows_audit.KNOWN_SCANNER_PROCESSES)
        )
        self.assertIsNone(allowlist.matches("C:\\Users\\alanr\\Downloads\\stealer.exe"))
        self.assertIsNone(allowlist.matches("C:\\Windows\\System32\\cmd.exe"))

    def test_the_known_scanner_list_covers_the_observed_offenders(self):
        allowlist = windows_audit.ProcessAllowlist(
            list(windows_audit.KNOWN_SCANNER_PROCESSES)
        )
        for image in (
            "C:\\Program Files\\Backblaze\\bztransmit1234.exe",
            "C:\\Program Files\\Backblaze\\bzserv.exe",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe",
            "C:\\Windows\\System32\\SearchIndexer.exe",
        ):
            self.assertTrue(allowlist.matches(image), image)

    def test_an_empty_allowlist_is_falsey_and_matches_nothing(self):
        allowlist = windows_audit.ProcessAllowlist([])
        self.assertFalse(allowlist)
        self.assertIsNone(allowlist.matches("C:\\anything.exe"))

    def test_blank_patterns_are_discarded(self):
        self.assertFalse(windows_audit.ProcessAllowlist(["", "   "]))


class WinAuditAllowlistTests(TempHomeCase):
    def watcher(self, patterns):
        row = CanaryRow(
            canary_id="windows.npmrc",
            path="/mnt/c/Users/alanr/.npmrc",
            kind="npm_token",
            severity="high",
            profile="windows-developer",
            platform="windows",
            intrusiveness="low",
            last_baseline_atime=None,
            active=1,
        )
        return windows_audit.WinAuditWatcher(
            self.db,
            [row],
            queue.Queue(),
            threading.Event(),
            allowlist=windows_audit.ProcessAllowlist(patterns),
            log=self.log,
        )

    def stage(self, watcher, process_info):
        self.db.stage_windows_record(
            checkpoint_key=windows_audit.LAST_RECORD_KEY,
            log_generation=0,
            record_id=1,
            hit={
                "path": "/mnt/c/Users/alanr/.npmrc",
                "detail": "4663 record 1",
                "process_info": process_info,
                "at": time.time(),
            },
        )
        watcher._emit_pending_inbox()
        return watcher.sink.get_nowait()

    def test_an_allowlisted_read_is_emitted_as_advisory(self):
        watcher = self.watcher(["bzserv.exe"])
        emitted = self.stage(watcher, "C:\\Backblaze\\bzserv.exe pid=6248 user=alanr")
        self.assertTrue(emitted.advisory)
        self.assertIn("allowlisted process: bzserv.exe", emitted.detail)

    def test_an_allowlisted_read_keeps_its_process_info(self):
        """The event still has to say who did it — it just does not push."""
        watcher = self.watcher(["bzserv.exe"])
        emitted = self.stage(watcher, "C:\\Backblaze\\bzserv.exe pid=6248 user=alanr")
        self.assertIn("bzserv.exe", emitted.process_info)

    def test_an_unlisted_process_still_alerts(self):
        watcher = self.watcher(["bzserv.exe"])
        emitted = self.stage(watcher, "C:\\Users\\alanr\\stealer.exe pid=99 user=alanr")
        self.assertFalse(emitted.advisory)
        self.assertNotIn("allowlisted", emitted.detail)

    def test_a_read_with_no_process_name_is_never_allowlisted(self):
        watcher = self.watcher(["bzserv.exe"])
        emitted = self.stage(watcher, None)
        self.assertFalse(emitted.advisory)


# --------------------------------------------------------------------------
# Linux reader attribution
# --------------------------------------------------------------------------


class ProcScanTests(TempHomeCase):
    def test_it_names_a_process_holding_the_file_open(self):
        path = self.write("canary", "secret\n")
        handle = open(path, "rb")
        try:
            readers = procscan.readers_of(str(path))
        finally:
            handle.close()
        self.assertTrue(any(f"pid={os.getpid()}" in r for r in readers))

    def test_a_closed_reader_is_not_reported(self):
        path = self.write("canary", "secret\n")
        open(path, "rb").close()
        self.assertEqual(procscan.readers_of(str(path)), [])

    def test_our_own_pid_can_be_excluded(self):
        path = self.write("canary", "secret\n")
        handle = open(path, "rb")
        try:
            readers = procscan.readers_of(str(path), exclude_pids=(os.getpid(),))
        finally:
            handle.close()
        self.assertEqual(readers, [])

    def test_a_missing_file_yields_nothing(self):
        self.assertEqual(procscan.readers_of(str(self.home / "absent")), [])

    def test_a_symlinked_canary_is_not_followed(self):
        """Attribution must never become a probe of somewhere else."""
        target = self.write("real", "secret\n")
        link = self.home / "canary"
        link.symlink_to(target)
        handle = open(target, "rb")
        try:
            self.assertEqual(procscan.readers_of(str(link)), [])
        finally:
            handle.close()

    def test_a_directory_is_not_a_canary(self):
        self.assertEqual(procscan.readers_of(str(self.home)), [])

    def test_an_unreadable_proc_yields_nothing_rather_than_raising(self):
        path = self.write("canary", "secret\n")
        self.assertEqual(
            procscan.readers_of(str(path), proc_root=str(self.home / "no-proc")), []
        )

    def test_describe_readers_returns_none_when_nothing_holds_it(self):
        path = self.write("canary", "secret\n")
        self.assertIsNone(procscan.describe_readers(str(path)))


class InotifyAttributionTests(TempHomeCase):
    def make_watcher(self, paths, **kwargs):
        return monitor_mod.InotifyWatcher(
            [str(p) for p in paths],
            queue.Queue(),
            threading.Event(),
            log=self.log,
            **kwargs,
        )

    def test_an_open_event_names_the_reader(self):
        """A *separate* process: Honeypath's own pid is deliberately excluded."""
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        with holding_open(path) as reader:
            watcher._handle_line(f"OPEN|{path.parent}/|{path.name}")
        emitted = watcher.sink.get_nowait()
        self.assertIsNotNone(emitted.process_info)
        self.assertIn(f"pid={reader.pid}", emitted.process_info)

    def test_honeypaths_own_open_is_never_attributed_to_honeypath(self):
        """Re-arming holds the canary open; that must not read as a detection."""
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        handle = open(path, "rb")
        try:
            watcher._handle_line(f"OPEN|{path.parent}/|{path.name}")
        finally:
            handle.close()
        self.assertIsNone(watcher.sink.get_nowait().process_info)

    def test_access_and_close_do_not_repeat_the_scan(self):
        """Only OPEN can plausibly catch the descriptor; the rest is wasted work."""
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        with holding_open(path):
            watcher._handle_line(f"ACCESS|{path.parent}/|{path.name}")
            watcher._handle_line(f"CLOSE_NOWRITE,CLOSE|{path.parent}/|{path.name}")
        self.assertIsNone(watcher.sink.get_nowait().process_info)
        self.assertIsNone(watcher.sink.get_nowait().process_info)

    def test_attribution_can_be_disabled(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path], attribute=False)
        with holding_open(path):
            watcher._handle_line(f"OPEN|{path.parent}/|{path.name}")
        self.assertIsNone(watcher.sink.get_nowait().process_info)

    def test_a_read_is_still_reported_when_nobody_can_be_named(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        watcher._handle_line(f"OPEN|{path.parent}/|{path.name}")
        emitted = watcher.sink.get_nowait()
        self.assertEqual(emitted.event_type, monitor_mod.EVENT_READ)
        self.assertIsNone(emitted.process_info)


# --------------------------------------------------------------------------
# End to end: suppressed alert, recorded event
# --------------------------------------------------------------------------


class SuppressionKeepsTheRecordTests(TempHomeCase):
    class FakePushover:
        def __init__(self):
            self.sent = []

        def send(self, message, **kwargs):
            self.sent.append(message)
            return True, None

    def build(self, platform="windows", **kwargs):
        path = self.write("credentials", "secret\n")
        row = CanaryRow(
            canary_id="windows.aws.credentials",
            path=str(path),
            kind="aws_credentials",
            severity="critical",
            profile="windows-developer",
            platform=platform,
            intrusiveness="low",
            last_baseline_atime=None,
            active=1,
        )
        pushover = self.FakePushover()
        kwargs.setdefault("dedup_window", 0.0)
        kwargs.setdefault("sweep_window", 0.0)
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=pushover,
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
            **kwargs,
        )
        return monitor, pushover, path

    def test_an_advisory_event_is_recorded_but_not_delivered(self):
        monitor, pushover, path = self.build()
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "atime", at=time.time(), advisory=True))
            monitor.pump(0.4)
            time.sleep(0.3)
        finally:
            monitor.stop()

        self.assertEqual(pushover.sent, [])
        stored = self.db.recent_events(limit=1)[0]
        self.assertEqual(
            stored["pushover_error"], "suppressed: advisory detection method"
        )
        self.assertEqual(stored["path"], str(path))

    def test_an_advisory_event_does_not_consume_the_cooldown(self):
        """Otherwise a scanner blinds Honeypath to a real read for five minutes."""
        monitor, pushover, path = self.build(cooldown=600.0)
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "atime", at=time.time(), advisory=True))
            monitor.pump(0.4)
            monitor.hits.put(hit(str(path), "inotify", at=time.time()))
            monitor.pump(0.4)
            time.sleep(0.3)
        finally:
            monitor.stop()

        self.assertEqual(len(pushover.sent), 1)
        self.assertEqual(self.db.count_events(), 2)

    def test_a_swept_burst_delivers_one_summary_and_records_every_event(self):
        monitor, pushover, path = self.build(
            platform="linux", sweep_window=0.05, sweep_threshold=2, cooldown=0.0
        )
        others = [self.write(f"canary{i}", "secret\n") for i in range(4)]
        monitor.start()
        try:
            for target in [path, *others]:
                monitor.hits.put(hit(str(target), "inotify", at=time.time()))
                monitor.pump(0.05)
            time.sleep(0.3)
            monitor.pump(0.2)
            time.sleep(0.3)
        finally:
            monitor.stop()

        self.assertEqual(self.db.count_events(), 5)
        # One immediate alert for the first canary, one summary for the rest.
        self.assertEqual(len(pushover.sent), 2)
        self.assertIn("more canaries read", pushover.sent[1])

    def test_every_event_in_a_summary_gets_its_own_delivery_record(self):
        monitor, _, path = self.build(
            platform="linux", sweep_window=0.05, sweep_threshold=2, cooldown=0.0
        )
        others = [self.write(f"canary{i}", "secret\n") for i in range(3)]
        monitor.start()
        try:
            for target in [path, *others]:
                monitor.hits.put(hit(str(target), "inotify", at=time.time()))
                monitor.pump(0.05)
            time.sleep(0.3)
            monitor.pump(0.2)
            time.sleep(0.3)
        finally:
            monitor.stop()

        delivered = [e for e in self.db.recent_events(limit=10) if e["pushover_sent"]]
        self.assertEqual(len(delivered), 4)

    def test_shutdown_flushes_a_held_burst_rather_than_dropping_it(self):
        monitor, pushover, path = self.build(
            platform="linux", sweep_window=600.0, sweep_threshold=99, cooldown=0.0
        )
        other = self.write("canary-b", "secret\n")
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "inotify", at=time.time()))
            monitor.pump(0.1)
            monitor.hits.put(hit(str(other), "inotify", at=time.time()))
            monitor.pump(0.1)
        finally:
            monitor.stop()
            time.sleep(0.2)

        self.assertEqual(len(pushover.sent), 2)

    def test_a_muted_advisory_event_is_still_recorded(self):
        monitor, pushover, path = self.build()
        self.db.set_meta("mute_until_epoch", str(time.time() + 600))
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "atime", at=time.time(), advisory=True))
            monitor.pump(0.4)
        finally:
            monitor.stop()

        self.assertEqual(pushover.sent, [])
        self.assertEqual(self.db.count_events(), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
