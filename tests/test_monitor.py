"""Dedup, cooldown, mute, and atime re-arming (§7.4)."""

from __future__ import annotations

import os
import queue
import threading
import time
import unittest

from .support import TempHomeCase

from honeypath import monitor as monitor_mod  # noqa: E402
from honeypath.database import CanaryRow  # noqa: E402


def hit(path, method, event_type=monitor_mod.EVENT_READ, at=1000.0, **kwargs):
    return monitor_mod.RawHit(
        path=path, method=method, event_type=event_type, at=at, **kwargs
    )


class CoalescerTests(unittest.TestCase):
    def test_open_access_close_collapse_into_one_event(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        for detail in ("OPEN", "ACCESS", "CLOSE_NOWRITE"):
            coalescer.add(hit("/x/id_rsa", "inotify", at=1000.0, detail=detail))
        self.assertEqual(coalescer.due(now=1001.0), [])
        due = coalescer.due(now=1002.5)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].methods, ["inotify"])
        self.assertEqual(due[0].details, ["OPEN", "ACCESS", "CLOSE_NOWRITE"])

    def test_cross_method_hits_collapse_and_record_both_methods(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/x/id_rsa", "inotify", at=1000.0))
        coalescer.add(hit("/x/id_rsa", "atime", at=1000.5))
        coalescer.add(
            hit("/x/id_rsa", "win-audit", at=1001.0, process_info="C:\\evil.exe")
        )
        due = coalescer.due(now=1003.0)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].methods, ["inotify", "atime", "win-audit"])
        self.assertEqual(due[0].process_info, "C:\\evil.exe")

    def test_different_paths_stay_separate(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/x/a", "inotify", at=1000.0))
        coalescer.add(hit("/x/b", "inotify", at=1000.0))
        self.assertEqual(len(coalescer.due(now=1003.0)), 2)

    def test_different_event_types_stay_separate(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/x/a", "inotify", monitor_mod.EVENT_READ, at=1000.0))
        coalescer.add(hit("/x/a", "inotify", monitor_mod.EVENT_REMOVED, at=1000.0))
        self.assertEqual(len(coalescer.due(now=1003.0)), 2)

    def test_a_later_burst_is_a_new_event(self):
        coalescer = monitor_mod.Coalescer(window=2.0)
        coalescer.add(hit("/x/a", "inotify", at=1000.0))
        self.assertEqual(len(coalescer.due(now=1003.0)), 1)
        coalescer.add(hit("/x/a", "inotify", at=1010.0))
        self.assertEqual(len(coalescer.due(now=1013.0)), 1)

    def test_flush_drains_everything(self):
        coalescer = monitor_mod.Coalescer(window=100.0)
        coalescer.add(hit("/x/a", "inotify", at=1000.0))
        self.assertEqual(len(coalescer.flush()), 1)
        self.assertEqual(coalescer.flush(), [])


class CooldownTests(unittest.TestCase):
    def test_second_alert_within_the_window_is_suppressed(self):
        cooldown = monitor_mod.CooldownTracker(seconds=300)
        self.assertTrue(cooldown.allow("/x/a", now=0))
        self.assertFalse(cooldown.allow("/x/a", now=100))
        self.assertTrue(cooldown.allow("/x/a", now=301))

    def test_paths_have_independent_cooldowns(self):
        cooldown = monitor_mod.CooldownTracker(seconds=300)
        self.assertTrue(cooldown.allow("/x/a", now=0))
        self.assertTrue(cooldown.allow("/x/b", now=1))

    def test_remaining_reports_the_wait(self):
        cooldown = monitor_mod.CooldownTracker(seconds=300)
        cooldown.allow("/x/a", now=0)
        self.assertAlmostEqual(cooldown.remaining("/x/a", now=100), 200)
        self.assertEqual(cooldown.remaining("/x/never-seen"), 0.0)


class MuteTests(TempHomeCase):
    def test_mute_window_is_honoured(self):
        self.assertFalse(self.db.is_muted())
        self.db.set_meta("mute_until_epoch", str(time.time() + 600))
        self.assertTrue(self.db.is_muted())

    def test_expired_mute_stops_suppressing(self):
        self.db.set_meta("mute_until_epoch", str(time.time() - 1))
        self.assertFalse(self.db.is_muted())

    def test_malformed_value_is_treated_as_unmuted(self):
        self.db.set_meta("mute_until_epoch", "not-a-number")
        self.assertFalse(self.db.is_muted())


class AtimeWatcherTests(TempHomeCase):
    def make_watcher(self, paths, **kwargs):
        canaries = [
            CanaryRow(
                canary_id="k",
                path=str(p),
                kind="ssh_private_key",
                severity="critical",
                profile="linux-developer",
                platform="linux",
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

    def test_atime_advance_is_reported_once(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        self.assertEqual(watcher.poll_once(), [])

        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns + 10_000_000_000, st.st_mtime_ns))
        emitted = watcher.poll_once()
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0].event_type, monitor_mod.EVENT_READ)
        self.assertEqual(emitted[0].method, monitor_mod.METHOD_ATIME)
        # No repeat without a further advance.
        self.assertEqual(watcher.poll_once(), [])

    def test_rearm_bumps_mtime_above_atime(self):
        path = self.write("canary", "secret\n")
        # Simulate the post-read state: atime newer than mtime, which under
        # relatime would stop the kernel updating atime on the next read.
        st = os.stat(path)
        os.utime(path, ns=(st.st_mtime_ns + 60_000_000_000, st.st_mtime_ns))
        watcher = self.make_watcher([path])
        watcher.baselines[str(path)] = st.st_atime_ns

        watcher.poll_once()
        after = os.stat(path)
        self.assertGreater(after.st_mtime_ns, after.st_atime_ns)

    def test_rearm_can_be_disabled(self):
        path = self.write("canary", "secret\n")
        st = os.stat(path)
        os.utime(path, ns=(st.st_mtime_ns + 60_000_000_000, st.st_mtime_ns))
        watcher = self.make_watcher([path], rearm=False)
        watcher.baselines[str(path)] = st.st_atime_ns
        before = os.stat(path).st_mtime_ns
        watcher.poll_once()
        self.assertEqual(os.stat(path).st_mtime_ns, before)

    def test_windows_canary_is_never_rearmed(self):
        path = self.write("windows-canary", "secret\n")
        st = os.stat(path)
        canary = CanaryRow(
            canary_id="windows.maven",
            path=str(path),
            kind="maven_credentials",
            severity="medium",
            profile="wsl-windows-supply-chain",
            platform="windows",
            intrusiveness="low",
            last_baseline_atime=st.st_atime_ns,
            active=1,
            file_dev=st.st_dev,
            file_ino=st.st_ino,
        )
        watcher = monitor_mod.AtimeWatcher(
            [canary], queue.Queue(), threading.Event(), log=self.log
        )
        os.utime(path, ns=(st.st_atime_ns + 10_000_000_000, st.st_mtime_ns))
        before_mtime = os.stat(path).st_mtime_ns

        emitted = watcher.poll_once()

        self.assertEqual(
            [event.event_type for event in emitted], [monitor_mod.EVENT_READ]
        )
        self.assertEqual(os.stat(path).st_mtime_ns, before_mtime)

    def test_deletion_then_recreation_rearms(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        watcher.poll_once()

        path.unlink()
        emitted = watcher.poll_once()
        self.assertEqual([e.event_type for e in emitted], [monitor_mod.EVENT_REMOVED])
        # Still missing: do not spam.
        self.assertEqual(watcher.poll_once(), [])

        path.write_text("secret again\n")
        emitted = watcher.poll_once()
        self.assertEqual([e.event_type for e in emitted], [monitor_mod.EVENT_RECREATED])

        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns + 10_000_000_000, st.st_mtime_ns))
        emitted = watcher.poll_once()
        self.assertEqual([e.event_type for e in emitted], [monitor_mod.EVENT_READ])

    def test_baseline_persists_through_the_writer(self):
        path = self.write("canary", "secret\n")
        writer = monitor_mod.WriterQueue(self.db)
        writer.start()
        try:
            self.db.record_canary(
                canary_id="k",
                path=str(path),
                kind="ssh_private_key",
                severity="critical",
                profile="linux-developer",
                platform="linux",
                intrusiveness="high",
                baseline_atime=None,
            )
            watcher = self.make_watcher([path], writer=writer)
            st = os.stat(path)
            os.utime(path, ns=(st.st_atime_ns + 10_000_000_000, st.st_mtime_ns))
            watcher.poll_once()
            time.sleep(0.3)
        finally:
            writer.stop()
        row = self.db.get_canary_by_path(str(path))
        assert row is not None
        self.assertIsNotNone(row.last_baseline_atime)

    def test_symlink_replacement_never_touches_target_and_alerts_once(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        target = self.write("sensitive-target", "real\n")
        fixed_atime = 1_700_000_000_000_000_000
        fixed_mtime = fixed_atime + 5_000_000_000
        os.utime(target, ns=(fixed_atime, fixed_mtime))
        path.unlink()
        path.symlink_to(target)
        before = os.stat(target)
        emitted = watcher.poll_once()
        self.assertEqual([e.event_type for e in emitted], [monitor_mod.EVENT_REPLACED])
        self.assertEqual(watcher.poll_once(), [])
        after = os.stat(target)
        self.assertEqual(after.st_atime_ns, before.st_atime_ns)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

    def test_symlinked_parent_never_touches_external_target(self):
        path = self.write(".aws/canary", "secret\n")
        watcher = self.make_watcher([path])
        original_parent = path.parent
        original_parent.rename(self.home / ".aws-original")
        outside = self.root / "outside"
        outside.mkdir()
        target = outside / "canary"
        target.write_text("external\n")
        fixed_atime = 1_700_000_000_000_000_000
        fixed_mtime = fixed_atime + 9_000_000_000
        os.utime(target, ns=(fixed_atime, fixed_mtime))
        original_parent.symlink_to(outside)

        emitted = watcher.poll_once()
        self.assertEqual([e.event_type for e in emitted], [monitor_mod.EVENT_REPLACED])
        self.assertFalse(watcher.rearm_path(str(path)))
        after = os.stat(target)
        self.assertEqual(after.st_atime_ns, fixed_atime)
        self.assertEqual(after.st_mtime_ns, fixed_mtime)

    def test_regular_file_inode_replacement_is_not_rebaselined(self):
        path = self.write("canary", "secret\n")
        watcher = self.make_watcher([path])
        replacement = self.write("replacement-source", "replacement\n")
        os.replace(replacement, path)
        self.assertEqual(
            [e.event_type for e in watcher.poll_once()],
            [monitor_mod.EVENT_REPLACED],
        )
        self.assertEqual(watcher.poll_once(), [])


class InotifyLineParsingTests(TempHomeCase):
    def make_watcher(self, paths):
        return monitor_mod.InotifyWatcher(
            [str(p) for p in paths], queue.Queue(), threading.Event(), log=self.log
        )

    def drain(self, watcher):
        out = []
        while True:
            try:
                out.append(watcher.sink.get_nowait())
            except queue.Empty:
                return out

    def test_read_events_are_classified(self):
        path = self.home / ".ssh" / "id_rsa"
        watcher = self.make_watcher([path])
        for events in ("OPEN", "ACCESS", "CLOSE_NOWRITE", "OPEN,ACCESS"):
            watcher._handle_line(f"{events}|{path.parent}/|{path.name}")
        hits = self.drain(watcher)
        self.assertEqual(len(hits), 4)
        self.assertTrue(all(h.event_type == monitor_mod.EVENT_READ for h in hits))

    def test_delete_and_create_are_classified(self):
        path = self.home / ".netrc"
        watcher = self.make_watcher([path])
        watcher._handle_line(f"DELETE|{path.parent}/|{path.name}")
        watcher._handle_line(f"CREATE|{path.parent}/|{path.name}")
        watcher._handle_line(f"MOVED_TO|{path.parent}/|{path.name}")
        hits = self.drain(watcher)
        self.assertEqual(
            [h.event_type for h in hits],
            [
                monitor_mod.EVENT_REMOVED,
                monitor_mod.EVENT_RECREATED,
                monitor_mod.EVENT_RECREATED,
            ],
        )

    def test_unrelated_files_in_a_watched_directory_are_ignored(self):
        path = self.home / ".netrc"
        watcher = self.make_watcher([path])
        watcher._handle_line(f"ACCESS|{path.parent}/|.bashrc")
        self.assertEqual(self.drain(watcher), [])

    def test_writes_are_ignored(self):
        path = self.home / ".netrc"
        watcher = self.make_watcher([path])
        watcher._handle_line(f"MODIFY|{path.parent}/|{path.name}")
        self.assertEqual(self.drain(watcher), [])

    def test_it_watches_parent_directories_not_files(self):
        paths = [self.home / ".netrc", self.home / ".ssh" / "id_rsa"]
        watcher = self.make_watcher(paths)
        self.assertEqual(
            set(watcher.directories),
            {str(self.home), str(self.home / ".ssh")},
        )


class MonitorDispatchTests(TempHomeCase):
    class FakePushover:
        def __init__(self):
            self.sent = []

        def send(self, message, **kwargs):
            self.sent.append(message)
            return True, None

    def build(self, **kwargs):
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
        pushover = self.FakePushover()
        dedup_window = kwargs.pop("dedup_window", 0.0)
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=pushover,
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
            dedup_window=dedup_window,
            **kwargs,
        )
        return monitor, pushover, path

    def test_event_is_logged_and_alerted(self):
        monitor, pushover, path = self.build()
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "inotify", at=time.time()))
            monitor.pump(0.4)
            time.sleep(0.4)
        finally:
            monitor.stop()
        events = self.db.recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertEqual(events[0]["kind"], "netrc")
        self.assertEqual(len(pushover.sent), 1)
        self.assertIn("HONEYPATH critical netrc", pushover.sent[0])

    def test_unconfigured_pushover_is_recorded_without_repeated_failure_log(self):
        class Unconfigured:
            def configured(self):
                return False

            def send(self, *args, **kwargs):
                raise AssertionError("send must not be called when unconfigured")

        path = self.write("local-only-canary", "secret\n")
        row = CanaryRow(
            canary_id="local",
            path=str(path),
            kind="netrc",
            severity="high",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            last_baseline_atime=None,
            active=1,
        )
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=Unconfigured(),
            enable_inotify=False,
            enable_atime=False,
            log=self.log,
            dedup_window=0.0,
        )
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "inotify", at=time.time()))
            monitor.pump(0.3)
        finally:
            monitor.stop()
        event = self.db.recent_events(limit=1)[0]
        self.assertEqual(event["pushover_error"], "pushover not configured")
        self.assertNotIn("delivery failed", self.logged())

    def test_cooldown_suppresses_the_alert_but_not_the_event(self):
        monitor, pushover, path = self.build(cooldown=600.0)
        monitor.start()
        try:
            for offset in (0, 5):
                monitor.hits.put(hit(str(path), "inotify", at=time.time() + offset))
                monitor.pump(0.3)
            time.sleep(0.4)
        finally:
            monitor.stop()
        events = self.db.recent_events(limit=10)
        self.assertEqual(len(events), 2)
        self.assertEqual(len(pushover.sent), 1)
        self.assertEqual(monitor.counts["suppressed"], 1)
        self.assertIn("cooldown", events[0]["pushover_error"])

    def test_mute_suppresses_the_alert_but_not_the_event(self):
        monitor, pushover, path = self.build()
        self.db.set_meta("mute_until_epoch", str(time.time() + 600))
        monitor.start()
        try:
            monitor.hits.put(hit(str(path), "inotify", at=time.time()))
            monitor.pump(0.3)
            time.sleep(0.3)
        finally:
            monitor.stop()
        events = self.db.recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(pushover.sent, [])
        self.assertIn("muted", events[0]["pushover_error"])

    def test_recreation_is_logged_but_not_alerted(self):
        monitor, pushover, path = self.build()
        monitor.start()
        try:
            monitor.hits.put(
                hit(str(path), "inotify", monitor_mod.EVENT_RECREATED, at=time.time())
            )
            monitor.pump(0.3)
            time.sleep(0.3)
        finally:
            monitor.stop()
        self.assertEqual(len(self.db.recent_events(limit=10)), 1)
        self.assertEqual(pushover.sent, [])

    def test_process_info_is_stored_and_appended_to_the_alert(self):
        monitor, pushover, path = self.build()
        monitor.start()
        try:
            monitor.hits.put(
                hit(
                    str(path),
                    "win-audit",
                    at=time.time(),
                    process_info="C:\\Users\\alanr\\evil.exe pid=42",
                )
            )
            monitor.pump(0.3)
            time.sleep(0.3)
        finally:
            monitor.stop()
        events = self.db.recent_events(limit=10)
        self.assertIn("evil.exe", events[0]["process_info"])
        self.assertIn("evil.exe", pushover.sent[0])

    def test_stop_drains_hit_queued_immediately_before_shutdown(self):
        monitor, _, path = self.build(dedup_window=120.0)
        monitor.start()
        monitor.hits.put(hit(str(path), "inotify", at=time.time()))
        monitor.stop()
        self.assertEqual(self.db.count_events(), 1)

    def test_stop_flushes_multiple_pending_coalesced_events(self):
        monitor, _, path = self.build(dedup_window=120.0)
        monitor.start()
        monitor.hits.put(hit(str(path), "inotify", at=time.time()))
        monitor.hits.put(
            hit(str(path), "inotify", monitor_mod.EVENT_REMOVED, at=time.time())
        )
        monitor.stop()
        self.assertEqual(self.db.count_events(), 2)

    def test_slow_failing_pushover_cannot_prevent_event_persistence(self):
        class SlowFailure:
            def send(self, *args, **kwargs):
                time.sleep(0.2)
                return False, "simulated failure"

        path = self.write("slow-canary", "secret\n")
        row = CanaryRow(
            canary_id="slow",
            path=str(path),
            kind="netrc",
            severity="critical",
            profile="linux-developer",
            platform="linux",
            intrusiveness="low",
            last_baseline_atime=None,
            active=1,
        )
        monitor = monitor_mod.Monitor(
            self.db,
            [row],
            pushover=SlowFailure(),
            enable_inotify=False,
            enable_atime=False,
            dedup_window=120.0,
            log=self.log,
        )
        monitor.start()
        monitor.hits.put(hit(str(path), "inotify", at=time.time()))
        monitor.stop(alert_timeout=1.0)
        self.assertEqual(self.db.count_events(), 1)
        self.assertTrue(monitor._stopped)

    def test_stop_waits_for_late_producer_and_drains_its_hit(self):
        monitor, _, path = self.build(dedup_window=120.0)

        class LateWatcher(monitor_mod.Watcher):
            def run(inner):
                inner.stop_event.wait()
                time.sleep(0.08)
                inner.emit(hit(str(path), "win-audit", at=time.time()))

        late = LateWatcher("late-watcher", monitor.hits, monitor.stop_event)
        monitor.win_audit = late
        monitor.start()
        monitor.stop(watcher_timeout=0.01)
        self.assertEqual(self.db.count_events(), 1)


if __name__ == "__main__":
    unittest.main()
