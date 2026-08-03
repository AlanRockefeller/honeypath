"""Watchers: inotify, atime polling with re-arming, and Windows SACL audit.

Three independent detection methods feed one coalescer, which collapses the
OPEN/ACCESS/CLOSE_NOWRITE burst of a single logical read — and any duplicate
sightings from the other methods — into one event, then applies a per-path
alert cooldown and the global mute.

The atime poller deserves a note.  Under ``relatime`` (the default nearly
everywhere) the kernel only updates a file's atime if the old atime is older
than its mtime, or more than 24 h stale.  After the first detected read, a
canary's atime is newer than its mtime, so subsequent reads would go
unnoticed.  Honeypath therefore *re-arms* each canary after an observed
access by bumping its mtime to now, restoring the "mtime newer than atime"
condition the kernel needs.
"""

from __future__ import annotations

import os
import queue
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import alerts as alerts_mod
from . import eventlog as eventlog_mod
from . import safe_write
from .database import CanaryRow, Database, WriterQueue, utc_now

METHOD_INOTIFY = "inotify"
METHOD_ATIME = "atime"
METHOD_WIN_AUDIT = "win-audit"

READ_EVENTS = {"ACCESS", "OPEN", "CLOSE_NOWRITE"}
REMOVE_EVENTS = {"DELETE", "MOVED_FROM", "DELETE_SELF", "MOVE_SELF"}
CREATE_EVENTS = {"CREATE", "MOVED_TO"}

EVENT_READ = "read"
EVENT_REMOVED = "removed"
EVENT_RECREATED = "recreated"
EVENT_REPLACED = "replaced"

DEFAULT_DEDUP_WINDOW = 2.0
DEFAULT_COOLDOWN = 300.0
DEFAULT_POLL_INTERVAL = 20.0


@dataclass
class RawHit:
    path: str
    method: str
    event_type: str
    detail: str = ""
    process_info: str | None = None
    at: float = field(default_factory=time.time)
    durable_record_ids: tuple[int, ...] = ()


@dataclass
class Coalesced:
    path: str
    event_type: str
    methods: list[str]
    details: list[str]
    process_info: str | None
    first_seen: float
    durable_record_ids: list[int] = field(default_factory=list)


class Watcher(threading.Thread):
    """Base class for the detection threads."""

    def __init__(
        self, name: str, sink: "queue.Queue[RawHit]", stop_event: threading.Event
    ):
        super().__init__(name=name, daemon=False)
        self.sink = sink
        self.stop_event = stop_event
        self.status: str = "not started"

    def emit(self, hit: RawHit) -> None:
        self.sink.put(hit)


# --------------------------------------------------------------------------
# inotify
# --------------------------------------------------------------------------


class InotifyWatcher(Watcher):
    """Watches the *parent directories* of canaries via inotifywait.

    Watching a file directly is a trap: the watch dies when the file is
    replaced (which is exactly what an attacker or a restore does).  Watching
    the directory survives deletion and re-creation, and lets Honeypath
    re-arm automatically when a canary reappears.
    """

    RESTART_BACKOFF = (1, 2, 5, 10, 30)

    def __init__(self, paths, sink, stop_event, *, log=print):
        super().__init__("honeypath-inotify", sink, stop_event)
        self.paths = {str(p) for p in paths}
        self.directories = sorted({str(Path(p).parent) for p in self.paths})
        self.log = log
        self.proc: subprocess.Popen | None = None

    @staticmethod
    def available() -> str | None:
        return shutil.which("inotifywait")

    def _command(self, existing_dirs) -> list[str]:
        cmd = [
            self.available() or "inotifywait",
            "-m",
            "-q",
            "--format",
            "%e|%w|%f",
        ]
        for event in (
            "access",
            "open",
            "close_nowrite",
            "create",
            "moved_to",
            "delete",
            "moved_from",
        ):
            cmd += ["-e", event]
        cmd += existing_dirs
        return cmd

    def run(self) -> None:
        binary = self.available()
        if not binary:
            self.status = "unavailable (inotifywait not installed)"
            return
        if not self.directories:
            self.status = "idle (no canary directories)"
            return

        attempt = 0
        while not self.stop_event.is_set():
            existing = [d for d in self.directories if os.path.isdir(d)]
            if not existing:
                self.status = "waiting for canary directories to exist"
                self.stop_event.wait(10)
                continue
            try:
                self.proc = subprocess.Popen(
                    self._command(existing),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except OSError as exc:
                self.status = f"failed to start inotifywait: {exc}"
                return

            self.status = f"watching {len(existing)} directories"
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                if self.stop_event.is_set():
                    break
                self._handle_line(line.rstrip("\n"))

            if self.stop_event.is_set():
                break
            delay = self.RESTART_BACKOFF[min(attempt, len(self.RESTART_BACKOFF) - 1)]
            attempt += 1
            self.status = f"inotifywait exited; restarting in {delay}s"
            self.log(f"[inotify] watcher exited unexpectedly; restarting in {delay}s")
            self.stop_event.wait(delay)

        self._terminate()

    def _handle_line(self, line: str) -> None:
        parts = line.split("|")
        if len(parts) < 3:
            return
        raw_events, directory, filename = parts[0], parts[1], "|".join(parts[2:])
        if not filename:
            return
        full = str(Path(directory) / filename)
        if full not in self.paths:
            return
        names = set(raw_events.split(","))
        if names & READ_EVENTS:
            event_type = EVENT_READ
        elif names & REMOVE_EVENTS:
            event_type = EVENT_REMOVED
        elif names & CREATE_EVENTS:
            event_type = EVENT_RECREATED
        else:
            return
        self.emit(
            RawHit(
                path=full,
                method=METHOD_INOTIFY,
                event_type=event_type,
                detail=raw_events,
            )
        )

    def _terminate(self) -> None:
        proc = self.proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# --------------------------------------------------------------------------
# atime polling
# --------------------------------------------------------------------------


class AtimeWatcher(Watcher):
    """Polls canary atimes, with mtime re-arming for relatime filesystems."""

    def __init__(
        self,
        canaries,
        sink,
        stop_event,
        *,
        writer=None,
        interval=DEFAULT_POLL_INTERVAL,
        rearm=True,
        log=print,
    ):
        super().__init__("honeypath-atime", sink, stop_event)
        self.interval = interval
        self.rearm = rearm
        self.writer = writer
        self.log = log
        self.baselines: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int] | None] = {}
        self.rearmable: dict[str, bool] = {}
        self.seen_missing: set[str] = set()
        for canary in canaries:
            self.baselines[canary.path] = canary.last_baseline_atime or 0
            self.identities[canary.path] = (
                (canary.file_dev, canary.file_ino)
                if canary.file_dev is not None and canary.file_ino is not None
                else None
            )
            # DrvFS/9p can update NTFS atime merely from the descriptor open
            # used while re-arming.  That creates a self-sustaining detection
            # every polling interval.  Windows atime is best-effort only; SACL
            # auditing is the reliable Windows-side mechanism.
            self.rearmable[canary.path] = canary.platform != "windows"

    def add_path(self, path: str, baseline: int | None = None) -> None:
        if path not in self.baselines:
            self.baselines[path] = baseline or 0
            self.identities[path] = None
            self.rearmable[path] = True

    @staticmethod
    def _root_for(path: str) -> Path:
        return Path(Path(path).anchor or "/")

    def _inspect(self, path: str) -> tuple[int, os.stat_result]:
        # O_PATH observes metadata without generating the read whose atime we
        # are trying to detect.  Every parent is opened O_NOFOLLOW from '/'.
        flags = getattr(os, "O_PATH", os.O_RDONLY)
        fd = safe_write.open_regular_nofollow(
            Path(path), root=self._root_for(path), flags=flags
        )
        return fd, os.fstat(fd)

    def _identity_matches(self, path: str, st: os.stat_result) -> bool:
        expected = self.identities.get(path)
        actual = (st.st_dev, st.st_ino)
        if expected is None:
            # Legacy/unverified rows are not silently adopted at watch time.
            # Recreate or explicitly re-register them so the manifest contains
            # the inode identity observed through the anchored creator path.
            return False
        return expected == actual

    def run(self) -> None:
        self.status = f"polling every {self.interval:.0f}s"
        # Establish baselines for anything we do not have one for yet.
        for path in list(self.baselines):
            if self.baselines[path] == 0:
                self._baseline(path)
        while not self.stop_event.is_set():
            self.poll_once()
            self.stop_event.wait(self.interval)

    def _baseline(self, path: str) -> None:
        try:
            fd, st = self._inspect(path)
        except (OSError, safe_write.SafeWriteError):
            return
        try:
            if not self._identity_matches(path, st):
                return
            self.baselines[path] = st.st_atime_ns
            self._persist(path, st.st_atime_ns)
        finally:
            os.close(fd)

    def _persist(self, path: str, atime_ns: int) -> None:
        if self.writer is not None:
            self.writer.update_baseline_atime(path, atime_ns)

    def poll_once(self) -> list[RawHit]:
        """One polling pass.  Returns the hits emitted (handy for tests)."""
        emitted: list[RawHit] = []
        for path in list(self.baselines):
            try:
                fd, st = self._inspect(path)
            except FileNotFoundError:
                if path not in self.seen_missing:
                    self.seen_missing.add(path)
                    hit = RawHit(
                        path=path,
                        method=METHOD_ATIME,
                        event_type=EVENT_REMOVED,
                        detail="file disappeared",
                    )
                    self.emit(hit)
                    emitted.append(hit)
                continue
            except (OSError, safe_write.SafeWriteError):
                # A symlinked/non-directory parent is a replacement, not an
                # invitation to follow it or silently ignore it.
                if path not in self.seen_missing:
                    self.seen_missing.add(path)
                    hit = RawHit(
                        path=path,
                        method=METHOD_ATIME,
                        event_type=EVENT_REPLACED,
                        detail="canary path or a parent was replaced or became unsafe",
                    )
                    self.emit(hit)
                    emitted.append(hit)
                continue
            try:
                identity_matches = self._identity_matches(path, st)
            finally:
                os.close(fd)

            if not identity_matches:
                if path not in self.seen_missing:
                    self.seen_missing.add(path)
                    hit = RawHit(
                        path=path,
                        method=METHOD_ATIME,
                        event_type=EVENT_REPLACED,
                        detail="canary regular-file device/inode identity changed",
                    )
                    self.emit(hit)
                    emitted.append(hit)
                continue

            if path in self.seen_missing:
                # Only the original recorded inode clears replacement state.
                self.seen_missing.discard(path)
                self.baselines[path] = st.st_atime_ns
                self._persist(path, st.st_atime_ns)
                hit = RawHit(
                    path=path,
                    method=METHOD_ATIME,
                    event_type=EVENT_RECREATED,
                    detail="file reappeared",
                )
                self.emit(hit)
                emitted.append(hit)
                continue

            previous = self.baselines.get(path, 0)
            if previous and st.st_atime_ns > previous:
                hit = RawHit(
                    path=path,
                    method=METHOD_ATIME,
                    event_type=EVENT_READ,
                    detail=f"atime advanced {previous} -> {st.st_atime_ns}",
                )
                self.emit(hit)
                emitted.append(hit)
                self.baselines[path] = st.st_atime_ns
                self._persist(path, st.st_atime_ns)
                if self.rearmable.get(path, True):
                    self.rearm_path(path, st)
            elif not previous:
                self.baselines[path] = st.st_atime_ns
                self._persist(path, st.st_atime_ns)
        return emitted

    def rearm_path(self, path: str, st=None) -> bool:
        """Bump mtime so relatime will record the *next* read too."""
        if not self.rearm:
            return False
        try:
            if st is None:
                inspect_fd, st = self._inspect(path)
                os.close(inspect_fd)
            if not stat.S_ISREG(st.st_mode):
                return False
            if not self._identity_matches(path, st):
                return False
            fd = safe_write.open_regular_nofollow(Path(path), root=self._root_for(path))
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    return False
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    self.log(f"[atime] replacement detected while re-arming {path}")
                    return False
                # mtime must end up strictly newer than atime.  Use the opened
                # descriptor so a last-moment symlink swap cannot redirect it.
                new_mtime = max(time.time_ns(), opened.st_atime_ns + 1_000_000)
                os.utime(fd, ns=(opened.st_atime_ns, new_mtime))
                return True
            finally:
                os.close(fd)
        except (OSError, safe_write.SafeWriteError) as exc:
            self.log(f"[atime] could not re-arm {path}: {exc}")
            return False


# --------------------------------------------------------------------------
# Coalescing, cooldown, dispatch
# --------------------------------------------------------------------------


class Coalescer:
    """Collapses a burst of hits for one path into a single logical event."""

    def __init__(self, window: float = DEFAULT_DEDUP_WINDOW):
        self.window = window
        self._pending: dict[tuple[str, str], Coalesced] = {}

    def add(self, hit: RawHit) -> None:
        key = (hit.path, hit.event_type)
        pending = self._pending.get(key)
        if pending is None:
            self._pending[key] = Coalesced(
                path=hit.path,
                event_type=hit.event_type,
                methods=[hit.method],
                details=[hit.detail] if hit.detail else [],
                process_info=hit.process_info,
                first_seen=hit.at,
                durable_record_ids=list(hit.durable_record_ids),
            )
            return
        if hit.method not in pending.methods:
            pending.methods.append(hit.method)
        if hit.detail and hit.detail not in pending.details:
            pending.details.append(hit.detail)
        if hit.process_info and not pending.process_info:
            pending.process_info = hit.process_info
        for record_id in hit.durable_record_ids:
            if record_id not in pending.durable_record_ids:
                pending.durable_record_ids.append(record_id)

    def due(self, now: float | None = None) -> list[Coalesced]:
        now = time.time() if now is None else now
        ready = [
            key
            for key, value in self._pending.items()
            if now - value.first_seen >= self.window
        ]
        return [self._pending.pop(key) for key in ready]

    def flush(self) -> list[Coalesced]:
        items = list(self._pending.values())
        self._pending.clear()
        return items


class CooldownTracker:
    def __init__(self, seconds: float = DEFAULT_COOLDOWN):
        self.seconds = seconds
        self._last: dict[str, float] = {}

    def allow(self, path: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        last = self._last.get(path)
        if last is not None and now - last < self.seconds:
            return False
        self._last[path] = now
        return True

    def remaining(self, path: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        last = self._last.get(path)
        if last is None:
            return 0.0
        return max(0.0, self.seconds - (now - last))


class Monitor:
    """Wires the watchers, the coalescer, the writer queue and the alerter."""

    def __init__(
        self,
        db: Database,
        canaries: list[CanaryRow],
        *,
        cooldown: float = DEFAULT_COOLDOWN,
        dedup_window: float = DEFAULT_DEDUP_WINDOW,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        pushover: alerts_mod.Pushover | None = None,
        enable_inotify: bool = True,
        enable_atime: bool = True,
        win_audit_watcher=None,
        rearm: bool = True,
        log=print,
        event_log=None,
    ):
        self.db = db
        self.canaries = {c.path: c for c in canaries}
        self.log = log
        # Console output is for whoever is watching the terminal; the event log
        # is what survives to be read after the fact.  Both get every failure.
        self.event_log = (
            event_log if event_log is not None else eventlog_mod.NullEventLog()
        )
        self.stop_event = threading.Event()
        self.hits: "queue.Queue[RawHit]" = queue.Queue()
        self.coalescer = Coalescer(dedup_window)
        self.cooldown = CooldownTracker(cooldown)
        self.pushover = pushover if pushover is not None else alerts_mod.Pushover()
        self.writer = WriterQueue(db)
        self.hostname = alerts_mod.hostname()
        self.counts = {"events": 0, "alerts": 0, "suppressed": 0, "muted": 0}

        # Everything a watcher logs is a failure or a degradation — a dead
        # inotifywait, a canary it could not re-arm — so it belongs in the log
        # file at WARN, not only on a terminal nobody is reading.
        self.inotify = (
            InotifyWatcher(
                self.canaries.keys(), self.hits, self.stop_event, log=self._warn
            )
            if enable_inotify
            else None
        )
        self.atime = (
            AtimeWatcher(
                canaries,
                self.hits,
                self.stop_event,
                writer=self.writer,
                interval=poll_interval,
                rearm=rearm,
                log=self._warn,
            )
            if enable_atime
            else None
        )
        self.win_audit = win_audit_watcher
        if self.win_audit is not None:
            self.win_audit.sink = self.hits
            self.win_audit.stop_event = self.stop_event
            # A failed Security-log poll, or a catch-up that replayed reads
            # missed while the watcher was down, must both survive in the log.
            self.win_audit.log = self._warn

        self._alert_queue: "queue.Queue" = queue.Queue()
        self._alert_thread = threading.Thread(
            target=self._alert_loop, name="honeypath-alerts", daemon=False
        )
        self._lifecycle_lock = threading.Lock()
        self._started = False
        self._stopped = False

    # -- reporting ---------------------------------------------------------

    def _report(self, message: str, level: str = eventlog_mod.LEVEL_INFO) -> None:
        """Say it once on the console and once in the log file."""
        self.log(message)
        self.event_log.write(level, message)

    def _warn(self, message: str) -> None:
        self._report(message, eventlog_mod.LEVEL_WARN)

    def _error(self, message: str) -> None:
        self._report(message, eventlog_mod.LEVEL_ERROR)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._started:
                return
            self._started = True
        self.writer.start()
        self._alert_thread.start()
        for watcher in (self.inotify, self.atime, self.win_audit):
            if watcher is not None:
                watcher.start()

    def stop(self, watcher_timeout: float = 5.0, alert_timeout: float = 5.0) -> None:
        """Stop producers, drain every accepted hit, then stop consumers."""
        with self._lifecycle_lock:
            if self._stopped:
                return
            self._stopped = True
        self.stop_event.set()
        if not self._started:
            return
        if self.inotify is not None:
            # Setting the event alone cannot wake a thread blocked iterating
            # inotifywait's stdout.  Terminate the child first so the producer
            # can observe the stop event and join normally.
            self.inotify._terminate()
        watchers = [
            watcher
            for watcher in (self.inotify, self.atime, self.win_audit)
            if watcher is not None
        ]
        for watcher in watchers:
            if watcher is not None and watcher.is_alive():
                watcher.join(watcher_timeout)
                if watcher.is_alive():
                    self._warn(
                        f"[{watcher.name}] did not terminate before shutdown timeout"
                    )
                    cancel = getattr(watcher, "cancel", None)
                    if callable(cancel):
                        cancel()

        # A producer that timed out may still return from an OS/PowerShell
        # call and enqueue detections.  Keep draining until every producer has
        # definitely terminated; shutting the writer down earlier creates a
        # deterministic loss window.
        while any(watcher.is_alive() for watcher in watchers):
            for watcher in watchers:
                if watcher.is_alive():
                    watcher.join(0.05)
            while True:
                try:
                    self.coalescer.add(self.hits.get_nowait())
                except queue.Empty:
                    break

        # Watchers can enqueue between the signal and their final return.
        while True:
            try:
                self.coalescer.add(self.hits.get_nowait())
            except queue.Empty:
                break
        for item in self.coalescer.flush():
            self._dispatch(item)  # synchronous event insert: durable before alerts
        self.writer.drain()

        self._alert_queue.put(None)
        self._alert_thread.join(alert_timeout)
        if self._alert_thread.is_alive():
            self._warn("[pushover] shutdown drain timeout; events are already durable")
        else:
            self.writer.drain()
        self.writer.stop()

    def status_lines(self) -> list[str]:
        lines = []
        for label, watcher in (
            ("inotify", self.inotify),
            ("atime", self.atime),
            ("win-audit", self.win_audit),
        ):
            if watcher is None:
                lines.append(f"  {label}: disabled")
            else:
                lines.append(f"  {label}: {watcher.status}")
        return lines

    def run_forever(self, tick: float = 0.5) -> None:
        while not self.stop_event.is_set():
            self.pump(tick)
        self.pump(0)

    def pump(self, tick: float = 0.5) -> None:
        """Drain pending hits and dispatch anything past the dedup window."""
        deadline = time.time() + tick
        while True:
            timeout = max(0.0, deadline - time.time())
            try:
                hit = (
                    self.hits.get(timeout=timeout)
                    if timeout
                    else self.hits.get_nowait()
                )
            except queue.Empty:
                break
            self.coalescer.add(hit)
            if time.time() >= deadline:
                break
        for item in self.coalescer.due():
            self._dispatch(item)

    # -- dispatch ----------------------------------------------------------

    def _dispatch(self, item: Coalesced) -> None:
        canary = self.canaries.get(item.path)
        methods = "+".join(item.methods)
        message_bits = [f"methods={methods}"]
        if item.details:
            message_bits.append("; ".join(item.details))
        event = {
            "timestamp": utc_now(),
            "hostname": self.hostname,
            "method": methods,
            "event_type": item.event_type,
            "path": item.path,
            "canary_id": canary.canary_id if canary else None,
            "kind": canary.kind if canary else None,
            "severity": canary.severity if canary else None,
            "message": " | ".join(message_bits),
            "process_info": item.process_info,
            "pushover_sent": 0,
            "pushover_error": None,
        }
        self.counts["events"] += 1

        alertable = item.event_type in (EVENT_READ, EVENT_REMOVED, EVENT_REPLACED)
        muted = self.db.is_muted()
        if alertable and muted:
            self.counts["muted"] += 1
            event["pushover_error"] = "suppressed: alerts muted"
            alertable = False
        elif alertable and not self.cooldown.allow(item.path):
            self.counts["suppressed"] += 1
            event["pushover_error"] = "suppressed: per-path cooldown"
            alertable = False

        try:
            event_id = self.writer.record_windows_event_sync(
                event, item.durable_record_ids
            )
        except Exception as exc:
            self._error(f"[db] failed to record event for {item.path}: {exc}")
            event_id = None

        self.log(
            f"{event['timestamp']}  {item.event_type.upper():9} "
            f"{event['severity'] or '-':8} via {methods:22} {item.path}"
            + (f"  [{item.process_info}]" if item.process_info else "")
        )
        # The log line carries its own UTC timestamp and the suppression
        # reason, so it is not the console line repeated.
        self.event_log.detection(event, alerting=alertable)

        # ``None`` means every durable Windows inbox row in this coalesced item
        # was already consumed after a retry; do not send a duplicate alert.
        if alertable and (event_id is not None or not item.durable_record_ids):
            self._alert_queue.put((event_id, dict(event)))

    def _alert_loop(self) -> None:
        while True:
            item = self._alert_queue.get()
            try:
                if item is None:
                    return
                event_id, event = item
                body = alerts_mod.format_alert(event)
                priority = alerts_mod.alert_priority(event.get("severity"))
                configured = getattr(self.pushover, "configured", None)
                if callable(configured) and not configured():
                    # cmd_watch prints one actionable startup message.  Keep
                    # recording delivery state, but do not repeat the same
                    # missing-file failure for every detected path.
                    sent, error = False, "pushover not configured"
                else:
                    sent, error = self.pushover.send(body, priority=priority)
                if sent:
                    self.counts["alerts"] += 1
                elif error != "pushover not configured":
                    self.log(f"[pushover] delivery failed: {error}")
                # ``error`` is already redacted by Pushover.send; nothing on
                # this path can put a credential into the log file.
                self.event_log.delivery(event, sent, error)
                if event_id is not None:
                    self.writer.update_event_delivery(event_id, sent, error)
            finally:
                self._alert_queue.task_done()
