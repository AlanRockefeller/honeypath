"""The human-readable operations log at ``/var/lib/honeypath/honeypath.log``.

SQLite is the authoritative event store; this file is the thing an operator
actually reads — ``tail -f`` during a test, ``less`` after an incident, ``grep``
when asked "did anything touch the AWS canary last week?".  It records every
detection, every alert delivery outcome, and every error or degradation the
watcher notices.

Four properties are deliberate:

* **One event, one line.**  Detections carry attacker-influenced text (a
  Windows process image path from the Security log, a canary path).  Every
  field goes through :func:`sanitize`, which escapes control characters and
  caps length, so nothing injected into a filename can forge a log line.
* **Append-only, ``O_APPEND``.**  Single-line appends under 4 KiB are atomic on
  Linux, so the watcher's alert thread, its main thread and a concurrent
  ``test-alert`` process never interleave a half line.
* **Never fatal.**  A full disk, a read-only mount or a revoked permission
  disables logging with a reason the caller can print once.  It must not take
  down a monitor whose events are already durable in SQLite.
* **No secrets.**  The only credential-adjacent text that reaches this file is
  a Pushover error string, and every one of those has already passed through
  :func:`honeypath.alerts.redact_secrets` at the point it was built.

Timestamps are UTC, matching ``events.timestamp`` in SQLite so the two views of
one detection line up without mental arithmetic.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
import time
from pathlib import Path

from . import safe_write

LOG_NAME = "honeypath.log"
STATE_DIR = Path("/var/lib/honeypath")
DEFAULT_LOG_PATH = STATE_DIR / LOG_NAME

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_KEEP = 3
LOG_MODE = 0o600

LEVEL_INFO = "INFO"
LEVEL_EVENT = "EVENT"
LEVEL_ALERT = "ALERT"
LEVEL_WARN = "WARN"
LEVEL_ERROR = "ERROR"

# Long enough for any real path plus process attribution, short enough that a
# hostile 10 MB "filename" cannot fill the disk one detection at a time.
MAX_MESSAGE_CHARS = 2000

_CONTROL_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def sanitize(text: str) -> str:
    """Make arbitrary text safe to append as exactly one log line."""
    out = []
    for char in str(text):
        if char in _CONTROL_ESCAPES:
            out.append(_CONTROL_ESCAPES[char])
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(char)
    result = "".join(out)
    if len(result) > MAX_MESSAGE_CHARS:
        result = result[:MAX_MESSAGE_CHARS] + "...[truncated]"
    return result


def timestamp(now: float | None = None) -> str:
    """UTC, in the same calendar order as ``events.timestamp``."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)) + "Z"


def default_log_path(db_path: Path | str | None = None) -> Path:
    """The log sits beside the database, so ``--db`` keeps the two together."""
    if db_path is None:
        return DEFAULT_LOG_PATH
    return Path(db_path).parent / LOG_NAME


class NullEventLog:
    """Stand-in used for dry runs, tests, and disabled logging."""

    path: Path | None = None
    error: str | None = None
    enabled = False

    def write(self, level: str, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        pass

    def error_line(self, message: str) -> None:
        pass

    def detection(self, event: dict, *, alerting: bool = True) -> None:
        pass

    def delivery(self, event: dict, sent: bool, error: str | None) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self) -> "NullEventLog":
        return self

    def __exit__(self, *exc_info) -> None:
        pass


class EventLog:
    """Appends human-readable lines to ``honeypath.log``.

    Construction never raises: if the file cannot be opened, :attr:`error`
    explains why and every write becomes a no-op.  Callers report that once
    rather than losing a monitoring session to a logging problem.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep: int = DEFAULT_KEEP,
        version: str | None = None,
    ):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.keep = keep
        self.version = version
        self.error: str | None = None
        self._fd: int | None = None
        self._lock = threading.RLock()
        self._open()

    # -- plumbing ----------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._fd is not None

    def _root(self) -> Path:
        return Path(self.path.anchor or "/")

    def _disable(self, reason: str) -> None:
        if self.error is None:
            self.error = reason
            # stderr, not stdout: a broken log must not corrupt piped output,
            # and under systemd this lands in the journal.
            print(
                f"honeypath: logging to {self.path} disabled: {reason}", file=sys.stderr
            )
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _open(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._disable(f"cannot create {self.path.parent}: {exc}")
            return
        try:
            with safe_write.anchored_parent(self.path, self._root()) as (
                parent_fd,
                name,
            ):
                fd = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_APPEND
                    | os.O_CREAT
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    LOG_MODE,
                    dir_fd=parent_fd,
                )
        except (OSError, safe_write.SafeWriteError) as exc:
            self._disable(str(exc))
            return
        try:
            info = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            self._disable(f"cannot stat {self.path}: {exc}")
            return
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            self._disable(f"{self.path} is not a regular file")
            return
        # A log left group- or world-readable leaks the canary layout.  Best
        # effort: another owner's file stays as it is rather than failing.
        if info.st_mode & 0o077:
            try:
                os.fchmod(fd, LOG_MODE)
            except OSError:
                pass
        self._fd = fd
        self.error = None
        if info.st_size == 0:
            self._header()

    def _header(self) -> None:
        banner = "honeypath" + (f" {self.version}" if self.version else "")
        self._emit(LEVEL_INFO, f"--- {banner} log started (timestamps are UTC) ---")

    def _maybe_rotate(self) -> None:
        """Roll over at ``max_bytes`` into ``honeypath.log.1 .. .N``."""
        if self._fd is None or self.max_bytes <= 0 or self.keep <= 0:
            return
        try:
            if os.fstat(self._fd).st_size < self.max_bytes:
                return
        except OSError:
            return
        name = self.path.name
        try:
            with safe_write.anchored_parent(self.path, self._root()) as (
                parent_fd,
                base,
            ):
                oldest = f"{base}.{self.keep}"
                try:
                    os.unlink(oldest, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                for index in range(self.keep - 1, 0, -1):
                    try:
                        os.replace(
                            f"{base}.{index}",
                            f"{base}.{index + 1}",
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                        )
                    except FileNotFoundError:
                        continue
                os.replace(
                    base, f"{base}.1", src_dir_fd=parent_fd, dst_dir_fd=parent_fd
                )
        except (OSError, safe_write.SafeWriteError) as exc:
            self._disable(f"cannot rotate {name}: {exc}")
            return
        fd, self._fd = self._fd, None
        try:
            os.close(fd)
        except OSError:
            pass
        self._open()

    def _emit(self, level: str, message: str) -> None:
        if self._fd is None:
            return
        line = f"{timestamp()}  {level:<5}  {sanitize(message)}\n".encode(
            "utf-8", errors="replace"
        )
        try:
            os.write(self._fd, line)
        except OSError as exc:
            self._disable(f"write failed: {exc}")

    # -- public API --------------------------------------------------------

    def write(self, level: str, message: str) -> None:
        with self._lock:
            self._maybe_rotate()
            self._emit(level, message)

    def info(self, message: str) -> None:
        self.write(LEVEL_INFO, message)

    def warn(self, message: str) -> None:
        self.write(LEVEL_WARN, message)

    def error_line(self, message: str) -> None:
        self.write(LEVEL_ERROR, message)

    def detection(self, event: dict, *, alerting: bool = True) -> None:
        self.write(
            LEVEL_ALERT if alerting else LEVEL_EVENT,
            format_detection(event, alerting=alerting),
        )

    def delivery(self, event: dict, sent: bool, error: str | None) -> None:
        path = event.get("path") or "-"
        if sent:
            self.write(LEVEL_INFO, f"alert delivered via Pushover for {path}")
        elif error == "pushover not configured":
            self.write(
                LEVEL_WARN, f"alert NOT sent for {path}: Pushover is not configured"
            )
        else:
            self.write(
                LEVEL_ERROR,
                f"alert delivery FAILED for {path}: {error or 'unknown error'}",
            )

    def close(self) -> None:
        with self._lock:
            fd, self._fd = self._fd, None
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def __enter__(self) -> "EventLog":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def format_detection(event: dict, *, alerting: bool = True) -> str:
    """One line describing a detection, in the order an operator scans."""
    bits = [
        (event.get("event_type") or "event").upper(),
        f"severity={event.get('severity') or '-'}",
        f"kind={event.get('kind') or '-'}",
        f"path={event.get('path') or '-'}",
        f"via={event.get('method') or '-'}",
    ]
    process_info = event.get("process_info")
    if process_info:
        bits.append(f"process={process_info}")
    message = event.get("message")
    if message:
        bits.append(f"detail=({message})")
    if not alerting:
        reason = event.get("pushover_error") or "no alert for this event type"
        bits.append(f"[{reason}]")
    return "  ".join(bits)


def open_log(
    path: Path | str | None,
    *,
    version: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep: int = DEFAULT_KEEP,
) -> EventLog | NullEventLog:
    """Open ``path`` for logging, or return a no-op log if it is disabled."""
    if path is None:
        return NullEventLog()
    return EventLog(path, version=version, max_bytes=max_bytes, keep=keep)
