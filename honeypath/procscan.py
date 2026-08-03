"""Best-effort reader attribution for Linux canaries.

inotify says that a canary was read.  It never says by whom, and that is the
single most useful fact about a detection: ``bztransmit.exe walked your
profile`` and ``something is harvesting your credentials`` produce identical
inotify lines.

The kernel will answer, but only while the reader still holds the descriptor
open, so this module races the reader's ``close()``: on an OPEN event it walks
``/proc`` looking for a file descriptor pointing at the canary's inode.  A
reader that opens, reads and closes in a few microseconds wins that race, so
attribution is a bonus and never a guarantee — an unattributed read is still a
read, and is still alerted on exactly as before.

Honeypath runs unprivileged by design (see ``systemd/honeypath.service``),
which means the scan only sees processes owned by the same user.  That is
precisely the threat model that matters for a credential canary: malware
running as you, reading your secrets, needs no privilege at all.  Anything
running as another user is invisible here — the Windows SACL watcher is what
covers the equivalent gap on the Windows side.

Nothing in here can block, follow a symlink into somewhere it should not go, or
touch the canary's own atime: it stats descriptors under ``/proc``, never the
canary path itself.
"""

from __future__ import annotations

import os
import stat as stat_mod

PROC_ROOT = "/proc"

# One line per reader in an alert body, so a sweep that names every process on
# the box would push the message past Pushover's limit for no added meaning.
MAX_READERS = 4


def _comm(pid: str) -> str:
    """The process name, or a placeholder if it exited mid-scan."""
    try:
        with open(f"{PROC_ROOT}/{pid}/comm", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip() or "?"
    except OSError:
        return "?"


def _identity(path: str) -> tuple[int, int] | None:
    """The canary's (dev, ino), or None if it is not a regular file.

    ``lstat`` rather than ``stat``: if the canary has been swapped for a
    symlink, the symlink's own inode matches no descriptor and attribution
    simply comes back empty.  Following it would be the one way this module
    could be turned into a probe of somewhere else on the filesystem.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat_mod.S_ISREG(info.st_mode):
        return None
    return (info.st_dev, info.st_ino)


def readers_of(
    path: str,
    *,
    identity: tuple[int, int] | None = None,
    exclude_pids: tuple[int, ...] = (),
    proc_root: str = PROC_ROOT,
) -> list[str]:
    """Processes currently holding *path* open, as ``name pid=N`` strings.

    Returns an empty list whenever the answer is not knowable — the reader
    already closed, the process belongs to another user, ``/proc`` is not
    mounted.  Never raises: attribution failing must not cost a detection.
    """
    target = identity if identity is not None else _identity(path)
    if target is None:
        return []
    excluded = {str(pid) for pid in exclude_pids}
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return []

    found: list[str] = []
    for pid in entries:
        if not pid.isdigit() or pid in excluded:
            continue
        fd_dir = f"{proc_root}/{pid}/fd"
        try:
            descriptors = os.listdir(fd_dir)
        except OSError:
            # Not ours to inspect, or the process exited between listdir and
            # here.  Both are ordinary; neither is worth reporting.
            continue
        for descriptor in descriptors:
            try:
                info = os.stat(f"{fd_dir}/{descriptor}")
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == target:
                found.append(f"{_comm(pid)} pid={pid}")
                break
        if len(found) >= MAX_READERS:
            break
    return found


def describe_readers(
    path: str,
    *,
    exclude_pids: tuple[int, ...] = (),
    proc_root: str = PROC_ROOT,
) -> str | None:
    """``readers_of`` formatted for ``events.process_info``, or None."""
    readers = readers_of(path, exclude_pids=exclude_pids, proc_root=proc_root)
    if not readers:
        return None
    return ", ".join(readers)
