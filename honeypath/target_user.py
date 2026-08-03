"""Target-user resolution.

Every Honeypath command operates on behalf of a *target user*, not on behalf
of whoever happens to be running the process.  Running

    sudo python3 honeypath.py create-canaries

must plant canaries in /home/alan, owned by alan — never in /root, never
owned by root.  This module is the single source of truth for that decision,
and for the ownership/mode rules that follow from it.
"""

from __future__ import annotations

import grp
import os
import pwd
from dataclasses import dataclass
from pathlib import Path

# Modes applied to everything Honeypath creates under the target home.
MODE_DIR_PRIVATE = 0o700
MODE_FILE_PRIVATE = 0o600
MODE_FILE_PUBLIC = 0o644
MODE_EXEC = 0o755


class TargetUserError(Exception):
    """Raised when the target user cannot be resolved or is not permitted."""


@dataclass
class TargetUserContext:
    """The user whose home directory Honeypath acts on."""

    username: str
    uid: int
    gid: int
    home: Path

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def describe(self) -> str:
        return f"{self.username} (uid={self.uid} gid={self.gid}) home={self.home}"


def _context_for_username(username: str) -> TargetUserContext:
    try:
        entry = pwd.getpwnam(username)
    except KeyError as exc:  # pragma: no cover - depends on host passwd db
        raise TargetUserError(f"no such user: {username}") from exc
    return TargetUserContext(
        username=entry.pw_name,
        uid=entry.pw_uid,
        gid=entry.pw_gid,
        home=Path(entry.pw_dir),
    )


def _context_for_uid(uid: int) -> TargetUserContext:
    try:
        entry = pwd.getpwuid(uid)
    except KeyError as exc:  # pragma: no cover - depends on host passwd db
        raise TargetUserError(f"no passwd entry for uid {uid}") from exc
    return TargetUserContext(
        username=entry.pw_name,
        uid=entry.pw_uid,
        gid=entry.pw_gid,
        home=Path(entry.pw_dir),
    )


def resolve_target_user(
    explicit_user: str | None = None,
    *,
    allow_root: bool = False,
    environ: dict | None = None,
) -> TargetUserContext:
    """Resolve the target user.

    Resolution order:
      1. ``--user`` (``explicit_user``)
      2. ``SUDO_USER`` when present and not root
      3. the current effective user

    Operating on root's home is refused unless ``allow_root`` is set, because
    planting canaries in /root under sudo is almost always a mistake.
    """
    env = os.environ if environ is None else environ

    if explicit_user:
        ctx = _context_for_username(explicit_user)
        source = "--user"
    else:
        sudo_user = (env.get("SUDO_USER") or "").strip()
        if sudo_user and sudo_user != "root":
            ctx = _context_for_username(sudo_user)
            source = "SUDO_USER"
        else:
            ctx = _context_for_uid(os.geteuid())
            source = "effective user"

    if (ctx.is_root or ctx.home == Path("/root")) and not allow_root:
        raise TargetUserError(
            f"refusing to operate on root's home ({ctx.home}) resolved via {source}.\n"
            "Pass --user <name> to select a real user, or --allow-root to override."
        )
    return ctx


def group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:  # pragma: no cover - depends on host group db
        return str(gid)


def can_change_ownership() -> bool:
    """True when this process can chown files to arbitrary users."""
    return os.geteuid() == 0


def apply_ownership(
    path: Path,
    target: TargetUserContext,
    *,
    mode: int | None = None,
    best_effort: bool = False,
) -> list[str]:
    """chown/chmod ``path`` for the target user.

    Returns a list of human-readable problems.  On DrvFS (/mnt/c) chown and
    chmod frequently fail; with ``best_effort`` those failures are reported
    but never raised.
    """
    problems: list[str] = []
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError as exc:
            msg = f"chmod {oct(mode)} {path}: {exc}"
            if not best_effort:
                raise
            problems.append(msg)
    if can_change_ownership():
        try:
            os.chown(path, target.uid, target.gid)
        except OSError as exc:
            msg = f"chown {target.username} {path}: {exc}"
            if not best_effort:
                raise
            problems.append(msg)
    return problems


def ensure_directory(
    path: Path,
    target: TargetUserContext,
    *,
    mode: int = MODE_DIR_PRIVATE,
    best_effort: bool = False,
) -> list[str]:
    """Create ``path`` (and missing parents) owned by the target user."""
    problems: list[str] = []
    missing: list[Path] = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    path.mkdir(parents=True, exist_ok=True)
    for created in reversed(missing):
        problems.extend(
            apply_ownership(created, target, mode=mode, best_effort=best_effort)
        )
    return problems
