"""Directory-FD-anchored filesystem operations for sensitive paths.

All traversal below an approved root is performed one component at a time with
``O_DIRECTORY | O_NOFOLLOW``.  Once a directory has been checked, its file
descriptor remains the authority for the operation: no validated parent is
looked up again by pathname.

New files are installed from an unnamed ``O_TMPFILE`` inode while its descriptor
is still open.  Linux ``linkat(AT_EMPTY_PATH)`` binds that exact inode to the
destination, so an observer can never substitute a pathname staging file.  A
managed refresh uses ``renameat2(RENAME_EXCHANGE)`` and verifies which old inode
was exchanged; a mismatch is exchanged back and reported as a race.
"""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
import sys
import ctypes
import warnings
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_TMPFILE = getattr(os, "O_TMPFILE", 0)
_AT_EMPTY_PATH = 0x1000
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
TEMP_PREFIX = ".honeypath-tmp-"

_LIBC: ctypes.CDLL | None = None
_LIBC_PROTOTYPES = {
    "renameat2": (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ),
    "renameatx_np": (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ),
    "linkat": (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ),
}


def _libc() -> ctypes.CDLL:
    """One process-wide libc handle with the syscall prototypes declared.

    Without argtypes ctypes guesses each argument's width, which is exactly the
    wrong thing to leave implicit for calls whose correctness decides whether a
    rename replaces a file.  Declaring them once also avoids re-opening libc on
    every safe rename.
    """
    global _LIBC
    if _LIBC is None:
        libc = ctypes.CDLL(None, use_errno=True)
        for name, argtypes in _LIBC_PROTOTYPES.items():
            func = getattr(libc, name, None)
            if func is not None:
                func.argtypes = list(argtypes)
                func.restype = ctypes.c_int
        _LIBC = libc
    return _LIBC


class SafeWriteError(Exception):
    """An operation could not be completed with the required guarantees."""


class InstallHookError(Exception):
    """An ``on_installed`` hook rejected a write that has since been undone.

    Deliberately *not* a :class:`SafeWriteError`: the filesystem did everything
    it was asked to, and callers that turn a ``SafeWriteError`` into "this path
    was refused" must not swallow a caller's own rejection.
    """


class RollbackError(SafeWriteError):
    """A rejected installation could not be undone.

    The destination may now hold content that no caller committed to, so this
    is reported separately from an ordinary refusal and always demands
    operator attention.
    """


def resolve_root(root: Path | str) -> Path:
    """Resolve the approved root itself; descendants are never resolved."""
    return Path(os.path.realpath(str(root)))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _relative_parts(path: Path | str, root: Path | str) -> tuple[Path, tuple[str, ...]]:
    path = Path(path)
    root_written = Path(os.path.abspath(str(root)))
    root_real = resolve_root(root)
    if not path.is_absolute():
        raise SafeWriteError(f"refusing a relative path: {path}")
    if ".." in path.parts:
        raise SafeWriteError(f"refusing a path containing '..': {path}")
    absolute = Path(os.path.abspath(str(path)))
    base = root_real if _is_within(absolute, root_real) else root_written
    try:
        relative = absolute.relative_to(base)
    except ValueError:
        raise SafeWriteError(
            f"refusing {path}: outside the approved root {root_real}"
        ) from None
    parts = relative.parts
    for part in parts:
        if part in ("", ".", "..") or os.path.isabs(part) or "/" in part:
            raise SafeWriteError(f"refusing unsafe path component {part!r} in {path}")
    return root_real, parts


def _open_root(root_real: Path) -> int:
    try:
        return os.open(
            str(root_real), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
        )
    except OSError as exc:
        raise SafeWriteError(
            f"cannot anchor approved root {root_real}: {exc}"
        ) from None


def _open_dir(parent_fd: int, name: str, display: Path) -> int:
    try:
        fd = os.open(
            name,
            os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise SafeWriteError(
                f"refusing {display}: a parent component is a symlink or not a directory"
            ) from None
        raise
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise SafeWriteError(f"refusing {display}: parent is not a directory")
    return fd


@contextmanager
def anchored_parent(path: Path | str, root: Path | str):
    """Yield ``(parent_fd, final_name)`` with every parent FD kept anchored."""
    root_real, parts = _relative_parts(path, root)
    if not parts:
        raise SafeWriteError("the approved root itself is not a file destination")
    fds: list[int] = [_open_root(root_real)]
    try:
        display = root_real
        for part in parts[:-1]:
            display /= part
            fds.append(_open_dir(fds[-1], part, display))
        yield fds[-1], parts[-1]
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def validate_destination(
    path: Path,
    root: Path | str,
    *,
    allow_symlink_destination: bool = False,
) -> Path:
    """Validate containment and all existing parents through anchored FDs."""
    path = Path(path)
    root_real, parts = _relative_parts(path, root)
    fds = [_open_root(root_real)]
    try:
        display = root_real
        for part in parts[:-1]:
            display /= part
            try:
                fds.append(_open_dir(fds[-1], part, display))
            except FileNotFoundError:
                return path
        try:
            info = os.stat(parts[-1], dir_fd=fds[-1], follow_symlinks=False)
        except FileNotFoundError:
            return path
        except OSError as exc:
            raise SafeWriteError(f"cannot inspect {path}: {exc}") from None
        if stat.S_ISLNK(info.st_mode) and not allow_symlink_destination:
            raise SafeWriteError(f"refusing {path}: it is a symlink")
    finally:
        for fd in reversed(fds):
            os.close(fd)
    return path


def stat_nofollow(path: Path, *, root: Path | str) -> os.stat_result:
    with anchored_parent(path, root) as (parent_fd, name):
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def rename_noreplace(source: Path, destination: Path, *, root: Path | str) -> None:
    """Atomically rename within ``root`` while refusing an existing target."""
    with anchored_parent(source, root) as (source_parent, source_name):
        source_info = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        with anchored_parent(destination, root) as (dest_parent, dest_name):
            try:
                os.stat(dest_name, dir_fd=dest_parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(
                    errno.EEXIST, "destination exists", str(destination)
                )
            _renameat_noreplace(source_parent, source_name, dest_parent, dest_name)
            moved = os.stat(dest_name, dir_fd=dest_parent, follow_symlinks=False)
            if (moved.st_dev, moved.st_ino) != (source_info.st_dev, source_info.st_ino):
                raise SafeWriteError("renamed object identity verification failed")
            for fd, label in (
                (source_parent, source.parent),
                (dest_parent, destination.parent),
            ):
                problem = _fsync_fd(fd, str(label))
                if problem:
                    warnings.warn(problem, RuntimeWarning, stacklevel=2)


def _renameat_noreplace(src_fd: int, src: str, dst_fd: int, dst: str) -> None:
    libc = _libc()
    src_b, dst_b = os.fsencode(src), os.fsencode(dst)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            ctypes.c_int(src_fd),
            ctypes.c_char_p(src_b),
            ctypes.c_int(dst_fd),
            ctypes.c_char_p(dst_b),
            ctypes.c_uint(_RENAME_NOREPLACE),
        )
    elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            ctypes.c_int(src_fd),
            ctypes.c_char_p(src_b),
            ctypes.c_int(dst_fd),
            ctypes.c_char_p(dst_b),
            ctypes.c_uint(0x00000004),
        )
    else:
        raise SafeWriteError(
            "this platform cannot guarantee atomic no-replace directory rename"
        )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, "destination exists", dst)
        if error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise SafeWriteError(
                "the filesystem does not support atomic no-replace rename"
            ) from None
        raise OSError(error, os.strerror(error), dst)


def _renameat_exchange(parent_fd: int, first: str, second: str) -> None:
    """Atomically exchange two names in one already-open Linux directory."""
    libc = _libc()
    if not sys.platform.startswith("linux") or not hasattr(libc, "renameat2"):
        raise SafeWriteError("this platform cannot guarantee managed compare-and-swap")
    result = libc.renameat2(
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(os.fsencode(first)),
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(os.fsencode(second)),
        ctypes.c_uint(_RENAME_EXCHANGE),
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise SafeWriteError(
                "the filesystem does not support atomic managed compare-and-swap"
            ) from None
        raise OSError(error, os.strerror(error), second)


def supports_unnamed_temporary() -> bool:
    """True when this kernel can create an inode that has no directory name.

    Only Linux implements ``O_TMPFILE`` plus ``linkat(AT_EMPTY_PATH)``, the pair
    that lets Honeypath install the exact inode it just wrote.  Callers use this
    to decide *in advance* whether the portable creation path is the only one
    available on the host, rather than discovering it from a failed write.
    """
    return bool(_O_TMPFILE) and sys.platform.startswith("linux")


def _open_unnamed_temporary(parent_fd: int, path: Path) -> int:
    """Create an inode with no directory name; fail closed if unsupported."""
    if not supports_unnamed_temporary():
        raise SafeWriteError(
            f"cannot safely install {path}: unnamed temporary files are unsupported"
        )
    try:
        return os.open(
            ".", os.O_RDWR | _O_TMPFILE | _O_CLOEXEC, 0o600, dir_fd=parent_fd
        )
    except OSError as exc:
        if exc.errno in (
            errno.EISDIR,
            errno.EOPNOTSUPP,
            errno.ENOTSUP,
            errno.EINVAL,
            errno.ENOSYS,
            errno.EPERM,
        ):
            raise SafeWriteError(
                f"cannot safely install {path}: this filesystem does not support "
                "identity-preserving O_TMPFILE installation"
            ) from None
        raise


def _link_open_fd_noreplace(fd: int, parent_fd: int, name: str) -> None:
    """Link the exact open unnamed inode, never a re-resolved source name."""
    libc = _libc()
    if not hasattr(libc, "linkat"):
        raise SafeWriteError("linkat(AT_EMPTY_PATH) is unavailable")
    result = libc.linkat(
        ctypes.c_int(fd),
        ctypes.c_char_p(b""),
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(os.fsencode(name)),
        ctypes.c_int(_AT_EMPTY_PATH),
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, "destination exists", name)
        if error in (errno.ENOENT, errno.EPERM) and sys.platform.startswith("linux"):
            # Some kernels/security profiles reject AT_EMPTY_PATH for an
            # unprivileged process.  procfs exposes this process's immutable
            # descriptor as a magic link; following that link still binds the
            # exact open inode and never resolves a user-controlled temp name.
            try:
                os.link(
                    f"/proc/self/fd/{fd}",
                    name,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=True,
                )
                return
            except FileExistsError:
                raise
            except OSError as fallback:
                # A rare OSError carries no errno; os.strerror(None) would
                # raise TypeError and bury the real failure.
                error = fallback.errno if fallback.errno is not None else errno.EIO
        if error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EPERM):
            raise SafeWriteError(
                "the filesystem cannot link an unnamed temporary inode safely"
            ) from None
        raise OSError(error, os.strerror(error), name)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _undo_exchange(
    parent_fd: int,
    stage_name: str,
    name: str,
    installed: os.stat_result,
    exchanged: os.stat_result,
    temp_info: os.stat_result,
    path: Path,
) -> bool:
    """Put the replaced inode back at ``name``.

    Only performed while both names still identify the objects observed
    immediately after the exchange: anything else means a third party is moving
    these entries, and guessing would be worse than stopping.  Returns ``True``
    when the rejected new inode was also removed, so the caller knows the
    staging name no longer needs cleaning up.
    """
    now_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    now_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if not _same_identity(now_final, installed) or not _same_identity(
        now_stage, exchanged
    ):
        raise RollbackError(
            f"FATAL: managed replacement race at {path}; automatic rollback "
            f"cannot identify both exchanged entries"
        )
    _renameat_exchange(parent_fd, stage_name, name)
    restored = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    staged = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if not _same_identity(restored, exchanged) or not _same_identity(staged, installed):
        raise RollbackError(
            f"FATAL: managed replacement rollback identity failed at {path}"
        )
    if _same_identity(staged, temp_info):
        _unlink_if_identity(parent_fd, stage_name, staged)
        return True
    return False


def _stat_optional(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _unlink_if_identity(parent_fd: int, name: str, expected: os.stat_result) -> None:
    """Best available exact-entry cleanup, refusing a detected substitution."""
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _same_identity(current, expected):
        raise SafeWriteError(f"refusing to unlink substituted staging entry {name}")
    os.unlink(name, dir_fd=parent_fd)


def open_regular_nofollow(
    path: Path, *, root: Path | str, flags: int | None = None
) -> int:
    """Open and return a regular file FD anchored below ``root``."""
    with anchored_parent(path, root) as (parent_fd, name):
        try:
            fd = os.open(
                name,
                (os.O_RDONLY if flags is None else flags) | _O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise SafeWriteError(
                    f"refusing to read {path}: it is a symlink"
                ) from None
            raise
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise SafeWriteError(f"refusing to read {path}: it is not a regular file")
    return fd


def open_directory_nofollow(path: Path, *, root: Path | str) -> int:
    """Open a descendant directory itself without following its final name."""
    with anchored_parent(path, root) as (parent_fd, name):
        return _open_dir(parent_fd, name, path)


def read_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def read_bytes_anchored(path: Path, *, root: Path | str) -> bytes:
    fd = open_regular_nofollow(path, root=root)
    try:
        return read_fd(fd)
    finally:
        os.close(fd)


def read_bytes_nofollow(path: Path, *, root: Path | str | None = None) -> bytes:
    """Read a regular file without following its final component.

    Callers handling a sensitive tree should pass its approved ``root``.  The
    compatibility default anchors the containing directory itself.
    """
    return read_bytes_anchored(path, root=root if root is not None else path.parent)


def read_text_nofollow(
    path: Path, *, errors: str = "replace", root: Path | str | None = None
) -> str:
    return read_bytes_nofollow(path, root=root).decode("utf-8", errors=errors)


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def sha256_anchored(path: Path, *, root: Path | str) -> str:
    fd = open_regular_nofollow(path, root=root)
    try:
        return sha256_fd(fd)
    finally:
        os.close(fd)


def unlink_regular_if_hash(
    path: Path,
    *,
    root: Path | str,
    expected_sha256: str,
    expected_dev: int | None = None,
    expected_ino: int | None = None,
) -> None:
    """Unlink only the exact regular directory entry whose opened bytes match."""
    with anchored_parent(path, root) as (parent_fd, name):
        fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or sha256_fd(fd) != expected_sha256:
                raise SafeWriteError(
                    f"refusing to remove modified or non-regular {path}"
                )
            if (
                expected_dev is not None
                and expected_ino is not None
                and (opened.st_dev, opened.st_ino) != (expected_dev, expected_ino)
            ):
                raise SafeWriteError(f"refusing to remove replacement inode at {path}")
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise SafeWriteError(f"refusing to remove {path}: entry changed")
            os.unlink(name, dir_fd=parent_fd)
            problem = _fsync_fd(parent_fd, str(path.parent))
            if problem:
                warnings.warn(problem, RuntimeWarning, stacklevel=2)
        finally:
            os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write to the temporary file")
        view = view[written:]


def _random_temp_name() -> str:
    return f"{TEMP_PREFIX}{secrets.token_hex(16)}"


def _unlink_at_quietly(parent_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def _fsync_fd(fd: int, label: str) -> str | None:
    try:
        os.fsync(fd)
        return None
    except OSError as exc:
        return f"could not fsync {label}: {exc}"


def atomic_write(
    path: Path,
    data: bytes | str,
    *,
    mode: int,
    root: Path | str,
    uid: int | None = None,
    gid: int | None = None,
    fsync_data: bool = False,
    fsync_dir: bool = True,
    best_effort_metadata: bool = True,
    allow_symlink_destination: bool = False,
    replace: bool = True,
    expected_sha256: str | None = None,
    allow_exclusive_create_fallback: bool = False,
    on_installed: Callable[[], None] | None = None,
) -> list[str]:
    """Atomically write below an anchored root.

    The payload has no pathname until ``linkat(AT_EMPTY_PATH)`` installs the
    exact still-open inode.  First creation is a single no-clobber link.
    Replacement exchanges a private staging link with the destination, then
    verifies that the exchanged-out inode is the exact object inspected through
    this parent FD.  If it is not, the exchange is rolled back and the call
    fails.  Filesystems lacking these Linux guarantees are refused unless
    ``allow_exclusive_create_fallback`` is requested for a brand-new,
    reproducible file.  That fallback still uses O_EXCL, O_NOFOLLOW and an
    anchored directory descriptor, so it can never overwrite an existing
    credential; only all-at-once content visibility is relaxed.

    ``on_installed`` runs once the destination name refers to the new inode but
    *before* the replaced one is discarded, with the parent descriptor still
    open.  Raising from it undoes the installation — the previous inode is
    exchanged back, or a first creation is unlinked — and re-raises, which is
    how a caller keeps its own record of the write in step with the filesystem.
    A rollback that cannot itself be completed raises :class:`RollbackError`.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    problems: list[str] = []
    with anchored_parent(path, root) as (parent_fd, name):
        current = _stat_optional(parent_fd, name)
        if current is not None:
            if stat.S_ISLNK(current.st_mode) and not allow_symlink_destination:
                raise SafeWriteError(f"refusing to write {path}: it is a symlink")
            if not stat.S_ISREG(current.st_mode):
                raise SafeWriteError(f"refusing to write {path}: not a regular file")
            if not replace:
                raise FileExistsError(errno.EEXIST, "destination exists", str(path))
        elif expected_sha256 is not None:
            raise SafeWriteError(
                f"refusing managed refresh of {path}: file disappeared"
            )

        try:
            fd = _open_unnamed_temporary(parent_fd, path)
        except SafeWriteError:
            if current is not None or not allow_exclusive_create_fallback:
                raise
            return _exclusive_write_new(
                parent_fd,
                name,
                path,
                data,
                mode=mode,
                uid=uid,
                gid=gid,
                fsync_data=fsync_data,
                fsync_dir=fsync_dir,
                best_effort_metadata=best_effort_metadata,
                on_installed=on_installed,
            )
        stage_name: str | None = None
        check_fd = -1
        try:
            _write_all(fd, data)
            try:
                os.fchmod(fd, mode)
            except OSError as exc:
                if not best_effort_metadata:
                    raise
                problems.append(f"chmod {oct(mode)} {path}: {exc}")
            if uid is not None and gid is not None and os.geteuid() == 0:
                try:
                    os.fchown(fd, uid, gid)
                except OSError as exc:
                    if not best_effort_metadata:
                        raise
                    problems.append(f"chown {uid}:{gid} {path}: {exc}")
            if fsync_data:
                problem = _fsync_fd(fd, str(path))
                if problem:
                    problems.append(problem)

            temp_info = os.fstat(fd)

            if current is not None:
                check_fd = os.open(
                    name, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=parent_fd
                )
                check_stat = os.fstat(check_fd)
                if not stat.S_ISREG(check_stat.st_mode):
                    raise SafeWriteError(f"refusing replacement of {path}: not regular")
                if expected_sha256 is not None:
                    if sha256_fd(check_fd) != expected_sha256:
                        raise SafeWriteError(
                            f"refusing managed refresh of {path}: exact content hash changed"
                        )
                now = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_identity(now, check_stat):
                    raise SafeWriteError(
                        f"refusing replacement of {path}: destination changed during verification"
                    )

            if current is None or not replace:
                try:
                    _link_open_fd_noreplace(fd, parent_fd, name)
                except FileExistsError:
                    raise SafeWriteError(
                        f"refusing to create {path}: destination appeared during installation"
                    ) from None
                installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_identity(installed, temp_info):
                    raise SafeWriteError(
                        f"installed inode identity mismatch for {path}"
                    )
                if on_installed is not None:
                    try:
                        on_installed()
                    except BaseException as rejection:
                        try:
                            _unlink_if_identity(parent_fd, name, temp_info)
                        except (OSError, SafeWriteError) as failure:
                            raise RollbackError(
                                f"FATAL: {path} was created, the creation was rejected "
                                f"({rejection}), and the file could not be removed "
                                f"again: {failure}"
                            ) from rejection
                        raise
            else:
                for _ in range(32):
                    candidate = _random_temp_name()
                    try:
                        _link_open_fd_noreplace(fd, parent_fd, candidate)
                    except FileExistsError:
                        continue
                    stage_name = candidate
                    break
                if stage_name is None:
                    raise SafeWriteError(
                        f"cannot allocate a private staging name for {path}"
                    )

                _renameat_exchange(parent_fd, stage_name, name)
                installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                exchanged = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
                expected_old = os.fstat(check_fd)
                if not _same_identity(installed, temp_info) or not _same_identity(
                    exchanged, expected_old
                ):
                    # The staged or destination name changed after verification.
                    if _undo_exchange(
                        parent_fd,
                        stage_name,
                        name,
                        installed,
                        exchanged,
                        temp_info,
                        Path(path),
                    ):
                        stage_name = None
                    raise SafeWriteError(
                        f"refusing replacement of {path}: destination or staging entry "
                        "changed after verification"
                    )
                if on_installed is not None:
                    # The replaced inode is still staged, so a caller that
                    # cannot commit its own record of this write gets the old
                    # file back rather than an unrecorded new one.
                    try:
                        on_installed()
                    except BaseException as rejection:
                        try:
                            cleared = _undo_exchange(
                                parent_fd,
                                stage_name,
                                name,
                                installed,
                                exchanged,
                                temp_info,
                                Path(path),
                            )
                        except (OSError, SafeWriteError) as failure:
                            # The previous inode is still linked under the
                            # staging name, so name it: that entry is the only
                            # remaining handle on the original file.
                            raise RollbackError(
                                f"FATAL: {path} was replaced, the replacement was "
                                f"rejected ({rejection}), and the previous file could "
                                f"not be put back: {failure}. The original is still "
                                f"linked as {Path(path).parent / stage_name}"
                            ) from rejection
                        if cleared:
                            stage_name = None
                        raise
                _unlink_if_identity(parent_fd, stage_name, exchanged)
                stage_name = None
        finally:
            if check_fd >= 0:
                os.close(check_fd)
            if stage_name:
                # Cleanup is exact when possible.  Never delete a substituted
                # staging entry merely because it reused Honeypath's name.
                try:
                    stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
                    if _same_identity(stage, os.fstat(fd)):
                        os.unlink(stage_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(fd)

        if fsync_dir:
            problem = _fsync_fd(parent_fd, str(Path(path).parent))
            if problem:
                problems.append(problem)
    return problems


def _exclusive_write_new(
    parent_fd: int,
    name: str,
    path: Path,
    data: bytes,
    *,
    mode: int,
    uid: int | None,
    gid: int | None,
    fsync_data: bool,
    fsync_dir: bool,
    best_effort_metadata: bool,
    on_installed: Callable[[], None] | None = None,
) -> list[str]:
    """Descriptor-anchored no-clobber creation for DrvFS-style filesystems."""
    problems: list[str] = []
    try:
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
            mode,
            dir_fd=parent_fd,
        )
    except FileExistsError:
        raise SafeWriteError(
            f"refusing to create {path}: destination appeared during installation"
        ) from None
    created = os.fstat(fd)
    try:
        _write_all(fd, data)
        try:
            os.fchmod(fd, mode)
        except OSError as exc:
            if not best_effort_metadata:
                raise
            problems.append(f"chmod {oct(mode)} {path}: {exc}")
        if uid is not None and gid is not None and os.geteuid() == 0:
            try:
                os.fchown(fd, uid, gid)
            except OSError as exc:
                if not best_effort_metadata:
                    raise
                problems.append(f"chown {uid}:{gid} {path}: {exc}")
        if fsync_data:
            problem = _fsync_fd(fd, str(path))
            if problem:
                problems.append(problem)
        installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(installed, created):
            raise SafeWriteError(f"installed inode identity mismatch for {path}")
    except BaseException:
        try:
            _unlink_if_identity(parent_fd, name, created)
        except (OSError, SafeWriteError):
            pass
        raise
    else:
        if on_installed is not None:
            try:
                on_installed()
            except BaseException as rejection:
                try:
                    _unlink_if_identity(parent_fd, name, created)
                except (OSError, SafeWriteError) as failure:
                    raise RollbackError(
                        f"FATAL: {path} was created, the creation was rejected "
                        f"({rejection}), and the file could not be removed again: "
                        f"{failure}"
                    ) from rejection
                raise
    finally:
        os.close(fd)
    if fsync_dir:
        problem = _fsync_fd(parent_fd, str(path.parent))
        if problem:
            problems.append(problem)
    return problems


def atomic_copy(
    source: Path,
    destination: Path,
    *,
    mode: int,
    root: Path | str,
    source_root: Path | str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    fsync_data: bool = True,
    replace: bool = True,
    expected_sha256: str | None = None,
) -> list[str]:
    data = read_bytes_nofollow(source, root=source_root)
    return atomic_write(
        destination,
        data,
        mode=mode,
        root=root,
        uid=uid,
        gid=gid,
        fsync_data=fsync_data,
        replace=replace,
        expected_sha256=expected_sha256,
    )


def cleanup_stale_temporaries(directory: Path) -> int:
    """Retained compatibility hook; arbitrary prefix matches are never deleted.

    Current writes clean their still-identified staging inode before returning.
    After a crash there is no trustworthy metadata proving that a similarly
    named entry was created by Honeypath rather than by another same-user
    process, so automatic pathname-prefix cleanup must fail closed.
    """
    return 0


def safe_mkdir(
    path: Path,
    root: Path | str,
    *,
    mode: int = 0o700,
    uid: int | None = None,
    gid: int | None = None,
    best_effort_metadata: bool = True,
) -> list[str]:
    """Create a directory chain using mkdirat/openat and descriptor metadata."""
    root_real, parts = _relative_parts(path, root)
    problems: list[str] = []
    fds: list[int] = [_open_root(root_real)]
    try:
        display = root_real
        for part in parts:
            display /= part
            created = False
            try:
                before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            except FileNotFoundError:
                before = None
                try:
                    os.mkdir(part, mode, dir_fd=fds[-1])
                    created = True
                except FileExistsError:
                    pass
            if before is not None and not stat.S_ISDIR(before.st_mode):
                kind = "symlink" if stat.S_ISLNK(before.st_mode) else "non-directory"
                raise SafeWriteError(
                    f"refusing to create {path}: {display} is a {kind}"
                )
            child = _open_dir(fds[-1], part, display)
            fds.append(child)
            if created:
                # Metadata is applied to the inode we actually opened, even if
                # its directory entry is renamed immediately afterward.
                try:
                    os.fchmod(child, mode)
                except OSError as exc:
                    if not best_effort_metadata:
                        raise
                    problems.append(f"chmod {oct(mode)} {display}: {exc}")
                if uid is not None and gid is not None and os.geteuid() == 0:
                    try:
                        os.fchown(child, uid, gid)
                    except OSError as exc:
                        if not best_effort_metadata:
                            raise
                        problems.append(f"chown {uid}:{gid} {display}: {exc}")
                now = os.stat(part, dir_fd=fds[-2], follow_symlinks=False)
                opened = os.fstat(child)
                if (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino):
                    raise SafeWriteError(
                        f"refusing {display}: directory changed after mkdir"
                    )
                problem = _fsync_fd(fds[-2], str(display.parent))
                if problem:
                    problems.append(problem)
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
    return problems


def create_directory_exclusive(
    path: Path,
    *,
    root: Path | str,
    mode: int,
    uid: int | None = None,
    gid: int | None = None,
    best_effort_metadata: bool = False,
) -> os.stat_result:
    """Create exactly one directory and return its verified inode metadata."""
    with anchored_parent(path, root) as (parent_fd, name):
        os.mkdir(name, mode, dir_fd=parent_fd)
        fd = -1
        identity: os.stat_result | None = None
        try:
            fd = _open_dir(parent_fd, name, path)
            identity = os.fstat(fd)
            try:
                os.fchmod(fd, mode)
            except OSError:
                if not best_effort_metadata:
                    raise
            if uid is not None and gid is not None and os.geteuid() == 0:
                try:
                    os.fchown(fd, uid, gid)
                except OSError:
                    if not best_effort_metadata:
                        raise
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise SafeWriteError(f"refusing {path}: directory changed after mkdir")
            problem = _fsync_fd(parent_fd, str(path.parent))
            if problem:
                raise SafeWriteError(problem)
            return os.fstat(fd)
        except BaseException:
            if identity is not None:
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (
                        identity.st_dev,
                        identity.st_ino,
                    ):
                        os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)


def remove_tree_if_identity(
    path: Path, *, root: Path | str, expected_dev: int, expected_ino: int
) -> None:
    """Remove an anchored tree only if its root is the exact expected inode."""
    with anchored_parent(path, root) as (parent_fd, name):
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (
            expected_dev,
            expected_ino,
        ):
            raise SafeWriteError(
                f"refusing to remove {path}: replacement inode detected"
            )
        fd = _open_dir(parent_fd, name, path)
        try:
            _remove_open_tree(fd)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=parent_fd)
        problem = _fsync_fd(parent_fd, str(path.parent))
        if problem:
            warnings.warn(problem, RuntimeWarning, stacklevel=2)


def _remove_open_tree(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = _open_dir(directory_fd, name, Path(name))
            try:
                _remove_open_tree(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)
