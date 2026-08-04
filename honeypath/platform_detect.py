"""Platform detection.

Deliberately named ``platform_detect`` rather than ``platform`` so it cannot
shadow the standard library module for anything importing it.

Also hosts the low-level WSL-interop runner, because "can we shell out to
Windows?" is a platform fact.  Everything here degrades gracefully: interop
being disabled is a normal condition, never a crash.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .target_user import TargetUserContext

OS_LINUX = "linux"
OS_WSL = "wsl"
OS_MACOS = "macos"
OS_UNKNOWN = "unknown"

# Drives scanned for a Windows user profile directory, in order.
WINDOWS_DRIVE_ROOTS = ("/mnt/c", "/mnt/d", "/mnt/e")

# Directories under X:\Users that are never a real user's profile.
_NON_USER_PROFILE_DIRS = {
    "all users",
    "default",
    "default user",
    "public",
    "defaultapppool",
    "wsiaccount",
    "desktop.ini",
}

INTEROP_TIMEOUT = 20


@dataclass
class PlatformContext:
    os_name: str
    home: Path
    windows_homes: list[Path] = field(default_factory=list)
    default_profiles: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_wsl(self) -> bool:
        return self.os_name == OS_WSL

    @property
    def windows_home(self) -> Path | None:
        return self.windows_homes[0] if self.windows_homes else None


# --------------------------------------------------------------------------
# WSL / OS detection
# --------------------------------------------------------------------------


def wsl_signals(environ: dict | None = None) -> list[str]:
    """Return the WSL indicators found on this system.  Any one is enough."""
    env = os.environ if environ is None else environ
    signals: list[str] = []

    for var in ("WSL_DISTRO_NAME", "WSL_INTEROP", "WSLENV"):
        if env.get(var):
            signals.append(f"env:{var}")

    for probe in (Path("/proc/version"), Path("/proc/sys/kernel/osrelease")):
        try:
            text = probe.read_text(errors="replace").lower()
        except OSError:
            continue
        if "microsoft" in text or "wsl" in text:
            signals.append(f"file:{probe}")

    return signals


def _parent_pid(pid: int) -> int | None:
    """The parent of ``pid`` from procfs, tolerating parens in the comm field."""
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    try:
        fields = stat_text[stat_text.rindex(")") + 1 :].split()
        return int(fields[1])
    except (ValueError, IndexError):
        return None


def wsl_distro_name(environ: dict | None = None) -> str | None:
    """This distribution's name, spelled the way ``wsl.exe -d`` expects it.

    ``sudo`` clears ``WSL_DISTRO_NAME``, and every privileged Honeypath command
    runs under ``sudo`` — so fall back to walking up the process tree, where the
    invoking login shell still carries it.
    """
    env = os.environ if environ is None else environ
    name = env.get("WSL_DISTRO_NAME")
    if name:
        return name

    pid: int | None = os.getppid()
    seen: set[int] = set()
    while pid and pid > 1 and pid not in seen:
        seen.add(pid)
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError:
            return None
        for entry in raw.split(b"\0"):
            key, _, value = entry.partition(b"=")
            if key == b"WSL_DISTRO_NAME" and value:
                return value.decode("utf-8", errors="replace")
        pid = _parent_pid(pid)
    return None


def detect_os_name(environ: dict | None = None) -> str:
    if wsl_signals(environ):
        return OS_WSL
    uname = os.uname()
    sysname = uname.sysname.lower()
    if sysname == "darwin":
        return OS_MACOS
    if sysname == "linux":
        return OS_LINUX
    return OS_UNKNOWN


# --------------------------------------------------------------------------
# WSL interop
# --------------------------------------------------------------------------


@dataclass
class InteropResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    returncode: int | None = None


# Windows executables are frequently absent from PATH — WSL only appends the
# Windows PATH for interactive shells, and appendWindowsPath can be off — so
# resolve them by hand before giving up.
_WINDOWS_EXE_DIRS = (
    "/mnt/c/Windows/System32",
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0",
    "/mnt/c/Windows",
    "/mnt/c/Windows/SysWOW64",
)


def resolve_windows_exe(name: str) -> str | None:
    """Find a Windows executable, on PATH or in the usual System32 locations."""
    if not name.lower().endswith(".exe"):
        return name
    found = shutil.which(name)
    if found:
        return found
    for directory in _WINDOWS_EXE_DIRS:
        candidate = Path(directory) / name
        if candidate.exists():
            return str(candidate)
    return None


def interop_available() -> bool:
    """True when Windows executables can plausibly be launched from WSL."""
    if detect_os_name() != OS_WSL:
        return False
    return (
        resolve_windows_exe("powershell.exe") is not None
        or resolve_windows_exe("cmd.exe") is not None
    )


def run_interop(
    args: list[str],
    *,
    timeout: int = INTEROP_TIMEOUT,
    input_text: str | None = None,
) -> InteropResult:
    """Run a Windows-side command, tolerating interop being unavailable."""
    args = list(args)
    resolved = resolve_windows_exe(args[0])
    if resolved is None:
        return InteropResult(ok=False, error=f"not found: {args[0]}")
    args[0] = resolved
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except FileNotFoundError:
        return InteropResult(ok=False, error=f"not found: {args[0]}")
    except PermissionError as exc:
        return InteropResult(
            ok=False, error=f"permission denied running {args[0]}: {exc}"
        )
    except subprocess.TimeoutExpired:
        return InteropResult(ok=False, error=f"timed out after {timeout}s: {args[0]}")
    except OSError as exc:
        # ENOEXEC / "Exec format error" is what a disabled interop looks like.
        return InteropResult(ok=False, error=f"interop unavailable ({exc})")
    return InteropResult(
        ok=proc.returncode == 0,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )


def run_powershell(script: str, *, timeout: int = INTEROP_TIMEOUT) -> InteropResult:
    """Run a PowerShell snippet through interop."""
    return run_interop(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def windows_username() -> str | None:
    """Detect the Windows username via interop, or None if unavailable."""
    result = run_interop(["cmd.exe", "/c", "echo %USERNAME%"], timeout=10)
    if result.ok:
        name = (
            result.stdout.strip().splitlines()[-1].strip()
            if result.stdout.strip()
            else ""
        )
        if name and name != "%USERNAME%":
            return name
    result = run_powershell("[Environment]::UserName", timeout=10)
    if result.ok and result.stdout.strip():
        return result.stdout.strip().splitlines()[-1].strip()
    return None


def to_windows_path(path: Path) -> str | None:
    """Convert a WSL path to a Windows path using wslpath."""
    result = run_interop(["wslpath", "-w", str(path)], timeout=10)
    if result.ok and result.stdout.strip():
        return result.stdout.strip()
    return None


# --------------------------------------------------------------------------
# Windows home detection
# --------------------------------------------------------------------------


def _candidate_windows_homes(roots=WINDOWS_DRIVE_ROOTS) -> list[Path]:
    candidates: list[Path] = []
    for root in roots:
        users_dir = Path(root) / "Users"
        try:
            if not users_dir.is_dir():
                continue
            entries = sorted(users_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.name.lower() in _NON_USER_PROFILE_DIRS:
                continue
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            candidates.append(entry)
    return candidates


def detect_windows_homes(
    explicit: Path | None = None,
    *,
    roots=WINDOWS_DRIVE_ROOTS,
    probe_username: bool = True,
) -> tuple[list[Path], list[str]]:
    """Find plausible Windows user profile directories.

    Returns ``(homes, notes)``.  When the Windows username is detectable, the
    matching profile is moved to the front so a single obvious answer wins.
    """
    notes: list[str] = []

    if explicit is not None:
        if explicit.is_dir():
            return [explicit], [f"Windows home supplied explicitly: {explicit}"]
        notes.append(f"--windows-home {explicit} does not exist or is not a directory")
        return [], notes

    candidates = _candidate_windows_homes(roots)
    if not candidates:
        notes.append(
            "no Windows user profile directories found under /mnt/{c,d,e}/Users"
        )
        return [], notes

    # A live profile has a registry hive; a stray D:\Users\name usually does not.
    with_hive = [p for p in candidates if (p / "NTUSER.DAT").exists()]
    if with_hive and len(with_hive) < len(candidates):
        dropped = [p for p in candidates if p not in with_hive]
        notes.append(
            "ignoring directories without an NTUSER.DAT registry hive: "
            + ", ".join(str(p) for p in dropped)
        )
        candidates = with_hive

    winuser = windows_username() if probe_username else None
    if winuser:
        notes.append(f"Windows username detected via interop: {winuser}")
        matches = [p for p in candidates if p.name.lower() == winuser.lower()]
        others = [p for p in candidates if p.name.lower() != winuser.lower()]
        candidates = matches + others
    else:
        notes.append(
            "Windows username not detectable (interop disabled or unavailable)"
        )

    if len(candidates) > 1:
        notes.append(
            "multiple candidate Windows homes: " + ", ".join(str(p) for p in candidates)
        )
    return candidates, notes


# --------------------------------------------------------------------------
# Filesystem facts (used by `doctor` for the per-volume report)
# --------------------------------------------------------------------------


@dataclass
class MountInfo:
    mountpoint: str
    fstype: str
    options: list[str]

    @property
    def atime_policy(self) -> str:
        for opt in ("noatime", "strictatime", "relatime", "nodiratime", "lazytime"):
            if opt in self.options:
                return opt
        return "unspecified (kernel default, usually relatime)"


def read_mounts() -> list[MountInfo]:
    mounts: list[MountInfo] = []
    try:
        text = Path("/proc/mounts").read_text(errors="replace")
    except OSError:
        return mounts
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mounts.append(
            MountInfo(
                mountpoint=parts[1].replace("\\040", " "),
                fstype=parts[2],
                options=parts[3].split(","),
            )
        )
    return mounts


def mount_for(path: Path, mounts: list[MountInfo] | None = None) -> MountInfo | None:
    """Return the most specific mount containing ``path``."""
    if mounts is None:
        mounts = read_mounts()
    try:
        target = str(path.resolve())
    except OSError:
        target = str(path)
    best: MountInfo | None = None
    for mount in mounts:
        mp = mount.mountpoint
        if target == mp or target.startswith(mp.rstrip("/") + "/") or mp == "/":
            if best is None or len(mp) > len(best.mountpoint):
                best = mount
    return best


def is_windows_filesystem(mount: MountInfo | None) -> bool:
    return bool(
        mount and mount.fstype in {"9p", "drvfs", "virtiofs", "cifs", "ntfs", "ntfs3"}
    )


def inotifywait_path() -> str | None:
    return shutil.which("inotifywait")


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


def default_profiles_for(
    os_name: str,
    *,
    has_windows_home: bool,
    include_crypto: bool = False,
) -> list[str]:
    """Expand ``--profiles auto`` for a platform."""
    profiles: list[str] = []
    if os_name == OS_MACOS:
        profiles = ["macos-developer", "macos-supply-chain"]
        if include_crypto:
            profiles.append("macos-crypto")
        return profiles

    # linux, wsl and unknown all get the Linux set as the base.
    profiles = ["linux-developer", "linux-supply-chain"]
    if os_name == OS_WSL and has_windows_home:
        profiles += ["wsl-windows-developer", "wsl-windows-supply-chain"]
    if include_crypto:
        profiles.append("linux-crypto")
        if os_name == OS_WSL and has_windows_home:
            profiles.append("wsl-windows-crypto")
    return profiles


def detect_platform_context(
    target: TargetUserContext,
    *,
    windows_home: Path | None = None,
    include_crypto: bool = False,
    probe_windows: bool = True,
) -> PlatformContext:
    """Build the full platform picture for the target user."""
    os_name = detect_os_name()
    notes: list[str] = []

    signals = wsl_signals()
    if signals:
        notes.append("WSL signals: " + ", ".join(signals))

    windows_homes: list[Path] = []
    if os_name == OS_WSL:
        if probe_windows or windows_home is not None:
            windows_homes, win_notes = detect_windows_homes(
                windows_home, probe_username=probe_windows
            )
            notes.extend(win_notes)
    elif windows_home is not None:
        notes.append("--windows-home ignored: not running under WSL")

    if os_name == OS_UNKNOWN:
        notes.append(
            "WARNING: unrecognised platform; falling back to generic Linux canaries"
        )

    profiles = default_profiles_for(
        os_name,
        has_windows_home=bool(windows_homes),
        include_crypto=include_crypto,
    )

    return PlatformContext(
        os_name=os_name,
        home=target.home,
        windows_homes=windows_homes,
        default_profiles=profiles,
        notes=notes,
    )


def fsutil_disablelastaccess() -> tuple[str | None, str | None]:
    """Query NTFS last-access-time policy.  Returns (value, error)."""
    result = run_interop(
        ["fsutil.exe", "behavior", "query", "disablelastaccess"], timeout=15
    )
    if not result.ok:
        detail = result.error or result.stderr.strip() or "command failed"
        return None, detail
    text = result.stdout.strip()
    match = re.search(r"=\s*(\d+)", text)
    if match:
        codes = {
            "0": "0 (User Managed, Last Access Updates Enabled)",
            "1": "1 (User Managed, Last Access Updates Disabled)",
            "2": "2 (System Managed, Last Access Updates Enabled)",
            "3": "3 (System Managed, Last Access Updates Disabled)",
        }
        return codes.get(match.group(1), match.group(1)), None
    return text or None, None
