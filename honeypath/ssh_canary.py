"""SSH canarying: relocate the real client state, canary ``~/.ssh``.

No part of OpenSSH is modified, patched or recompiled.  The whole mechanism
is two standard features: ``ssh -F <file>`` and a wrapper script earlier in
PATH.

Three OpenSSH facts shape the design of the relocated config:

1. ``ssh -F file`` makes the system-wide ``/etc/ssh/ssh_config`` be ignored,
   so Honeypath re-includes it at the very end.
2. Relative ``Include`` paths in a *user* config resolve against ``~/.ssh``
   no matter where the config file itself lives.  A naively relocated config
   would therefore keep loading files out of the canary directory; relative
   includes are rewritten to absolute relocated paths.
3. Most options are first-match-wins, but ``IdentityFile`` and
   ``CertificateFile`` accumulate.  The Honeypath block is appended *after*
   the user's content so their ``Host`` entries keep winning.

Credential boundary: this module copies SSH files as opaque bytes and hashes
them locally for drift detection.  It never parses, prints, logs or transmits
private-key contents.  The SSH *config* is the sole exception, parsed only to
rewrite paths.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import safe_write
from .catalog import (
    PLATFORM_LINUX,
    create_canary_file,
    managed_marker,
    sha256_file,
    sha256_text,
    ssh_entries,
)
from .database import Database, utc_now
from .target_user import (
    MODE_DIR_PRIVATE,
    MODE_EXEC,
    MODE_FILE_PRIVATE,
    TargetUserContext,
    apply_ownership,
    ensure_directory,
)

RELOCATED_REL = ".local/share/honeypath/real-ssh"
# How many parents up from the relocated directory the home directory sits.
# Derived rather than written as a literal 3, so that changing RELOCATED_REL
# cannot silently leave the anchor pointing partway down the path.
_RELOCATED_HOME_PARENT = len(Path(RELOCATED_REL).parts) - 1
BACKUP_ROOT_REL = ".local/share/honeypath/backups"
WRAPPER_DIR_REL = "bin"

SSH_BINARIES = {
    "ssh": "/usr/bin/ssh",
    "scp": "/usr/bin/scp",
    "sftp": "/usr/bin/sftp",
}

WRAPPER_MARKER = "# Honeypath-managed SSH wrapper."

MANAGED_BEGIN = "# BEGIN HONEYPATH MANAGED SSH CONFIG"
MANAGED_END = "# END HONEYPATH MANAGED SSH CONFIG"
RC_BEGIN = "# BEGIN HONEYPATH MANAGED PATH"
RC_END = "# END HONEYPATH MANAGED PATH"

CHANGE_WRAPPER = "ssh-wrapper"
CHANGE_RC_BLOCK = "rc-path-block"
CHANGE_GIT_SSH = "git-core-sshcommand"

PHASE_PREPARED = "prepared"
PHASE_ACTIVATED = "activated"
PHASE_RESTORED = "restored"

SYSTEM_SSH_CONFIG = Path("/etc/ssh/ssh_config")
SSH_BINARY = "/usr/bin/ssh"


def resolve_ssh_binary(name: str = "ssh", *, exclude: Path | None = None) -> str:
    """Locate the real ``ssh``/``scp``/``sftp`` on PATH.

    The wrapper has to exec the genuine binary, and /usr/bin is only where it
    usually lives — on Nix, Homebrew or a locally built OpenSSH it is not there
    at all, and a wrapper pointing at a missing path breaks ssh outright.
    ``exclude`` keeps Honeypath's own wrapper directory out of the search, so a
    wrapper can never end up calling itself.
    """
    search = [
        directory
        for directory in os.environ.get("PATH", os.defpath).split(os.pathsep)
        if directory and (exclude is None or Path(directory) != exclude)
    ]
    found = shutil.which(name, path=os.pathsep.join(search))
    return found or SSH_BINARIES.get(name, SSH_BINARY)

# Directives whose arguments are paths that must follow the relocation.
REWRITE_DIRECTIVES = {
    "include",
    "identityfile",
    "certificatefile",
    "userknownhostsfile",
    "globalknownhostsfile",
    "controlpath",
    "identityagent",
    "knownhostscommand",
    "revokedhostkeys",
    "securitykeyprovider",
    "pkcs11provider",
}

# Directives containing shell text.  Honeypath never regex-rewrites shell;
# a reference to .ssh in one of these blocks activation until the user fixes
# it by hand.
SHELL_DIRECTIVES = {"proxycommand", "localcommand"}

# `ssh -G` keys whose values are expected to change under relocation.
_EXPECTED_DIFF_KEYS = {
    "identityfile",
    "certificatefile",
    "userknownhostsfile",
    "globalknownhostsfile",
    "controlpath",
    "identityagent",
    "knownhostscommand",
    "revokedhostkeys",
    "securitykeyprovider",
    "pkcs11provider",
    "identitiesonly",
    "forwardagent",
    # Honeypath sets this deliberately; see build_managed_block.
    "updatehostkeys",
}

_DIRECTIVE_RE = re.compile(r"^(\s*)([A-Za-z][A-Za-z0-9_-]*)([=\s]+)(.*)$")
_TOKEN_RE = re.compile(r'"[^"]*"|\S+')


class SSHCanaryError(Exception):
    pass


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def relocated_dir(home: Path) -> Path:
    return home / RELOCATED_REL


def relocated_config(home: Path) -> Path:
    return relocated_dir(home) / "config"


def backup_root(home: Path) -> Path:
    return home / BACKUP_ROOT_REL


def wrapper_dir(home: Path) -> Path:
    return home / WRAPPER_DIR_REL


def relocated_tilde() -> str:
    return "~/" + RELOCATED_REL


def wrapper_content(binary: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        f"{WRAPPER_MARKER}\n"
        "# Runs the stock OpenSSH client against Honeypath's relocated config.\n"
        f'exec {binary} -F "$HOME/{RELOCATED_REL}/config" "$@"\n'
    )


def is_honeypath_wrapper(path: Path) -> bool:
    try:
        return WRAPPER_MARKER in safe_write.read_text_nofollow(
            path, root=path.parent.parent, errors="replace"
        )
    except (OSError, safe_write.SafeWriteError):
        return False


def timestamp_slug() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def run_as_target(argv, target: TargetUserContext, **kwargs):
    """Run a command as the target user (dropping privileges when root)."""
    env = dict(os.environ)
    env["HOME"] = str(target.home)
    env["USER"] = target.username
    env["LOGNAME"] = target.username
    env.pop("SUDO_USER", None)
    extra = {}
    if os.geteuid() == 0 and target.uid != 0:
        extra = {"user": target.uid, "group": target.gid}
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        env=env,
        check=False,
        cwd=str(target.home) if target.home.is_dir() else None,
        **extra,
        **kwargs,
    )


# --------------------------------------------------------------------------
# Source inventory (§8.2)
# --------------------------------------------------------------------------


@dataclass
class InventoryEntry:
    relative: str
    mode: int
    size: int
    sha256: str
    content: bytes = field(repr=False, default=b"")


@dataclass
class Inventory:
    entries: dict[str, InventoryEntry] = field(default_factory=dict)
    refused: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)

    def hashes(self) -> dict[str, str]:
        return {rel: entry.sha256 for rel, entry in self.entries.items()}


def inventory_ssh_dir(source: Path) -> Inventory:
    """Inventory ``~/.ssh`` without following symlinks out of the tree.

    Sockets, devices and FIFOs are refused outright: copying an agent socket
    or a device node is never what the user wants, and following a symlink
    out of the tree would drag unrelated files into the relocated directory.

    Symlinks are always refused: the migration reads through anchored
    descriptors and has no mode in which it follows one.
    """
    inventory = Inventory()
    try:
        root_fd = safe_write.open_directory_nofollow(source, root=source.parent)
    except (OSError, safe_write.SafeWriteError):
        return inventory

    def walk(directory_fd: int, prefix: str = "") -> None:
        for name in sorted(os.listdir(directory_fd)):
            rel = f"{prefix}/{name}" if prefix else name
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                inventory.refused.append(f"{rel} (unreadable: {exc})")
                continue
            if stat.S_ISLNK(info.st_mode):
                inventory.refused.append(
                    f"{rel} (symlink; anchored migration never follows it)"
                )
                continue
            if stat.S_ISDIR(info.st_mode):
                inventory.directories.append(rel)
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    inventory.refused.append(f"{rel} (unreadable directory: {exc})")
                    continue
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        inventory.refused.append(
                            f"{rel} (directory changed during inventory)"
                        )
                        continue
                    walk(child, rel)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                kind = (
                    "socket"
                    if stat.S_ISSOCK(info.st_mode)
                    else (
                        "fifo"
                        if stat.S_ISFIFO(info.st_mode)
                        else (
                            "device"
                            if stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode)
                            else "special file"
                        )
                    )
                )
                inventory.refused.append(f"{rel} ({kind}; not copied)")
                continue
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(fd)
                    if not stat.S_ISREG(opened.st_mode) or (
                        opened.st_dev,
                        opened.st_ino,
                    ) != (info.st_dev, info.st_ino):
                        raise SSHCanaryError("file changed during inventory")
                    content = safe_write.read_fd(fd)
                finally:
                    os.close(fd)
            except (OSError, SSHCanaryError) as exc:
                inventory.refused.append(f"{rel} (unreadable: {exc})")
                continue
            digest = sha256_text_bytes(content)
            inventory.entries[rel] = InventoryEntry(
                relative=rel,
                mode=stat.S_IMODE(opened.st_mode),
                size=len(content),
                sha256=digest,
                content=content,
            )

    try:
        walk(root_fd)
    finally:
        os.close(root_fd)
    return inventory


def sha256_text_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# The relocated `config` is *generated* by the rewriter, never copied. Copying
# it would put an un-rewritten config at the destination path, which the
# hand-edit guard in prepare_relocated_config would then preserve verbatim —
# silently defeating every path rewrite.
# ``config`` is generated.  authorized_keys* are sshd server-side state and
# are restored separately; the client wrappers neither need nor use them.
AUTHORIZED_KEYS_FILES = ("authorized_keys", "authorized_keys2")
GENERATED_FILES = frozenset({"config", *AUTHORIZED_KEYS_FILES})


@dataclass
class CopyPlan:
    to_copy: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    generated: list[str] = field(default_factory=list)
    expected_hashes: dict[str, str] = field(default_factory=dict)


def plan_copy(
    inventory: Inventory,
    destination: Path,
    *,
    previous_hashes: dict[str, str] | None = None,
    root: Path | str | None = None,
) -> CopyPlan:
    """Decide what to copy, and where a destination file would be clobbered."""
    plan = CopyPlan(refused=list(inventory.refused))
    previous_hashes = previous_hashes or {}
    destination_anchor = (
        Path(root)
        if root is not None
        else (
            destination.parents[_RELOCATED_HOME_PARENT]
            if len(destination.parents) > _RELOCATED_HOME_PARENT
            else destination.parent
        )
    )
    for rel, entry in sorted(inventory.entries.items()):
        if rel in GENERATED_FILES:
            plan.generated.append(rel)
            continue
        target = destination / rel
        try:
            safe_write.stat_nofollow(target, root=destination_anchor)
        except FileNotFoundError:
            plan.to_copy.append(rel)
            continue
        except (OSError, safe_write.SafeWriteError):
            plan.conflicts.append(rel)
            continue
        try:
            target_hash = safe_write.sha256_anchored(target, root=destination_anchor)
        except (OSError, safe_write.SafeWriteError):
            plan.conflicts.append(rel)
            continue
        if target_hash == entry.sha256:
            plan.unchanged.append(rel)
        elif previous_hashes.get(rel) == target_hash:
            # Destination still holds what we copied last time; the source
            # has legitimately changed since, so refreshing is safe.
            plan.to_copy.append(rel)
            plan.expected_hashes[rel] = target_hash
        else:
            plan.conflicts.append(rel)
            plan.expected_hashes[rel] = target_hash
    return plan


def copy_inventory(
    source: Path,
    destination: Path,
    inventory: Inventory,
    plan: CopyPlan,
    target: TargetUserContext,
    *,
    force: bool = False,
    dry_run: bool = False,
    strict: bool = False,
    log=print,
) -> list[str]:
    """Copy the planned files.  Activation uses ``strict`` all-or-nothing mode."""
    warnings: list[str] = []
    if plan.conflicts and not force:
        raise SSHCanaryError(
            "destination files differ from the source and were not written by "
            "Honeypath:\n  "
            + "\n  ".join(str(destination / rel) for rel in plan.conflicts)
            + "\nResolve them by hand, or re-run with --force."
        )

    if dry_run:
        for rel in plan.to_copy:
            log(f"  [dry-run] copy {source / rel} -> {destination / rel}")
        return warnings

    ensure_directory(destination, target, mode=MODE_DIR_PRIVATE)
    for rel_dir in inventory.directories:
        ensure_directory(destination / rel_dir, target, mode=MODE_DIR_PRIVATE)

    for rel in plan.to_copy + (plan.conflicts if force else []):
        entry = inventory.entries[rel]
        dst = destination / rel
        mode = entry.mode
        if rel.endswith(".pub"):
            mode = 0o644
        elif mode & 0o077:
            mode = MODE_FILE_PRIVATE
        try:
            safe_write.safe_mkdir(
                dst.parent,
                target.home,
                mode=MODE_DIR_PRIVATE,
                uid=target.uid,
                gid=target.gid,
            )
            # Opaque byte copy: contents are never inspected.  fsync'd because
            # this is migrated private-key material — a crash between the copy
            # and the ~/.ssh rename must not lose it.
            warnings.extend(
                safe_write.atomic_write(
                    dst,
                    entry.content,
                    mode=mode,
                    root=target.home,
                    uid=target.uid,
                    gid=target.gid,
                    fsync_data=True,
                    replace=rel in plan.expected_hashes,
                    expected_sha256=plan.expected_hashes.get(rel),
                )
            )
        except safe_write.SafeWriteError as exc:
            warnings.append(f"refused to copy {rel}: {exc}")
            continue
        except OSError as exc:
            warnings.append(f"could not copy {rel}: {exc}")
            continue
        log(f"  copied {rel} (mode {oct(mode)})")
    if strict and warnings:
        raise SSHCanaryError(
            "SSH migration did not copy every required file:\n  "
            + "\n  ".join(warnings)
        )
    return warnings


def verify_relocated_inventory(
    inventory: Inventory, destination: Path, *, root: Path
) -> None:
    """Require every opaque source file to match its relocated counterpart.

    ``config`` is generated and validated separately.  Any refused source
    object or missing/stale relocated byte is an activation blocker.
    """
    if inventory.refused:
        raise SSHCanaryError(
            "source inventory contains objects that cannot be migrated:\n  "
            + "\n  ".join(inventory.refused)
        )
    failures: list[str] = []
    for rel, entry in sorted(inventory.entries.items()):
        if rel in GENERATED_FILES:
            continue
        target = destination / rel
        try:
            actual = safe_write.sha256_anchored(target, root=root)
        except (OSError, safe_write.SafeWriteError) as exc:
            failures.append(f"{rel}: unavailable or unsafe ({exc})")
            continue
        if actual != entry.sha256:
            failures.append(f"{rel}: relocated bytes do not match current ~/.ssh")
    if failures:
        raise SSHCanaryError(
            "relocated SSH state is incomplete or stale:\n  " + "\n  ".join(failures)
        )


def verify_inventory_unchanged(expected: Inventory, actual: Inventory) -> None:
    """Compare the renamed backup with the final pre-rename inventory."""
    if actual.refused:
        raise SSHCanaryError(
            "renamed SSH backup cannot be inventoried safely:\n  "
            + "\n  ".join(actual.refused)
        )
    if expected.hashes() != actual.hashes() or sorted(expected.directories) != sorted(
        actual.directories
    ):
        expected_keys = set(expected.entries)
        actual_keys = set(actual.entries)
        changed = sorted(
            rel
            for rel in expected_keys & actual_keys
            if expected.entries[rel].sha256 != actual.entries[rel].sha256
        )
        added = sorted(actual_keys - expected_keys)
        removed = sorted(expected_keys - actual_keys)
        detail = (
            ", ".join(
                part
                for part in (
                    f"changed={changed}" if changed else "",
                    f"added={added}" if added else "",
                    f"removed={removed}" if removed else "",
                )
                if part
            )
            or "directory set changed"
        )
        raise SSHCanaryError(f"~/.ssh changed during activation ({detail})")


# --------------------------------------------------------------------------
# Config rewriting (§8.3)
# --------------------------------------------------------------------------


@dataclass
class Rewrite:
    lineno: int
    before: str
    after: str


@dataclass
class RewriteResult:
    text: str
    rewrites: list[Rewrite] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    declares_identity: bool = False
    # True only when the user pointed UserKnownHostsFile somewhere *other* than
    # the OpenSSH default.  See build_managed_block for why this matters.
    declares_custom_known_hosts: bool = False


# Paths OpenSSH itself would use for UserKnownHostsFile.  Pointing at one of
# these is not a "custom" choice, it is the default spelled out.
_DEFAULT_KNOWN_HOSTS_TOKENS = {
    "~/.ssh/known_hosts",
    "~/.ssh/known_hosts2",
    "$HOME/.ssh/known_hosts",
    "$HOME/.ssh/known_hosts2",
    "${HOME}/.ssh/known_hosts",
    "${HOME}/.ssh/known_hosts2",
    "%d/.ssh/known_hosts",
    "%d/.ssh/known_hosts2",
}


def _split_token(token: str) -> tuple[str, str, str]:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return '"', token[1:-1], '"'
    return "", token, ""


def rewrite_path_token(token: str, home: Path, destination: Path) -> str:
    """Rewrite a single ``~/.ssh``-rooted path token to the relocated tree."""
    dest_abs = str(destination)
    dest_tilde = relocated_tilde()
    home_str = str(home).rstrip("/")

    replacements = [
        ("~/.ssh/", dest_tilde + "/"),
        ("$HOME/.ssh/", "$HOME/" + RELOCATED_REL + "/"),
        ("${HOME}/.ssh/", "${HOME}/" + RELOCATED_REL + "/"),
        ("%d/.ssh/", "%d/" + RELOCATED_REL + "/"),
        (home_str + "/.ssh/", dest_abs + "/"),
    ]
    exact = {
        "~/.ssh": dest_tilde,
        "$HOME/.ssh": "$HOME/" + RELOCATED_REL,
        "${HOME}/.ssh": "${HOME}/" + RELOCATED_REL,
        "%d/.ssh": "%d/" + RELOCATED_REL,
        home_str + "/.ssh": dest_abs,
    }
    if token in exact:
        return exact[token]
    for prefix, replacement in replacements:
        if token.startswith(prefix):
            return replacement + token[len(prefix) :]
    return token


def _is_relative_include(token: str) -> bool:
    return not token.startswith(("/", "~", "%", "$"))


def _still_references_ssh(token: str) -> bool:
    return (
        token.startswith(".ssh/")
        or token == ".ssh"
        or "/.ssh/" in token
        or token.endswith("/.ssh")
    )


def rewrite_user_config(
    text: str,
    home: Path,
    destination: Path,
) -> RewriteResult:
    """Rewrite a user's ssh_config so it works from the relocated directory."""
    result = RewriteResult(text="")
    out_lines: list[str] = []

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue

        match = _DIRECTIVE_RE.match(line)
        if not match:
            out_lines.append(line)
            continue

        indent, keyword, separator, args = match.groups()
        lowered = keyword.lower()

        if lowered == "match" and re.search(r"\bexec\b", args, re.IGNORECASE):
            if ".ssh" in args:
                result.blockers.append(
                    f"line {lineno}: `Match exec` references .ssh — Honeypath will not "
                    f"rewrite shell text. Fix by hand:\n      {stripped}"
                )
            out_lines.append(line)
            continue

        if lowered in SHELL_DIRECTIVES:
            if ".ssh" in args:
                result.blockers.append(
                    f"line {lineno}: `{keyword}` references .ssh — Honeypath will not "
                    f"rewrite shell text. Fix by hand:\n      {stripped}"
                )
            out_lines.append(line)
            continue

        if lowered == "identityfile":
            result.declares_identity = True
        elif lowered == "userknownhostsfile":
            for raw in _TOKEN_RE.findall(args):
                _, inner, _ = _split_token(raw)
                if (
                    inner not in _DEFAULT_KNOWN_HOSTS_TOKENS
                    and inner != f"{home}/.ssh/known_hosts"
                    and inner != f"{home}/.ssh/known_hosts2"
                ):
                    result.declares_custom_known_hosts = True

        if lowered not in REWRITE_DIRECTIVES:
            if _contains_ssh_path(args):
                result.blockers.append(
                    f"line {lineno}: `{keyword}` references .ssh but is not a path "
                    f"directive Honeypath rewrites. Fix by hand:\n      {stripped}"
                )
            out_lines.append(line)
            continue

        new_tokens: list[str] = []
        changed = False
        for raw in _TOKEN_RE.findall(args):
            open_q, inner, close_q = _split_token(raw)
            rewritten = rewrite_path_token(inner, home, destination)
            if (
                lowered == "include"
                and rewritten == inner
                and _is_relative_include(inner)
            ):
                # Fact 2: relative includes resolve against ~/.ssh, not against
                # the directory holding this file.
                rewritten = str(destination / inner)
            if rewritten != inner:
                changed = True
            if _still_references_ssh(rewritten):
                result.blockers.append(
                    f"line {lineno}: could not rewrite `{keyword} {inner}` — it still "
                    "points into a .ssh directory. Fix by hand."
                )
            if open_q or " " in rewritten:
                new_tokens.append(f'"{rewritten}"')
            else:
                new_tokens.append(rewritten)

        new_line = f"{indent}{keyword}{separator}{' '.join(new_tokens)}"
        if changed:
            result.rewrites.append(Rewrite(lineno=lineno, before=line, after=new_line))
        out_lines.append(new_line)

    result.text = "\n".join(out_lines)
    if text.endswith("\n") and not result.text.endswith("\n"):
        result.text += "\n"
    return result


def _contains_ssh_path(args: str) -> bool:
    for raw in _TOKEN_RE.findall(args):
        _, inner, _ = _split_token(raw)
        if _still_references_ssh(inner) or inner.startswith("~/.ssh"):
            return True
    return False


# --------------------------------------------------------------------------
# Identity discovery and the managed block
# --------------------------------------------------------------------------


def discover_identity_files(directory: Path) -> list[Path]:
    """Find private keys in the relocated directory.

    Looks for the conventional names *and* anything with a matching ``.pub``
    sibling, so ``id_work``/``id_work.pub`` is not missed.  File contents are
    never read.
    """
    found: list[Path] = []
    conventional = (
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519_sk",
        "id_dsa",
    )
    try:
        anchor = (
            directory.parents[_RELOCATED_HOME_PARENT]
            if len(directory.parents) > _RELOCATED_HOME_PARENT
            else directory.parent
        )
        fd = safe_write.open_directory_nofollow(directory, root=anchor)
        try:
            names = {
                name
                for name in os.listdir(fd)
                if stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode)
            }
        finally:
            os.close(fd)
    except (OSError, safe_write.SafeWriteError):
        return []
    for name in sorted(names):
        if name.endswith(".pub"):
            continue
        if name in conventional or f"{name}.pub" in names:
            found.append(directory / name)
    return found


def probe_identityfile_none(ssh_binary: str | None = None) -> bool:
    """Does this OpenSSH accept ``IdentityFile none``?

    Old releases reject it, in which case Honeypath falls back to an explicit
    nonexistent path inside the relocated directory.
    """
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as handle:
            handle.write("Host *\n    IdentityFile none\n")
            probe_path = handle.name
    except OSError:
        return False
    try:
        proc = subprocess.run(
            [ssh_binary or resolve_ssh_binary(), "-G", "-F", probe_path, "probe.invalid"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        try:
            os.unlink(probe_path)
        except OSError:
            pass


def build_managed_block(
    *,
    identity_files: list[Path],
    declares_identity: bool,
    identityfile_none_ok: bool,
    allow_agent_forwarding: bool,
    force_managed_identities: bool = False,
    declares_custom_known_hosts: bool = False,
) -> tuple[str, list[str]]:
    """Render the Honeypath managed block.  Returns (text, warnings)."""
    warnings: list[str] = []
    lines = [
        MANAGED_BEGIN,
        "# Appended after your configuration on purpose: OpenSSH is",
        "# first-match-wins, so your own Host blocks still take precedence.",
        "Host *",
        "    IdentitiesOnly yes",
    ]

    if declares_identity and not force_managed_identities:
        # No extra default *keys* — they would accumulate and could change
        # which key is offered first.  But the built-in ~/.ssh/id_* fallback
        # must still be suppressed, or hosts your config does not cover would
        # be offered the canaries.  `IdentityFile none` does exactly that: it
        # suppresses the built-ins and adds nothing offerable, leaving your own
        # entries and their order untouched.
        if identityfile_none_ok:
            lines.append("    IdentityFile none")
            suppression = "`IdentityFile none`"
        else:
            placeholder = f"{relocated_tilde()}/no-identity-configured"
            lines.append(f"    IdentityFile {placeholder}")
            suppression = f"the nonexistent path {placeholder}"
        warnings.append(
            "Your config already declares IdentityFile entries, so Honeypath added no "
            "default keys (they would accumulate and change which key is offered "
            f"first). It did append {suppression} to suppress OpenSSH's built-in "
            "~/.ssh/id_* fallback, which after activation points at canaries.\n"
            "  Consequence: hosts your config does not cover will offer no key at all. "
            "Pass --force-managed-identities to add the relocated keys as trailing "
            "defaults instead."
        )
    elif identity_files:
        for key in identity_files:
            lines.append(f"    IdentityFile {relocated_tilde()}/{key.name}")
    elif identityfile_none_ok:
        lines.append("    IdentityFile none")
        warnings.append(
            "No SSH keys were found, so the managed block uses `IdentityFile none` to "
            "suppress OpenSSH's built-in ~/.ssh/id_* defaults (which are canaries after "
            "activation)."
        )
    else:
        placeholder = f"{relocated_tilde()}/no-identity-configured"
        lines.append(f"    IdentityFile {placeholder}")
        warnings.append(
            f"This OpenSSH rejected `IdentityFile none`; using the nonexistent path "
            f"{placeholder} instead to suppress the built-in ~/.ssh/id_* defaults."
        )

    lines.append(f"    UserKnownHostsFile {relocated_tilde()}/known_hosts")
    lines.append(
        "    ForwardAgent yes" if allow_agent_forwarding else "    ForwardAgent no"
    )
    # OpenSSH silently disables UpdateHostKeys whenever UserKnownHostsFile is
    # not the default path, so relocating known_hosts would quietly turn off
    # host-key rotation learning. Restore the documented default explicitly;
    # a value the user set earlier still wins under first-match-wins.
    lines.append("    # relocating known_hosts would otherwise disable this")
    lines.append("    UpdateHostKeys yes")
    if declares_custom_known_hosts:
        warnings.append(
            "Your config points UserKnownHostsFile at a non-default file. For hosts "
            "covered by that setting OpenSSH had UpdateHostKeys off; the managed block "
            "now turns it on, matching OpenSSH's default behaviour everywhere else. "
            "Set `UpdateHostKeys no` in your own config if you want it off."
        )
    lines.append(MANAGED_END)
    return "\n".join(lines) + "\n", warnings


GENERATED_HEADER = (
    "# Honeypath relocated SSH client configuration.\n"
    "# Generated from your original ~/.ssh/config with paths rewritten.\n"
    "# Used automatically by the ~/bin/ssh, ~/bin/scp and ~/bin/sftp wrappers.\n"
)


def split_managed_block(text: str) -> tuple[str, str, str]:
    """Split a relocated config into (user section, managed block, tail).

    The generated header is stripped from the user section so that re-running
    setup does not stack a fresh copy of it on every pass.
    """
    if MANAGED_BEGIN not in text:
        return _strip_generated_header(text), "", ""
    head, rest = text.split(MANAGED_BEGIN, 1)
    head = _strip_generated_header(head)
    if MANAGED_END in rest:
        block, tail = rest.split(MANAGED_END, 1)
        return head, MANAGED_BEGIN + block + MANAGED_END + "\n", tail.lstrip("\n")
    return head, MANAGED_BEGIN + rest, ""


def _strip_generated_header(text: str) -> str:
    if text.startswith(GENERATED_HEADER):
        return text[len(GENERATED_HEADER) :]
    return text


def assemble_relocated_config(
    user_section: str,
    managed_block: str,
    *,
    system_config: Path | None = None,
) -> str:
    if system_config is None:
        system_config = SYSTEM_SSH_CONFIG
    parts = [GENERATED_HEADER]
    user_section = _strip_generated_header(user_section).strip("\n")
    if user_section:
        parts.append(user_section + "\n")
    parts.append(managed_block)
    if system_config.exists():
        parts.append(
            "\n# `ssh -F` suppresses the system-wide config, so it is re-included\n"
            "# last: user settings above still win under first-match-wins.\n"
            f"Include {system_config}\n"
        )
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Validation (§8.3)
# --------------------------------------------------------------------------


def ssh_dash_g(
    host: str,
    *,
    config: Path | None = None,
    target: TargetUserContext | None = None,
    ssh_binary: str | None = None,
) -> tuple[bool, list[str], str]:
    argv = [ssh_binary or resolve_ssh_binary(), "-G"]
    if config is not None:
        argv += ["-F", str(config)]
    argv.append(host)
    try:
        if target is not None:
            proc = run_as_target(argv, target, timeout=30)
        else:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=30, check=False
            )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, [], str(exc)
    if proc.returncode != 0:
        return False, [], (proc.stderr or "").strip() or f"exit {proc.returncode}"
    return True, proc.stdout.splitlines(), ""


def diff_ssh_g(baseline: list[str], candidate: list[str]) -> list[str]:
    """Differences between two ``ssh -G`` dumps, ignoring expected changes."""

    def index(lines):
        table: dict[str, list[str]] = {}
        for line in lines:
            key, _, value = line.partition(" ")
            table.setdefault(key.lower(), []).append(value)
        return table

    before, after = index(baseline), index(candidate)
    differences: list[str] = []
    for key in sorted(set(before) | set(after)):
        if key in _EXPECTED_DIFF_KEYS:
            continue
        if before.get(key) != after.get(key):
            differences.append(
                f"{key}: {before.get(key, ['<unset>'])} -> {after.get(key, ['<unset>'])}"
            )
    return differences


def validate_relocated_config(
    config: Path,
    *,
    baseline: list[str] | None = None,
    host: str = "github.com",
    target: TargetUserContext | None = None,
) -> tuple[str, list[str]]:
    """Returns (status, messages).  Status is ok / differences / failed."""
    ok, lines, error = ssh_dash_g(host, config=config, target=target)
    if not ok:
        return "failed", [f"ssh -G -F {config} {host} failed: {error}"]
    messages = [f"ssh -G -F {config} {host}: parsed successfully"]
    if baseline:
        differences = diff_ssh_g(baseline, lines)
        if differences:
            messages.append("unexpected differences vs the previous configuration:")
            messages += [f"  {d}" for d in differences]
            return "differences", messages
        messages.append("no unexpected differences vs the previous configuration")
    return "ok", messages


# --------------------------------------------------------------------------
# Wrappers (§8.1)
# --------------------------------------------------------------------------


@dataclass
class WrapperStatus:
    name: str
    path: Path
    exists: bool
    ours: bool
    executable: bool

    def describe(self) -> str:
        if not self.exists:
            return f"{self.path}: absent"
        kind = "Honeypath wrapper" if self.ours else "FOREIGN file (not Honeypath's)"
        return f"{self.path}: {kind}{'' if self.executable else ' (not executable)'}"


def wrapper_statuses(home: Path) -> list[WrapperStatus]:
    statuses = []
    for name in SSH_BINARIES:
        path = wrapper_dir(home) / name
        try:
            info = safe_write.stat_nofollow(path, root=home)
            exists = stat.S_ISREG(info.st_mode)
        except (OSError, safe_write.SafeWriteError):
            info = None
            exists = False
        statuses.append(
            WrapperStatus(
                name=name,
                path=path,
                exists=exists,
                ours=exists and is_honeypath_wrapper(path),
                executable=bool(exists and info and stat.S_IMODE(info.st_mode) & 0o111),
            )
        )
    return statuses


def install_wrappers(
    db: Database,
    target: TargetUserContext,
    *,
    force: bool = False,
    dry_run: bool = False,
    log=print,
) -> list[str]:
    """Install ~/bin/{ssh,scp,sftp}.  Returns problems (empty on success)."""
    problems: list[str] = []
    directory = wrapper_dir(target.home)
    if not dry_run:
        safe_write.safe_mkdir(
            directory, target.home, mode=0o755, uid=target.uid, gid=target.gid
        )

    for name in SSH_BINARIES:
        path = directory / name
        # Resolved now, not at import time: the wrapper records an absolute
        # path and must record the one that exists on this host.
        binary = resolve_ssh_binary(name, exclude=directory)
        content = wrapper_content(binary)
        digest = sha256_text(content)
        try:
            path_info = safe_write.stat_nofollow(path, root=target.home)
            path_exists = True
        except FileNotFoundError:
            path_info = None
            path_exists = False
        except (OSError, safe_write.SafeWriteError) as exc:
            problems.append(f"cannot safely inspect {path}: {exc}")
            continue

        if path_exists:
            if path_info is None or not stat.S_ISREG(path_info.st_mode):
                problems.append(f"{path} exists and is not a regular file; refusing")
                continue
            if is_honeypath_wrapper(path):
                if (
                    not dry_run
                    and safe_write.sha256_anchored(path, root=target.home) == digest
                ):
                    log(f"  {path}: already current")
                    continue
            elif not force:
                problems.append(
                    f"{path} exists and is not a Honeypath wrapper; refusing to "
                    "overwrite (use --force to replace it)"
                )
                continue

        if dry_run:
            log(
                f"  [dry-run] install wrapper {path} -> {binary} -F "
                f"$HOME/{RELOCATED_REL}/config"
            )
            continue

        previous = None
        if path_exists:
            try:
                previous = safe_write.sha256_anchored(path, root=target.home)
            except (OSError, safe_write.SafeWriteError):
                previous = None
        try:
            # The wrapper is executable and lives in ~/bin, a directory the
            # target user owns; a symlink pre-positioned there must never be
            # followed while Honeypath is running under sudo.
            safe_write.atomic_write(
                path,
                content,
                mode=MODE_EXEC,
                root=target.home,
                uid=target.uid,
                gid=target.gid,
                replace=previous is not None,
                expected_sha256=previous,
            )
        except safe_write.SafeWriteError as exc:
            problems.append(f"refused to write {path}: {exc}")
            continue
        except OSError as exc:
            problems.append(f"could not write {path}: {exc}")
            continue
        db.record_managed_change(
            change_type=CHANGE_WRAPPER,
            target=str(path),
            home=str(target.home),
            previous_existed=previous is not None,
            previous_value=previous,
            new_value=str(binary),
            content_hash=digest,
            notes="Honeypath ssh wrapper",
        )
        log(f"  installed {path}")
    return problems


def remove_wrappers(
    db: Database, target: TargetUserContext, *, log=print, dry_run=False
) -> None:
    for change in db.get_managed_changes(
        change_type=CHANGE_WRAPPER, home=str(target.home)
    ):
        path = Path(change["target"])
        try:
            current = safe_write.sha256_anchored(path, root=target.home)
        except FileNotFoundError:
            if not dry_run:
                db.retire_managed_change(change["id"])
            continue
        except (OSError, safe_write.SafeWriteError) as exc:
            log(f"  {path}: cannot hash ({exc}); leaving in place")
            continue
        if current != change["content_hash"]:
            log(f"  {path}: modified since installation; leaving in place")
            continue
        if dry_run:
            log(f"  [dry-run] remove {path}")
            continue
        try:
            safe_write.unlink_regular_if_hash(
                path, root=target.home, expected_sha256=change["content_hash"]
            )
            log(f"  removed {path}")
        except (OSError, safe_write.SafeWriteError) as exc:
            log(f"  could not remove {path}: {exc}")
            continue
        db.retire_managed_change(change["id"])


# --------------------------------------------------------------------------
# PATH and Git integration (§8.4)
# --------------------------------------------------------------------------


def path_contains_wrapper_dir(target: TargetUserContext) -> bool:
    """Whether the target user's login shell puts the wrapper dir on PATH.

    The question is about the shell the target user will type ``ssh`` into, not
    about this process: under sudo ``os.environ["PATH"]`` is root's secure_path,
    which answers "no" no matter what the user's rc files do.
    """
    wanted = str(wrapper_dir(target.home))
    try:
        proc = run_as_target(
            ["sh", "-lc", "printf %s \"$PATH\""], target, timeout=15
        )
    except (FileNotFoundError, PermissionError, subprocess.SubprocessError):
        return wanted in os.environ.get("PATH", "").split(os.pathsep)
    if proc.returncode != 0:
        return wanted in os.environ.get("PATH", "").split(os.pathsep)
    return wanted in proc.stdout.strip().split(os.pathsep)


def rc_block_text() -> str:
    return (
        f"{RC_BEGIN}\n"
        "# Puts the Honeypath ssh/scp/sftp wrappers ahead of /usr/bin.\n"
        'export PATH="$HOME/bin:$PATH"\n'
        f"{RC_END}\n"
    )


def install_rc_block(
    db: Database,
    target: TargetUserContext,
    rc_file: Path,
    *,
    dry_run: bool = False,
    log=print,
) -> bool:
    block = rc_block_text()
    existing = ""
    rc_exists = False
    mode = MODE_FILE_PRIVATE
    try:
        info = safe_write.stat_nofollow(rc_file, root=target.home)
        rc_exists = True
        if stat.S_ISLNK(info.st_mode):
            log(
                f"  {rc_file} is a symlink; refusing to edit it. Add this line by hand:"
            )
            log('    export PATH="$HOME/bin:$PATH"')
            return False
        existing = safe_write.read_text_nofollow(
            rc_file, root=target.home, errors="replace"
        )
        mode = stat.S_IMODE(info.st_mode)
    except FileNotFoundError:
        pass
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"  cannot read {rc_file}: {exc}")
        return False
    if rc_exists:
        if RC_BEGIN in existing:
            log(f"  {rc_file}: Honeypath PATH block already present")
            return True
    if dry_run:
        log(f"  [dry-run] append the Honeypath PATH block to {rc_file}")
        return True

    # Read-modify-write through the atomic writer rather than appending in
    # place: an rc file is user-owned and Honeypath is often running as root.
    updated = existing
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += "\n" + block
    try:
        safe_write.atomic_write(
            rc_file,
            updated,
            mode=mode,
            root=target.home,
            uid=target.uid,
            gid=target.gid,
            replace=rc_exists,
            expected_sha256=sha256_text(existing) if rc_exists else None,
        )
    except safe_write.SafeWriteError as exc:
        log(f"  refusing to write {rc_file}: {exc}")
        return False
    except OSError as exc:
        log(f"  cannot write {rc_file}: {exc}")
        return False
    db.record_managed_change(
        change_type=CHANGE_RC_BLOCK,
        target=str(rc_file),
        home=str(target.home),
        previous_existed=bool(existing),
        content_hash=sha256_text(block),
        new_value=RC_BEGIN,
        notes="PATH block adding ~/bin",
    )
    log(f"  added the Honeypath PATH block to {rc_file}")
    return True


def remove_rc_blocks(
    db: Database, target: TargetUserContext, *, log=print, dry_run=False
) -> None:
    for change in db.get_managed_changes(
        change_type=CHANGE_RC_BLOCK, home=str(target.home)
    ):
        rc_file = Path(change["target"])
        try:
            info = safe_write.stat_nofollow(rc_file, root=target.home)
            text = safe_write.read_text_nofollow(
                rc_file, root=target.home, errors="replace"
            )
        except FileNotFoundError:
            if not dry_run:
                db.retire_managed_change(change["id"])
            continue
        except (OSError, safe_write.SafeWriteError) as exc:
            log(f"  cannot read {rc_file}: {exc}")
            continue
        if RC_BEGIN not in text:
            if not dry_run:
                db.retire_managed_change(change["id"])
            continue
        if dry_run:
            log(f"  [dry-run] remove the Honeypath PATH block from {rc_file}")
            continue
        cleaned = _strip_rc_block(text)
        try:
            mode = stat.S_IMODE(info.st_mode)
            safe_write.atomic_write(
                rc_file,
                cleaned,
                mode=mode,
                root=target.home,
                uid=target.uid,
                gid=target.gid,
                replace=True,
                expected_sha256=sha256_text(text),
            )
        except safe_write.SafeWriteError as exc:
            log(f"  refusing to write {rc_file}: {exc}")
            continue
        except OSError as exc:
            log(f"  cannot write {rc_file}: {exc}")
            continue
        log(f"  removed the Honeypath PATH block from {rc_file}")
        db.retire_managed_change(change["id"])


def _strip_rc_block(text: str) -> str:
    out: list[str] = []
    seams: list[int] = []
    skipping = False
    for line in text.splitlines(keepends=True):
        if line.strip() == RC_BEGIN:
            skipping = True
            continue
        if line.strip() == RC_END:
            skipping = False
            seams.append(len(out))
            continue
        if not skipping:
            out.append(line)
    # Only the join the removed block left behind is tidied.  Collapsing every
    # run of blank lines in the file would reformat rc content the user wrote,
    # in a file Honeypath is supposed to be leaving as it found it.
    for seam in reversed(seams):
        before = seam - 1
        while before >= 0 and not out[before].strip():
            before -= 1
        after = seam
        while after < len(out) and not out[after].strip():
            after += 1
        blanks = out[before + 1 : after]
        # One blank line survives between surrounding content; none if the
        # block sat at the very start or end of the file.
        keep = blanks[:1] if before >= 0 and after < len(out) else []
        out[before + 1 : after] = keep
    return "".join(out)


def git_installed(target: TargetUserContext) -> bool:
    """Whether a git binary is runnable as the target user."""
    try:
        run_as_target(["git", "--version"], target)
    except (FileNotFoundError, PermissionError):
        return False
    return True


def git_ssh_command(target: TargetUserContext) -> str | None:
    try:
        proc = run_as_target(["git", "config", "--global", "core.sshCommand"], target)
    except (FileNotFoundError, PermissionError):
        # Git is optional.  Not having it is not a setup failure.
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def set_git_ssh_command(
    db: Database,
    target: TargetUserContext,
    *,
    force: bool = False,
    dry_run: bool = False,
    log=print,
    confirm=None,
) -> bool:
    wrapper = wrapper_dir(target.home) / "ssh"
    desired = str(wrapper)
    if not git_installed(target):
        log("  git is not installed; nothing to point at the wrapper")
        return True
    current = git_ssh_command(target)

    log(f"  current core.sshCommand: {current if current else '<unset>'}")
    if current == desired:
        log("  already set to the Honeypath wrapper")
        return True
    if current and current != desired:
        if not force and (
            confirm is None
            or not confirm(f"Replace git core.sshCommand ({current}) with {desired}?")
        ):
            log("  leaving core.sshCommand unchanged")
            return False
    if dry_run:
        log(f"  [dry-run] git config --global core.sshCommand {desired}")
        return True

    proc = run_as_target(
        ["git", "config", "--global", "core.sshCommand", desired], target
    )
    if proc.returncode != 0:
        log(f"  git config failed: {(proc.stderr or '').strip()}")
        return False
    db.record_managed_change(
        change_type=CHANGE_GIT_SSH,
        target="core.sshCommand",
        home=str(target.home),
        previous_existed=current is not None,
        previous_value=current,
        new_value=desired,
        notes="absolute wrapper path: avoids a duplicate -F via PATH and "
        "survives cron, IDEs and su'd shells",
    )
    log(f"  set core.sshCommand = {desired}")
    return True


def restore_git_ssh_command(
    db: Database, target: TargetUserContext, *, log=print, dry_run=False
) -> None:
    changes = db.get_managed_changes(change_type=CHANGE_GIT_SSH, home=str(target.home))
    if not changes:
        log("  no recorded core.sshCommand change")
        return
    change = changes[0]
    if not git_installed(target):
        # Git was removed after Honeypath pointed it at the wrapper.  There is
        # nothing left to restore, and this must not abort the rest of the
        # restore run.
        log("  git is no longer installed; leaving the recorded change in place")
        return
    current = git_ssh_command(target)
    desired = change.get("new_value")
    if current and desired and current != desired:
        log(
            f"  core.sshCommand is now {current}, not the value Honeypath set "
            f"({desired}); leaving it alone"
        )
        return
    if change.get("previous_existed"):
        previous = change.get("previous_value") or ""
        if dry_run:
            log(f"  [dry-run] restore core.sshCommand to {previous}")
            return
        proc = run_as_target(
            ["git", "config", "--global", "core.sshCommand", previous], target
        )
        log(
            f"  restored core.sshCommand = {previous}"
            if proc.returncode == 0
            else f"  could not restore core.sshCommand: {(proc.stderr or '').strip()}"
        )
    else:
        if dry_run:
            log("  [dry-run] unset core.sshCommand (it was originally unset)")
            return
        proc = run_as_target(
            ["git", "config", "--global", "--unset", "core.sshCommand"], target
        )
        # git exits 5 when the key is already gone.
        log(
            "  unset core.sshCommand (it was originally unset)"
            if proc.returncode in (0, 5)
            else f"  could not unset core.sshCommand: {(proc.stderr or '').strip()}"
        )
    if not dry_run:
        db.retire_managed_change(change["id"])


# --------------------------------------------------------------------------
# Canarytokens (§8.4)
# --------------------------------------------------------------------------


def load_canarytoken_aws(path: Path) -> dict:
    """Parse user-supplied Canarytokens AWS material.

    Accepts an AWS credentials-style file or plain ``key = value`` lines.
    Honeypath never generates token material; it only reads what it is given.
    """
    try:
        text = path.read_text()
    except OSError as exc:
        raise SSHCanaryError(f"cannot read {path}: {exc}") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[", ";")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            key, sep, value = line.partition(":")
        if sep:
            values[key.strip().lower()] = value.strip()
    key_id = values.get("aws_access_key_id") or values.get("accesskeyid")
    secret = values.get("aws_secret_access_key") or values.get("secretaccesskey")
    if not key_id or not secret:
        raise SSHCanaryError(
            f"{path} does not contain aws_access_key_id and aws_secret_access_key"
        )
    return {"aws_access_key_id": key_id, "aws_secret_access_key": secret}


# --------------------------------------------------------------------------
# Phase 1 and Phase 2
# --------------------------------------------------------------------------

CONFIRM_PROMPT = """\
Do you want Honeypath to canary your standard ~/.ssh directory?
This will copy your real SSH client files to:
  ~/.local/share/honeypath/real-ssh
Then Honeypath will install ~/bin/ssh, ~/bin/scp, and ~/bin/sftp wrappers
that call the system OpenSSH tools with:
  -F ~/.local/share/honeypath/real-ssh/config
Agent forwarding will be disabled by default in the relocated config.
Your original ~/.ssh will not be deleted."""

# Run these BEFORE activating, and again afterwards.  None of them needs to
# reach a real host: `example.invalid` cannot resolve, which is the point —
# they verify which binary and which configuration got selected, not whether a
# connection succeeded.  A DNS/"could not resolve hostname" failure is a PASS.
PHASE1_TEST_COMMANDS = [
    "~/bin/ssh -G github.com",
    "~/bin/ssh -T git@github.com",
    "~/bin/scp -v /dev/null example.invalid:/tmp/",
    "~/bin/sftp -v example.invalid",
    "git config --global core.sshCommand",
    "which ssh",
    "ssh -G github.com",
    "rsync --version",
]

PHASE1_TEST_NOTES = [
    "What to look for:",
    "  ~/bin/ssh -G github.com        identityfile/userknownhostsfile must point",
    "                                 into ~/.local/share/honeypath/real-ssh,",
    "                                 never into ~/.ssh",
    "  ~/bin/ssh -T git@github.com    should authenticate exactly as before",
    "  ~/bin/scp -v ... example.invalid   the -v banner must show the relocated",
    "  ~/bin/sftp -v example.invalid      config; a DNS failure afterwards is fine",
    "                                 and expected — example.invalid never resolves",
    "  git config --global core.sshCommand   should name the ~/bin/ssh wrapper",
    "  which ssh                      should be ~/bin/ssh once PATH is set up",
    "  ssh -G github.com              this is the BYPASS case: before activation it",
    "                                 still works; AFTER activation it fails with a",
    "                                 parse error, by design (see below)",
    "  rsync --version                rsync shells out to `ssh` from PATH, so it",
    "                                 picks up the wrapper; confirm it still runs",
]

# After activation the canary ~/.ssh/config is deliberately invalid, so this is
# the honest description of what breaks.  See catalog._SSH_CANARY_CONFIG.
DIRECT_SSH_WARNING = [
    "AFTER ACTIVATION, PROGRAMS THAT BYPASS THE WRAPPERS WILL FAIL LOUDLY.",
    "",
    "The canary ~/.ssh/config is deliberately syntactically invalid. Any program",
    "that invokes /usr/bin/ssh, /usr/bin/scp or /usr/bin/sftp directly — instead",
    "of ~/bin/ssh, ~/bin/scp or ~/bin/sftp — will exit with an OpenSSH",
    "configuration parse error pointing at ~/.ssh/config.",
    "",
    "That is deliberate: the alternative is being silently handed canary keys and",
    "getting a confusing authentication failure plus an alert about your own",
    "tooling. A visible, diagnosable breakage now beats a mysterious one later.",
    "",
    "Direct /usr/bin/ssh use is UNSUPPORTED after activation unless you configure",
    "it explicitly. Things that commonly bypass the wrappers:",
    "  * cron jobs and systemd units with a hardcoded /usr/bin/ssh",
    "  * IDEs and GUI git clients with an absolute ssh path in their settings",
    "  * scripts using an absolute path, or running with a PATH that omits ~/bin",
    "  * anything running before your shell rc files are sourced",
    "",
    "To make a specific program work, pick one:",
    "  * point it at ~/bin/ssh instead of /usr/bin/ssh",
    "  * pass -F ~/.local/share/honeypath/real-ssh/config yourself",
    "  * for git:  git config --global core.sshCommand ~/bin/ssh  (setup does this)",
    "  * or run `honeypath.py restore-ssh-canary` to undo activation entirely",
]


def direct_ssh_status(db: Database, target: TargetUserContext) -> dict:
    """Is invoking the system ssh directly (bypassing the wrappers) supported?

    Returns ``{"activated", "supported", "reason", "lines"}``.  After
    activation the answer is No unless the operator has replaced the canary
    ~/.ssh/config with something that parses.
    """
    home = target.home
    installation = db.get_ssh_installation(str(home)) or {}
    activated = installation.get("phase") == PHASE_ACTIVATED
    canary_config = looks_like_canary_dir(home / ".ssh")

    if not activated:
        return {
            "activated": False,
            "supported": True,
            "reason": "activation has not been run; ~/.ssh is still your real one",
            "lines": [],
        }
    if not canary_config:
        return {
            "activated": True,
            "supported": True,
            "reason": (
                "~/.ssh/config is no longer the Honeypath canary, so direct "
                "/usr/bin/ssh use has been explicitly reconfigured"
            ),
            "lines": [],
        }
    return {
        "activated": True,
        "supported": False,
        "reason": (
            "UNSUPPORTED: ~/.ssh/config is the deliberately invalid canary, so "
            "/usr/bin/ssh exits with a parse error. Use ~/bin/ssh, or pass "
            f"-F {relocated_tilde()}/config explicitly."
        ),
        "lines": list(DIRECT_SSH_WARNING),
    }


def list_backups(home: Path) -> list[Path]:
    """Every ~/.ssh backup Honeypath has taken, oldest first.

    Covers both the normal location under ``backup_root`` and the EXDEV
    fallback directly in the home.  Backups are never deleted by Honeypath;
    this only finds them.
    """
    normal_prefix = "ssh-"
    fallback_prefix = ".ssh.honeypath-backup."
    found: list[tuple[str, Path]] = []
    root = backup_root(home)
    if root.is_dir():
        found += [
            (p.name[len(normal_prefix) :], p)
            for p in root.iterdir()
            if p.is_dir() and p.name.startswith(normal_prefix)
        ]
    if home.is_dir():
        found += [
            (p.name[len(fallback_prefix) :], p)
            for p in home.iterdir()
            if p.is_dir() and p.name.startswith(fallback_prefix)
        ]
    # The timestamp slug sorts lexicographically in chronological order, but
    # only once each name's own prefix is stripped: comparing whole names would
    # rank every EXDEV fallback above every normal backup regardless of age.
    return [p for _, p in sorted(found, key=lambda item: (item[0], str(item[1])))]


def latest_valid_backup(home: Path) -> Path | None:
    """The newest backup that still exists and is a real directory."""
    for candidate in reversed(list_backups(home)):
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    return None


@dataclass
class PrepareResult:
    ok: bool
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rewrites: list[Rewrite] = field(default_factory=list)
    validation_status: str = "not run"
    validation_messages: list[str] = field(default_factory=list)
    inventory: Inventory | None = None


def prepare_relocated_config(
    db: Database,
    target: TargetUserContext,
    *,
    allow_agent_forwarding: bool = False,
    force_managed_identities: bool = False,
    force: bool = False,
    dry_run: bool = False,
    baseline: list[str] | None = None,
    log=print,
) -> PrepareResult:
    """Build (or refresh) the relocated config from the current ~/.ssh/config."""
    home = target.home
    destination = relocated_dir(home)
    source_config = home / ".ssh" / "config"
    result = PrepareResult(ok=True)

    user_text = ""
    try:
        user_text = safe_write.read_text_nofollow(
            source_config, root=home, errors="replace"
        )
    except FileNotFoundError:
        pass
    except (OSError, safe_write.SafeWriteError) as exc:
        result.ok = False
        result.blockers.append(f"cannot safely read {source_config}: {exc}")
        return result

    rewritten = rewrite_user_config(user_text, home, destination)
    result.rewrites = rewritten.rewrites
    result.blockers.extend(rewritten.blockers)

    if rewritten.rewrites:
        log("  path rewrites:")
        for change in rewritten.rewrites:
            log(f"    line {change.lineno}:")
            log(f"      - {change.before.strip()}")
            log(f"      + {change.after.strip()}")
    elif user_text:
        log("  path rewrites: none needed")

    identity_files = discover_identity_files(destination)
    if not identity_files and dry_run:
        # Nothing has been copied yet, so project what the copy would produce.
        identity_files = [
            destination / key.name for key in discover_identity_files(home / ".ssh")
        ]
        if identity_files:
            log(
                "  keys that will be relocated: "
                + ", ".join(k.name for k in identity_files)
            )
    elif identity_files:
        log(
            "  keys found in the relocated directory: "
            + ", ".join(k.name for k in identity_files)
        )
    if dry_run:
        # The capability probe needs a temporary config file.  Dry-run's
        # contract is stricter than that convenience, so project the modern
        # OpenSSH behavior without creating a temp file.
        none_ok = True
        log("  [dry-run] skipped temporary `IdentityFile none` capability probe")
    else:
        none_ok = probe_identityfile_none()
        log(
            f"  `IdentityFile none` accepted by {resolve_ssh_binary()}: "
            f"{'yes' if none_ok else 'no'}"
        )

    managed, block_warnings = build_managed_block(
        identity_files=identity_files,
        declares_identity=rewritten.declares_identity,
        identityfile_none_ok=none_ok,
        allow_agent_forwarding=allow_agent_forwarding,
        force_managed_identities=force_managed_identities,
        declares_custom_known_hosts=rewritten.declares_custom_known_hosts,
    )
    if force_managed_identities and rewritten.declares_identity and identity_files:
        extra = "".join(
            f"    IdentityFile {relocated_tilde()}/{k.name}\n" for k in identity_files
        )
        managed = managed.replace(
            "    IdentitiesOnly yes\n", "    IdentitiesOnly yes\n" + extra
        )
    result.warnings.extend(block_warnings)

    # Decide the user section: prefer a hand-edited relocated config over
    # silently regenerating it.
    config_path = relocated_config(home)
    user_section = rewritten.text
    try:
        current = safe_write.read_text_nofollow(
            config_path, root=home, errors="replace"
        )
        config_exists = True
    except FileNotFoundError:
        current = ""
        config_exists = False
    except (OSError, safe_write.SafeWriteError) as exc:
        result.ok = False
        result.blockers.append(f"cannot safely read {config_path}: {exc}")
        return result
    if config_exists:
        existing_user, _, _ = split_managed_block(current)
        recorded = (db.get_ssh_installation(str(home)) or {}).get("source_hashes", {})
        expected = recorded.get("__relocated_user_section")
        # A relocated config that is byte-identical to the (un-rewritten) source
        # is a stale copy, not a hand edit — regenerate it.
        stale_copy = (
            existing_user.strip() and existing_user.strip() == user_text.strip()
        )
        if (
            existing_user.strip()
            and not stale_copy
            and sha256_text(existing_user) != expected
        ):
            if force:
                result.warnings.append(
                    f"{config_path} was edited by hand; --force replaced its user "
                    "section with a fresh rewrite of ~/.ssh/config"
                )
            else:
                user_section = existing_user
                result.warnings.append(
                    f"{config_path} contains hand-edited content; keeping it and "
                    "updating only the Honeypath managed block. Re-run with --force "
                    "to regenerate it from ~/.ssh/config."
                )

    text = assemble_relocated_config(user_section, managed)

    if dry_run:
        log(f"  [dry-run] would write {config_path} ({len(text.splitlines())} lines)")
        return result

    try:
        safe_write.safe_mkdir(
            destination,
            home,
            mode=MODE_DIR_PRIVATE,
            uid=target.uid,
            gid=target.gid,
        )
        for warning in safe_write.atomic_write(
            config_path,
            text,
            mode=0o600,
            root=home,
            uid=target.uid,
            gid=target.gid,
            fsync_data=True,
            replace=config_exists,
            expected_sha256=sha256_text(current) if config_exists else None,
        ):
            result.warnings.append(warning)
    except safe_write.SafeWriteError as exc:
        result.ok = False
        result.blockers.append(f"refusing to write {config_path}: {exc}")
        return result
    except OSError as exc:
        result.ok = False
        result.blockers.append(f"cannot write {config_path}: {exc}")
        return result
    log(f"  wrote {config_path}")

    status, messages = validate_relocated_config(
        config_path, baseline=baseline, target=target
    )
    result.validation_status = status
    result.validation_messages = messages
    for message in messages:
        log(f"  {message}")
    if status == "failed":
        result.ok = False
        result.blockers.append(
            "the relocated config does not parse; activation blocked"
        )

    hashes = {"__relocated_user_section": sha256_text(user_section)}
    db.upsert_ssh_installation(
        home=str(home),
        username=target.username,
        uid=target.uid,
        relocated_dir=str(destination),
        phase=(db.get_ssh_installation(str(home)) or {}).get("phase") or PHASE_PREPARED,
        config_validation=status,
        source_hashes={
            **((db.get_ssh_installation(str(home)) or {}).get("source_hashes") or {}),
            **hashes,
        },
    )
    return result


def known_hosts_seed(target: TargetUserContext, log=print) -> None:
    """Make sure the relocated known_hosts exists so ssh does not create it in ~/.ssh."""
    path = relocated_dir(target.home) / "known_hosts"
    if path.exists():
        return
    try:
        safe_write.safe_mkdir(
            path.parent,
            target.home,
            mode=MODE_DIR_PRIVATE,
            uid=target.uid,
            gid=target.gid,
        )
        safe_write.atomic_write(
            path,
            b"",
            mode=MODE_FILE_PRIVATE,
            root=target.home,
            uid=target.uid,
            gid=target.gid,
            replace=False,
        )
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"  could not create {path}: {exc}")
        return
    log(f"  created empty {path}")


def authorized_keys_warning(home: Path) -> list[str]:
    """Loud warnings when ~/.ssh holds server-side state."""
    ssh_dir = home / ".ssh"
    present = [name for name in AUTHORIZED_KEYS_FILES if (ssh_dir / name).exists()]
    if not present:
        return []
    named = " and ".join(present)
    lines = [
        f"!!  ~/.ssh/{named} exists — this directory holds SERVER-side state.",
        "!!  Moving it would break inbound SSH logins to this machine.",
        f"!!  Honeypath copies {named} back into the new ~/.ssh by default",
        "!!  (it is public material, and sshd reads are routine, so it is not a canary).",
        "!!  Use --no-authorized-keys to opt out.",
    ]
    if sshd_running():
        lines.insert(
            0, "!!  AN SSH SERVER (sshd) APPEARS TO BE RUNNING ON THIS MACHINE."
        )
    return lines


def sshd_running() -> bool:
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
            except OSError:
                continue
            if comm == "sshd":
                return True
    except OSError:
        pass
    return False


def choose_backup_path(home: Path) -> Path:
    return backup_root(home) / f"ssh-{timestamp_slug()}"


def activate(
    db: Database,
    target: TargetUserContext,
    *,
    keep_authorized_keys: bool = True,
    force: bool = False,
    dry_run: bool = False,
    expected_inventory: Inventory | None = None,
    log=print,
) -> tuple[bool, Path | None]:
    """Phase 2: a single-shot, all-or-nothing SSH-directory replacement.

    ``(False, backup)`` is reserved for a fatal rollback failure; both paths
    are printed in that case.  Ordinary refusal/failure returns ``(False,
    None)``.
    """
    home = target.home
    source = home / ".ssh"
    installation = db.get_ssh_installation(str(home))
    phase = installation.get("phase") if installation else None
    filesystem_active = looks_like_canary_dir(source)

    if phase == PHASE_ACTIVATED and filesystem_active:
        log("BLOCKED: this SSH canary installation is already activated.")
        log("         Activation is permanently single-shot; --force cannot repeat it.")
        return False, None
    if phase == PHASE_ACTIVATED and not filesystem_active:
        log("BLOCKED: the database says SSH is activated, but ~/.ssh is not the")
        log("         recorded Honeypath canary directory. Do not activate again.")
        log("         Run `ssh-status` and `restore-ssh-canary`, or recover manually")
        log(f"         from the recorded backup: {installation.get('backup_path')}")
        return False, None
    if phase != PHASE_ACTIVATED and filesystem_active:
        log("BLOCKED: ~/.ssh is a Honeypath canary but the database is not activated.")
        log(
            "         This is a dangerous interrupted-state mismatch. Do not use --force;"
        )
        log("         restore the original backup manually, then re-run Phase 1.")
        return False, None
    if installation is None or phase != PHASE_PREPARED:
        log("BLOCKED: Phase 1 is not complete for this home.")
        return False, None
    if installation.get("backup_path"):
        log("BLOCKED: this installation already has an original activation backup.")
        log("         Activation is permanently single-shot; use the recorded backup")
        log(f"         for recovery: {installation.get('backup_path')}")
        return False, None

    try:
        source_info = safe_write.stat_nofollow(source, root=home)
    except FileNotFoundError:
        log("BLOCKED: ~/.ssh does not exist; nothing to canary.")
        return False, None
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"BLOCKED: cannot safely inspect ~/.ssh: {exc}")
        return False, None
    if stat.S_ISLNK(source_info.st_mode):
        log("BLOCKED: ~/.ssh is a symlink (dotfile repos commonly do this).")
        log("         Honeypath will not rename a symlink. Replace it with a real")
        log("         directory, or point the symlink target elsewhere, then retry.")
        return False, None

    if not stat.S_ISDIR(source_info.st_mode):
        log("BLOCKED: ~/.ssh is not a real directory.")
        return False, None

    config_path = relocated_config(home)
    try:
        config_info = safe_write.stat_nofollow(config_path, root=home)
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"BLOCKED: relocated config is missing or unsafe: {exc}")
        return False, None
    if not stat.S_ISREG(config_info.st_mode):
        log("BLOCKED: relocated config is not a regular file.")
        return False, None
    try:
        config_hash_before_rename = safe_write.sha256_anchored(config_path, root=home)
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"BLOCKED: cannot hash the relocated config safely: {exc}")
        return False, None

    validation, messages = validate_relocated_config(config_path, target=target)
    for message in messages:
        log(f"  {message}")
    if validation == "failed":
        log("BLOCKED: relocated SSH config validation failed.")
        return False, None
    bad_wrappers = [s for s in wrapper_statuses(home) if not s.exists or not s.ours]
    if bad_wrappers:
        log("BLOCKED: Phase-1 SSH wrappers are missing or no longer Honeypath-managed:")
        for wrapper in bad_wrappers:
            log(f"  {wrapper.describe()}")
        return False, None

    # This inventory is taken immediately before the rename.  The caller may
    # pass the just-synchronized snapshot; any intervening change then blocks.
    current_inventory = inventory_ssh_dir(source)
    if current_inventory.refused:
        log("BLOCKED: ~/.ssh contains entries that cannot be migrated safely:")
        for item in current_inventory.refused:
            log(f"  {item}")
        return False, None
    if expected_inventory is not None:
        try:
            verify_inventory_unchanged(expected_inventory, current_inventory)
        except SSHCanaryError as exc:
            log(f"BLOCKED: {exc}")
            return False, None
    try:
        verify_relocated_inventory(current_inventory, relocated_dir(home), root=home)
    except SSHCanaryError as exc:
        log(f"BLOCKED: {exc}")
        return False, None

    backup = choose_backup_path(home)
    if dry_run:
        try:
            safe_write.validate_destination(backup, home)
        except safe_write.SafeWriteError as exc:
            log(f"BLOCKED: unsafe backup destination: {exc}")
            return False, None
        log(f"  [dry-run] rename {source} -> {backup}")
        log(
            f"  [dry-run] create a fresh {source} (0700) with canaries: "
            # Same argument as the real creation path below, so the preview
            # cannot drift from what activation actually plants.
            + ", ".join(
                e.relative_path.split("/", 1)[1] for e in ssh_entries(PLATFORM_LINUX)
            )
        )
        return True, backup

    try:
        safe_write.safe_mkdir(
            backup_root(home),
            home,
            mode=MODE_DIR_PRIVATE,
            uid=target.uid,
            gid=target.gid,
            best_effort_metadata=False,
        )
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"BLOCKED: backup parent is unsafe or cannot be created: {exc}")
        return False, None
    try:
        safe_write.stat_nofollow(backup, root=home)
    except FileNotFoundError:
        pass
    except (OSError, safe_write.SafeWriteError) as exc:
        log(f"BLOCKED: cannot validate backup destination {backup}: {exc}")
        return False, None
    else:
        log(f"BLOCKED: backup destination already exists: {backup}")
        return False, None
    replacement_identity: os.stat_result | None = None
    renamed = False
    try:
        try:
            safe_write.rename_noreplace(source, backup, root=home)
        except OSError as rename_exc:
            if rename_exc.errno != errno.EXDEV:
                raise
            backup = home / f".ssh.honeypath-backup.{timestamp_slug()}"
            try:
                safe_write.stat_nofollow(backup, root=home)
            except FileNotFoundError:
                pass
            else:
                raise SSHCanaryError(f"fallback backup already exists: {backup}")
            log("WARNING: backup root is on a different filesystem (EXDEV).")
            log(f"         Falling back to {backup}; this path is more glob-visible.")
            safe_write.rename_noreplace(source, backup, root=home)
        renamed = True
        log(f"  original ~/.ssh backed up to: {backup}")

        # Re-open from the anchored backup name and prove that the directory
        # actually renamed is byte-for-byte the snapshot whose relocated copy
        # was just verified.  A late key/config/known_hosts change restores the
        # original name and aborts before any canary is created.
        backup_inventory = inventory_ssh_dir(backup)
        verify_inventory_unchanged(current_inventory, backup_inventory)
        verify_relocated_inventory(backup_inventory, relocated_dir(home), root=home)
        if (
            safe_write.sha256_anchored(config_path, root=home)
            != config_hash_before_rename
        ):
            raise SSHCanaryError("relocated config changed during activation")
        final_validation, final_messages = validate_relocated_config(
            config_path, target=target
        )
        for message in final_messages:
            log(f"  {message}")
        if final_validation == "failed":
            raise SSHCanaryError("relocated config failed validation after SSH backup")

        replacement_identity = safe_write.create_directory_exclusive(
            source,
            root=home,
            mode=MODE_DIR_PRIVATE,
            uid=target.uid,
            gid=target.gid,
            best_effort_metadata=False,
        )
        manifest: list[dict] = []
        for entry in ssh_entries(PLATFORM_LINUX):
            path = home / entry.relative_path
            outcome = create_canary_file(
                path,
                entry.content,
                entry.mode,
                target,
                replace_managed=False,
                root=home,
                best_effort=False,
                durable=True,
            )
            log(f"  {outcome.reason}: {path}")
            if not outcome.created or outcome.problems:
                raise SSHCanaryError(
                    f"required canary creation failed for {path}: "
                    f"{outcome.reason}; {'; '.join(outcome.problems)}"
                )
            # The verification read advances atime.  Capture the baseline
            # afterwards from the exact descriptor that was hashed, otherwise
            # the first watch run reports Honeypath's own read as an alert.
            verify_fd = safe_write.open_regular_nofollow(path, root=home)
            try:
                content_hash = safe_write.sha256_fd(verify_fd)
                info = os.fstat(verify_fd)
            finally:
                os.close(verify_fd)
            expected_hash = sha256_text(entry.content)
            if not stat.S_ISREG(info.st_mode) or content_hash != expected_hash:
                raise SSHCanaryError(f"exact identity verification failed for {path}")
            if stat.S_IMODE(info.st_mode) != entry.mode:
                raise SSHCanaryError(
                    f"mode verification failed for {path}: "
                    f"{oct(stat.S_IMODE(info.st_mode))} != {oct(entry.mode)}"
                )
            if (info.st_uid, info.st_gid) != (target.uid, target.gid):
                raise SSHCanaryError(
                    f"ownership verification failed for {path}: "
                    f"{info.st_uid}:{info.st_gid} != {target.uid}:{target.gid}"
                )
            manifest.append(
                {
                    "canary_id": entry.key,
                    "path": str(path),
                    "kind": entry.kind,
                    "severity": entry.severity,
                    "profile": entry.profile,
                    "platform": entry.platform,
                    "intrusiveness": entry.intrusiveness,
                    "baseline_atime": info.st_atime_ns,
                    "content_hash": content_hash,
                    "managed_marker": managed_marker(entry.key),
                    "file_dev": info.st_dev,
                    "file_ino": info.st_ino,
                }
            )

        authorized_changes: list[dict] = []
        if keep_authorized_keys:
            authorized_changes = _restore_authorized_keys(
                backup, source, target, log=log
            )

        db.finalize_ssh_activation(
            home=str(home),
            backup_path=str(backup),
            activated_at=utc_now(),
            canaries=manifest,
            authorized_changes=authorized_changes,
        )
    except Exception as exc:
        log(f"FAILED: SSH activation did not complete: {exc}")
        if not renamed:
            return False, None
        try:
            if replacement_identity is not None:
                safe_write.remove_tree_if_identity(
                    source,
                    root=home,
                    expected_dev=replacement_identity.st_dev,
                    expected_ino=replacement_identity.st_ino,
                )
            else:
                # Exclusive directory creation cleans itself up on metadata
                # failure, so the original name should still be absent.
                try:
                    safe_write.stat_nofollow(source, root=home)
                except FileNotFoundError:
                    pass
                else:
                    raise SSHCanaryError(
                        "an unverified replacement appeared at ~/.ssh during rollback"
                    )
            safe_write.rename_noreplace(backup, source, root=home)
            log(f"ROLLBACK COMPLETE: restored original SSH directory to {source}")
            return False, None
        except Exception as rollback_exc:
            log("FATAL: AUTOMATIC SSH ACTIVATION ROLLBACK FAILED")
            log(f"  incomplete/new location: {source}")
            log(f"  original SSH backup:     {backup}")
            log(f"  activation error:        {exc}")
            log(f"  rollback error:          {rollback_exc}")
            log("Do not activate again. Move the original backup back manually after")
            log("inspecting both locations.")
            return False, backup

    # The database transaction above is the activation commit boundary.
    # Post-commit reporting failures must not restore the old filesystem while
    # leaving SQLite in the activated state.
    log(f"  registered {len(manifest)} SSH canaries")
    return True, backup


def _restore_authorized_keys(
    backup: Path,
    ssh_dir: Path,
    target: TargetUserContext,
    *,
    log=print,
) -> list[dict]:
    """Copy every server-side authorized-keys file back into the new ~/.ssh.

    Both names are in GENERATED_FILES, so neither is migrated to the relocated
    directory.  Restoring only ``authorized_keys`` would therefore silently
    discard a configured ``authorized_keys2``.
    """
    changes: list[dict] = []
    for name in AUTHORIZED_KEYS_FILES:
        change = _restore_one_authorized_keys(backup, ssh_dir, target, name, log=log)
        if change is not None:
            changes.append(change)
    return changes


def _restore_one_authorized_keys(
    backup: Path,
    ssh_dir: Path,
    target: TargetUserContext,
    name: str,
    *,
    log=print,
) -> dict | None:
    source = backup / name
    try:
        source_info = safe_write.stat_nofollow(source, root=backup)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(source_info.st_mode):
        raise SSHCanaryError(f"{name} in the backup is not a regular file")
    destination = ssh_dir / name
    try:
        # fsync'd: losing this file silently breaks inbound SSH logins.
        for warning in safe_write.atomic_copy(
            source,
            destination,
            mode=MODE_FILE_PRIVATE,
            root=target.home,
            source_root=backup,
            uid=target.uid,
            gid=target.gid,
            fsync_data=True,
            replace=False,
        ):
            raise SSHCanaryError(f"{name} metadata/durability failure: {warning}")
    except (OSError, safe_write.SafeWriteError) as exc:
        raise SSHCanaryError(f"could not restore {name}: {exc}") from None
    destination_info = safe_write.stat_nofollow(destination, root=target.home)
    source_hash = safe_write.sha256_anchored(source, root=backup)
    if safe_write.sha256_anchored(destination, root=target.home) != source_hash:
        raise SSHCanaryError(f"{name} verification failed after restoration")
    log(f"  preserved {name} (from {source}) — not registered as a canary")
    return {
        "target": str(destination),
        "source": str(source),
        "content_hash": source_hash,
        "file_dev": destination_info.st_dev,
        "file_ino": destination_info.st_ino,
    }


def looks_like_canary_dir(ssh_dir: Path) -> bool:
    config = ssh_dir / "config"
    try:
        return "HONEYPATH CANARY" in safe_write.read_text_nofollow(
            config, root=ssh_dir.parent, errors="replace"
        )
    except (OSError, safe_write.SafeWriteError):
        return False


# --------------------------------------------------------------------------
# Status (§8.9)
# --------------------------------------------------------------------------


def which_ssh(target: TargetUserContext) -> str | None:
    proc = run_as_target(["bash", "-lc", "command -v ssh"], target)
    value = (proc.stdout or "").strip().splitlines()
    return value[-1] if value else None


def ssh_state(db: Database, target: TargetUserContext) -> dict:
    home = target.home
    ssh_dir = home / ".ssh"
    installation = db.get_ssh_installation(str(home))
    return {
        "home": home,
        "ssh_dir_exists": ssh_dir.exists(),
        "ssh_dir_is_symlink": ssh_dir.is_symlink(),
        "ssh_dir_is_canary": looks_like_canary_dir(ssh_dir),
        "relocated_dir": relocated_dir(home),
        "relocated_dir_exists": relocated_dir(home).is_dir(),
        "relocated_config": relocated_config(home),
        "relocated_config_exists": relocated_config(home).is_file(),
        "wrappers": wrapper_statuses(home),
        "installation": installation,
        "authorized_keys": (ssh_dir / "authorized_keys").exists(),
        "sshd_running": sshd_running(),
    }
