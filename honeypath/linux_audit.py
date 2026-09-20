"""Linux Audit preflight and persistent read rules for Honeypath canaries.

Audit owns the durable, attributed record. Honeypath's unprivileged inotify
watcher still owns immediate alert delivery: giving it access to the complete
root audit log would expose unrelated security records and weaken the service
boundary for little benefit.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from . import safe_write

AUDIT_SERVICE = "auditd.service"
AUDIT_KEY = "honeypath-read"
RULES_PATH = Path("/etc/audit/rules.d/70-honeypath.rules")
MANAGED_MARKER = "# Managed by Honeypath; do not edit by hand."


def command_available(name: str) -> bool:
    return shutil.which(name) is not None


def service_state() -> tuple[bool, bool, str]:
    """Return auditd's (active, enabled, diagnostic) state."""
    if not command_available("systemctl"):
        return False, False, "systemctl is not installed"
    active = subprocess.run(
        ["systemctl", "is-active", "--quiet", AUDIT_SERVICE],
        capture_output=True,
        text=True,
        check=False,
    ).returncode == 0
    enabled = subprocess.run(
        ["systemctl", "is-enabled", "--quiet", AUDIT_SERVICE],
        capture_output=True,
        text=True,
        check=False,
    ).returncode == 0
    detail = f"{AUDIT_SERVICE} is {'active' if active else 'inactive'} and "
    detail += "enabled" if enabled else "disabled"
    return active, enabled, detail


def enable_service(*, dry_run: bool = False) -> tuple[bool, str]:
    command = ["systemctl", "enable", "--now", AUDIT_SERVICE]
    if dry_run:
        return True, "[dry-run] would run: " + " ".join(command)
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return True, f"{AUDIT_SERVICE} enabled and active"
    detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
    return False, detail


def audit_arches(machine: str | None = None) -> tuple[str, ...]:
    """Architectures needed to cover native and compat processes."""
    machine = (machine or platform.machine()).lower()
    if machine in {"x86_64", "amd64"}:
        return ("b64", "b32")
    if machine in {"aarch64", "arm64", "ppc64", "ppc64le", "s390x"}:
        return ("b64",)
    return ("b32",) if machine else ("b64",)


def _safe_rule_path(raw: str) -> str:
    path = Path(raw)
    if not path.is_absolute():
        raise ValueError(f"audit path is not absolute: {raw}")
    # audit.rules is whitespace-tokenised and has no general shell-style path
    # quoting. Catalog paths do not contain whitespace; refuse rather than
    # generate a different rule than the one shown to the operator.
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"audit path contains unsupported whitespace: {raw}")
    return raw


def rules_text(canaries, *, machine: str | None = None) -> str:
    """Render exact-path read rules for active native-Linux canaries."""
    paths = sorted(
        {
            _safe_rule_path(canary.path)
            for canary in canaries
            if canary.active and canary.platform == "linux"
        }
    )
    lines = [
        MANAGED_MARKER,
        "# Records opens requesting read access; inotify delivers immediate alerts.",
    ]
    for path in paths:
        for arch in audit_arches(machine):
            lines.append(
                f"-a always,exit -F arch={arch} -F path={path} "
                f"-F perm=r -F key={AUDIT_KEY}"
            )
    return "\n".join(lines) + "\n"


def install_rules(
    canaries,
    *,
    rules_path: Path = RULES_PATH,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Install and load the managed audit rule file without clobbering others."""
    canaries = list(canaries)
    try:
        content = rules_text(canaries)
    except ValueError as exc:
        return False, str(exc)
    count = sum(
        1
        for canary in canaries
        if canary.active and canary.platform == "linux"
    )
    if count == 0:
        return False, "no active Linux canaries are recorded"
    if dry_run:
        return (
            True,
            f"[dry-run] would write {rules_path} for {count} canary path(s) "
            "and load it with augenrules",
        )
    if os.geteuid() != 0:
        return False, "installing Linux Audit rules requires sudo"
    if not command_available("augenrules"):
        return False, "augenrules is not installed (install the audit package)"

    try:
        previous_hash = None
        if rules_path.exists():
            existing = rules_path.read_text(encoding="utf-8", errors="replace")
            if not existing.startswith(MANAGED_MARKER):
                return False, f"refusing to replace unmanaged file {rules_path}"
            previous_hash = safe_write.sha256_anchored(
                rules_path, root=rules_path.parent
            )
        safe_write.atomic_write(
            rules_path,
            content,
            mode=0o600,
            root=rules_path.parent,
            uid=0,
            gid=0,
            fsync_data=True,
            replace=previous_hash is not None,
            expected_sha256=previous_hash,
        )
    except (OSError, safe_write.SafeWriteError) as exc:
        return False, f"could not write {rules_path}: {exc}"

    for command in (["augenrules", "--check"], ["augenrules", "--load"]):
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
            return False, f"{' '.join(command)} failed: {detail}"
    listed = subprocess.run(
        ["auditctl", "-l"], capture_output=True, text=True, check=False
    )
    if listed.returncode != 0:
        detail = listed.stderr.strip() or listed.stdout.strip() or "unknown error"
        return False, f"rules were written but runtime verification failed: {detail}"
    missing = []
    for path in sorted(
        {
            canary.path
            for canary in canaries
            if canary.active and canary.platform == "linux"
        }
    ):
        for arch in audit_arches():
            if not any(
                f"arch={arch}" in line
                and f"path={path}" in line
                and (f"key={AUDIT_KEY}" in line or f"-k {AUDIT_KEY}" in line)
                for line in listed.stdout.splitlines()
            ):
                missing.append(f"{arch}:{path}")
    if missing:
        return (
            False,
            "persistent rules were written but are not active; Audit may be "
            "immutable or another rule may have blocked loading (missing "
            + ", ".join(missing[:3])
            + (" ..." if len(missing) > 3 else "")
            + ")",
        )
    return True, f"installed Audit read rules for {count} canary path(s)"
