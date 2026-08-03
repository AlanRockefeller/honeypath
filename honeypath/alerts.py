"""Pushover alerting.

What happens to the token and user key
--------------------------------------
They are read from /etc/honeypath/ and **transmitted over HTTPS to the
official Pushover API** (https://api.pushover.net/1/messages.json) as the
``token`` and ``user`` form fields.  That transmission is unavoidable: it is
how Pushover authenticates the alert request, and it is the entire point of
configuring them.

Everything else is prohibited, and enforced by tests:

* they are never printed to stdout/stderr;
* they are never written into an alert message body;
* they are never stored in SQLite — not in ``events``, not in
  ``managed_changes``, not in ``schema_metadata``;
* they are never interpolated into an error string, including the strings
  built from HTTP error responses;
* ``doctor`` reports only their existence, mode and owner, never contents.

The single deliberate exception, clearly flagged at the point of use, is the
optional Windows-resident watcher (``setup-windows-audit
--install-windows-watcher``), which writes a PowerShell script containing both
values onto the Windows filesystem.  It is opt-in, prompts first, and
``setup-windows-audit --restore`` removes it.

A delivery failure never loses an event: the event is still recorded, with the
failure reason in ``events.pushover_error``.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import safe_write

CONFIG_DIR = Path("/etc/honeypath")
TOKEN_FILE = CONFIG_DIR / "pushover-token"
USER_FILE = CONFIG_DIR / "pushover-user"
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"

SEVERITY_PRIORITY = {"critical": 1, "high": 0, "medium": -1, "low": -1}


@dataclass
class CredentialStatus:
    """Existence and permissions only — never contents."""

    path: Path
    exists: bool
    mode: str | None
    owner_uid: int | None
    world_readable: bool

    def describe(self) -> str:
        if not self.exists:
            return f"{self.path}: MISSING"
        flag = "  (WORLD-READABLE)" if self.world_readable else ""
        return f"{self.path}: present, mode {self.mode}, uid {self.owner_uid}{flag}"


def _status(path: Path) -> CredentialStatus:
    try:
        st = path.stat()
    except OSError:
        return CredentialStatus(path, False, None, None, False)
    return CredentialStatus(
        path=path,
        exists=True,
        mode=oct(st.st_mode & 0o777),
        owner_uid=st.st_uid,
        world_readable=bool(st.st_mode & 0o004),
    )


def credential_status() -> list[CredentialStatus]:
    return [_status(TOKEN_FILE), _status(USER_FILE)]


def store_credentials(
    token: str,
    user_key: str,
    *,
    group_gid: int,
    config_dir: Path = CONFIG_DIR,
) -> tuple[Path, Path]:
    """Securely store Pushover credentials for root and the service group."""
    token = token.strip()
    user_key = user_key.strip()
    if not token or not user_key:
        raise ValueError("both the application token and user key are required")
    if any(ch in token or ch in user_key for ch in ("\n", "\r", "\x00")):
        raise ValueError("credentials must each be a single line")

    try:
        config_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        info = config_dir.lstat()
    except OSError as exc:
        raise OSError(f"cannot create {config_dir}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"refusing unsafe configuration directory: {config_dir}")

    # The service runs as the target user.  Root-owned, group-readable files
    # let it read the credentials without making them world-readable.
    os.chown(config_dir, 0, group_gid)
    os.chmod(config_dir, 0o750)
    token_file = config_dir / TOKEN_FILE.name
    user_file = config_dir / USER_FILE.name
    for path, value in ((token_file, token), (user_file, user_key)):
        safe_write.atomic_write(
            path,
            value + "\n",
            mode=0o640,
            root=config_dir,
            uid=0,
            gid=group_gid,
            fsync_data=True,
            best_effort_metadata=False,
            replace=True,
        )
    return token_file, user_file


def _read_secret(path: Path) -> str | None:
    try:
        value = path.read_text().strip()
    except OSError:
        return None
    return value or None


REDACTED = "<redacted>"

# Anything shorter than this is not a real Pushover credential (both are 30
# characters), and blanket-replacing a 1-3 character string would mangle
# unrelated error text into uselessness.
_MIN_REDACTABLE = 8


def redact_secrets(text: str, *secrets: str | None) -> str:
    """Remove credential values from a string that may be stored or printed.

    Defence in depth: no code path is *supposed* to put a credential into an
    error message, but error text arrives from urllib, from the remote server
    and from the OS, and any of those could echo the request back.  Every
    error string leaving :meth:`Pushover.send` goes through here before it can
    reach ``events.pushover_error``.
    """
    for secret in secrets:
        if secret and len(secret) >= _MIN_REDACTABLE:
            text = text.replace(secret, REDACTED)
    return text


class Pushover:
    def __init__(self, token_file: Path = TOKEN_FILE, user_file: Path = USER_FILE):
        self.token_file = token_file
        self.user_file = user_file

    def configured(self) -> bool:
        return bool(_read_secret(self.token_file) and _read_secret(self.user_file))

    def missing_reason(self) -> str | None:
        if not _read_secret(self.token_file):
            return f"missing or empty {self.token_file}"
        if not _read_secret(self.user_file):
            return f"missing or empty {self.user_file}"
        return None

    def send(
        self,
        message: str,
        *,
        title: str = "Honeypath",
        priority: int = 0,
        timeout: int = 15,
    ) -> tuple[bool, str | None]:
        """Send a notification.  Returns ``(sent, error)``.

        The error string is safe to store and print: every path that builds one
        passes it through :func:`redact_secrets` first.  This matters because
        the returned string is persisted in ``events.pushover_error`` and
        printed by ``honeypath.py events`` — an error text that happened to
        echo the request (a hostile endpoint, a proxy, a urllib internal that
        includes the payload) would otherwise leak the credentials into the
        database and onto the operator's terminal.
        """
        token = _read_secret(self.token_file)
        user = _read_secret(self.user_file)
        if not token or not user:
            return False, self.missing_reason() or "pushover not configured"

        def fail(reason: str) -> tuple[bool, str | None]:
            return False, redact_secrets(reason, token, user)

        payload = urllib.parse.urlencode(
            {
                "token": token,
                "user": user,
                "message": message,
                "title": title,
                "priority": str(priority),
            }
        ).encode("ascii")

        request = urllib.request.Request(
            PUSHOVER_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body else {}
            if parsed.get("status") == 1:
                return True, None
            errors = parsed.get("errors") or ["unexpected Pushover response"]
            return fail("; ".join(str(e) for e in errors))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
                parsed = json.loads(body)
                detail = "; ".join(str(e) for e in parsed.get("errors", []))
            except Exception:
                detail = ""
            return fail(f"HTTP {exc.code}{': ' + detail if detail else ''}")
        except urllib.error.URLError as exc:
            return fail(f"network error: {exc.reason}")
        except (TimeoutError, socket.timeout):
            return fail(f"timed out after {timeout}s")
        except json.JSONDecodeError:
            return fail("malformed Pushover response")
        except OSError as exc:
            return fail(f"send failed: {exc}")


def format_alert(event: dict) -> str:
    """The short alert body defined in §10."""
    severity = event.get("severity") or "unknown"
    kind = event.get("kind") or "canary"
    method = event.get("method") or "unknown"
    lines = [
        f"HONEYPATH {severity} {kind} via {method}",
        event.get("path", ""),
    ]
    process_info = event.get("process_info")
    if process_info:
        lines.append(str(process_info))
    return "\n".join(line for line in lines if line)


def alert_priority(severity: str | None) -> int:
    return SEVERITY_PRIORITY.get((severity or "").lower(), 0)


def hostname() -> str:
    return os.environ.get("HONEYPATH_HOSTNAME") or socket.gethostname()
