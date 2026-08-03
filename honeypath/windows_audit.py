"""Windows-side read detection from WSL, via SACL auditing and interop.

Why this module exists
----------------------
inotify on ``/mnt/c`` (9p/drvfs) only sees reads performed *by WSL*.  A
Windows-native stealer opening ``C:\\Users\\alanr\\.ssh\\id_rsa`` is completely
invisible to it, and NTFS last-access times are unreliable by default.

Windows object-access auditing (Security log event 4663) is the one clean
read-detection mechanism available here.  It also gives what inotify cannot:
the image path of the process that did the reading.  And because the OS
writes the Security log whether or not WSL is running, Honeypath can catch up
on everything it missed after a reboot.

``FileSystemWatcher`` is *not* an alternative — it reports creates, writes,
renames and deletes, never reads.
"""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import safe_write
from .database import Database
from .monitor import EVENT_READ, METHOD_WIN_AUDIT, RawHit, Watcher
from .platform_detect import (
    InteropResult,
    fsutil_disablelastaccess,
    interop_available,
    run_interop,
    run_powershell,
    to_windows_path,
)

CHANGE_SACL = "windows-sacl"
CHANGE_AUDIT_POLICY = "windows-audit-policy"
CHANGE_SCHEDULED_TASK = "windows-scheduled-task"
CHANGE_FSUTIL = "windows-fsutil-lastaccess"

TASK_NAME = "HoneypathCanaryWatcher"
LAST_RECORD_KEY = "win_audit_last_record_id"
LOG_GENERATION_KEY = "win_audit_log_generation"

_PS_EXTRACT_4663 = r"""
$ErrorActionPreference = 'SilentlyContinue'
$checkpoint = [int64]{checkpoint}
$xpath = "*[System[(EventID=4663) and (EventRecordID > $checkpoint)]]"
$events = Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents {max_events} -ErrorAction SilentlyContinue
$oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
$newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
$out = foreach ($e in $events) {{
  $x = [xml]$e.ToXml()
  $d = @{{}}
  foreach ($n in $x.Event.EventData.Data) {{ $d[$n.Name] = $n.'#text' }}
  [pscustomobject]@{{
    RecordId    = [string]$e.RecordId
    TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
    ObjectName  = [string]$d['ObjectName']
    ProcessName = [string]$d['ProcessName']
    ProcessId   = [string]$d['ProcessId']
    SubjectUser = [string]$d['SubjectUserName']
    AccessList  = [string]$d['AccessList']
  }}
}}
[pscustomobject]@{{
  OldestRecordId = if ($oldest) {{ [string]$oldest.RecordId }} else {{ '0' }}
  NewestRecordId = if ($newest) {{ [string]$newest.RecordId }} else {{ '0' }}
  Events = @($out)
}} | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class WindowsAuditStatus:
    interop: bool = False
    elevated: bool | None = None
    audit_policy: str | None = None
    audit_policy_error: str | None = None
    security_log_readable: bool | None = None
    security_log_error: str | None = None
    sacl_paths: list[tuple[str, str, bool]] = field(default_factory=list)
    scheduled_task: str | None = None
    fsutil_value: str | None = None
    fsutil_error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def audit_enabled(self) -> bool:
        return bool(self.audit_policy and "Success" in self.audit_policy)


def _ps_bool(result: InteropResult) -> bool | None:
    if not result.ok:
        return None
    text = result.stdout.strip().lower()
    if text.startswith("true"):
        return True
    if text.startswith("false"):
        return False
    return None


def is_elevated() -> bool | None:
    return _ps_bool(
        run_powershell(
            "([Security.Principal.WindowsPrincipal]"
            "[Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
        )
    )


def audit_policy_state() -> tuple[str | None, str | None]:
    result = run_interop(["auditpol.exe", "/get", "/subcategory:File System"])
    if not result.ok:
        return None, result.error or result.stderr.strip() or "auditpol failed"
    for line in result.stdout.splitlines():
        if "File System" in line:
            return line.strip(), None
    return result.stdout.strip() or None, None


def enable_audit_policy() -> tuple[bool, str]:
    result = run_interop(
        ["auditpol.exe", "/set", "/subcategory:File System", "/success:enable"]
    )
    if result.ok:
        return True, "object-access auditing (File System / Success) enabled"
    return False, result.error or result.stderr.strip() or "auditpol failed"


def disable_success_audit_policy() -> tuple[bool, str]:
    result = run_interop(
        ["auditpol.exe", "/set", "/subcategory:File System", "/success:disable"]
    )
    if result.ok:
        return True, "File System / Success auditing disabled"
    return False, result.error or result.stderr.strip() or "auditpol failed"


def security_log_readable() -> tuple[bool, str | None]:
    result = run_powershell(
        "try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | "
        "Out-Null; 'OK' } catch { 'ERR: ' + $_.Exception.Message }"
    )
    if not result.ok:
        return False, result.error or result.stderr.strip() or "powershell failed"
    text = result.stdout.strip()
    if text.startswith("OK"):
        return True, None
    return False, text or "unknown error"


def has_audit_rule(windows_path: str) -> bool | None:
    script = (
        f"$p = '{_ps_quote(windows_path)}'; "
        "try { $a = (Get-Acl -Path $p -Audit).Audit | "
        "Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value "
        "-eq 'S-1-1-0' }; "
        "if ($a) { 'YES' } else { 'NO' } } catch { 'ERR' }"
    )
    result = run_powershell(script)
    if not result.ok:
        return None
    text = result.stdout.strip()
    if text == "YES":
        return True
    if text == "NO":
        return False
    return None


def _ps_quote(value: str) -> str:
    """Escape for a PowerShell single-quoted string."""
    return value.replace("'", "''")


def capture_and_apply_audit_rule(
    windows_path: str,
) -> tuple[bool, str, str | None, str | None]:
    """Capture the exact SACL, add our SID ACE, and return both exact states."""
    script = (
        f"$p = '{_ps_quote(windows_path)}'; "
        "try {"
        " $acl = Get-Acl -Path $p -Audit -ErrorAction Stop;"
        " $sections = [System.Security.AccessControl.AccessControlSections]::Audit;"
        " $before = $acl.GetSecurityDescriptorSddlForm($sections);"
        " if ($null -eq $before) { throw 'original SACL capture returned null' };"
        " $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0');"
        " $rule = New-Object System.Security.AccessControl.FileSystemAuditRule("
        "$sid,'ReadData','None','None','Success');"
        " $acl.AddAuditRule($rule);"
        " Set-Acl -Path $p -AclObject $acl -ErrorAction Stop;"
        " $afterAcl = Get-Acl -Path $p -Audit -ErrorAction Stop;"
        " $after = $afterAcl.GetSecurityDescriptorSddlForm($sections);"
        " [pscustomobject]@{Ok=$true;Before=$before;After=$after;Error=''} | "
        "ConvertTo-Json -Compress"
        "} catch { [pscustomobject]@{Ok=$false;Before=$before;After=$null;"
        "Error=$_.Exception.Message} | ConvertTo-Json -Compress }"
    )
    result = run_powershell(script, timeout=30)
    if not result.ok:
        return (
            False,
            result.error or result.stderr.strip() or "powershell failed",
            None,
            None,
        )
    try:
        payload = json.loads(result.stdout.strip())
    except (json.JSONDecodeError, TypeError):
        return False, "unparseable SACL capture/apply response", None, None
    if payload.get("Ok") and payload.get("Before") is not None and payload.get("After"):
        return (
            True,
            "audit ACE applied with exact SACL snapshot",
            payload["Before"],
            payload["After"],
        )
    return (
        False,
        payload.get("Error") or "SACL capture/apply failed",
        payload.get("Before"),
        None,
    )


def apply_audit_rule(windows_path: str) -> tuple[bool, str]:
    ok, detail, _before, _after = capture_and_apply_audit_rule(windows_path)
    return ok, detail


def restore_exact_sacl(
    windows_path: str, original_sddl: str, expected_post_sddl: str
) -> tuple[bool, str]:
    script = (
        f"$p = '{_ps_quote(windows_path)}'; "
        f"$before = '{_ps_quote(original_sddl)}'; "
        f"$expected = '{_ps_quote(expected_post_sddl)}'; "
        "try {"
        " $sections = [System.Security.AccessControl.AccessControlSections]::Audit;"
        " $acl = Get-Acl -Path $p -Audit -ErrorAction Stop;"
        " $current = $acl.GetSecurityDescriptorSddlForm($sections);"
        " if ($current -cne $expected) { 'CONFLICT: current SACL changed independently'; exit 3 };"
        " $acl.SetSecurityDescriptorSddlForm($before, $sections);"
        " Set-Acl -Path $p -AclObject $acl -ErrorAction Stop;"
        " $verify = (Get-Acl -Path $p -Audit -ErrorAction Stop)."
        "GetSecurityDescriptorSddlForm($sections);"
        " if ($verify -cne $before) { throw 'exact SACL verification failed' };"
        " 'OK: exact original SACL restored'"
        "} catch { 'ERR: ' + $_.Exception.Message }"
    )
    result = run_powershell(script, timeout=30)
    if not result.ok:
        return False, result.error or result.stderr.strip() or "powershell failed"
    text = result.stdout.strip()
    return (text.startswith("OK"), text or "unknown error")


def remove_audit_rule(windows_path: str) -> tuple[bool, str]:
    """Legacy entry point intentionally refuses heuristic ACE removal."""
    return False, "exact original SACL metadata is required for restoration"


def set_fsutil_lastaccess(value: str = "0") -> tuple[bool, str]:
    result = run_interop(
        ["fsutil.exe", "behavior", "set", "disablelastaccess", value], timeout=30
    )
    if result.ok:
        return True, result.stdout.strip() or f"disablelastaccess set to {value}"
    return False, result.error or result.stderr.strip() or "fsutil failed"


def scheduled_task_state() -> str | None:
    result = run_interop(["schtasks.exe", "/query", "/tn", TASK_NAME], timeout=20)
    if result.ok:
        return "installed"
    if result.error:
        return None
    return "not installed"


# --------------------------------------------------------------------------
# Status / setup
# --------------------------------------------------------------------------


def collect_status(db: Database, windows_home: Path | None) -> WindowsAuditStatus:
    status = WindowsAuditStatus()
    status.interop = interop_available()
    if not status.interop:
        status.notes.append(
            "WSL interop is unavailable; Windows-side auditing cannot be inspected"
        )
        return status

    status.elevated = is_elevated()
    status.audit_policy, status.audit_policy_error = audit_policy_state()
    status.security_log_readable, status.security_log_error = security_log_readable()
    status.fsutil_value, status.fsutil_error = fsutil_disablelastaccess()
    status.scheduled_task = scheduled_task_state()

    recorded = db.get_managed_changes(change_type=CHANGE_SACL)
    for change in recorded:
        win_path = change.get("new_value") or ""
        present = has_audit_rule(win_path) if win_path else None
        status.sacl_paths.append((change["target"], win_path, bool(present)))
    if not recorded and windows_home is not None:
        status.notes.append(
            "no SACLs recorded; run setup-windows-audit to enable Windows-side detection"
        )
    return status


def windows_canary_paths(db: Database) -> list:
    return [c for c in db.get_canaries(active_only=True, platform="windows")]


def setup_windows_audit(
    db: Database,
    *,
    dry_run: bool = False,
    log=print,
    offer_fsutil: bool = True,
    confirm=None,
) -> int:
    """Enable Windows object-access auditing for the recorded Windows canaries."""
    if not interop_available():
        log("WSL interop is unavailable — cannot configure Windows auditing.")
        log("Enable interop (/etc/wsl.conf: [interop] enabled=true) and retry.")
        return 2

    elevated = is_elevated()
    if elevated is False:
        log("This WSL session cannot run elevated Windows commands.")
        log("Open an ELEVATED PowerShell on Windows and run:")
        log('    auditpol /set /subcategory:"File System" /success:enable')
        log("then re-run this command from an elevated WSL session:")
        log(
            "    wsl.exe -d $WSL_DISTRO_NAME -- sudo python3 honeypath.py setup-windows-audit"
        )
        log("(SACL changes require SeSecurityPrivilege; they will fail without it.)")

    canaries = windows_canary_paths(db)
    if not canaries:
        log("No Windows-home canaries are recorded. Run create-canaries first.")
        return 1

    log(f"Windows canaries to audit: {len(canaries)}")
    for canary in canaries:
        log(f"  {canary.path}")
    if dry_run:
        log(
            "\n[dry-run] would enable auditpol File System/Success and apply "
            "ReadData audit ACEs to the paths above."
        )
        return 0
    if confirm is not None and not confirm("Apply Windows audit configuration?"):
        log("Aborted.")
        return 1

    original_policy, original_policy_error = audit_policy_state()
    if original_policy is None or original_policy_error:
        log(
            "Policy pre-state captured: NO — "
            + (original_policy_error or "auditpol returned no File System state")
        )
        log("No policy or SACL change was made; exact restoration would be impossible.")
        return 1
    log(f"Policy pre-state captured: YES — {original_policy}")
    ok, detail = enable_audit_policy()
    log(f"Policy enabled: {'YES' if ok else 'NO'} — {detail}")
    if not ok:
        log("No SACLs were changed because required audit-policy setup failed.")
        return 1
    verified_policy, verify_error = audit_policy_state()
    policy_verified = bool(verified_policy and "Success" in verified_policy)
    log(
        f"Policy verified: {'YES' if policy_verified else 'NO'} — "
        f"{verified_policy or verify_error or 'required Success state absent'}"
    )
    if not policy_verified:
        log(
            "No SACLs were changed because required detection components failed verification."
        )
        return 1

    # Record the external policy mutation as soon as it is verified.  Later
    # validation may fail, but restore must still know how to undo it.
    db.record_managed_change(
        change_type=CHANGE_AUDIT_POLICY,
        target="File System/Success",
        previous_existed=bool(original_policy and "Success" in original_policy),
        previous_value=original_policy or original_policy_error,
        new_value=verified_policy,
        notes="auditpol enable succeeded and was verified",
    )

    readable, readable_error = security_log_readable()
    log(
        f"Security log readable: {'YES' if readable else 'NO'}"
        + (f" — {readable_error}" if readable_error else "")
    )
    if not readable:
        log(
            "No SACLs were changed because required detection components failed verification."
        )
        return 1

    applied = failed = 0
    staged: list[tuple[object, str, str, str]] = []
    for canary in canaries:
        win_path = to_windows_path(Path(canary.path))
        if not win_path:
            log(f"  SKIP {canary.path}: wslpath conversion failed")
            failed += 1
            continue
        success, detail, before_sddl, after_sddl = capture_and_apply_audit_rule(
            win_path
        )
        if success:
            applied += 1
            log(f"  SACL applied: YES {canary.path} -> {win_path}")
            assert before_sddl is not None and after_sddl is not None
            staged.append((canary, win_path, before_sddl, after_sddl))
        else:
            failed += 1
            log(f"  SACL applied: NO  {canary.path}: {detail}")
            break

    if failed:
        rollback_failed = 0
        log("A later SACL failed; restoring every earlier exact original SACL:")
        for canary, win_path, before_sddl, after_sddl in reversed(staged):
            restored, restore_detail = restore_exact_sacl(
                win_path, before_sddl, after_sddl
            )
            log(f"  {canary.path}: {'restored' if restored else restore_detail}")
            rollback_failed += int(not restored)
        log(
            f"Audit ACEs applied before failure: {applied}; rollback failures: {rollback_failed}"
        )
        return 1

    recorded_ids: list[int] = []
    try:
        for canary, win_path, before_sddl, after_sddl in staged:
            recorded_ids.append(
                db.record_managed_change(
                    change_type=CHANGE_SACL,
                    target=canary.path,
                    previous_existed=True,
                    previous_value=before_sddl,
                    new_value=win_path,
                    content_hash=after_sddl,
                    notes="exact original SACL and expected post-Honeypath SACL (SDDL)",
                )
            )
    except Exception as exc:
        log(f"Database recording failed; rolling SACLs back: {exc}")
        for canary, win_path, before_sddl, after_sddl in reversed(staged):
            restored, restore_detail = restore_exact_sacl(
                win_path, before_sddl, after_sddl
            )
            log(f"  {canary.path}: {'restored' if restored else restore_detail}")
        for change_id in recorded_ids:
            try:
                db.retire_managed_change(change_id)
            except Exception:
                pass
        return 1

    log(f"\nAudit ACEs applied: {applied}, failed: {failed}")

    if offer_fsutil:
        value, error = fsutil_disablelastaccess()
        if error:
            log(f"fsutil behavior query disablelastaccess: unavailable ({error})")
        else:
            log(f"fsutil disablelastaccess = {value}")
            log(
                "NTFS last-access times remain a low-confidence fallback; the SACL "
                "audit trail is the primary Windows-side signal."
            )
            if value and not value.startswith("0") and confirm is not None:
                if confirm(
                    "Set 'fsutil behavior set disablelastaccess 0' (needs admin)?"
                ):
                    ok, detail = set_fsutil_lastaccess("0")
                    log(f"fsutil: {'OK' if ok else 'FAILED'} — {detail}")
                    db.record_managed_change(
                        change_type=CHANGE_FSUTIL,
                        target="disablelastaccess",
                        previous_existed=True,
                        previous_value=value,
                        new_value="0" if ok else None,
                        notes="offered by setup-windows-audit",
                    )

    return 0


# --------------------------------------------------------------------------
# Optional Windows-resident watcher (scheduled task)
# --------------------------------------------------------------------------

WATCHER_SCRIPT = r"""# Honeypath Windows-side canary watcher (optional component).
# Pages forward through every unseen Security/4663 record and posts to Pushover.
# Restore through: honeypath.py setup-windows-audit --restore
$ErrorActionPreference = 'SilentlyContinue'
$Paths = @(
{paths}
)
$StateFile = Join-Path $env:LOCALAPPDATA 'honeypath-watcher.state'
$QueueFile = Join-Path $env:LOCALAPPDATA 'honeypath-watcher.pending.jsonl'
$GapLog = Join-Path $env:LOCALAPPDATA 'honeypath-watcher.gaps.log'
$Token = '{token}'
$User  = '{user}'

function Get-LastRecord {{
  if (Test-Path $StateFile) {{ [int64](Get-Content $StateFile -Raw).Trim() }} else {{ 0 }}
}}

while ($true) {{
  $last = Get-LastRecord
  $QueuedIds = @{{}}
  if (Test-Path $QueueFile) {{
    foreach ($queuedLine in @(Get-Content $QueueFile)) {{
      try {{
        $queuedHit = $queuedLine | ConvertFrom-Json
        $QueuedIds[[string]([int64]$queuedHit.RecordId)] = $true
      }} catch {{}}
    }}
  }}
  $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
  $newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
  if ($last -gt 0 -and $oldest -and (($oldest.RecordId -gt ($last + 1)) -or ($newest -and $last -gt $newest.RecordId))) {{
    Add-Content -Path $GapLog -Value ("{{0:o}} coverage gap: checkpoint={{1}} retained={{2}}..{{3}}" -f (Get-Date),$last,$oldest.RecordId,$newest.RecordId)
    $last = [int64]$oldest.RecordId - 1
    Set-Content -Path $StateFile -Value $last
  }}
  while ($true) {{
    $xpath = "*[System[(EventID=4663) and (EventRecordID > $last)]]"
    $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 400 -ErrorAction SilentlyContinue)
    if ($events.Count -eq 0) {{ break }}
    foreach ($e in $events) {{
      $x = [xml]$e.ToXml()
      $d = @{{}}
      foreach ($n in $x.Event.EventData.Data) {{ $d[$n.Name] = $n.'#text' }}
      $obj = [string]$d['ObjectName']
      foreach ($p in $Paths) {{
        if ($obj -and $obj.ToLower() -eq $p.ToLower()) {{
          # Durable local queue first.  Alert failure cannot lose the detection.
          $recordKey = [string]([int64]$e.RecordId)
          if (-not $QueuedIds.ContainsKey($recordKey)) {{
            [pscustomobject]@{{RecordId=[int64]$e.RecordId;ObjectName=$obj;ProcessName=[string]$d['ProcessName']}} |
              ConvertTo-Json -Compress | Add-Content -Path $QueueFile
            $QueuedIds[$recordKey] = $true
          }}
        }}
      }}
      $last = [int64]$e.RecordId
      Set-Content -Path $StateFile -Value $last
    }}
    if ($events.Count -lt 400) {{ break }}
  }}

  if (Test-Path $QueueFile) {{
    $pending = @(Get-Content $QueueFile)
    $remaining = New-Object System.Collections.Generic.List[string]
    foreach ($line in $pending) {{
      try {{
        $hit = $line | ConvertFrom-Json
        $msg = "HONEYPATH win-audit read`n" + $hit.ObjectName + "`n" + $hit.ProcessName
        Invoke-RestMethod -Method Post -Uri 'https://api.pushover.net/1/messages.json' -Body @{{
          token=$Token; user=$User; title='Honeypath'; message=$msg; priority=1
        }} -ErrorAction Stop | Out-Null
      }} catch {{ $remaining.Add($line) }}
    }}
    if ($remaining.Count) {{ Set-Content -Path $QueueFile -Value $remaining }}
    else {{ Remove-Item -Path $QueueFile -Force }}
  }}
  Start-Sleep -Seconds 60
}}
"""


def install_windows_watcher(
    db: Database,
    windows_home: Path,
    *,
    token: str,
    user_key: str,
    log=print,
    dry_run: bool = False,
) -> int:
    """Install the optional Windows-resident watcher as a logon scheduled task."""
    canaries = windows_canary_paths(db)
    win_paths = []
    for canary in canaries:
        win_path = to_windows_path(Path(canary.path))
        if win_path:
            win_paths.append(win_path)
    if not win_paths:
        log("No Windows canary paths could be converted; watcher not installed.")
        return 1

    script_dir = windows_home / ".honeypath"
    script_path = script_dir / "honeypath-watcher.ps1"
    body = WATCHER_SCRIPT.format(
        task=TASK_NAME,
        paths="\n".join(f"  '{_ps_quote(p)}'" for p in win_paths),
        token=_ps_quote(token),
        user=_ps_quote(user_key),
    )

    log(f"Watcher script: {script_path}")
    log("NOTE: this script contains your Pushover token and user key in plain text")
    log("      on the Windows filesystem. It is the only Windows-resident piece of")
    log("      Honeypath, it is entirely optional, and restore removes it.")
    if dry_run:
        log("[dry-run] would write the script and register the scheduled task.")
        return 0

    # This script carries the Pushover credentials, and it is written into the
    # Windows home while Honeypath may be running under sudo — so it goes
    # through the symlink-safe atomic writer like every other sensitive write.
    # Mode 0600 is best-effort here: DrvFS usually ignores it, which is exactly
    # why the plaintext-credential warning above is printed unconditionally.
    try:
        safe_write.safe_mkdir(script_dir, windows_home, mode=0o700)
        try:
            previous_hash = safe_write.sha256_anchored(script_path, root=windows_home)
            previous_bytes = safe_write.read_bytes_anchored(
                script_path, root=windows_home
            )
        except FileNotFoundError:
            previous_hash = None
            previous_bytes = None
        recorded_scripts = db.get_managed_changes(change_type=CHANGE_SCHEDULED_TASK)
        if previous_hash is not None and not any(
            change.get("new_value") == str(script_path) for change in recorded_scripts
        ):
            log(f"refusing to replace unrecorded watcher script {script_path}")
            return 1
        for warning in safe_write.atomic_write(
            script_path,
            body,
            mode=0o600,
            root=windows_home,
            fsync_data=True,
            replace=previous_hash is not None,
            expected_sha256=previous_hash,
        ):
            log(f"  note: {warning}")
    except safe_write.SafeWriteError as exc:
        log(f"refusing to write {script_path}: {exc}")
        return 1
    except OSError as exc:
        log(f"cannot write {script_path}: {exc}")
        return 1

    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    def rollback_script() -> bool:
        try:
            if previous_bytes is None:
                safe_write.unlink_regular_if_hash(
                    script_path, root=windows_home, expected_sha256=body_hash
                )
            else:
                safe_write.atomic_write(
                    script_path,
                    previous_bytes,
                    mode=0o600,
                    root=windows_home,
                    fsync_data=True,
                    replace=True,
                    expected_sha256=body_hash,
                )
            log(f"rolled back watcher script {script_path}")
            return True
        except Exception as exc:
            log(
                f"FATAL: could not roll back plaintext watcher script {script_path}: {exc}"
            )
            return False

    win_script = to_windows_path(script_path)
    if not win_script:
        log("wslpath could not convert the script path; task not registered.")
        rollback_script()
        return 1

    result = run_interop(
        [
            "schtasks.exe",
            "/create",
            "/f",
            "/tn",
            TASK_NAME,
            "/sc",
            "onlogon",
            "/tr",
            f'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{win_script}"',
        ],
        timeout=30,
    )
    if not result.ok:
        log(f"schtasks failed: {result.error or result.stderr.strip()}")
        rollback_script()
        return 1
    log(f"Scheduled task '{TASK_NAME}' registered (runs at logon).")
    try:
        db.record_managed_change(
            change_type=CHANGE_SCHEDULED_TASK,
            target=TASK_NAME,
            home=str(windows_home),
            new_value=str(script_path),
            content_hash=body_hash,
            notes="optional Windows-resident 4663 watcher",
        )
    except Exception as exc:
        log(f"database registration failed for scheduled watcher: {exc}")
        deleted = run_interop(
            ["schtasks.exe", "/delete", "/tn", TASK_NAME, "/f"], timeout=30
        )
        if not deleted.ok:
            log(
                f"FATAL: could not roll back scheduled task: {deleted.error or deleted.stderr}"
            )
        rollback_script()
        return 1
    return 0


def remove_windows_watcher(db: Database, log=print, dry_run: bool = False) -> None:
    for change in db.get_managed_changes(change_type=CHANGE_SCHEDULED_TASK):
        if dry_run:
            log(
                f"  [dry-run] would remove scheduled task {change['target']} and script"
            )
            continue
        result = run_interop(
            ["schtasks.exe", "/delete", "/tn", change["target"], "/f"], timeout=30
        )
        log(
            f"  scheduled task {change['target']}: "
            f"{'removed' if result.ok else result.error or result.stderr.strip()}"
        )
        if not result.ok:
            continue
        script = change.get("new_value")
        if script:
            try:
                expected = change.get("content_hash")
                home = change.get("home")
                if not expected or not home:
                    raise safe_write.SafeWriteError(
                        "legacy row lacks exact script identity"
                    )
                safe_write.unlink_regular_if_hash(
                    Path(script), root=Path(home), expected_sha256=expected
                )
                log(f"  removed {script}")
            except (OSError, safe_write.SafeWriteError) as exc:
                log(f"  could not remove {script}: {exc}")
                continue
        db.retire_managed_change(change["id"])


def remove_windows_sacls(db: Database, log=print, dry_run: bool = False) -> None:
    for change in db.get_managed_changes(change_type=CHANGE_SACL):
        win_path = change.get("new_value") or ""
        original = change.get("previous_value")
        expected = change.get("content_hash")
        if not win_path or original is None or not expected:
            log(
                f"  SACL {change['target']}: legacy row lacks exact SDDL; "
                "refusing heuristic removal"
            )
            continue
        if dry_run:
            log(f"  [dry-run] would restore exact original SACL for {change['target']}")
            continue
        ok, detail = restore_exact_sacl(win_path, original, expected)
        log(f"  SACL {change['target']}: {'exact original restored' if ok else detail}")
        if ok:
            db.retire_managed_change(change["id"])


def restore_windows_audit_policy(
    db: Database, log=print, dry_run: bool = False
) -> None:
    for change in db.get_managed_changes(change_type=CHANGE_AUDIT_POLICY):
        if dry_run:
            log("  [dry-run] would restore the recorded File System audit-policy state")
            continue
        current, error = audit_policy_state()
        expected = change.get("new_value")
        if error or current != expected:
            log(
                "  audit policy: CONFLICT; current state differs from the exact "
                "post-Honeypath state, refusing to overwrite it"
            )
            continue
        if change.get("previous_existed"):
            log("  audit policy: Success auditing was already enabled; left unchanged")
            db.retire_managed_change(change["id"])
            continue
        ok, detail = disable_success_audit_policy()
        verify, verify_error = audit_policy_state()
        restored = ok and not (verify and "Success" in verify)
        log(f"  audit policy: {'restored' if restored else detail or verify_error}")
        if restored:
            db.retire_managed_change(change["id"])


# --------------------------------------------------------------------------
# The watch-time poller
# --------------------------------------------------------------------------


class WinAuditWatcher(Watcher):
    """Polls Security-log 4663 records and maps them back to canary paths.

    On startup it replays everything recorded since the last event Honeypath
    saw, so reads that happened while WSL was shut down are still reported.
    """

    def __init__(
        self,
        db: Database,
        canaries,
        sink=None,
        stop_event=None,
        *,
        interval: float = 60.0,
        max_events: int = 400,
        log=print,
    ):
        import queue as _queue
        import threading as _threading

        super().__init__(
            "honeypath-win-audit",
            sink if sink is not None else _queue.Queue(),
            stop_event if stop_event is not None else _threading.Event(),
        )
        self.db = db
        self.interval = interval
        self.max_events = max_events
        self.log = log
        # Windows path (lowercased) -> WSL path
        self.path_map: dict[str, str] = {}
        for canary in canaries:
            win_path = to_windows_path(Path(canary.path))
            if win_path:
                self.path_map[win_path.lower()] = canary.path
        self.last_record_id = int(db.get_meta(LAST_RECORD_KEY, "0") or 0)
        self.log_generation = int(db.get_meta(LOG_GENERATION_KEY, "0") or 0)
        self._emitted_inbox_ids: set[int] = set()

    def _emit_pending_inbox(self, *, catch_up: bool = False) -> int:
        emitted = 0
        while True:
            rows = self.db.pending_windows_records(limit=self.max_events)
            fresh = [r for r in rows if int(r["id"]) not in self._emitted_inbox_ids]
            if not fresh:
                return emitted
            for row in fresh:
                inbox_id = int(row["id"])
                detail = row["detail"]
                if catch_up and "(catch-up)" not in detail:
                    detail += " (catch-up)"
                self.emit(
                    RawHit(
                        path=row["path"],
                        method=METHOD_WIN_AUDIT,
                        event_type=EVENT_READ,
                        detail=detail,
                        process_info=row.get("process_info"),
                        at=float(row.get("observed_at") or time.time()),
                        durable_record_ids=(inbox_id,),
                    )
                )
                self._emitted_inbox_ids.add(inbox_id)
                emitted += 1
            if len(rows) < self.max_events:
                return emitted

    def run(self) -> None:  # pragma: no cover - needs a live Windows host
        if not self.path_map:
            self.status = "idle (no Windows canaries mapped)"
            return
        self.status = f"polling Security/4663 every {self.interval:.0f}s"
        first = True
        while not self.stop_event.is_set():
            try:
                found = self.poll_once(catch_up=first)
                if first and found:
                    self.log(f"[win-audit] catch-up replayed {found} missed read(s)")
                first = False
            except Exception as exc:
                self.status = f"error: {exc}"
                self.log(f"[win-audit] poll failed: {exc}")
            self.stop_event.wait(self.interval)

    def fetch_records(self, *, checkpoint: int | None = None) -> dict:
        script = _PS_EXTRACT_4663.format(
            checkpoint=self.last_record_id if checkpoint is None else checkpoint,
            max_events=self.max_events,
        )
        result = run_powershell(script, timeout=90)
        if not result.ok:
            raise RuntimeError(
                result.error or result.stderr.strip() or "powershell failed"
            )
        text = result.stdout.strip()
        if not text:
            return {"OldestRecordId": "0", "NewestRecordId": "0", "Events": []}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"unparseable Get-WinEvent output: {exc}") from None
        if not isinstance(data, dict):
            # Compatibility with older test doubles; real PowerShell always
            # returns the envelope above.
            data = {"OldestRecordId": "0", "NewestRecordId": "0", "Events": data}
        return data

    def poll_once(self, *, catch_up: bool = False) -> int:
        # A prior process may have crashed after staging a match/checkpoint but
        # before its in-memory queue was consumed.  Replay the durable inbox
        # first; Monitor's transactional consumer deduplicates retries.
        emitted = self._emit_pending_inbox(catch_up=catch_up)
        first_page = True
        while not self.stop_event.is_set():
            page = self.fetch_records(checkpoint=self.last_record_id)
            if isinstance(page, list):
                page = {"OldestRecordId": "0", "NewestRecordId": "0", "Events": page}
            records = page.get("Events") or []
            if isinstance(records, dict):
                records = [records]
            oldest = int(page.get("OldestRecordId") or 0)
            newest = int(page.get("NewestRecordId") or 0)
            reset = bool(
                first_page
                and self.last_record_id
                and newest
                and self.last_record_id > newest
            )
            gap = bool(
                first_page
                and self.last_record_id
                and (oldest > self.last_record_id + 1 or reset)
            )
            if gap:
                message = (
                    f"Security log rollover coverage gap: checkpoint {self.last_record_id}, "
                    f"retained range {oldest}..{newest}"
                )
                self.log(f"[win-audit] {message}")
                self.db.set_meta("win_audit_coverage_gap", message)
                # Continue forward from the oldest retained record.  This is
                # explicit gap recovery, not a claim that skipped events were seen.
                self.last_record_id = max(0, oldest - 1)
                if reset:
                    self.log_generation = self.db.rotate_windows_log(
                        checkpoint_key=LAST_RECORD_KEY,
                        generation_key=LOG_GENERATION_KEY,
                        checkpoint=self.last_record_id,
                    )
                else:
                    self.db.set_meta(LAST_RECORD_KEY, str(self.last_record_id))
                first_page = False
                continue
            if not records:
                break
            ordered = sorted(records, key=lambda r: int(r.get("RecordId") or 0))
            progressed = False
            for record in ordered:
                record_id = int(record.get("RecordId") or 0)
                if record_id <= self.last_record_id:
                    continue
                object_name = (record.get("ObjectName") or "").strip()
                wsl_path = self.path_map.get(object_name.lower())
                if wsl_path:
                    process = (
                        record.get("ProcessName") or ""
                    ).strip() or "unknown process"
                    pid = (record.get("ProcessId") or "").strip()
                    subject = (record.get("SubjectUser") or "").strip()
                    detail = f"4663 record {record_id}"
                    if catch_up:
                        detail += " (catch-up)"
                    hit = {
                        "path": wsl_path,
                        "detail": detail,
                        "process_info": f"{process} pid={pid} user={subject}".strip(),
                        "at": time.time(),
                    }
                else:
                    hit = None
                # Matching inbox insertion and checkpoint advancement are one
                # commit.  A crash can cause a retry, never a lost detection.
                self.db.stage_windows_record(
                    checkpoint_key=LAST_RECORD_KEY,
                    log_generation=self.log_generation,
                    record_id=record_id,
                    hit=hit,
                )
                self.last_record_id = record_id
                if hit is not None:
                    emitted += self._emit_pending_inbox(catch_up=catch_up)
                progressed = True
            if not progressed or len(records) < self.max_events:
                break
            first_page = False
        return emitted
