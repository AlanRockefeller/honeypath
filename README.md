# Honeypath

A defensive credential-canary monitor for Linux, WSL and macOS.

Honeypath plants obviously-fake credential files at the locations that
credential-stealing malware and malicious npm/pip/cargo packages routinely
scrape, watches them for access, records every event in SQLite, and sends a
Pushover alert. It also offers an optional SSH-canary flow that relocates your
real SSH client state and turns `~/.ssh` itself into a canary — without
modifying, patching or recompiling OpenSSH.

**Honeypath is detection, not prevention.** It does not block, quarantine or
stop anything. It tells you that something read a file nothing legitimate had
any reason to read.

---

## Table of contents

- [What it catches (and what it doesn't)](#what-it-catches-and-what-it-doesnt)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [The log file](#the-log-file)
- [Detection mechanics and their limits](#detection-mechanics-and-their-limits)
- [WSL: Linux-side vs Windows-side reads](#wsl-linux-side-vs-windows-side-reads)
- [macOS: an honest assessment](#macos-an-honest-assessment)
- [Canary categories, and what is opt-in](#canary-categories-and-what-is-opt-in)
- [Refreshing a managed canary](#refreshing-a-managed-canary)
- [SSH canarying](#ssh-canarying)
- [Running as a service](#running-as-a-service)
- [Canarytokens](#canarytokens)
- [Safety boundaries](#safety-boundaries)
- [Full walkthrough](#full-walkthrough)
- [Non-goals and future work](#non-goals-and-future-work)
- [Development](#development)

---

## What it catches (and what it doesn't)

Honeypath is built around one observation: most credential stealers are
**blind**. A malicious postinstall script, a typosquatted package, an
infostealer dropped by a phishing lure — they iterate a hardcoded list of
paths (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc`, `~/.config/gh/hosts.yml`,
browser login databases) and exfiltrate whatever exists. They do not check
whether the credentials are real, because checking is slow, noisy and usually
pointless.

That is exactly the behaviour a canary catches.

**It catches:**

- Blind scrapers that read a list of well-known secret paths.
- Malicious package install hooks running as your user.
- Anything that enumerates `~/.ssh` after SSH canarying is activated.
- On WSL with `setup-windows-audit`: Windows-native stealers reading
  `C:\Users\<you>\...`, **with the reading process's image path**.

**It does not catch:**

- Malware that reads only the specific real file it wants and nothing else.
- Anything running as root or in another namespace that avoids your home.
- Exfiltration through channels Honeypath never sees (memory scraping, agent
  hijacking, browser session theft in process).

**And it cannot hide from a determined attacker.** Same-user malware can still
read your real files if they are readable by your user — Honeypath does not
change that. Anything that reads `~/bin/ssh` learns the relocated path
immediately; the wrapper is a plain, readable shell script by design. An
attacker with `strace`, eBPF, or root can see everything Honeypath does.
Honeypath raises the cost of the *cheap, common* attack. It is not a defence
against a targeted adversary who already knows you run it.

---

## Install

Python 3.10+ and the standard library. No pip packages.

Optional but strongly recommended on Linux/WSL:

```bash
sudo apt install inotify-tools     # gives real read events instead of atime guessing
```

```bash
git clone <this repo> ~/honeypath
cd ~/honeypath
sudo python3 honeypath.py setup    # guided alerts, canaries, and service setup
```

The guided setup is the recommended first-run path. It detects the target user
and WSL homes, offers secure hidden-input Pushover configuration, summarizes
the safe-default canaries, creates only approved missing paths, explains the
Windows-audit privilege boundary, and optionally enables the systemd service.

To configure or replace only the Pushover credentials:

```bash
sudo python3 honeypath.py configure-alerts
```

The token and user key are entered without echo, never appear in shell history,
and are stored as `root:<target-group>` mode `0640` under a mode `0750`
`/etc/honeypath`. A test notification is sent immediately.

The `watch` service runs **as your unprivileged target user** (see
[Running as a service](#running-as-a-service)), so it must be able to read
these two files without them becoming world-readable. Use one of:

```bash
# root-owned, group-readable by the service user (recommended)
sudo chown root:alan /etc/honeypath/pushover-token /etc/honeypath/pushover-user
sudo chmod 0640     /etc/honeypath/pushover-token /etc/honeypath/pushover-user
sudo chmod 0750     /etc/honeypath

# or owned outright by the service user
sudo chown alan:alan /etc/honeypath/pushover-token /etc/honeypath/pushover-user
sudo chmod 0600      /etc/honeypath/pushover-token /etc/honeypath/pushover-user
```

Never `chmod 0644` them. `doctor` flags a world-readable credential file.
`install-systemd` prints the exact commands for your resolved user and group.

### What happens to the Pushover token and user key

Be precise about this, because "never transmitted" would be wrong:

* They are **read locally** from `/etc/honeypath/`.
* They **are transmitted over HTTPS to the official Pushover API**
  (`https://api.pushover.net/1/messages.json`) as the `token` and `user` form
  fields. That is unavoidable — it is how Pushover authenticates the request,
  and it is the entire point of configuring them. Nothing is sent anywhere
  else, and no alert is sent at all until a canary is actually read.
* They are **never printed** to stdout or stderr, **never included in an alert
  message body**, **never stored in SQLite** (not in `events`, not in
  `managed_changes`, not in `schema_metadata`), and **never interpolated into
  an error string** — including error strings built from HTTP responses, which
  are additionally passed through a redaction pass before they can reach
  `events.pushover_error`.
* `doctor` reports only their existence, mode and owner — never contents.
* A Pushover delivery failure never loses the detection: the event is still
  recorded, with the (credential-free) failure reason in
  `events.pushover_error`.

The one deliberate exception is the optional Windows-resident watcher
(`setup-windows-audit --install-windows-watcher`), which writes a PowerShell
script containing both values onto the Windows filesystem. It is opt-in, it
prompts first, it says so loudly, and `setup-windows-audit --restore` removes
it.

---

## Quick start

```bash
sudo python3 honeypath.py setup
```

For a manual/non-wizard workflow, use `doctor`, `plan`, `create-canaries`, then
`watch`. Under `sudo`, Honeypath
targets `$SUDO_USER` — canaries land in `/home/alan`, owned by `alan`, never in
`/root`. Use `--user <name>` to override, `--allow-root` if you really mean
root's home.

---

## Commands

| Command | What it does |
| --- | --- |
| `setup` | Guided first run: alerts, safe-default canaries, WSL guidance, and optional service installation. |
| `doctor` | Environment report: OS, WSL, target user, homes, per-filesystem monitoring capability, Pushover status, DB writability, log-file status, SSH/wrapper state, Windows audit status. |
| `plan` | Exactly what `create-canaries` would do, including every skip and its reason. |
| `create-canaries` | Creates the canaries. Idempotent. **Never overwrites an existing path — there is no `--force`.** |
| `watch` | Watches recorded canaries; records events in SQLite and in [`honeypath.log`](#the-log-file), sends alerts. |
| `mute --minutes N` | Suppress alerts for N minutes. Events are still recorded. |
| `configure-alerts` | Securely prompt for, store, and test Pushover credentials. |
| `test-alert` | Send a Pushover test message. |
| `events` | Recent events (`--limit`, `--severity`, `--path-substring`). |
| `install-systemd` | Write `/etc/systemd/system/honeypath.service`. Does not enable it unless `--enable`. |
| `setup-ssh-canary` | Phase 1: relocate real SSH state, install wrappers. |
| `setup-ssh-canary --activate` | Single-shot Phase 2: transactionally back up `~/.ssh`, replace it with canaries. |
| `restore-ssh-canary` | Undo everything the SSH flow changed. |
| `ssh-status` | Current SSH canary state. |
| `setup-windows-audit` | WSL only: enable Windows SACL auditing on the Windows-home canaries. `--restore` restores exact recorded SACLs. |

Global options work before or after the sub-command: `--user`, `--allow-root`,
`--db`, `--log-file`, `--no-log-file`, `--windows-home`, `--yes`, `--dry-run`.

`--dry-run` works everywhere and changes nothing persistent. If SQLite exists,
Honeypath copies the database and its live WAL/SHM state into a private
temporary directory, queries that disposable snapshot without migrations, and
removes it on exit. This sees committed WAL-only changes without touching the
real database or sidecars. If no database exists, an in-memory empty manifest
is used and neither the database nor its parent directories are created.

### `--force` is deliberately narrow

`--force` exists only on the SSH sub-commands, where it resolves a specific,
named conflict: replacing a foreign `~/bin/ssh` wrapper, taking a hand-edited
relocated SSH file, or restoring over a `~/.ssh` that no longer looks
Honeypath-managed.

It never means “reactivate”: once Phase 2 succeeds, activation is permanently
single-shot and `--force` cannot inventory, resynchronise, rename, or replace
the activated canary directory or its original recorded backup path.

**`plan` and `create-canaries` do not accept it and will exit non-zero if you
pass it**, including via the top-level `honeypath.py --force create-canaries`
form. Those commands must never be able to replace a file that could be your
real AWS, Kubernetes, npm, Docker, Git or database credentials — so the option
that would let them simply does not exist. To update a canary that Honeypath
itself created, use [`--refresh-managed`](#refreshing-a-managed-canary).

---

## The log file

Honeypath keeps a plain-text, human-readable log at

```
/var/lib/honeypath/honeypath.log
```

SQLite is the authoritative event store; this is the file you `tail -f` during
a test, `less` after an incident, and `grep` when someone asks whether anything
touched the AWS canary last week.

```
2026-08-02 06:47:17Z  INFO   --- honeypath 0.1.0 log started (timestamps are UTC) ---
2026-08-02 06:47:17Z  INFO   watch started on dev-laptop as uid 1000: 14 canaries, cooldown 300.0s, dedup 2.0s, poll 20.0s
2026-08-02 06:47:17Z  INFO   watcher inotify: watching 9 directories
2026-08-02 06:47:21Z  ALERT  READ  severity=critical  kind=aws-credentials  path=/home/alan/.aws/credentials  via=inotify+atime  detail=(methods=inotify+atime | OPEN; ACCESS; CLOSE_NOWRITE,CLOSE)
2026-08-02 06:47:22Z  INFO   alert delivered via Pushover for /home/alan/.aws/credentials
2026-08-02 06:49:02Z  EVENT  READ  severity=critical  kind=aws-credentials  path=/home/alan/.aws/credentials  via=inotify  detail=(methods=inotify | OPEN)  [suppressed: per-path cooldown]
2026-08-02 07:15:44Z  WARN   [atime] could not re-arm /mnt/c/Users/alan/.aws/credentials: Operation not permitted
2026-08-02 07:20:03Z  ERROR  alert delivery FAILED for /home/alan/.pgpass: HTTP 429
```

Five levels, so `grep` is enough to triage:

| Level | Meaning |
| --- | --- |
| `ALERT` | A detection that Honeypath tried to deliver. |
| `EVENT` | A detection that was **not** alerted — muted, inside the per-path cooldown, or a non-alertable type. The reason is in brackets. |
| `ERROR` | Something failed: alert delivery, an event insert, the watch loop. |
| `WARN` | Degraded monitoring: `inotifywait` missing, Pushover unconfigured, alerts muted, a watcher that died and restarted, a canary that could not be re-armed. |
| `INFO` | Lifecycle: start, watcher status, delivery success, signals, shutdown counts. |

What is recorded: every detection with its severity, kind, path, detection
methods and (on Windows) process attribution; every alert delivery outcome; the
reasons a session is degraded; `mute`/un-mute; and the result of `test-alert`.

Properties worth knowing:

- **The log follows the database.** It is written to `honeypath.log` in the
  `--db` directory, so the default is `/var/lib/honeypath/honeypath.log` and a
  custom database keeps both halves of the record together. `--log-file <path>`
  overrides it; `--no-log-file` turns it off. `install-systemd` carries either
  choice into the generated unit, with a `ReadWritePaths=` grant if the log
  lands outside the state directory.
- **Mode `0600`.** The log names every canary path, which is a map of the trap
  layout. An existing log found group- or world-readable is tightened on open.
- **One event is one line.** Canary paths and Windows process names are
  attacker-influenced text; control characters are escaped and over-long fields
  truncated, so nothing planted in a filename can forge a log line.
- **No credentials, ever.** The only credential-adjacent text that reaches the
  file is a Pushover error string, and those are redacted where they are built
  (see [What happens to the Pushover token and user key](#what-happens-to-the-pushover-token-and-user-key)).
- **A logging failure is never fatal.** A full disk, a read-only mount, a
  symlink where the log should be: logging disables itself, prints one reason
  to stderr (the journal, under systemd), and monitoring continues — the events
  are durable in SQLite regardless.
- **Rotation is built in.** At 5 MB the log rotates to `honeypath.log.1`
  through `.3`; no logrotate configuration is required.

`doctor` reports the log's path, size, mode and writability.

---

## Detection mechanics and their limits

Honeypath uses up to three independent methods and merges their findings.

### inotify (primary on Linux/WSL)

Honeypath shells out to `inotifywait` and watches the **parent directory** of
each canary, not the file. A watch on a file dies the moment the file is
replaced — which is precisely what an attacker, a restore, or a dotfile sync
does. Watching the directory survives deletion and re-creation, and lets
Honeypath re-arm automatically when a canary reappears.

inotify gives **no process attribution**. You learn that a read happened, not
who did it. (Windows SACL auditing does give you the process — see below.)

Without `inotify-tools` installed, `watch` degrades to atime polling only and
says so loudly.

### atime polling (fallback, with re-arming)

atime is unreliable, and you should understand why before trusting it:

- **`relatime`** (the default on nearly every Linux system) only updates a
  file's atime if the old atime is older than its mtime, or more than 24 hours
  stale. After the first detected read, the canary's atime is newer than its
  mtime, so **every subsequent read goes unrecorded**.
- **`noatime`** disables atime updates entirely. Honeypath's `doctor` reports
  this per volume; if you see it, atime detection will not work at all.
- **`O_NOATIME`** lets a caller read a file without updating atime. A stealer
  that uses it is invisible to this method.
- **NTFS** disables last-access updates by default (`fsutil behavior query
  disablelastaccess`) — but not always. Where they *are* enabled, the problem
  inverts: every backup agent, anti-malware scan and search-indexer pass that
  walks the profile advances the atime of every canary, and atime cannot say
  which of them did it. See
  [Windows canary atime is advisory by default](#windows-canary-atime-is-advisory-by-default).

Honeypath's workaround for `relatime` on native Linux filesystems: after
recording an access, it bumps the canary's **mtime** to now (`os.utime`, mtime
only), restoring the "mtime newer than atime" condition the kernel needs to
log the next read. This is the `--no-rearm` behaviour if you want it off.
Re-arming is deliberately disabled for Windows-home canaries: DrvFS/9p can
advance NTFS atime from Honeypath's own re-arm open, creating a false event on
every polling interval. Windows atime remains best-effort and SACL auditing is
the reliable mechanism.

atime remains a low-confidence fallback. Treat inotify (or Windows SACL) as the
real signal.

### Windows canary atime is advisory by default

On a WSL host with NTFS last-access updates enabled, atime polling of
`/mnt/c` canaries reports a full set of critical reads roughly once an hour,
forever. The cause is ordinary machine activity — a backup pass, a scheduled
anti-malware scan, the search indexer — and atime carries **no process
attribution**, so Honeypath cannot tell any of them from a stealer.

Since 0.2, atime reads of `platform=windows` canaries are therefore
**advisory**: recorded as events, visible in `honeypath.py events` and the log
file, never delivered. The event row says
`suppressed: advisory detection method`.

```bash
watch --windows-atime=log     # default: record, do not alert
watch --windows-atime=alert   # pre-0.2 behaviour
watch --windows-atime=off     # do not even record the read
```

Three things this deliberately does **not** silence:

- **Removal or replacement** of a Windows canary still alerts in every mode.
  A scanner reads files; it does not delete them.
- **Any Linux canary.** `platform=linux` atime hits are unaffected.
- **A corroborated read.** If SACL auditing or inotify sees the same read
  inside the coalescing window, the event is delivered — those methods name
  the process, so the event is no longer just an unexplained timestamp move.

If you want Windows-side reads detected properly rather than merely quietened,
that is what [`setup-windows-audit`](#the-fix-setup-windows-audit) is for. You
can also turn the noise off at the source, on the Windows side:

```powershell
fsutil behavior set DisableLastAccess 1   # the Windows default on most systems
```

### Windows SACL auditing (WSL only)

See [the WSL section](#wsl-linux-side-vs-windows-side-reads).

### Allowlisting known scanners

SACL auditing gives what atime cannot: the image path of the reading process.
That makes it possible to suppress a backup agent by name rather than by
guesswork.

```bash
# Repeatable, case-insensitive glob on the image path or its basename.
watch --allow-process 'bzserv.exe' --allow-process 'C:\Program Files\Backblaze\*'

# Or take the bundled list: Backblaze, Defender, Windows Search.
watch --allow-known-scanners
```

Allowlisted reads are recorded with their process name and marked
`allowlisted process: <pattern>` in the event detail; they are never delivered.
The active patterns are printed at startup and written to the log every
session, because **an allowlist is a deliberate blind spot**: malware running
inside an allowlisted process — injected, or simply named to match a loose
pattern — reads every canary without waking anyone. Prefer basenames over
directory globs, keep the list short, and remember `honeypath.py events`
remains the ground truth regardless of what was delivered.

### Naming the reader on Linux

inotify reports that a canary was read and never says by whom. On an OPEN
event Honeypath walks `/proc` looking for a descriptor pointing at the canary's
inode, and attaches whatever it finds to the event and the alert body:

```
HONEYPATH high pgpass via inotify
/home/alan/.pgpass
psql pid=48213
```

This races the reader's `close()` and loses against anything that opens, reads
and closes quickly, so attribution is a bonus and never a guarantee — an
unattributed read is alerted on exactly as before. Because Honeypath [runs
unprivileged by design](#the-service-runs-as-your-unprivileged-target-user-not-as-root),
the scan only sees processes owned by the same user, which is precisely the
threat model that matters: malware running as you needs no privilege to read
your secrets. Disable with `--no-attribution`.

### Sweep aggregation

A profile-wide read touches every canary at once, and twelve notifications say
nothing that one summary naming twelve paths does not — they are just the ones
that get swiped away. The **first** detection of a burst is delivered
immediately; the rest are held until the burst goes quiet (default 30 s) and
then summarised:

```
HONEYPATH sweep: 11 more canaries read (critical)
/mnt/c/Users/alanr/.git-credentials
/mnt/c/Users/alanr/.npmrc
...
```

Tune with `--sweep-window` (0 disables) and `--sweep-threshold`. A burst
smaller than the threshold is sent as individual alerts rather than summarised.
Every event is written to SQLite and the log file before it reaches the
aggregator, so a summary omits nothing that was actually recorded — and a burst
still being held at shutdown is flushed, not dropped.

Note that this does **not** suppress a credential stealer sweeping your
canaries: that produces the same shape, and it produces it as an alert.

### Dedup, cooldown, mute

A single logical read produces an `OPEN`/`ACCESS`/`CLOSE_NOWRITE` burst.
Honeypath collapses everything for one path within a short window (default 2 s)
into **one** event, and merges sightings across methods — an inotify hit, an
atime hit and a win-audit hit for the same file become one event that lists all
three methods.

A per-path alert cooldown (default 300 s) stops one noisy file from flooding
your phone. **Events are always recorded during cooldown**; only the alert is
suppressed, and the event row says why.

`mute --minutes N` does the same globally, for when *you* are the one touching
the canaries (backups, dotfile syncs, housekeeping).

Every alert that survives dedup, cooldown and mute is delivered at Pushover's
normal priority. There is no per-severity loudness: a read is either worth
alerting on or it is not, and Honeypath only sends the ones that are. The
canary's severity still labels the alert body, the log line and the
`events --severity` filter — it just never decides how the alert lands.

---

## WSL: Linux-side vs Windows-side reads

This is the part people get wrong, so `doctor` reports it per filesystem rather
than with one vague line:

```
Linux home (/home/alan, ext4):
  inotify access events: available
  atime: relatime (limited; re-arming enabled)
Windows home (/mnt/c/Users/alanr, 9p):
  Linux-side reads via inotify: best-effort (9p/drvfs can miss WSL file-access events)
  Windows-side reads via inotify: NOT detected (use setup-windows-audit)
  atime: unavailable/unreliable; re-arming disabled (fsutil disablelastaccess = 2 (...))
```

inotify on `/mnt/c` may see reads performed **by WSL**, but DrvFS/9p does not
reliably surface every file-access event. A Windows-native stealer opening
`C:\Users\alanr\.ssh\id_rsa` is completely invisible to it, and NTFS atime is
unreliable by default. You can prove the Windows-side limitation to yourself:

```bash
python3 honeypath.py doctor --windows-read-test
```

That creates a temporary file in your Windows home, reads it from Windows via
`powershell.exe`, and reports whether the WSL-side watcher saw anything. It
normally does not — which is the point.

### The fix: `setup-windows-audit`

Windows object-access auditing (Security log event **4663**) is the one clean
read-detection mechanism available here. It is better than inotify in three
ways: it reports the **image path of the reading process**, it works while WSL
is shut down (the OS writes the log regardless), and Honeypath can therefore
**catch up** on everything it missed after a reboot.

```bash
sudo python3 honeypath.py setup-windows-audit
```

This:

1. requires an exact successful query of the original File System audit-policy
   state, then enables `auditpol /set /subcategory:"File System" /success:enable`;
2. captures each complete original SACL as lossless SDDL, then applies an
   `S-1-1-0` (Everyone SID)/`ReadData`/`Success` audit ACE to each recorded
   Windows-home canary (via `wslpath -w` + PowerShell `Get-Acl`/`Set-Acl`);
3. reports `fsutil behavior query disablelastaccess` and offers to set it to 0
   (atime on NTFS stays a low-confidence fallback regardless — the SACL is the
   primary signal).

Both steps require **administrator** privileges — SACL changes need
`SeSecurityPrivilege`. When your WSL session is not elevated, Honeypath does not
start work that cannot finish: it offers to request elevation for you.
Answering yes raises a Windows UAC prompt and re-runs this one step as root in a
new console (`Start-Process -Verb RunAs` → `cmd.exe /k wsl.exe -d <distro> -u
root -- …`), which stays open so you can read the result. The exit code is `3`
("handed off to an elevated session"), distinct from success and from failure.

Decline the prompt — or run non-interactively — and it prints the manual
`auditpol` line plus the fully-resolved `wsl.exe -d <your-distro>` command,
with the real distribution name substituted. The name comes from
`WSL_DISTRO_NAME`, falling back to the environment of a parent process because
`sudo` strips it. If the name cannot be determined, Honeypath says so and points
at `wsl.exe -l -q` rather than emitting a command that would fail with
`WSL_E_DISTRO_NOT_FOUND`.

`watch` then queries `RecordId > checkpoint` oldest-first in bounded pages
until no unseen Security/4663 records remain. Each match is inserted
idempotently into a durable SQLite inbox in the same transaction that advances
the checkpoint. Monitor converts inbox rows into normal events transactionally,
so a crash between polling and queue consumption causes a retry, not a lost
read. The reading process is stored in `events.process_info`. The alert gets an
extra line:

```
HONEYPATH critical ssh_private_key via win-audit
C:\Users\alanr\.ssh\id_rsa
C:\Users\alanr\AppData\Local\Temp\updater.exe pid=8412 user=alanr
```

`--install-windows-watcher` additionally generates a small PowerShell script
that tails event 4663 itself and posts to Pushover directly, registered as a
logon scheduled task. It is the **only** Windows-resident piece of Honeypath,
it is entirely optional, it contains your Pushover credentials in plain text on
the Windows filesystem (Honeypath says so before writing it). It uses the same
paged catch-up and writes hits to a durable local queue before attempting
Pushover. `setup-windows-audit --restore` removes it.

Both watchers report a coverage gap if the Security log has rolled over past
the stored checkpoint. They continue from the oldest retained record without
pretending the missing interval was observed. Restoration compares the current
SACL with the exact expected post-Honeypath SDDL; an independent administrator
change is reported as a conflict rather than overwritten. Honeypath never uses
`RemoveAuditRuleAll`.

> **`FileSystemWatcher` is not an alternative.** It reports creates, writes,
> renames and deletes — never reads. SACL auditing is the only clean mechanism
> for read detection on Windows.

### Multiple Windows homes

If several plausible profiles exist (e.g. `C:\Users\alanr` and
`D:\Users\alanr`), `plan` lists them all and `create-canaries` asks before
picking one. Directories without an `NTUSER.DAT` registry hive are dropped as
implausible. Use `--windows-home <path>` to decide explicitly.

---

## macOS: an honest assessment

Canary **creation** on macOS is fully supported. Read **detection** is not
good, and pretending otherwise would be worse than saying so:

- **FSEvents does not report reads.** It is a file-change notification API.
- **kqueue** has the same problem, plus a file-descriptor per watched file.
- Reliable open-event monitoring on modern macOS requires the **Endpoint
  Security** framework, which needs a signed, notarised, entitled system
  extension. That is out of scope for a Python-only tool.
- What is left is **best-effort atime polling**, which on APFS may simply not
  fire.

So on macOS: use Honeypath to plant canaries and to catch what atime happens to
catch, and do not treat silence as evidence of safety. Endpoint Security
integration is documented as future work, not shipped.

---

## Canary categories, and what is opt-in

Every catalog entry is audited into exactly one category. The category, not a
severity label, decides whether `plan` and `create-canaries` will touch it.

| Category | Created by default? | What it is |
| --- | --- | --- |
| `safe-default` | **yes** | Adds an *isolated* credential — keyed by a reserved `.invalid` host, a named profile, or a custom option group — without changing any tool's default endpoint, profile, context, token cache or auth chain. |
| `active-config` | no — needs `--include-active-config` | Occupies a path a tool consults on every invocation, or *is* the default credential. Creating it **may affect legitimate commands**. |
| `watch-only` | never created | Browser login databases. Watched if present; Honeypath never writes into a live browser profile. |
| `ssh-gated` | no — only via `setup-ssh-canary --activate` | Everything under `~/.ssh`. |
| `crypto-opt-in` | no — needs `--include-crypto` | Wallet files. |

The test for `safe-default` is deliberately strict:

> A canary may remain enabled by default **only** when it adds an isolated
> credential for a reserved `.invalid` host or named profile **without**
> changing the application's default endpoint, profile, context or
> authentication chain.

### What moved behind `--include-active-config`

| Path | Why it is behaviour-changing |
| --- | --- |
| `.config/gcloud/application_default_credentials.json` | **The** Application Default Credentials location. `google-auth` picks it up with no configuration at all, so it can alter real authentication. |
| `.azure/accessTokens.json` | The Azure CLI token cache. |
| `.kube/config` | `kubectl`'s default kubeconfig. Even with no `current-context`, its presence changes `kubectl`'s behaviour from "no configuration" to "configuration with no context". |
| `.dbt/profiles.yml` | dbt's sole configuration path; it changes the failure mode of every dbt run in every project. |
| `.config/gh/hosts.yml` (and the Windows/macOS equivalents) | `gh` infers its default host from `hosts.yml` when the file holds a single entry, so this can repoint `gh`. |
| `.huggingface/token` | **The** `huggingface_hub` token file; its presence makes the client believe it is logged in. |
| `.config/doctl/config.yaml` | doctl's sole config, and `access-token` is the default credential it authenticates with. |

`plan` says so explicitly rather than silently omitting them:

```
Active configuration canaries excluded; pass --include-active-config to review and enable them.
```

Passing `--include-active-config` prints a prominent warning before anything is
created. Honeypath still never overwrites an existing file, so enabling these
only ever affects paths where you have no such configuration today.

### Entries that were fixed so they could stay enabled by default

Rather than gating these, their content was changed so they genuinely qualify:

* **`.aws/credentials`** no longer declares a `[default]` profile — a
  `[default]` profile becomes the credential every unqualified `aws` command
  uses. It now declares a named `[honeypath-canary]` profile, which is only
  ever used by someone who passes `--profile` or sets `AWS_PROFILE`. A scraper
  reading the file still finds exactly what it was looking for. The absence of
  a `[default]` section is enforced by tests, including for
  Canarytokens-spliced content.
* **`.kube/config`** no longer sets `current-context`, so `kubectl` cannot
  select the fake cluster. (It is still `active-config` for the reason above.)
* **`.pypirc`** no longer declares a `[distutils] index-servers` block, which
  redefines the set of servers `twine` knows about. A bare named repository
  section is inert unless asked for by name with `-r honeypath-canary`.

### Expect alerts from legitimate tools

`aws s3 ls` reading a canary `.aws/credentials` is a real read of a real file,
and Honeypath will tell you. That is useful signal — it teaches you what
normally touches your credentials — but it is noise if you did not expect it.

Two guarantees make this safe:

1. **Every host referenced is under the reserved `.invalid` TLD** (RFC 2606),
   which by definition never resolves. A canary `.npmrc` or `.pgpass` cannot
   cause curl, git, npm or psql to send anything to a real server. This is
   enforced by the test suite.
2. **Canaries add scoped credentials, they do not override defaults.** The
   canary `.npmrc` declares a token for a registry nobody uses; it does *not*
   set `registry=`, which would repoint every `npm install` at a dead host.
   The canary `.my.cnf` uses a custom option group, not `[client]`. The canary
   `NuGet.Config` supplies credentials without adding a package source. The
   canary `gradle.properties` uses namespaced `honeypathCanary*` keys and sets
   no `org.gradle.*` property.

Other things that will trip canaries, all benign:

- backup tools and dotfile syncers (Time Machine, restic, chezmoi, yadm)
- antivirus / EDR scanning your home directory
- Spotlight, `updatedb`/`mlocate`, IDE project indexers
- your own `grep -r` through `$HOME`

Use `mute --minutes 60` before doing housekeeping. Events keep being recorded,
so you can review afterwards with `events --limit 100`.

For the recurring, unattended cases — a backup agent scanning hourly forever —
muting is the wrong tool, because you have to remember to un-mute. Reach for
the mechanisms that suppress delivery without suppressing recording:
[advisory Windows atime](#windows-canary-atime-is-advisory-by-default),
[scanner allowlisting](#allowlisting-known-scanners) and
[sweep aggregation](#sweep-aggregation). The first thing to do, though, is find
out *what* is reading them — [`/proc` attribution](#naming-the-reader-on-linux)
on Linux, [`setup-windows-audit`](#the-fix-setup-windows-audit) on Windows.
Silencing an unidentified reader is the one move you should not make.

Sometimes the right answer is that the path is a bad canary. `~/.netrc` used to
be in the catalog and no longer is: git's HTTP transport enables libcurl's
`CURLOPT_NETRC`, so *every* `git push` or `git fetch` over HTTPS reads it before
the credential helper is consulted. On a machine where you push several times a
day that canary fires on ordinary work, and a canary that cries wolf on
`git push` is worse than no canary — you learn to swipe the alert away. A canary
belongs on a path nothing you run touches by routine.

Browser login databases are **watch/report-only**. Honeypath never creates a
fake `Login Data` or `logins.json` — writing files into a live browser profile
risks corrupting it. Those paths are excluded unless you pass `--include-noisy`
or name the `browser-noisy` profile explicitly, and even then they are only
watched.
Registration is independent of file creation: a browser-only run records every
existing regular-file match even when there are no creatable canaries, and a
later idempotent run picks up newly created Firefox profiles. Symlink and
non-regular replacements are skipped.

Crypto-wallet canaries are opt-in with `--include-crypto`. None of them
contains key-shaped material: the Electrum "seed" is not a valid BIP-39
mnemonic, and the Solana canary is a JSON **object** carrying an explicit
`HONEYPATH CANARY - NOT A SOLANA KEYPAIR` marker, not the 64-integer array a
real keypair is serialised as. A path-based stealer that grabs the file by
name is unaffected; anything that parses it fails immediately.

---

## Refreshing a managed canary

`create-canaries` never overwrites. When you genuinely need to update a canary
Honeypath created — most often to splice in
[Canarytokens](#canarytokens) material — use `--refresh-managed`:

```bash
sudo python3 honeypath.py create-canaries \
    --canarytoken-aws-file ~/canarytoken-aws.txt --refresh-managed
```

It replaces a path **only** when all five of these hold, each checked
independently and re-checked immediately before the write:

1. the exact path is recorded in SQLite as Honeypath-managed;
2. the path on disk is a regular file — never a symlink, directory, FIFO,
   socket or device node;
3. its exact SHA-256 content hash equals the bytes Honeypath last wrote;
4. its per-canary managed identifier matches the expected canary ID;
5. the destination is reached below the approved home through held directory
   file descriptors, with no
   symlinked parent component.

Together these mean a credential file Honeypath did not write can never be
selected — being recorded in the database is not on its own enough.

Anything that fails a check is reported and skipped, never replaced:

```
refused: not recorded as a Honeypath-managed canary (--refresh-managed declined): /home/alan/.pgpass
```

---

## SSH canarying

`~/.ssh` is the highest-value directory in a developer's home and the first
place every stealer looks. Making it a canary is the single most valuable thing
Honeypath can do — and the most invasive, so it is deliberately gated behind
two phases with a testing gap in between.

### Ordinary `create-canaries` never touches `.ssh`

This is a hard rule. If Honeypath dropped a fake `id_rsa` or `config` into a
**real, active** `~/.ssh` merely because that filename happened to be absent,
it would degrade or break your real SSH and then alert you about your own
usage. So every catalog entry under `.ssh/` is excluded until SSH-canary
activation is recorded for that home:

```
SSH canaries skipped: setup-ssh-canary --activate has not been completed
```

Only `setup-ssh-canary --activate` ever creates anything beneath `~/.ssh`.

### How it works: no OpenSSH modification

Two stock features, nothing more:

- `ssh -F <file>` — point the client at a config somewhere else.
- a wrapper script earlier in `PATH`.

```bash
#!/usr/bin/env bash
# Honeypath-managed SSH wrapper.
exec /usr/bin/ssh -F "$HOME/.local/share/honeypath/real-ssh/config" "$@"
```

`~/bin/ssh`, `~/bin/scp` and `~/bin/sftp` get one each. `/usr/bin/ssh` and
friends are never touched. Nothing is recompiled.

### Three OpenSSH facts that shape the design

1. **`ssh -F file` makes the system-wide `/etc/ssh/ssh_config` be ignored.**
   Honeypath therefore appends `Include /etc/ssh/ssh_config` at the very end of
   the relocated config, restoring system defaults while keeping
   user-before-system precedence.
2. **Relative `Include` paths in a user config resolve against `~/.ssh`**,
   regardless of where the config file actually lives. A naively relocated
   config with `Include config.d/*` would keep loading files out of the canary
   directory. Honeypath rewrites relative includes to absolute relocated paths.
3. **Most options are first-match-wins, but `IdentityFile` and
   `CertificateFile` accumulate.** The Honeypath block is appended *after* your
   content, so your `Host` entries keep winning.

### What the relocated config looks like

Your config, path-rewritten, then the managed block, then the system include:

```
Host work
    HostName work.example.com
    IdentityFile ~/.local/share/honeypath/real-ssh/id_ed25519
    UserKnownHostsFile ~/.local/share/honeypath/real-ssh/known_hosts_work

Include /home/alan/.local/share/honeypath/real-ssh/config.d/*.conf

# BEGIN HONEYPATH MANAGED SSH CONFIG
Host *
    IdentitiesOnly yes
    IdentityFile none
    UserKnownHostsFile ~/.local/share/honeypath/real-ssh/known_hosts
    ForwardAgent no
    # relocating known_hosts would otherwise disable this
    UpdateHostKeys yes
# END HONEYPATH MANAGED SSH CONFIG

Include /etc/ssh/ssh_config
```

Rewritten directives: `Include`, `IdentityFile`, `CertificateFile`,
`UserKnownHostsFile`, `GlobalKnownHostsFile`, `ControlPath`, `IdentityAgent`,
`KnownHostsCommand`, `RevokedHostKeys`, `SecurityKeyProvider`,
`PKCS11Provider`. Every rewrite is printed as a before/after diff.

`ProxyCommand`, `LocalCommand` and `Match exec` lines that reference `.ssh` are
**report-only activation blockers**. Honeypath will not regex-rewrite shell
text — it tells you which line to fix and refuses to continue until you do.

Three details worth knowing:

- **`IdentityFile none`.** If no keys exist, or if your config already declares
  its own identities, Honeypath appends `IdentityFile none` to suppress
  OpenSSH's built-in `~/.ssh/id_*` defaults — which after activation are the
  canaries. `none` suppresses the built-ins without disturbing your own entries
  or their order. Honeypath verifies at runtime that your OpenSSH accepts
  `none` (`ssh -G -F <tmpconfig>`) and falls back to an explicit nonexistent
  path if not, warning you either way. When your config declares identities,
  hosts it does *not* cover will offer no key at all; pass
  `--force-managed-identities` to add the relocated keys as trailing defaults
  instead.
- **`ForwardAgent no`** is the default, shown in the confirmation prompt, and
  overridable with `--allow-agent-forwarding`.
- **`UpdateHostKeys yes`.** OpenSSH silently disables `UpdateHostKeys` whenever
  `UserKnownHostsFile` is not the default path — so relocating `known_hosts`
  would quietly turn off host-key rotation learning. Honeypath restores the
  documented default explicitly. A value you set yourself still wins.

The result is validated with `ssh -G -F <relocated-config> github.com`, diffed
against `ssh -G github.com`, normalised for the intentionally-changed keys, and
any unexpected difference is printed. Validation status is recorded in the
database.

### Phase 1 — `setup-ssh-canary`

```bash
sudo python3 honeypath.py setup-ssh-canary
```

The wrappers work the same from zsh and bash: they are executable scripts, not
shell aliases or functions. When `~/bin` is not already on `PATH`, setup offers
a managed `export PATH="$HOME/bin:$PATH"` block for existing `.zshrc` and
`.bashrc` files; that syntax is valid in both shells. Guided `setup` also offers
to run this phase, but never activates the SSH canary in the same session—the
testing gap is intentional.

Copies `~/.ssh` to `~/.local/share/honeypath/real-ssh`, builds and validates the
relocated config, installs the wrappers, optionally fixes `PATH` and git, and
prints test commands. **Nothing under `~/.ssh` changes.**

Copy rules: sockets, devices and FIFOs are refused; symlinks pointing outside
the source tree are refused; no silent
overwrites in the destination. Files are copied as **opaque bytes** — Honeypath
never parses, displays or logs private-key contents. It does hash file bytes
locally for drift detection; those hashes live only in the local SQLite
database and are never transmitted.

The relocated `config` is **generated**, not copied. (Copying it would put an
un-rewritten config at the destination, which the hand-edit guard would then
preserve verbatim, silently defeating every rewrite.)

Then test — take as long as you like, days is fine:

```bash
~/bin/ssh -G github.com | grep -Ei '^(identityfile|userknownhostsfile|identitiesonly|forwardagent) '
~/bin/ssh -T git@github.com
git config --global core.sshCommand
which ssh
ssh -G github.com | grep -Ei '^(identityfile|userknownhostsfile|identitiesonly|forwardagent) '
```

**PATH.** If `~/bin` is not in `PATH`, Honeypath offers to add
`export PATH="$HOME/bin:$PATH"` to `~/.zshrc` and/or `~/.bashrc`, inside a
clearly marked managed block, never without asking, recorded for rollback.

**Git.** `core.sshCommand` is set to the **absolute wrapper path**
(`/home/alan/bin/ssh`), not `ssh -F …`. Via `PATH`, `ssh -F …` would invoke the
wrapper and produce a duplicate `-F`; the absolute path also survives cron,
IDEs and su'd shells. The current value is shown first, recorded (including
whether it was originally unset), and never overwritten without confirmation.
The git command runs **as the target user**.

### Phase 2 — `setup-ssh-canary --activate`

```bash
sudo python3 honeypath.py setup-ssh-canary --activate
```

Days may have passed. You may have added keys, hosts, `known_hosts` lines or
includes. After you complete the checklist and confirm, activation immediately
**re-synchronises**: it re-inventories the source, treats every copy failure as
a blocker, verifies every intended opaque file byte-for-byte at the relocated
path, and re-runs the config rewrite and validation. After the rename it
re-inventories the anchored backup and requires it to match that final snapshot
before creating any canary. Honeypath never activates a stale or partial copy.

That resynchronisation occurs only while SQLite and the filesystem both say
Phase 1 is prepared. If either says activation already happened, Honeypath
returns before inventorying the canary directory. A database/filesystem
mismatch is a recovery blocker with explicit guidance, never something
`--force` guesses through.

Then it:

1. refuses if `~/.ssh` is a **symlink** (common with dotfile repos — that is an
   activation blocker, not a rename target);
2. atomically renames `~/.ssh` to
   `~/.local/share/honeypath/backups/ssh-YYYYMMDD-HHMMSS` (mode 0700);
3. creates a fresh `~/.ssh` (0700) containing canaries: `id_rsa`, `id_ed25519`,
   `config`, `known_hosts`;
4. copies `authorized_keys` back;
5. registers the canaries in SQLite, which is what un-gates the `.ssh` catalog
   entries.

Steps 2–5 are transactional. After the rename, any directory, canary,
ownership, `authorized_keys`, verification, or database failure removes only
the inode-verified incomplete replacement and renames the original backup back
to `~/.ssh`. Canary rows and activation state commit together. If rollback
itself fails, both locations are printed prominently and activation returns a
distinct fatal status.

**The backup path matters.** It deliberately lives under
`~/.local/share/honeypath/backups/`, *not* `~/.ssh.honeypath-backup.*`, because
a trivial `~/.ssh*` glob — which is exactly what a scraper does — would find the
latter and hand the attacker your real keys. If the atomic rename fails with
`EXDEV` (unexpected on one volume, but possible), Honeypath falls back to
`~/.ssh.honeypath-backup.TIMESTAMP` **with a printed warning**, rather than
doing a copy-then-delete of your private keys.

**Backups are never deleted.** Not by activation, not by restore, not ever.

### The canary `~/.ssh/config` is deliberately invalid

```
### This file is INTENTIONALLY INVALID.
!!! HONEYPATH CANARY - NOT A VALID SSH CONFIG !!!
```

**After activation, programs that bypass `~/bin/ssh`, `~/bin/scp` or
`~/bin/sftp` may fail with an SSH configuration parse error.** This is
deliberate, and it is the single most disruptive thing Honeypath does.

Any program that calls `/usr/bin/ssh`, `/usr/bin/scp` or `/usr/bin/sftp`
directly will exit with a parse error pointing at `~/.ssh/config`, instead of
silently being handed fake keys and producing a confusing authentication
failure (plus a Honeypath alert about your own tooling).

That is the trade-off: a visible, diagnosable breakage now, rather than a
mysterious one later. The file explains itself and tells you how to fix your
`PATH` or run `restore-ssh-canary`.

**Direct `/usr/bin/ssh` use is unsupported after activation** unless you
configure it explicitly. `ssh-status` reports this as a first-class state:

```
Direct /usr/bin/ssh use (bypassing the wrappers)
  supported: NO
  UNSUPPORTED: ~/.ssh/config is the deliberately invalid canary, so /usr/bin/ssh
  exits with a parse error. Use ~/bin/ssh, or pass
  -F ~/.local/share/honeypath/real-ssh/config explicitly.
```

Things that commonly bypass the wrappers:

* cron jobs and systemd units with a hardcoded `/usr/bin/ssh`
* IDEs and GUI git clients with an absolute ssh path in their settings
* scripts using an absolute path, or running with a `PATH` that omits `~/bin`
* anything running before your shell rc files are sourced

To make a specific program work, pick one:

* point it at `~/bin/ssh` instead of `/usr/bin/ssh`
* pass `-F ~/.local/share/honeypath/real-ssh/config` yourself
* for git: `git config --global core.sshCommand ~/bin/ssh` (setup does this)
* or run `restore-ssh-canary` to undo activation entirely

### Pre-activation checklist

Run these **before** activating and again afterwards. None of them needs to
reach a real host — `example.invalid` never resolves, so a DNS failure is a
**pass**. What they verify is *which binary* and *which configuration* got
selected.

```bash
~/bin/ssh -G github.com
~/bin/ssh -T git@github.com
~/bin/scp -v /dev/null example.invalid:/tmp/
~/bin/sftp -v example.invalid
git config --global core.sshCommand
which ssh
ssh -G github.com
rsync --version
```

What to look for:

| Command | Expected |
| --- | --- |
| `~/bin/ssh -G github.com` | `identityfile` / `userknownhostsfile` point into `~/.local/share/honeypath/real-ssh`, never into `~/.ssh` |
| `~/bin/ssh -T git@github.com` | authenticates exactly as before |
| `~/bin/scp -v … example.invalid` | the `-v` banner shows the relocated config; the DNS failure afterwards is expected |
| `~/bin/sftp -v example.invalid` | same |
| `git config --global core.sshCommand` | names the `~/bin/ssh` wrapper |
| `which ssh` | `~/bin/ssh`, once `PATH` is set up |
| `ssh -G github.com` | **the bypass case**: works before activation, fails with a parse error after — by design |
| `rsync --version` | rsync shells out to `ssh` from `PATH`, so it picks up the wrapper; confirm it still runs |

`setup-ssh-canary` prints this checklist at the end of phase 1, and again with
the breakage warning immediately before the phase 2 confirmation prompt.

Guided `setup` prints it a third time, as its closing section, whenever it
prepared phase 1 during that run — a wizard that ends without saying so would
leave you believing SSH was covered when `~/.ssh` still holds the real keys and
no canary exists. That section states what is and is not protected, the tests
above, the `setup-ssh-canary --activate` command that completes the work, and
the `ssh-status` / `restore-ssh-canary` commands for checking and backing out.

### `authorized_keys` — server-side state

`~/.ssh` is client *and* server state. If `sshd` (or macOS Remote Login) is in
use, moving `authorized_keys` into the backup silently breaks inbound SSH.

`doctor`, `plan` and the activation prompt all warn loudly when
`authorized_keys` exists, extra-loudly if an `sshd` process is detected. On
activation Honeypath **copies `authorized_keys` back** into the new `~/.ssh` by
default — it is public material, not a secret — mode 0600, target-owned,
recorded as Honeypath-managed but explicitly **not** a canary, because sshd
reading it is routine and must not alert. `--no-authorized-keys` opts out.

### Undo — `restore-ssh-canary`

```bash
sudo python3 honeypath.py restore-ssh-canary
```

Removes the wrappers (hash-verified as Honeypath's; a modified wrapper is left
alone), restores the original recorded backup to `~/.ssh` (refusing to overwrite a
`~/.ssh` that does not look Honeypath-managed, unless `--force`), restores git
`core.sshCommand` to its **exact recorded previous value** — or unsets it only
if it was originally unset — removes the PATH block, and deactivates the SSH canary rows so the
catalog is gated again. The relocated directory and all backups are kept.

Windows auditing has its own restoration path:
`sudo python3 honeypath.py setup-windows-audit --restore`.

---

## Running as a service

```bash
sudo python3 honeypath.py install-systemd
```

This prints the resolved user, group, Python interpreter, executable path and
database path **before** it writes anything. It reports whether the service can
already read the Pushover credentials and prints exact permission-remediation
commands only when they are needed. It then writes
`/etc/systemd/system/honeypath.service`. It never enables or starts the service
unless you pass `--enable`.

The guided `setup` command passes `--enable` after you approve service
installation. It reloads systemd and enables and starts Honeypath itself; the
commands it prints afterward are optional status/log inspection, not required
setup steps.

### The service runs as your unprivileged target user, not as root

```ini
User=alan
Group=alan
ExecStart=/usr/bin/python3 /home/alan/development/honeypath/honeypath.py --user alan --db /var/lib/honeypath/events.sqlite3 watch
```

This is the important part, and it is a deliberate fix to a real
privilege-escalation path. Honeypath's code lives in a checkout that the target
user can write. A **root** service executing that checkout would mean that
anyone able to edit a `.py` file there — the user, or same-user malware — gets
root at the next service restart. Since the whole premise of Honeypath is that
same-user malware may already be running, that is exactly the adversary the
design has to survive.

Running as the target user removes the escalation entirely, and costs nothing:
the service only ever needs what that user could already reach — their
canaries, their home, and their Windows-mounted home under WSL.

Running from a development checkout is therefore fine, **but only because the
service runs as the same unprivileged user that owns it.** If you ever change
`User=` to `root`, move the code somewhere that user cannot write first.

### State directory

```ini
StateDirectory=honeypath
StateDirectoryMode=0700
```

systemd creates and chowns `/var/lib/honeypath` to the service user before the
process starts, so the database and the [`honeypath.log`](#the-log-file) beside
it live at their documented paths with no root-owned directory and no manual
`chown`. A non-default `--db` or `--log-file` gets an explicit
`ReadWritePaths=` grant instead.

That grant only relaxes systemd's filesystem sandbox — it cannot make a
root-owned SQLite file writable by an unprivileged `User=`. So when a run under
`sudo` creates a custom database, Honeypath hands the database, its `-wal`/`-shm`
sidecars and any directory it had to create to the target user before the unit
is ever written. A directory that already existed keeps whatever ownership you
gave it, and `install-systemd` checks that the service user can actually write
the database, printing the `chown` to run — and declining to `--enable` a
service that would only fail to start.

### Hardening, and what is deliberately absent

`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute` and
`SystemCallArchitectures=native` are all set.

Deliberately **not** set, because each would break the tool's actual job:

| Directive | Why not |
| --- | --- |
| `ProtectHome` | Hides the very canaries the service exists to watch. |
| `ProtectSystem=strict` | Breaks the state directory. |
| `PrivateUsers` | Breaks reading files owned by the target user. |
| `ReadOnlyPaths=/mnt` | Breaks Windows-home monitoring on WSL. |
| `AmbientCapabilities`, `CapabilityBoundingSet`, `SecureBits` | Would grant capabilities to a service running user-writable code. |

Verify before enabling:

```bash
sudo systemd-analyze verify /etc/systemd/system/honeypath.service
```

`systemd/honeypath.service` in this repo is the same design as a checked-in
example — safe by default, with `User=`/`Group=` set to a placeholder you must
change. Tests assert that both the generated and the checked-in unit set a
non-root `User=` and `Group=`, define exactly one `ExecStart` that does not
re-elevate, and set none of the privilege-raising directives above.

### An advanced root-owned installation

If you would rather run the service as root, that is supportable, but the code
must then live somewhere the target user cannot write — for example
`/opt/honeypath`, owned `root:root`, mode `0755`. Install a copy there, point
`ExecStart` at it, and keep `--user <name>` so canaries still land in the right
home. This is *not* what `install-systemd` generates, and it buys nothing
Honeypath needs; it is documented only so the trade-off is explicit.

---

## Canarytokens

Honeypath's canary AWS keys are internally fake, so a stealer that *uses* them
gets nothing — and you learn nothing either, unless the local read was caught.

[Canarytokens](https://canarytokens.org/) closes that gap: generate an AWS key
canarytoken there, and you get an alert when the credentials are **used**,
anywhere in the world, even if the local read went unobserved.

```bash
sudo python3 honeypath.py create-canaries \
    --canarytoken-aws-file ~/canarytoken-aws.txt --refresh-managed
```

The file should contain `aws_access_key_id` and `aws_secret_access_key` lines
(a downloaded credentials file works as-is). Honeypath splices that material
into the `.aws/credentials` canaries in place of its default fake content.

**Honeypath never generates token material.** It only uses what you supply.

---

## Safety boundaries

These are hard constraints, enforced in code and covered by tests:

- **Never overwrites an existing canary file** unless its recorded exact hash
  and managed identifier match. SSH `--force` is limited to named Phase-1
  wrapper/copy conflicts and restore; it cannot reactivate. Symlinks and non-regular files are
  always refused.
- **Never deletes real SSH keys or any user data.** Backups are never deleted
  automatically.
- **Credential-content boundary.** Honeypath may copy real SSH files as opaque
  bytes and hash them locally for drift detection. It never parses, displays,
  logs, inspects or transmits private-key contents. Hashes stay in the local
  database. The SSH *config* is the sole exception — parsed only to rewrite
  paths.
- **Anchored filesystem boundary.** Sensitive Linux/macOS traversal opens the
  approved root and every descendant directory with no-follow semantics and
  keeps those directory descriptors open through the operation. On Linux, new
  bytes live in an unnamed `O_TMPFILE` inode and are linked directly from its
  still-open descriptor, so a watched temporary name cannot substitute content.
  First creation is a no-clobber link. Managed replacement uses an atomic
  exchange, verifies that the exchanged-out inode is the exact hash-checked
  object, and exchanges back on mismatch without destroying the independently
  appeared file. Managed replacement on unsupported filesystems fails closed.
  For brand-new reproducible canaries where `O_TMPFILE` does not exist — DrvFS
  Windows homes, and macOS, whose kernel has no equivalent at all — Honeypath
  falls back to anchored `O_EXCL|O_NOFOLLOW` creation. That fallback can never
  clobber an existing credential; only all-at-once content visibility is
  relaxed, and managed *replacement* still requires the Linux primitives.
- **A write and its manifest row commit together.** Verification and database
  registration run inside the write, while the replaced inode is still staged.
  If either fails — an unreadable file, a full database — the previous canary is
  exchanged back and a brand-new one is removed, so a refresh can never leave a
  file on disk that the recorded hash and inode no longer describe.
  This relaxes only all-at-once content visibility: containment, inode identity,
  and no-clobber are never relaxed. Important files and parent directories are
  fsynced; DrvFS may relax mode/ownership only.
- **Symlink-safe atime polling.** The atime watcher anchors every parent from
  the filesystem root with no-follow directory FDs, treats symlinks and changed
  regular-file device/inode identities as replacement events, and never adopts
  an unverified legacy row. Relatime re-arming verifies the recorded identity
  and calls `utime` through the opened descriptor.
- **No real secrets.** No funded wallets, no valid private keys, no valid seed
  phrases, no real tokens. The canary "private key" is a base64 blob that
  decodes to a warning message; the Solana canary is an unmistakably invalid
  JSON object, never a 64-integer keypair array; the
  Electrum seed is not a valid BIP-39 mnemonic.
- **`.invalid` hosts only.** No canary can cause a real tool to contact a real
  endpoint.
- **No process hiding, log tampering, privilege escalation or anti-debugging.**
  The only persistence is the optional, ordinary systemd service.
- **System binaries are untouched.** No OpenSSH recompilation.
- **Never creates anything outside the detected (or explicitly supplied) target
  home / Windows home.**
- **Every created file is chowned to the target user** — `sudo` never leaves
  root-owned files in your home. On DrvFS (`/mnt/c`), chown/chmod failures are
  reported, not fatal.

---

## Full walkthrough

For the ordinary first run, the walkthrough is now one command:

```bash
sudo python3 honeypath.py setup
```

The equivalent advanced/manual sequence follows.

```bash
# 1. See what this machine can actually do.
sudo python3 honeypath.py doctor
sudo python3 honeypath.py doctor --windows-read-test        # WSL: prove the gap

# 2. Configure alerting with hidden-input prompts and verify it.
sudo python3 honeypath.py configure-alerts

# 3. Review, then create the canaries.
sudo python3 honeypath.py plan
sudo python3 honeypath.py create-canaries
sudo python3 honeypath.py create-canaries --include-crypto  # optional

# 4. WSL only: catch Windows-native reads, with process attribution.
sudo python3 honeypath.py setup-windows-audit
sudo python3 honeypath.py setup-windows-audit --install-windows-watcher  # optional

# 5. SSH canary, phase 1. Nothing under ~/.ssh changes yet.
sudo python3 honeypath.py setup-ssh-canary --dry-run
sudo python3 honeypath.py setup-ssh-canary

#    Test thoroughly. Take days if you want.
~/bin/ssh -G github.com | grep -Ei '^(identityfile|userknownhostsfile|identitiesonly|forwardagent) '
~/bin/ssh -T git@github.com
git config --global core.sshCommand
which ssh
ssh -G github.com | grep -Ei '^(identityfile|userknownhostsfile|identitiesonly|forwardagent) '

# 6. SSH canary, phase 2. Note the printed backup path.
sudo python3 honeypath.py setup-ssh-canary --activate
sudo python3 honeypath.py ssh-status

# 7. Now that ~/.ssh is a canary, the gated entries are available.
sudo python3 honeypath.py plan

# 8. Watch.
sudo python3 honeypath.py watch

# 9. Or run it as a service. It runs as your unprivileged target user, so make
#    sure the Pushover credentials are readable by that user first (see Install).
sudo python3 honeypath.py install-systemd
sudo systemd-analyze verify /etc/systemd/system/honeypath.service
sudo systemctl daemon-reload
sudo systemctl enable --now honeypath.service
sudo journalctl -u honeypath -f

# 10. Day-to-day.
sudo python3 honeypath.py events --limit 20
sudo python3 honeypath.py events --severity critical
sudo python3 honeypath.py events --path-substring ssh
sudo python3 honeypath.py mute --minutes 60     # before backups/housekeeping
sudo python3 honeypath.py mute --minutes 0      # un-mute

# 11. Undo everything SSH-related.
sudo python3 honeypath.py restore-ssh-canary
```

---

## Non-goals and future work

Documented, deliberately not built:

- **Windows-native SSH canarying** — relocating `%USERPROFILE%\.ssh` for
  `C:\Windows\System32\OpenSSH\ssh.exe`, `.cmd` wrappers, and Windows-side git
  config. Same two-phase design; this is phase two of the project, not of the
  flow. The Windows `.ssh` catalog entries exist and are gated accordingly.
- **macOS Endpoint Security integration** — the only route to reliable read
  detection on macOS, and incompatible with a Python-only, dependency-free tool.
- **Any prevention or blocking feature.** Honeypath detects. That is the whole
  scope.

---

## Development

```
honeypath.py                  # entry point
honeypath/
    cli.py                    # argparse wiring, command implementations
    platform_detect.py        # OS/WSL/Windows-home detection, interop
    target_user.py            # TargetUserContext, ownership rules
    catalog.py                # canary profiles, templates, metadata
    safe_write.py             # anchored, symlink-safe, atomic filesystem writes
    database.py               # SQLite schema, writer queue, migrations
    monitor.py                # inotify + atime watchers, dedup, cooldown
    alerts.py                 # Pushover
    ssh_canary.py             # setup / activate / restore / status
    windows_audit.py          # WSL to Windows SACL auditing via interop
tests/
systemd/honeypath.service
```

Standard library only. The only external programs Honeypath ever runs are
`inotifywait`, the system `ssh`/`git`, and — on WSL — `powershell.exe`,
`cmd.exe`, `auditpol.exe`, `fsutil.exe`, `schtasks.exe` and `wslpath` through
interop. Every interop call tolerates interop being disabled and degrades with
a clear message rather than crashing.

```bash
python3 -m unittest discover -s tests -t .
```

The suite covers target-user resolution, catalog content safety (no real hosts,
no valid keys or seeds), the `.ssh` activation gate, every config-rewrite form,
wrapper installation and refusal, activation and rollback including the `EXDEV`
fallback, event dedup/cooldown/mute, symlink-safe atime re-arming, writer-queue
shutdown draining, and paged Windows 4663 catch-up. On shutdown, watcher
producers stop first, queued hits and coalesced events are committed, and only
then does alert delivery receive a bounded drain period. `tests/test_integration_ssh.py`
runs the whole SSH flow against the real OpenSSH client and asserts that the
relocated config resolves identically to the original.

**Log file.** `/var/lib/honeypath/honeypath.log` is the human-readable record —
one line per detection, delivery outcome, degradation and error, at mode `0600`
with 5 MB rotation. See [The log file](#the-log-file). It is best-effort by
design: `tests/test_eventlog.py` asserts that a symlinked, unwritable or
mid-flight-broken log disables itself instead of propagating, that a newline
planted in a Windows process name cannot forge a line, and that a Pushover
error echoing the token is written redacted.

**Database.** `/var/lib/honeypath/events.sqlite3` holds both the events and the
canary manifest, plus `managed_changes` (every mutation Honeypath makes outside
its own directories, with previous values, so rollback restores rather than
merely unsets), `ssh_installations`, and the durable Windows-event inbox. WAL
mode uses a busy timeout. sqlite3
connections are thread-bound, so `watch` routes every write through a single
writer-queue thread and one-shot commands use short-lived per-operation
connections — a connection is never shared across threads.
