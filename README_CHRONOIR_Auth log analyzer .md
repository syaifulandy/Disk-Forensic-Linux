# ChronoIR AuthLog Analyzer v0.5.6

ChronoIR AuthLog Analyzer is a lightweight DFIR helper for Linux authentication logs such as `auth.log` and `secure`.

It parses authentication-related events, builds investigation-friendly CSVs, generates summaries, enriches source IP context, and keeps the original evidence fields intact.

> **Design principle:** fast triage first, deeper evidence optional.

> **Important:** ChronoIR findings, risk scores, and reputation enrichment are triage aids. They are not proof of compromise by themselves. Always validate using raw logs, endpoint telemetry, network telemetry, asset inventory, and environment context.

---

## Table of Contents

- [Features](#features)
- [Supported Input Logs](#supported-input-logs)
- [Quick Start](#quick-start)
- [Recommended Commands](#recommended-commands)
- [Command Line Options](#command-line-options)
- [hostipdb Format](#hostipdb-format)
- [VirusTotal Enrichment](#virustotal-enrichment)
- [User Events Modes](#user-events-modes)
- [Risk and Scoring Model](#risk-and-scoring-model)
- [Suggested Investigation Workflow](#suggested-investigation-workflow)
- [Output Structure](#output-structure)
- [Important Output Files](#important-output-files)
- [CSV Delimiters](#csv-delimiters)
- [Parser Coverage and Raw Evidence](#parser-coverage-and-raw-evidence)
- [Field Notes](#field-notes)
- [Performance Notes](#performance-notes)
- [Troubleshooting](#troubleshooting)
- [Version Notes](#version-notes)

---

## Features

### Core parsing

ChronoIR parses common Linux auth log activities:

- SSH successful login
- SSH failed login
- SSH invalid user
- SSH PAM authentication failure
- sudo command activity
- su success and TTY context
- PAM session opened / closed
- local account creation
- password change
- group creation
- user added to privileged group
- account deletion
- user info change

### DFIR outputs

ChronoIR generates:

- case summary
- parsed event timeline
- indicator CSVs
- behavior analytics CSVs
- per-IP reports
- per-user reports
- optional per-user event timelines
- alerts
- MITRE mapping
- VirusTotal enrichment table

### Context enrichment

ChronoIR supports:

- local source IP inventory via `--hostipdb`
- VirusTotal reputation enrichment
- optional VT context join with `--join-vt-context`

Original fields such as `src_ip` are never replaced.

---

## Supported Input Logs

ChronoIR supports a single file or a folder.

Supported file patterns include:

```text
auth.log
auth.log.*
auth.log.*.gz
secure
secure-*
secure.*
```

Examples:

```bash
python3 chronoir.py /var/log
python3 chronoir.py /var/log/auth.log
python3 chronoir.py ./evidence/var/log
```

---

## Quick Start

### Fast triage

```bash
python3 chronoir.py /var/log --fast
```

### Normal parse without VirusTotal

```bash
python3 chronoir.py /var/log --year 2026 --no-vt
```

### Parse a specific auth log file

```bash
python3 chronoir.py /var/log/auth.log --year 2026 --no-vt
```

### Parse with source IP context database

```bash
python3 chronoir.py /var/log --year 2026 --hostipdb hostipdb.csv --no-vt
```

### Generate parsed user event timelines

```bash
python3 chronoir.py /var/log --year 2026 --user-events-mode parsed --no-vt
```

### Deep raw user event timelines

```bash
python3 chronoir.py /var/log --year 2026 --user-events-mode raw --no-vt
```

> Raw mode can be slow and can generate large output on big auth log collections.

---

## Recommended Commands

### 1. Fastest triage mode

```bash
python3 chronoir.py /path/to/logs --fast
```

Equivalent intent:

```text
--no-vt
--user-events-mode off
--no-near-login
--join-vt-context disabled
```

Use this when:

- logs are very large
- you need quick summary and indicators
- you do not need per-user event timelines yet

---

### 2. Standard offline DFIR mode

```bash
python3 chronoir.py /path/to/logs --year 2026 --no-vt
```

Use this when:

- you want normal parsing
- you do not want external API calls
- you still want behavior analytics

---

### 3. Standard mode with host/IP inventory

```bash
python3 chronoir.py /path/to/logs --year 2026 --hostipdb hostipdb.csv --no-vt
```

Use this when:

- you have known bastion hosts
- you have known admin workstations
- you want IPs displayed with friendly names

---

### 4. Parsed user timeline mode

```bash
python3 chronoir.py /path/to/logs --year 2026 --user-events-mode parsed --no-vt
```

Use this when:

- you want `user_events/<user>.events.csv`
- you want fast parsed-only user timelines
- you do not need raw grep-like user matching

---

### 5. Raw user timeline mode

```bash
python3 chronoir.py /path/to/logs --year 2026 --user-events-mode raw --no-vt
```

Use this only when:

- you need grep-like raw user timelines
- you accept slower runtime
- you accept larger output size

---

## Command Line Options

Run help:

```bash
python3 chronoir.py -h
```

### Required argument

#### `input`

Path to auth log file or folder.

Examples:

```bash
python3 chronoir.py /var/log
python3 chronoir.py /var/log/auth.log
python3 chronoir.py ./evidence/var/log
```

---

### `--case`

Output case directory.

Default:

```text
Output_Analyzer
```

Example:

```bash
python3 chronoir.py /var/log --case CASE001_AUTHLOG
```

---

### `--year`

Linux syslog-style auth logs often do not include a year in each line.

Example log:

```text
May 15 14:52:33 abc.co.id sshd[6190]: Accepted publickey for admin from 169.254.14.237 port 53030 ssh2
```

ChronoIR needs a year to build ISO timestamps.

Example:

```bash
python3 chronoir.py /var/log --year 2026
```

---

### `--hostipdb`

CSV or whitespace file used to enrich source IPs with friendly context.

Example:

```bash
python3 chronoir.py /var/log --hostipdb hostipdb.csv
```

This does **not** replace the original IP. It adds enrichment fields such as:

```text
src_ip
src_ip_display
src_ip_name
src_ip_role
src_ip_owner
ip_context_display
```

---

### `--vt-key-file`

Path to VirusTotal API key file.

Default:

```text
api_key_virustotal.txt
```

Example:

```bash
python3 chronoir.py /var/log --vt-key-file ./api_key_virustotal.txt
```

The file should contain only the API key string.

---

### `--no-vt`

Disable VirusTotal enrichment even if an API key file exists.

Example:

```bash
python3 chronoir.py /var/log --no-vt
```

Recommended for:

- offline investigation
- fastest local triage
- privacy-sensitive environments

---

### `--vt-sleep`

Sleep seconds between VirusTotal API calls.

Default:

```text
16
```

Example:

```bash
python3 chronoir.py /var/log --vt-sleep 20
```

---

### `--no-cache`

Do not use cached VirusTotal responses.

Example:

```bash
python3 chronoir.py /var/log --no-cache
```

By default, cached VT JSON responses are reused when available.

---

### `--join-vt-context`

Join VirusTotal context into timeline and key tables.

Default:

```text
off
```

Example:

```bash
python3 chronoir.py /var/log --join-vt-context
```

When enabled, fields such as these can appear in timeline/key outputs:

```text
vt_country
vt_organization
vt_malicious
vt_suspicious
vt_total_malicious_suspicious
vt_status
ip_context_display
```

Recommended only when you need VT context directly in the main CSVs.

For fast triage, leave this disabled.

---

### `--near-minutes`

Window size for near-login behavioral analytics.

Default:

```text
10
```

Example:

```bash
python3 chronoir.py /var/log --near-minutes 15
```

This affects output:

```text
behavior/near_login_events.csv
```

---

### `--no-near-login`

Skip near-login analytics.

Example:

```bash
python3 chronoir.py /var/log --no-near-login
```

Use this if:

- logs are very large
- you need faster processing
- near-login behavior is not needed for the current run

---

### `--user-events-mode`

Controls generation of per-user event timelines.

Choices:

```text
off
parsed
raw
```

Default:

```text
off
```

#### `off`

Do not generate per-user event timelines.

```bash
python3 chronoir.py /var/log --user-events-mode off
```

Fastest and smallest output.

#### `parsed`

Generate user timelines from parsed events only.

```bash
python3 chronoir.py /var/log --user-events-mode parsed
```

This is fast and recommended when user event timelines are needed.

#### `raw`

Generate grep-like raw user timelines.

```bash
python3 chronoir.py /var/log --user-events-mode raw
```

This can be slow and large because it scans raw log lines for usernames.

---

### `--raw-user-events`

Alias for:

```text
--user-events-mode raw
```

Example:

```bash
python3 chronoir.py /var/log --raw-user-events
```

---

### `--fast`

Fast triage shortcut.

Example:

```bash
python3 chronoir.py /var/log --fast
```

Equivalent intent:

```text
--no-vt
--user-events-mode off
--no-near-login
--join-vt-context disabled
```

Use this when speed matters more than optional enrichment/detail.

---

### `--version`

Print version.

```bash
python3 chronoir.py --version
```

---

## hostipdb Format

`hostipdb` enriches source IPs with friendly context.

It does **not** replace the original IP.

### CSV format

Recommended file name:

```text
hostipdb.csv
```

Required column:

```text
ip
```

Recommended columns:

```text
ip,hostname,role,owner,notes
```

Example:

```csv
ip,hostname,role,owner,notes
10.10.10.5,jump-host-prod,bastion,infra,Known admin jump host
192.168.1.20,admin-laptop-budi,workstation,budi,Internal admin laptop
169.254.14.237,linklocal-admin,linklocal,unknown,Observed in auth.log
1.1.1.1,cloudflare-dns,public-dns,external,Reference public DNS
8.8.8.8,google-dns,public-dns,external,Reference public DNS
```

Run with:

```bash
python3 chronoir.py /var/log --hostipdb hostipdb.csv
```

### Whitespace format

A simpler whitespace-separated format is also supported:

```text
10.10.10.5 jump-host-prod bastion infra Known admin jump host
192.168.1.20 admin-laptop-budi workstation budi Internal admin laptop
169.254.14.237 linklocal-admin linklocal unknown Observed in auth.log
```

### Enriched fields

When `hostipdb` matches an IP, ChronoIR can add:

```text
src_ip=10.10.10.5
src_ip_name=jump-host-prod
src_ip_role=bastion
src_ip_owner=infra
src_ip_display=10.10.10.5 (jump-host-prod)
ip_context_display=10.10.10.5 (jump-host-prod)
```

If `--join-vt-context` is enabled, `ip_context_display` can include VT context too.

---

## VirusTotal Enrichment

VirusTotal enrichment is optional.

By default, ChronoIR looks for:

```text
api_key_virustotal.txt
```

If the file exists, public IPs may be enriched and results are written to:

```text
indicators/vt_ip_enrichment.csv
enrichment/virustotal/<ip>.json
```

Private and non-global IPs are skipped for VT and recorded as:

```text
PRIVATE_SKIPPED
```

### Disable VirusTotal

```bash
python3 chronoir.py /var/log --no-vt
```

### Join VT context into main outputs

```bash
python3 chronoir.py /var/log --join-vt-context
```

Without `--join-vt-context`, VT results remain in the VT enrichment table and are not joined into every event.

### Important note

VirusTotal is context only. It is not proof of compromise by itself.

---

## User Events Modes

ChronoIR can generate optional per-user timelines in:

```text
user_events/
```

### Default mode: off

```bash
python3 chronoir.py /var/log
```

No `user_events/*.events.csv` files are generated.

This is fastest.

### Parsed mode

```bash
python3 chronoir.py /var/log --user-events-mode parsed
```

Generates per-user timelines from parsed events only.

Example output:

```text
user_events/admin.events.csv
user_events/admin.events.log
```

### Raw mode

```bash
python3 chronoir.py /var/log --user-events-mode raw
```

Generates grep-like raw user timelines.

This can be slow and large on big auth log sets.

For complete manual raw review, it may be better to use original logs listed in:

```text
raw/source_files.txt
```

with tools such as EmEditor, grep, ripgrep, lnav, or awk.

---

## Risk and Scoring Model

Risk scores and risk labels in ChronoIR are **heuristic triage signals**.

They are intended to help prioritize review, not to declare compromise.

Always validate with:

```text
raw/source_files.txt
original auth logs
timeline.csv
endpoint telemetry
network telemetry
asset inventory
known administration patterns
```

---

### Near Login Risk Scoring

Near-login findings are written to:

```text
behavior/near_login_events.csv
```

The score is additive. Multiple conditions in the same time window can increase the total risk score.

Default time window:

```text
10 minutes
```

Change it with:

```bash
--near-minutes 15
```

Disable it with:

```bash
--no-near-login
```

#### Near-login scoring rules

| Condition | Score |
|---|---:|
| Multiple users logged in near each other | +10 |
| Same source IP logged in to multiple users | +20 |
| Mixed authentication methods in the same window | +10 |
| Multiple users near-login involving high privilege user(s) | +25 |
| Multiple high privilege users near-login | +35 |
| Multiple users near-login from public IP | +20 |
| Multiple password-based successful logins in the window | +15 |

#### Near-login risk level thresholds

| Score | Risk Level |
|---:|---|
| 80 and above | CRITICAL |
| 55 to 79 | HIGH |
| 25 to 54 | MEDIUM |
| 1 to 24 | LOW |
| 0 | INFO |

#### Near-login example

If the same public IP logs in to multiple users within 10 minutes, including an admin user, using mixed authentication methods:

```text
multiple_users_near_login                  +10
same_ip_multiple_users                     +20
mixed_auth_method_burst                    +10
multiple_users_near_login_with_high_priv   +25
multiple_users_near_login_from_public_ip   +20
------------------------------------------------
Total                                      85
Risk Level                                 CRITICAL
```

#### Near-login interpretation notes

A high near-login score can be legitimate in some environments.

Examples:

```text
known bastion host
jump server
PAM gateway
shared admin workstation
automation host
scheduled operational login pattern
```

Use `--hostipdb` to add local environment context.

---

### IP Report Risk Scoring

Per-IP reports are written to:

```text
ip/<src_ip>.txt
```

Risk score is additive.

#### IP risk scoring rules

| Condition | Score |
|---|---:|
| Failed SSH/PAM attempts >= 10 | +10 |
| Successful SSH login observed from the IP | +20 |
| VirusTotal malicious/suspicious total >= 1 | +10 |
| VirusTotal malicious/suspicious total >= 3 | +25 |

#### IP risk severity thresholds

| Score | Severity |
|---:|---|
| 120 and above | CRITICAL |
| 70 to 119 | HIGH |
| 30 to 69 | MEDIUM |
| 1 to 29 | LOW |
| 0 | INFO |

#### IP risk notes

VirusTotal-based scoring only applies when VT context is joined into event context.

Enable VT context join with:

```bash
--join-vt-context
```

VirusTotal results are context only and are not proof of malicious activity.

---

### High Privilege User Heuristic

High privilege user access is written to:

```text
behavior/high_priv_user_access.csv
```

A user may be treated as high privilege when one or more of these conditions match:

```text
user is root
username contains admin-related keyword
username contains sudo/wheel/security/ops/backup/db keywords
user was added to a privileged group
```

Common keyword examples:

```text
root
admin
adm
sudo
wheel
ops
sec
security
backup
oracle
postgres
mysql
dbadmin
vmanage-admin
```

This is heuristic. Review with local account policy and asset context.

---

### Failed Password User Risk

File:

```text
indicators/failed_password_by_user.csv
```

Current risk logic:

| Condition | Risk |
|---|---|
| Target user is `root` | HIGH |
| Failed auth count >= 20 | HIGH |
| Otherwise | LOW |

This is a simple triage label.

---

### Alert Severity

Alerts are written to:

```text
alerts/alerts.md
alerts/alerts.json
```

Alert severity is generated from detection logic, not from a single global risk model.

Examples of alert drivers:

- repeated brute-force from one source IP
- local account creation
- privileged account-related activity
- successful login patterns after failures

Always validate alert evidence using:

```text
timeline.csv
raw/events.jsonl
raw/source_files.txt
original auth logs
```

---

## Suggested Investigation Workflow

1. Open:

```text
summary.md
```

2. Review host/log sources:

```text
Host Logs Observed
```

3. Review top failed users:

```text
indicators/failed_password_by_user.csv
```

4. Review successful login source IPs:

```text
indicators/success_login_by_ip.csv
```

5. Review high privilege access:

```text
behavior/high_priv_user_access.csv
```

6. Review near-login behavior:

```text
behavior/near_login_events.csv
```

7. Pivot to entity reports:

```text
ip/<src_ip>.txt
user/<username>.txt
```

8. Validate with parsed timeline:

```text
timeline.csv
```

9. Validate with original raw evidence:

```text
raw/source_files.txt
original auth logs
```

---

## Output Structure

Default output directory:

```text
Output_Analyzer/
```

Typical structure:

```text
Output_Analyzer/
├── summary.md
├── README_OUTPUT.md
├── timeline.csv
├── raw/
│   ├── events.jsonl
│   └── source_files.txt
├── indicators/
│   ├── all_ips.txt
│   ├── public_ips.txt
│   ├── private_ips.txt
│   ├── failed_password_by_user.csv
│   ├── failed_password_by_ip_user.csv
│   ├── success_login_by_ip.csv
│   ├── success_login_by_user.csv
│   ├── success_after_failed_ips.csv
│   ├── success_after_failed_ip_user.csv
│   ├── created_users.csv
│   ├── deleted_users.csv
│   ├── groups_created.csv
│   ├── privileged_users_added.csv
│   ├── user_info_changed.csv
│   ├── account_lifecycle.csv
│   └── vt_ip_enrichment.csv
├── behavior/
│   ├── auth_success_by_method.csv
│   ├── high_priv_user_access.csv
│   ├── login_patterns_by_user.csv
│   ├── login_patterns_by_ip.csv
│   ├── near_login_events.csv
│   ├── auth_method_transitions.csv
│   └── first_seen_logins.csv
├── ip/
│   └── <src_ip>.txt
├── user/
│   └── <username>.txt
├── user_events/
│   └── optional, depending on --user-events-mode
├── alerts/
│   ├── alerts.md
│   └── alerts.json
├── mitre/
│   └── attack_matrix.md
└── enrichment/
    └── virustotal/
```

---

## Important Output Files

### `summary.md`

Start here.

Contains:

- processed files
- host logs observed
- totals
- VirusTotal signal summary
- top event types
- failed password/PAM users
- successful login IPs
- high privilege access samples
- near-login findings
- investigation pointers

### `timeline.csv`

Main parsed event timeline.

Useful columns include:

```text
timestamp
host
source_file
event_type
severity
actor_user
user
target_user
src_ip
src_ip_display
ip_context_display
process
pid
auth_method
command
raw
```

### `raw/events.jsonl`

Parsed events as JSONL.

### `raw/source_files.txt`

List of source log files processed.

Use this when you need to return to the original raw evidence.

### `indicators/success_login_by_ip.csv`

Successful SSH login summary by source IP.

### `indicators/failed_password_by_user.csv`

Failed password/PAM summary by user.

### `behavior/near_login_events.csv`

Near-login behavioral findings.

Examples of insights:

```text
multiple_users_near_login
same_ip_multiple_users
multiple_users_near_login_with_high_priv
multiple_high_priv_users_near_login
multiple_users_near_login_from_public_ip
password_success_burst
mixed_auth_method_burst
```

### `ip/<src_ip>.txt`

Per-IP report.

Includes:

- source IP context
- host/log hosts observed
- successful login summary
- failed auth summary
- timeline samples

### `user/<username>.txt`

Per-user report.

Includes:

- hosts observed
- login summary
- failed auth summary
- important parsed timeline
- pointers to user events if enabled

### `user_events/<user>.events.csv`

Optional per-user timeline.

Only generated when:

```bash
--user-events-mode parsed
```

or:

```bash
--user-events-mode raw
```

---

## CSV Delimiters

Most indicator and behavior CSV files use semicolon delimiter:

```text
;
```

Example files:

```text
indicators/success_login_by_ip.csv
indicators/failed_password_by_user.csv
behavior/near_login_events.csv
behavior/high_priv_user_access.csv
```

The main timeline uses comma delimiter:

```text
,
```

File:

```text
timeline.csv
```

If a CSV does not split correctly in Excel, import it manually and choose the correct delimiter.

---

## Parser Coverage and Raw Evidence

`timeline.csv` contains parsed events only.

If a raw log line is not recognized by the parser, it may not appear in `timeline.csv`.

For complete raw evidence review, use the original logs listed in:

```text
raw/source_files.txt
```

Recommended manual review tools:

```bash
grep
ripgrep
awk
less
lnav
EmEditor
```

Example manual pivots:

```bash
grep -i "admin" auth.log
grep -i "169.254.14.237" auth.log
grep -i "Accepted publickey" auth.log
rg -i "admin|169.254.14.237" ./evidence/var/log
```

---

## Field Notes

### `host`

The syslog/logging host.

Example:

```text
Mar 16 08:12:04 app-1 login[4659]: ...
```

Here:

```text
host = app-1
```

This is not the remote source IP.

### `src_ip`

Remote source IP found in the log message.

Example:

```text
Accepted publickey for admin from 169.254.14.237 port 53030 ssh2
```

Here:

```text
src_ip = 169.254.14.237
```

### `process` and `pid`

Example:

```text
sshd[6190]
```

Here:

```text
process = sshd
pid = 6190
```

PID is useful for process/session correlation.

### `src_ip_display`

Human-friendly source IP display from `hostipdb`.

Example:

```text
169.254.14.237 (linklocal-admin)
```

### `ip_context_display`

Combined context display.

Without VT join:

```text
169.254.14.237 (linklocal-admin)
```

With VT join:

```text
169.254.14.237 (linklocal-admin) | VT org=UNKNOWN country=UNKNOWN total=0 status=PRIVATE_SKIPPED
```

---

## Performance Notes

### Fastest mode

```bash
python3 chronoir.py /var/log --fast
```

### Avoid heavy output

Use default:

```bash
python3 chronoir.py /var/log --no-vt
```

Avoid unless needed:

```bash
--user-events-mode raw
--join-vt-context
```

### If report writing is slow

Try writing output to a local non-synced directory:

```bash
python3 chronoir.py /var/log --fast --case /tmp/Output_Analyzer
```

Writing many files to synced folders, external drives, or network locations can be slower.

---

## Troubleshooting

### Help only shows `analyze`

Use v0.5.6 or newer.

Now this should show all options:

```bash
python3 chronoir.py -h
```

### VT seems slow

Disable VT:

```bash
python3 chronoir.py /var/log --no-vt
```

### Processing is still slow

Use fast mode:

```bash
python3 chronoir.py /var/log --fast
```

Check timing output:

```text
Timing: parse=... context=... tables=... user_events=... reports=... total=...
```

### Need full raw analysis for one user

Use original logs from:

```text
raw/source_files.txt
```

Then search manually with tools such as:

```bash
grep -i "admin" auth.log
rg -i "admin" ./evidence/var/log
```

Or use raw user events if acceptable:

```bash
python3 chronoir.py /var/log --user-events-mode raw
```

---

## Version Notes

### v0.5.6

- Performance reset.
- Direct CLI help fixed.
- Default `user_events` is `off`.
- VT context join is optional.
- `--fast` added.
- Host/log-host context retained.
- Risk and scoring model documented.

### v0.5.5

- Added user event modes.
- Default user events changed to parsed.

### v0.5.4

- Added VT context join fields.

### v0.5.3

- Added hostipdb.
- Added user_events.
- Added host/log-host context improvements.

### v0.5.2

- Added investigation navigation and output guide improvements.

---

## Disclaimer

ChronoIR findings are triage aids. Behavioral findings, risk scoring, and reputation enrichment are not proof of compromise by themselves. Validate with environment context, original raw logs, endpoint data, network telemetry, and incident response procedures.
