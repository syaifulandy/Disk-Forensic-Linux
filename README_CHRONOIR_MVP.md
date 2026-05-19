# ChronoIR AuthLog Analyzer v0.4.1

Default langsung analyze:

```bash
python3 chronoir.py /var/log
```

## v0.4.1 changes

- Fix `useradd` parsing when log line does **not** contain trailing `, from=...`.
- Add parser support for `groupadd`, `userdel`, and `chfn`.
- Add new indicator files:
  - `deleted_users.csv`
  - `groups_created.csv`
  - `user_info_changed.csv`
  - `account_lifecycle.csv`
- Keep v0.4 indicators:
  - `failed_password_by_user.csv`
  - `failed_password_by_ip_user.csv`
  - `success_login_by_ip.csv`
  - `success_login_by_user.csv`
  - `success_after_failed_ips.csv`
  - `success_after_failed_ip_user.csv`
  - `created_users.csv`
  - `privileged_users_added.csv`

## Default behavior

- Mandatory input hanya path file/folder log.
- Default output folder: `Output_Analyzer`
- Default VirusTotal key file: `api_key_virustotal.txt`
- Kalau file API key VT ada, VT enrichment otomatis jalan.
- Kalau file API key VT tidak ada, proses VT otomatis di-skip dan parsing tetap lanjut.
- Kalau ingin disable VT walaupun key ada: `--no-vt`

## Examples

```bash
python3 chronoir.py /var/log
python3 chronoir.py /var/log/auth.log --year 2026
python3 chronoir.py /var/log/auth.log.1.gz --year 2026
python3 chronoir.py ./evidence/var/log --case CASE001 --year 2026
```

With VirusTotal default key:

```bash
echo 'VT_API_KEY_KAMU' > api_key_virustotal.txt
python3 chronoir.py /var/log
```

Disable VirusTotal:

```bash
python3 chronoir.py /var/log --no-vt
```

## Main output

```text
Output_Analyzer/
├── summary.md
├── timeline.csv
├── raw/events.jsonl
├── raw/source_files.txt
├── indicators/
│   ├── all_ips.txt
│   ├── public_ips.txt
│   ├── private_ips.txt
│   ├── vt_ip_enrichment.csv
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
│   └── account_lifecycle.csv
├── ip/
├── user/
├── alerts/alerts.md
├── alerts/alerts.json
├── mitre/attack_matrix.md
└── enrichment/virustotal/
```
