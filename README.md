# 🔭 SSH Watchtower — Login Threat Detector

A lightweight Python tool that analyzes Linux SSH authentication logs and flags suspicious login activity: brute-force attempts, password spraying, possible account compromise, and unusual login patterns. It finishes with a SOC-style incident summary and recommended response actions.

**Zero dependencies. One file. Python 3.8+.**

---

## Features

- **Detects repeated failed SSH logins** using a sliding time window, so a burst is caught wherever it falls in the log
- **Identifies unusual login patterns:** off-hours logins, direct root logins, one user logging in from many IPs
- **Flags likely compromise:** a successful login right after a run of failures from the same IP
- **Produces an incident summary** with severity levels, timelines, top attacking IPs, and recommended actions
- **Configurable thresholds** via CLI flags or a JSON config file
- **Alert-friendly exit codes:** exits with `2` on HIGH/CRITICAL findings, handy for cron jobs and CI
- **Multiple log formats:** Debian/Ubuntu `auth.log`, RHEL/CentOS `secure`, and ISO-timestamp rsyslog output
- **Exports** findings as JSON or a saved text report

---

## Detection Rules

| Rule | Severity | What it catches |
|---|---|---|
| `SUCCESS_AFTER_FAIL` | 🔴 CRITICAL | Successful login after repeated failures from the same IP (possible credential compromise) |
| `BRUTE_FORCE` | 🟠 MEDIUM / HIGH | N failed logins from one IP within the time window |
| `TARGETED_ACCOUNT` | 🟠 HIGH | One account failing from many distinct IPs (distributed attack) |
| `ROOT_LOGIN` | 🟠 HIGH | Successful direct root login |
| `PASSWORD_SPRAY` | 🟡 MEDIUM | One IP trying many different usernames |
| `MULTI_IP_USER` | 🟡 MEDIUM | One user logging in successfully from many distinct IPs |
| `OFF_HOURS_LOGIN` | 🔵 LOW | Successful login outside configured working hours |

---

## Quick Start

```bash
git clone https://github.com/sandeepdas17/ssh-watchtower.git
cd ssh-watchtower

# Try it with a generated sample log containing every attack pattern
python3 ssh_watchtower.py --demo

# Analyze a real log (may need sudo to read it)
sudo python3 ssh_watchtower.py /var/log/auth.log
```

---

## Usage

```
python3 ssh_watchtower.py <logfile> [options]
```

| Option | Description | Default |
|---|---|---|
| `--fail-threshold N` | Failures within the window that trigger brute-force | `5` |
| `--window SECONDS` | Sliding window size | `300` |
| `--spray-users N` | Distinct usernames from one IP that trigger spraying | `4` |
| `--work-start H` / `--work-end H` | Working hours; logins outside are flagged | `7` / `20` |
| `--whitelist IP [IP ...]` | Trusted IPs to ignore | none |
| `--config FILE` | JSON file with threshold overrides | none |
| `--year YYYY` | Year for syslog timestamps (they don't include one) | current year |
| `--json FILE` | Also write findings as JSON | none |
| `--summary FILE` | Also save the text report | none |
| `--demo` | Generate and analyze a sample log | off |

CLI flags override the config file, and the config file overrides the defaults.

### Examples

```bash
# Stricter detection: 3 failures in 2 minutes
python3 ssh_watchtower.py /var/log/auth.log --fail-threshold 3 --window 120

# Ignore your office IP and export results
python3 ssh_watchtower.py auth.log --whitelist 203.0.113.10 --json report.json --summary report.txt

# Use a config file
python3 ssh_watchtower.py auth.log --config thresholds.json
```

**`thresholds.json`**

```json
{
  "fail_threshold": 3,
  "window_seconds": 120,
  "spray_user_threshold": 3,
  "targeted_ip_threshold": 4,
  "multi_ip_threshold": 3,
  "success_after_fail": 3,
  "work_hours_start": 9,
  "work_hours_end": 18,
  "whitelist_ips": ["10.0.0.1"]
}
```

### Run it on a schedule

```bash
# Check every hour and write a report; exit code 2 means HIGH/CRITICAL findings
0 * * * * /usr/bin/python3 /opt/ssh-watchtower/ssh_watchtower.py /var/log/auth.log --summary /var/log/watchtower.txt
```

---

## Sample Output

```
========================================================================
SSH WATCHTOWER - INCIDENT SUMMARY
========================================================================
Source file     : demo_auth.log
Log period      : 2026-10-21 09:00:00  ->  2026-10-22 12:00:00
Events analysed : 76  (59 failed, 10 successful)
Thresholds      : 5 fails / 300s, spray>=4 users, hours 07-20

Findings by severity: CRITICAL=1, HIGH=3, MEDIUM=4, LOW=2

Top failing source IPs
  203.0.113.45                                40 failures
  198.51.100.9                                 7 failures
  100.64.7.7                                   6 failures

Detailed findings
------------------------------------------------------------------------
[CRITICAL] SUCCESS_AFTER_FAIL carol@100.64.7.7
           successful password login after 6 failures from the same IP - possible compromised credentials
           when: 2026-10-21 15:00:00 -> 2026-10-21 15:01:15
[HIGH    ] BRUTE_FORCE        203.0.113.45
           40 failed logins within 300s (40 total from this IP)
           when: 2026-10-21 12:00:00 -> 2026-10-21 12:01:57
[HIGH    ] ROOT_LOGIN         root@172.16.5.5
           direct root login via publickey
[HIGH    ] TARGETED_ACCOUNT   bob
           account attacked from 6 distinct IPs (6 failures)
[MEDIUM  ] PASSWORD_SPRAY     198.51.100.9
           tried 7 different usernames: admin, git, oracle, pi, postgres, test, ubuntu
...

Recommended actions
------------------------------------------------------------------------
* URGENT: treat accounts in SUCCESS_AFTER_FAIL as compromised - reset credentials, kill active sessions, review shell history.
* Block offending IPs (fail2ban / firewall), enforce key-only auth (PasswordAuthentication no), consider a non-default port or VPN.
* Disable direct root SSH login (PermitRootLogin no) and use sudo.
* Verify off-hours / multi-location logins with the account owners.
========================================================================
```

---

## How It Works

1. **Parse:** Regexes match sshd lines (`Failed password`, `Invalid user`, `Accepted publickey`, `Connection closed by authenticating user`, and more) and extract timestamp, user, source IP, and auth method into structured events.
2. **Normalize:** Events are sorted by time, and December-to-January year rollover is handled for syslog stamps that carry no year.
3. **Detect:** Each rule runs over the events. Brute-force detection uses a two-pointer sliding window, so it runs in linear time after sorting.
4. **Report:** Findings are ranked by severity and rendered as a text summary, with optional JSON export.

---

## Project Structure

```
ssh-watchtower/
├── ssh_watchtower.py   # parser, detection engine, report generator, CLI
└── README.md
```

---

## Limitations

- Works on SSH logs only (`sshd` entries). It doesn't read `journald` directly; export with `journalctl -u ssh > ssh.log` first.
- Detection is rule-based with static thresholds. There is no per-user baseline or GeoIP yet.
- IPs behind NAT or a shared proxy can look like a single noisy source.

## Roadmap

- [ ] GeoIP / ASN enrichment for source IPs
- [ ] Per-user baseline of normal IPs and login hours
- [ ] Export offending IPs as `iptables` / `fail2ban` rules
- [ ] Live log following (`tail -f` mode) with real-time alerts
- [ ] Unit tests with a fixture log set

---

## Skills Demonstrated

Python · Regular expressions · Log analysis · Linux security · Threat detection · Incident reporting

---

## Disclaimer

For defensive use on systems and logs you own or are authorized to monitor.

## Author

**Sandeep Das**
GitHub: [@sandeepdas17](https://github.com/sandeepdas17) · LinkedIn: [sandeepdas00e](https://www.linkedin.com/in/sandeepdas00e)
