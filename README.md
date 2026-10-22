# 🛡️ SSH Watchtower

### A Python-Powered Linux SSH Authentication Log Analyzer

**SSH Watchtower** is a lightweight command-line security tool built with Python to analyze Linux SSH authentication logs, detect repeated failed password attempts, and identify IP addresses that exceed a configurable alert threshold.

Designed as a hands-on Linux System Administration and Defensive Security project, it demonstrates log analysis, IP address validation, Python automation, JSON reporting, and unit testing.

<p align="center">

  ![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
  ![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
  ![Security](https://img.shields.io/badge/Focus-Defensive%20Security-2E8B57?style=for-the-badge)
  ![Dependencies](https://img.shields.io/badge/Dependencies-Zero-6C757D?style=for-the-badge)

</p>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Example Output](#-example-output)
- [JSON Reporting](#-json-reporting)
- [Testing](#-testing)
- [Linux Log Integration](#-linux-log-integration)
- [Technical Details](#-technical-details)
- [Limitations](#-limitations)
- [Future Improvements](#-future-improvements)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

Linux servers commonly use SSH (Secure Shell) for remote administration. Monitoring authentication logs helps administrators investigate failed login attempts and recognize potentially suspicious activity.

SSH Watchtower automates a small part of this process.

Instead of manually searching through authentication logs, the tool:

1. Reads an authentication log file.
2. Extracts matching SSH failed-password events.
3. Validates the source IP addresses.
4. Counts failed attempts by IP.
5. Flags addresses that meet a configurable threshold.
6. Optionally exports the analysis to JSON.

**Important:** An alert indicates repeated failures, not confirmed malicious activity. Legitimate users can also make repeated login mistakes.

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 Log Parsing | Identifies supported OpenSSH failed-password messages. |
| 📊 Attempt Counting | Groups matching failed attempts by source IP. |
| 🌐 IP Validation | Validates IPv4 and IPv6 addresses using Python's `ipaddress` module. |
| 🚨 Threshold Alerts | Flags IP addresses that meet or exceed a configurable failure count. |
| 📄 JSON Reports | Exports scan results in machine-readable JSON format. |
| ⚙️ CLI Options | Configure the log file, alert threshold, and report destination. |
| 🧪 Unit Testing | Tests core detection and reporting behavior. |
| 🔒 Read-Only Analysis | Does not modify firewall rules or block IP addresses. |
| 📦 Zero Dependencies | Uses the Python standard library without third-party packages. |

## ⚙️ How It Works

SSH Watchtower uses a simple analysis pipeline:

```text
Linux Authentication Log
          |
          v
    Read Log Entries
          |
          v
 Match Failed Password Events
          |
          v
   Extract Source IPs
          |
          v
     Validate IPs
          |
          v
 Count Attempts Per Address
          |
          v
 Compare Against Threshold
          |
          v
 Display Alerts / JSON Report
```

### Detection Logic

The default alert threshold is `5` failed password attempts from the same IP address.

For example, if an IP produces seven matching failed-password events and the threshold is five, SSH Watchtower flags that address.

The threshold is configurable, so the same tool can be used for different lab scenarios and administrative requirements.

The current implementation counts matching events across the entire supplied file. It does not yet use a rolling time window.

## 📁 Project Structure

```text
ssh-watchtower/
│
├── src/
│   └── ssh_watchtower.py
│
├── tests/
│   └── test_ssh_watchtower.py
│
├── sample_logs/
│   └── auth.log
│
├── reports/
│   └── .gitkeep
│
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

### Directory Guide

- `src/` — Main Python application.
- `tests/` — Automated unit tests.
- `sample_logs/` — Fictional authentication events for safe testing.
- `reports/` — Destination for generated JSON reports.
- `requirements.txt` — Documents the dependency policy.
- `.gitignore` — Prevents generated and sensitive files from being committed.
- `LICENSE` — Project licensing information.

## 🧰 Requirements

- Linux operating system; Ubuntu is recommended.
- Python 3.10 or later.
- Git, if cloning the repository.
- Read access to the authentication log being analyzed.

No external Python packages are required.

## 🚀 Installation

### 1. Clone the repository

Replace `YOUR_USERNAME` with your GitHub username.

```bash
git clone https://github.com/YOUR_USERNAME/ssh-watchtower.git
cd ssh-watchtower
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

### 3. Verify Python

```bash
python3 --version
```

### 4. Run a sample scan

```bash
python3 src/ssh_watchtower.py \
  --log sample_logs/auth.log \
  --threshold 3
```

You are ready to use SSH Watchtower.

## 🖥️ Usage

SSH Watchtower provides three main command-line options.

| Option | Purpose | Default |
|---|---|---|
| `--log` | Path to the authentication log | `/var/log/auth.log` |
| `--threshold` | Failures required to trigger an alert | `5` |
| `--json-out` | Optional JSON report destination | No report |

### Basic Scan

```bash
python3 src/ssh_watchtower.py
```

This attempts to read `/var/log/auth.log` using the default threshold of five.

### Scan a Specific Log File

```bash
python3 src/ssh_watchtower.py \
  --log sample_logs/auth.log
```

### Change the Alert Threshold

```bash
python3 src/ssh_watchtower.py \
  --log sample_logs/auth.log \
  --threshold 3
```

### Generate a JSON Report

```bash
python3 src/ssh_watchtower.py \
  --log sample_logs/auth.log \
  --threshold 3 \
  --json-out reports/scan.json
```

### Display Help

```bash
python3 src/ssh_watchtower.py --help
```

## 📟 Example Output

The following is illustrative output from the included sample log.

```text
SSH WATCHTOWER
======================================
Log file: sample_logs/auth.log
Failed attempts: 4
Unique source IPs: 2
Alert threshold: 3

[!] THRESHOLD EXCEEDED
    192.0.2.45: 3 failed attempts
```

This example contains four matching failed-password events across two source IP addresses. One address reaches the threshold of three; the other does not.

Successful public-key authentication events are not counted as failed-password events.

## 📄 JSON Reporting

To save a scan report:

```bash
python3 src/ssh_watchtower.py \
  --log sample_logs/auth.log \
  --threshold 3 \
  --json-out reports/scan.json
```

The resulting JSON contains the generation timestamp, total failures, per-IP counts, suspicious IPs, and configured threshold.

Example:

```json
{
  "generated_at": "2026-10-22T15:30:00+00:00",
  "total_failed_attempts": 4,
  "attempts_by_ip": {
    "192.0.2.45": 3,
    "198.51.100.23": 1
  },
  "suspicious_ips": {
    "192.0.2.45": 3
  },
  "threshold": 3
}
```

The timestamp above is illustrative.

Generated JSON reports are intended to be excluded from version control because operational reports may contain sensitive information.

## 🧪 Testing

SSH Watchtower includes automated tests using Python's built-in `unittest` framework.

Run the tests from the project root:

```bash
python3 -m unittest discover -s tests -v
```

The test suite checks:

- Total failed-attempt counting.
- Threshold-based alert generation.
- Exclusion of successful logins.
- Rejection of invalid IP addresses.
- Validation of the alert threshold.
- JSON report generation.

A successful run should show six passing tests.

## 🐧 Linux Log Integration

On Ubuntu, SSH authentication events are commonly recorded in:

```text
/var/log/auth.log
```

Check whether the file exists:

```bash
ls -l /var/log/auth.log
```

If your account has the required permissions, scan it directly:

```bash
python3 src/ssh_watchtower.py \
  --log /var/log/auth.log \
  --threshold 5
```

If permission is denied, use authorized administrative access to export the log to a protected temporary file.

### Systems Using systemd Journald

Some Linux configurations rely on the system journal rather than a traditional authentication log file.

For an Ubuntu SSH service using `ssh.service`, export its journal entries:

```bash
sudo journalctl -u ssh.service --no-pager \
  > /tmp/ssh-watchtower.log
```

Then scan the exported file:

```bash
python3 src/ssh_watchtower.py \
  --log /tmp/ssh-watchtower.log \
  --threshold 5
```

The current parser is designed for a particular OpenSSH failed-password message format. Journal output and other distributions may use different formats, so not every SSH event will necessarily be recognized.

The scanner itself does not require root privileges if the input file is readable by the current user.

## 🧠 Technical Details

This project practices several useful Python and Linux concepts.

| Technology | Role |
|---|---|
| `argparse` | Command-line argument handling. |
| `re` | Matching SSH authentication messages. |
| `collections.Counter` | Counting failed attempts per IP. |
| `ipaddress` | Validating IPv4 and IPv6 addresses. |
| `pathlib` | Working with file paths. |
| `json` | Generating structured reports. |
| `datetime` | Recording report timestamps. |
| `unittest` | Testing application behavior. |
| Linux authentication logs | Source of SSH event data. |
| systemd journal | Alternative source of service logs. |

## ⚠️ Limitations

SSH Watchtower is an educational and administrative analysis tool, not a complete intrusion detection system.

Current limitations include:

- Only a specific failed-password log format is recognized.
- Events are counted across the entire input file rather than a time window.
- Repeated failures do not establish malicious intent.
- The tool does not currently detect all SSH authentication methods.
- It does not automatically block addresses.
- It does not modify firewall or SSH configuration.
- It does not provide continuous background monitoring by itself.
- Log rotation and multiple-file correlation are not yet implemented.

## 🛣️ Future Improvements

Potential future versions could introduce:

- [ ] Time-window-based brute-force detection.
- [ ] Support for `/var/log/secure` and additional log formats.
- [ ] Native systemd journal integration.
- [ ] Detection of successful logins following repeated failures.
- [ ] Configurable allowlists and exclusions.
- [ ] Email notifications for threshold alerts.
- [ ] Scheduled scans using cron or systemd timers.
- [ ] Improved structured logging and error reporting.
- [ ] Integration tests using representative log fixtures.
- [ ] Optional firewall integration with explicit administrative approval.

These improvements are planned features, not claims about the current implementation.

## 🔐 Security Considerations

- Use the tool only on systems and logs you are authorized to inspect.
- Do not commit real authentication logs to a public repository.
- Treat usernames, IP addresses, hostnames, and timestamps as potentially sensitive.
- Keep generated reports and temporary log exports protected.
- Do not treat a threshold alert as definitive evidence of an attack.
- Review results before taking any defensive action.

SSH Watchtower is read-only by design. It analyzes log data and reports findings without changing system security settings.

## 🤝 Contributing

Contributions and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement and test your change.
4. Run the unit test suite.
5. Open a pull request describing the change.

Please avoid including private server logs, credentials, or other sensitive operational data in issues and pull requests.

## 📜 License

This project is distributed under the MIT License. See the `LICENSE` file for details.

---

<p align="center">

  **Built with Python and Linux. Designed for defensive security and system administration.**

</p>
