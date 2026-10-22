#!/usr/bin/env python3
"""
SSH Watchtower - Login Threat Detector
Analyzes Linux SSH authentication logs (Debian/Ubuntu auth.log, RHEL/CentOS secure)
and reports suspicious login activity.

Detections
  1. BRUTE_FORCE        many failed logins from one IP inside a time window
  2. PASSWORD_SPRAY     one IP trying many different usernames
  3. TARGETED_ACCOUNT   many distinct IPs failing against a single account
  4. SUCCESS_AFTER_FAIL successful login from an IP that was failing just before (HIGH)
  5. ROOT_LOGIN         successful direct root login
  6. OFF_HOURS_LOGIN    successful login outside configured working hours
  7. MULTI_IP_USER      one user logging in successfully from many distinct IPs

Usage
  python3 ssh_watchtower.py /var/log/auth.log
  python3 ssh_watchtower.py auth.log --fail-threshold 3 --window 120 --json report.json
  python3 ssh_watchtower.py auth.log --config thresholds.json
  python3 ssh_watchtower.py --demo            # generate + analyze a sample log
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "fail_threshold": 5,         # failures from one IP within the window -> brute force
    "window_seconds": 300,       # sliding window size
    "spray_user_threshold": 4,   # distinct usernames from one IP -> password spraying
    "targeted_ip_threshold": 5,  # distinct IPs failing against one user -> targeted account
    "multi_ip_threshold": 3,     # distinct IPs with successful login for one user
    "success_after_fail": 3,     # prior failures (same IP, in window) before a success
    "work_hours_start": 7,       # 07:00 inclusive
    "work_hours_end": 20,        # 20:00 exclusive
    "whitelist_ips": [],         # trusted IPs ignored by all detections
}

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

# Classic syslog prefix: "Oct 22 10:15:32 host sshd[1234]: message"
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
# ISO prefix (rsyslog high-precision): "2026-10-22T10:15:32.123456+05:30 host sshd[1234]: ..."
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
MESSAGE_PATTERNS = [
    # Failed password for [invalid user] NAME from IP port N ssh2
    ("fail", re.compile(
        rf"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
        rf"(?P<user>\S+) from {IP} port \d+")),
    # Invalid user NAME from IP
    ("invalid", re.compile(rf"Invalid user (?P<user>\S*) from {IP}")),
    # Accepted password|publickey for NAME from IP port N
    ("success", re.compile(
        rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port \d+")),
    # Connection closed by authenticating user NAME IP port N [preauth]
    ("fail", re.compile(
        rf"(?:Connection closed|Disconnected) (?:by|from) authenticating user "
        rf"(?P<user>\S+) {IP} port \d+ \[preauth\]")),
]


@dataclass
class Event:
    time: datetime
    kind: str            # fail | invalid | success
    user: str
    ip: str
    method: str = ""


def parse_timestamp(raw, year):
    if "T" in raw:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S")
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def parse_log(path, year):
    """Yield Events from a log file. Handles year rollover for syslog-style stamps."""
    events, skipped = [], 0
    last = None
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = SYSLOG_RE.match(line) or ISO_RE.match(line)
            if not m:
                continue
            msg = m.group("msg")
            for kind, pat in MESSAGE_PATTERNS:
                pm = pat.search(msg)
                if not pm:
                    continue
                try:
                    ts = parse_timestamp(m.group("ts"), year)
                except ValueError:
                    skipped += 1
                    break
                # Dec -> Jan rollover for logs without a year
                if "T" not in m.group("ts") and last and ts < last - timedelta(days=180):
                    year += 1
                    ts = ts.replace(year=year)
                last = ts
                events.append(Event(
                    time=ts, kind=kind, user=pm.group("user"), ip=pm.group("ip"),
                    method=pm.groupdict().get("method", "") or ""))
                break
    events.sort(key=lambda e: e.time)
    return events, skipped


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    subject: str         # IP or user the finding is about
    detail: str
    first_seen: str = ""
    last_seen: str = ""
    count: int = 0
    extra: dict = field(default_factory=dict)


def fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S")


def max_in_window(times, window):
    """Largest number of timestamps inside any sliding window; returns (count, start, end)."""
    best, best_span, lo = 0, (None, None), 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best = hi - lo + 1
            best_span = (times[lo], times[hi])
    return best, best_span


def detect(events, cfg):
    window = timedelta(seconds=cfg["window_seconds"])
    trusted = set(cfg["whitelist_ips"])
    events = [e for e in events if e.ip not in trusted]
    findings = []

    # "invalid" lines are the same attempt as the "fail" line that follows them in
    # most sshd versions, so count only fail events as failures, but use invalid
    # usernames to enrich spraying detection.
    fails_by_ip = defaultdict(list)
    users_by_ip = defaultdict(set)
    ips_by_user = defaultdict(set)
    fail_times_by_user = defaultdict(list)
    successes = []

    for e in events:
        if e.kind == "fail":
            fails_by_ip[e.ip].append(e.time)
            fail_times_by_user[e.user].append(e.time)
            ips_by_user[e.user].add(e.ip)
            users_by_ip[e.ip].add(e.user)
        elif e.kind == "invalid":
            users_by_ip[e.ip].add(e.user)
        elif e.kind == "success":
            successes.append(e)

    # 1. Brute force
    brute_ips = set()
    for ip, times in fails_by_ip.items():
        n, (start, end) = max_in_window(times, window)
        if n >= cfg["fail_threshold"]:
            brute_ips.add(ip)
            sev = "HIGH" if n >= cfg["fail_threshold"] * 4 else "MEDIUM"
            findings.append(Finding(
                "BRUTE_FORCE", sev, ip,
                f"{n} failed logins within {cfg['window_seconds']}s "
                f"({len(times)} total from this IP)",
                fmt(start), fmt(end), len(times)))

    # 2. Password spraying
    for ip, users in users_by_ip.items():
        if len(users) >= cfg["spray_user_threshold"]:
            times = fails_by_ip.get(ip, [])
            findings.append(Finding(
                "PASSWORD_SPRAY", "MEDIUM", ip,
                f"tried {len(users)} different usernames: {', '.join(sorted(users)[:8])}"
                + ("..." if len(users) > 8 else ""),
                fmt(times[0]) if times else "", fmt(times[-1]) if times else "",
                len(times), {"usernames": sorted(users)}))

    # 3. Targeted account (distributed attack)
    for user, ips in ips_by_user.items():
        if len(ips) >= cfg["targeted_ip_threshold"]:
            times = sorted(fail_times_by_user[user])
            findings.append(Finding(
                "TARGETED_ACCOUNT", "HIGH", user,
                f"account attacked from {len(ips)} distinct IPs "
                f"({len(times)} failures)",
                fmt(times[0]), fmt(times[-1]), len(times),
                {"ips": sorted(ips)}))

    # 4-7. Success-based detections
    ips_by_success_user = defaultdict(set)
    for s in successes:
        ips_by_success_user[s.user].add(s.ip)

        # 4. Success after failures
        recent = [t for t in fails_by_ip.get(s.ip, [])
                  if s.time - window <= t <= s.time]
        if len(recent) >= cfg["success_after_fail"]:
            findings.append(Finding(
                "SUCCESS_AFTER_FAIL", "CRITICAL", f"{s.user}@{s.ip}",
                f"successful {s.method} login after {len(recent)} failures "
                f"from the same IP - possible compromised credentials",
                fmt(recent[0]), fmt(s.time), len(recent) + 1))

        # 5. Root login
        if s.user == "root":
            findings.append(Finding(
                "ROOT_LOGIN", "HIGH", f"root@{s.ip}",
                f"direct root login via {s.method}",
                fmt(s.time), fmt(s.time), 1))

        # 6. Off-hours
        h = s.time.hour
        if not (cfg["work_hours_start"] <= h < cfg["work_hours_end"]):
            findings.append(Finding(
                "OFF_HOURS_LOGIN", "LOW", f"{s.user}@{s.ip}",
                f"login at {s.time:%H:%M}, outside "
                f"{cfg['work_hours_start']:02d}:00-{cfg['work_hours_end']:02d}:00",
                fmt(s.time), fmt(s.time), 1))

    # 7. One user from many IPs
    for user, ips in ips_by_success_user.items():
        if len(ips) >= cfg["multi_ip_threshold"]:
            findings.append(Finding(
                "MULTI_IP_USER", "MEDIUM", user,
                f"successful logins from {len(ips)} distinct IPs: "
                f"{', '.join(sorted(ips))}",
                count=len(ips), extra={"ips": sorted(ips)}))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (order[f.severity], f.rule, f.subject))
    return findings, events


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_report(findings, events, cfg, source):
    fails = [e for e in events if e.kind == "fail"]
    succ = [e for e in events if e.kind == "success"]
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    top = defaultdict(int)
    for e in fails:
        top[e.ip] += 1
    top_ips = sorted(top.items(), key=lambda kv: -kv[1])[:5]

    lines = []
    w = lines.append
    w("=" * 72)
    w("SSH WATCHTOWER - INCIDENT SUMMARY")
    w("=" * 72)
    w(f"Source file     : {source}")
    if events:
        w(f"Log period      : {fmt(events[0].time)}  ->  {fmt(events[-1].time)}")
    w(f"Events analysed : {len(events)}  ({len(fails)} failed, {len(succ)} successful)")
    w(f"Thresholds      : {cfg['fail_threshold']} fails / {cfg['window_seconds']}s, "
      f"spray>={cfg['spray_user_threshold']} users, "
      f"hours {cfg['work_hours_start']:02d}-{cfg['work_hours_end']:02d}")
    w("")
    w("Findings by severity: " + (", ".join(
        f"{s}={sev_counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if sev_counts[s]) or "none"))
    w("")

    if top_ips:
        w("Top failing source IPs")
        for ip, n in top_ips:
            w(f"  {ip:<40} {n:>5} failures")
        w("")

    if not findings:
        w("No suspicious activity detected with the current thresholds.")
    else:
        w("Detailed findings")
        w("-" * 72)
        for f in findings:
            w(f"[{f.severity:<8}] {f.rule:<18} {f.subject}")
            w(f"           {f.detail}")
            if f.first_seen:
                span = f.first_seen if f.first_seen == f.last_seen \
                    else f"{f.first_seen} -> {f.last_seen}"
                w(f"           when: {span}")
        w("")
        w("Recommended actions")
        w("-" * 72)
        rules = {f.rule for f in findings}
        if "SUCCESS_AFTER_FAIL" in rules:
            w("* URGENT: treat accounts in SUCCESS_AFTER_FAIL as compromised - reset "
              "credentials, kill active sessions, review shell history.")
        if rules & {"BRUTE_FORCE", "PASSWORD_SPRAY", "TARGETED_ACCOUNT"}:
            w("* Block offending IPs (fail2ban / firewall), enforce key-only auth "
              "(PasswordAuthentication no), consider a non-default port or VPN.")
        if "ROOT_LOGIN" in rules:
            w("* Disable direct root SSH login (PermitRootLogin no) and use sudo.")
        if "OFF_HOURS_LOGIN" in rules or "MULTI_IP_USER" in rules:
            w("* Verify off-hours / multi-location logins with the account owners.")
    w("=" * 72)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Demo log generator
# --------------------------------------------------------------------------

def generate_demo_log(path):
    """Write a realistic sample auth.log containing every attack pattern."""
    random.seed(7)
    year = datetime.now().year
    base = datetime(year, 10, 21, 9, 0, 0)
    host = "web01"
    rows = []

    def add(t, msg):
        rows.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} {host} sshd[{random.randint(1000, 9999)}]: {msg}"))

    # Normal daytime activity
    for i, (user, ip) in enumerate([("alice", "10.0.0.12"), ("bob", "10.0.0.15"),
                                    ("alice", "10.0.0.12"), ("carol", "10.0.0.20")]):
        add(base + timedelta(hours=i * 2), f"Accepted publickey for {user} from {ip} port 50{i}22 ssh2")

    # Brute force on root
    t = base + timedelta(hours=3)
    for i in range(40):
        add(t + timedelta(seconds=i * 3),
            f"Failed password for root from 203.0.113.45 port {40000 + i} ssh2")

    # Password spraying
    t = base + timedelta(hours=4)
    for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git", "pi"]):
        add(t + timedelta(seconds=i * 20), f"Invalid user {u} from 198.51.100.9 port {5000 + i}")
        add(t + timedelta(seconds=i * 20 + 1),
            f"Failed password for invalid user {u} from 198.51.100.9 port {5000 + i} ssh2")

    # Distributed attack on 'bob'
    t = base + timedelta(hours=5)
    for i in range(6):
        add(t + timedelta(minutes=i),
            f"Failed password for bob from 192.0.2.{10 + i} port 6100{i} ssh2")

    # Compromise: failures then success
    t = base + timedelta(hours=6)
    for i in range(6):
        add(t + timedelta(seconds=i * 10),
            f"Failed password for carol from 100.64.7.7 port 7000{i} ssh2")
    add(t + timedelta(seconds=75), "Accepted password for carol from 100.64.7.7 port 70099 ssh2")

    # Off-hours + root + multi-IP logins
    add(base.replace(day=22, hour=2, minute=14), "Accepted password for alice from 10.0.0.12 port 51000 ssh2")
    add(base.replace(day=22, hour=3, minute=40), "Accepted publickey for root from 172.16.5.5 port 51001 ssh2")
    for i, ip in enumerate(["10.0.0.12", "45.33.32.156", "91.240.118.1"]):
        add(base.replace(day=22, hour=10 + i), f"Accepted publickey for dave from {ip} port 5200{i} ssh2")

    rows.sort(key=lambda r: r[0])
    Path(path).write_text("\n".join(r[1] for r in rows) + "\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="SSH Watchtower - login threat detector")
    ap.add_argument("logfile", nargs="?", help="path to auth.log / secure")
    ap.add_argument("--config", help="JSON file with threshold overrides")
    ap.add_argument("--fail-threshold", type=int)
    ap.add_argument("--window", type=int, help="window in seconds")
    ap.add_argument("--spray-users", type=int)
    ap.add_argument("--work-start", type=int)
    ap.add_argument("--work-end", type=int)
    ap.add_argument("--whitelist", nargs="*", help="trusted IPs to ignore")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for syslog timestamps (default: current)")
    ap.add_argument("--json", metavar="FILE", help="also write findings as JSON")
    ap.add_argument("--summary", metavar="FILE", help="also write the text report to a file")
    ap.add_argument("--demo", action="store_true", help="generate and analyze a sample log")
    args = ap.parse_args()

    if args.demo:
        args.logfile = "demo_auth.log"
        generate_demo_log(args.logfile)
        print(f"[demo] wrote sample log to {args.logfile}\n")
    if not args.logfile:
        ap.error("logfile required (or use --demo)")
    if not Path(args.logfile).exists():
        sys.exit(f"error: {args.logfile} not found")

    cfg = dict(DEFAULT_CONFIG)
    if args.config:
        cfg.update(json.loads(Path(args.config).read_text()))
    overrides = {
        "fail_threshold": args.fail_threshold, "window_seconds": args.window,
        "spray_user_threshold": args.spray_users,
        "work_hours_start": args.work_start, "work_hours_end": args.work_end,
        "whitelist_ips": args.whitelist,
    }
    cfg.update({k: v for k, v in overrides.items() if v is not None})

    events, skipped = parse_log(args.logfile, args.year)
    if not events:
        sys.exit("no SSH authentication events found - is this the right log file?")
    findings, kept = detect(events, cfg)
    report = build_report(findings, kept, cfg, args.logfile)
    print(report)
    if skipped:
        print(f"(skipped {skipped} lines with unparseable timestamps)")

    if args.summary:
        Path(args.summary).write_text(report + "\n")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"config": cfg, "findings": [asdict(f) for f in findings]}, indent=2))

    # Non-zero exit when serious findings exist (handy for cron / CI alerting)
    sys.exit(2 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0)


if __name__ == "__main__":
    main()
