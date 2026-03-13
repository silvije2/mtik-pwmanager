#!/usr/bin/env python3
"""
MikroTik Bulk Password Manager

Authors: Claude (anthropic), silvije2

Modes:
  change - push new password to all devices, verify, track revisions
  audit  - test a given password against all devices, record successes
  verify - check recorded passwords still work; mark drifted devices as UNKNOWN

hosts.txt format: one entry per line, either:
  192.168.1.1
  192.168.1.1:router-core-01
"""

import argparse
import csv
import os
import sys
import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import paramiko
    # Suppress paramiko's internal transport error messages (e.g. SSH banner errors)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except ImportError:
    print("ERROR: paramiko is required. Install with: pip install paramiko --break-system-packages")
    sys.exit(1)

# ── File paths ────────────────────────────────────────────────────────────────
PASSWORDS_DB    = "passwords.db"
DEVICE_STATUS   = "device_status.db"
DEVICE_REMOVED  = "device_status_removed.db"
HOSTS_SEEN      = "hosts_seen.db"
EXPOSED_FLAG    = "password_exposed.flag"

# ── Revision constants ────────────────────────────────────────────────────────
CHANGE_REVISION_START = 1000
AUDIT_REVISION_MAX    = 999   # sub-1000 space

# ── SSH settings ──────────────────────────────────────────────────────────────
SSH_PORT    = 22
SSH_TIMEOUT = 10  # seconds
MAX_WORKERS = 100  # parallel connections


# ══════════════════════════════════════════════════════════════════════════════
# Hosts file parsing
# ══════════════════════════════════════════════════════════════════════════════

def parse_hosts_line(line):
    """
    Parse a line from hosts.txt.
    Accepts: '192.168.1.1' or '192.168.1.1:router-core-01'
    Returns: (ip, hostname) — hostname is empty string if not provided.
    """
    line = line.strip()
    if ":" in line:
        ip, hostname = line.split(":", 1)
        return ip.strip(), hostname.strip()
    return line, ""


def load_hosts_file(path):
    """Return list of (ip, hostname) tuples from hosts file."""
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(parse_hosts_line(line))
    return hosts


# ══════════════════════════════════════════════════════════════════════════════
# passwords.db helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_passwords_db():
    """Return list of dicts sorted by revision."""
    rows = []
    if not os.path.exists(PASSWORDS_DB):
        return rows
    with open(PASSWORDS_DB, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["revision"] = int(row["revision"])
            rows.append(row)
    rows.sort(key=lambda r: r["revision"])
    return rows


def save_passwords_db(rows):
    """Write passwords.db sorted by revision."""
    rows_sorted = sorted(rows, key=lambda r: r["revision"])
    with open(PASSWORDS_DB, "w", newline="") as f:
        writer = csv.DictWriter(f, lineterminator="\n", fieldnames=["revision", "password", "timestamp"])
        writer.writeheader()
        writer.writerows(rows_sorted)


def add_password_entry(revision, password):
    rows = load_passwords_db()
    if any(r["revision"] == revision for r in rows):
        return
    rows.append({
        "revision":  revision,
        "password":  password,
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    })
    save_passwords_db(rows)


def get_password_for_revision(revision):
    for row in load_passwords_db():
        if row["revision"] == revision:
            return row["password"]
    return None


def next_change_revision():
    rows = load_passwords_db()
    change_revs = [r["revision"] for r in rows if r["revision"] >= CHANGE_REVISION_START]
    return max(change_revs) + 1 if change_revs else CHANGE_REVISION_START


def next_audit_revision():
    rows = load_passwords_db()
    audit_revs = [r["revision"] for r in rows if r["revision"] <= AUDIT_REVISION_MAX]
    return min(audit_revs) - 1 if audit_revs else AUDIT_REVISION_MAX


# ══════════════════════════════════════════════════════════════════════════════
# device_status.db helpers
# Fields: ip, hostname, last_successful_revision
# ══════════════════════════════════════════════════════════════════════════════

DEVICE_FIELDS = ["ip", "hostname", "last_successful_revision"]


def load_device_status():
    """Return dict {ip: {'hostname': str, 'revision': int or None}}."""
    status = {}
    if not os.path.exists(DEVICE_STATUS):
        return status
    with open(DEVICE_STATUS, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row["last_successful_revision"]
            status[row["ip"]] = {
                "hostname": row.get("hostname", ""),
                "revision": None if raw == "UNKNOWN" else int(raw),
            }
    return status


def save_device_status(status):
    """status: {ip: {'hostname': str, 'revision': int or None}}"""
    with open(DEVICE_STATUS, "w", newline="") as f:
        writer = csv.DictWriter(f, lineterminator="\n", fieldnames=DEVICE_FIELDS)
        writer.writeheader()
        for ip, data in sorted(status.items()):
            writer.writerow({
                "ip":                       ip,
                "hostname":                 data.get("hostname", ""),
                "last_successful_revision": "UNKNOWN" if data["revision"] is None else data["revision"],
            })


def update_device_status(ip_hostname_list, revision):
    """ip_hostname_list: list of (ip, hostname) tuples."""
    status = load_device_status()
    for ip, hostname in ip_hostname_list:
        entry = status.get(ip, {"hostname": hostname, "revision": revision})
        entry["revision"] = revision
        if hostname:
            entry["hostname"] = hostname
        status[ip] = entry
    save_device_status(status)


def load_removed_status():
    """Return dict {ip: {'hostname': str, 'revision': int}}."""
    status = {}
    if not os.path.exists(DEVICE_REMOVED):
        return status
    with open(DEVICE_REMOVED, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status[row["ip"]] = {
                "hostname": row.get("hostname", ""),
                "revision": int(row["last_successful_revision"]),
            }
    return status


def save_removed_status(status):
    with open(DEVICE_REMOVED, "w", newline="") as f:
        writer = csv.DictWriter(f, lineterminator="\n", fieldnames=DEVICE_FIELDS)
        writer.writeheader()
        for ip, data in sorted(status.items()):
            writer.writerow({
                "ip":                       ip,
                "hostname":                 data.get("hostname", ""),
                "last_successful_revision": data["revision"],
            })


# ══════════════════════════════════════════════════════════════════════════════
# hosts_seen.db helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_seen_hosts():
    """Return set of all IPs ever seen."""
    seen = set(load_device_status().keys())
    seen |= set(load_removed_status().keys())
    if os.path.exists(HOSTS_SEEN):
        with open(HOSTS_SEEN) as f:
            for line in f:
                line = line.strip()
                if line:
                    seen.add(line)
    return seen


def record_seen_hosts(ip_list):
    """Append any new IPs to hosts_seen.db."""
    seen = load_seen_hosts()
    new = [ip for ip in ip_list if ip not in seen]
    if new:
        with open(HOSTS_SEEN, "a") as f:
            for ip in sorted(new):
                f.write(ip + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# Exposed flag helpers
# ══════════════════════════════════════════════════════════════════════════════

def set_exposed_flag(user_display):
    """Write password_exposed.flag with who triggered it and when."""
    with open(EXPOSED_FLAG, "w") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}|{user_display}\n")


def clear_exposed_flag():
    """Remove the exposed flag — called after a successful change run."""
    if os.path.exists(EXPOSED_FLAG):
        os.remove(EXPOSED_FLAG)


def read_exposed_flag():
    """Return (timestamp, user_display) if flag exists, else None."""
    if not os.path.exists(EXPOSED_FLAG):
        return None
    with open(EXPOSED_FLAG) as f:
        line = f.read().strip()
    if "|" in line:
        ts, user = line.split("|", 1)
        return ts, user
    return line, "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# Reconciliation
# ══════════════════════════════════════════════════════════════════════════════

def reconcile_hosts(hosts):
    """
    Compare hosts list against device_status.db.
    - New hosts (never seen before): note they need audit, add to hosts_seen.db.
    - Hostname changes: update hostname in device_status.db.
    - Removed hosts (in device_status.db but not in hosts.txt): move to device_status_removed.db.
    """
    current_status = load_device_status()
    removed_status = load_removed_status()
    seen_hosts     = load_seen_hosts()

    hosts_by_ip = {ip: hostname for ip, hostname in hosts}
    hosts_ips   = set(hosts_by_ip.keys())
    tracked_ips = set(current_status.keys())

    new_ips     = hosts_ips - seen_hosts
    removed_ips = tracked_ips - hosts_ips
    changed     = False

    # New hosts
    if new_ips:
        print(f"\n  [HOSTS] {len(new_ips)} new host(s) detected — will appear as NO_RECORD until audited:")
        for ip in sorted(new_ips):
            hostname = hosts_by_ip[ip]
            label = f"{ip}:{hostname}" if hostname else ip
            print(f"    + {label}")
        record_seen_hosts(list(new_ips))
        changed = True

    # Removed hosts
    if removed_ips:
        print(f"  [HOSTS] {len(removed_ips)} host(s) removed — moved to device_status_removed.db:")
        for ip in sorted(removed_ips):
            data = current_status.pop(ip)
            label = f"{ip}:{data['hostname']}" if data.get("hostname") else ip
            print(f"    - {label}")
            removed_status[ip] = data
        save_device_status(current_status)
        save_removed_status(removed_status)
        changed = True

    # Hostname updates for existing tracked devices
    hostname_updates = []
    for ip, hostname in hosts:
        if ip in current_status and hostname and current_status[ip].get("hostname") != hostname:
            hostname_updates.append((ip, hostname))
            current_status[ip]["hostname"] = hostname
    if hostname_updates:
        save_device_status(current_status)
        print(f"  [HOSTS] {len(hostname_updates)} hostname(s) updated in device_status.db")
        changed = True

    if not changed:
        print(f"  [HOSTS] No changes detected in hosts list")


# ══════════════════════════════════════════════════════════════════════════════
# SSH helpers
# ══════════════════════════════════════════════════════════════════════════════

def ssh_connect(ip, username, password):
    """
    Attempt SSH connection.
    Returns (client, None) on success or (None, error_type).
    error_type is 'UNREACHABLE' or 'AUTH_FAILED'.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        return client, None
    except paramiko.AuthenticationException:
        return None, "AUTH_FAILED"
    except (socket.timeout, socket.error, paramiko.SSHException, OSError, EOFError):
        return None, "UNREACHABLE"
    except Exception:
        return None, "UNREACHABLE"


def ssh_change_password(client, new_password, username="manager"):
    """Send RouterOS command to change password. Returns True/False."""
    try:
        cmd = f'/user set {username} password="{new_password}"'
        stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
        stdout.channel.recv_exit_status()
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Per-device workers
# ══════════════════════════════════════════════════════════════════════════════

def worker_change(ip, hostname, device_status, new_password, new_revision, username="manager"):
    try:
        entry = device_status.get(ip)
        if entry is None:
            return ip, hostname, "NO_RECORD"

        old_password = get_password_for_revision(entry["revision"])
        if old_password is None:
            return ip, hostname, "NO_RECORD"

        client, err = ssh_connect(ip, username, old_password)
        if err:
            return ip, hostname, err

        changed = ssh_change_password(client, new_password, username)
        client.close()
        if not changed:
            return ip, hostname, "AUTH_FAILED"

        client2, err2 = ssh_connect(ip, username, new_password)
        if err2:
            return ip, hostname, "AUTH_FAILED"
        client2.close()

        return ip, hostname, "SUCCESS"
    except Exception:
        return ip, hostname, "UNREACHABLE"


def worker_audit(ip, hostname, password, username="manager"):
    try:
        client, err = ssh_connect(ip, username, password)
        if err:
            return ip, hostname, err
        client.close()
        return ip, hostname, "SUCCESS"
    except Exception:
        return ip, hostname, "UNREACHABLE"


def worker_verify(ip, hostname, device_status, username="manager"):
    """
    Attempt login using the recorded password for this device.
    Returns (ip, hostname, status) where status is:
      VERIFIED    - login succeeded, password still valid
      DRIFTED     - device reachable but login failed (password was changed externally)
      UNREACHABLE - device is down or not reachable
      NO_RECORD   - no password recorded for this device
    """
    try:
        entry = device_status.get(ip)
        if entry is None or entry["revision"] is None:
            return ip, hostname, "NO_RECORD"

        password = get_password_for_revision(entry["revision"])
        if password is None:
            return ip, hostname, "NO_RECORD"

        client, err = ssh_connect(ip, username, password)
        if err == "AUTH_FAILED":
            return ip, hostname, "DRIFTED"
        if err == "UNREACHABLE":
            return ip, hostname, "UNREACHABLE"
        client.close()
        return ip, hostname, "VERIFIED"
    except Exception:
        return ip, hostname, "UNREACHABLE"


def worker_upgrade(ip, hostname, current_revision, latest_revision, latest_password, username="manager"):
    """
    Connect using the device's current recorded password and change it to the latest password.
    Returns (ip, hostname, status) where status is SUCCESS, AUTH_FAILED, or UNREACHABLE.
    """
    try:
        old_password = get_password_for_revision(current_revision)
        if old_password is None:
            return ip, hostname, "NO_RECORD"

        client, err = ssh_connect(ip, username, old_password)
        if err:
            return ip, hostname, err

        changed = ssh_change_password(client, latest_password, username)
        client.close()
        if not changed:
            return ip, hostname, "AUTH_FAILED"

        client2, err2 = ssh_connect(ip, username, latest_password)
        if err2:
            return ip, hostname, "AUTH_FAILED"
        client2.close()

        return ip, hostname, "SUCCESS"
    except Exception:
        return ip, hostname, "UNREACHABLE"


def worker_recover(ip, hostname, passwords_by_revision, username="manager"):
    """
    Try all known passwords (newest first) against an untracked device.
    Returns (ip, hostname, status, matched_revision) where matched_revision is
    the revision whose password worked, or None if none matched.
    """
    try:
        for revision, password in passwords_by_revision:
            client, err = ssh_connect(ip, username, password)
            if err == "UNREACHABLE":
                return ip, hostname, "UNREACHABLE", None
            if err == "AUTH_FAILED":
                continue
            client.close()
            return ip, hostname, "RECOVERED", revision
        return ip, hostname, "AUTH_FAILED", None
    except Exception:
        return ip, hostname, "UNREACHABLE", None


# ══════════════════════════════════════════════════════════════════════════════
# Result file
# ══════════════════════════════════════════════════════════════════════════════

def write_results(results, revision):
    """results: {ip: {'hostname': str, 'status': str}}"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"results_{revision}_{timestamp}.txt"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, lineterminator="\n", fieldnames=["ip", "hostname", "status"])
        writer.writeheader()
        for ip, data in sorted(results.items()):
            writer.writerow({
                "ip":       ip,
                "hostname": data.get("hostname", ""),
                "status":   data["status"],
            })
    return filename


# ══════════════════════════════════════════════════════════════════════════════
# Modes
# ══════════════════════════════════════════════════════════════════════════════

def mode_change(hosts, username="manager"):
    revision     = next_change_revision()
    new_password = input(f"Enter NEW password for revision {revision}: ").strip()
    if not new_password:
        print("ERROR: Password cannot be empty.")
        sys.exit(1)

    device_status = load_device_status()

    no_record = [(ip, hn) for ip, hn in hosts if ip not in device_status]
    if no_record:
        print(f"\n  WARNING: {len(no_record)} device(s) have no recorded password — they will be skipped.")
        print(f"  Run audit mode first to discover passwords for untracked devices.")

    results = {}
    print(f"\n[CHANGE] Revision {revision} — pushing to {len(hosts)} devices...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(worker_change, ip, hn, device_status, new_password, revision, username): ip
            for ip, hn in hosts
        }
        done = 0
        for future in as_completed(futures):
            ip, hostname, status = future.result()
            results[ip] = {"hostname": hostname, "status": status}
            done += 1
            if done % 100 == 0 or done == len(hosts):
                print(f"  Progress: {done}/{len(hosts)}")

    add_password_entry(revision, new_password)

    successful = [(ip, d["hostname"]) for ip, d in results.items() if d["status"] == "SUCCESS"]
    if successful:
        update_device_status(successful, revision)

    filename = write_results(results, revision)

    total      = len(results)
    n_success  = sum(1 for d in results.values() if d["status"] == "SUCCESS")
    n_unreach  = sum(1 for d in results.values() if d["status"] == "UNREACHABLE")
    n_authfail = sum(1 for d in results.values() if d["status"] == "AUTH_FAILED")
    n_norecord = sum(1 for d in results.values() if d["status"] == "NO_RECORD")

    print(f"\n[DONE] Revision {revision}")
    print(f"  SUCCESS      : {n_success}/{total}")
    print(f"  UNREACHABLE  : {n_unreach}/{total}")
    print(f"  AUTH_FAILED  : {n_authfail}/{total}")
    if n_norecord:
        print(f"  NO_RECORD    : {n_norecord}/{total} (run audit first)")
    print(f"  Results file : {filename}")

    # Clear exposed flag if set — new password is now in place
    if n_success > 0 and read_exposed_flag():
        clear_exposed_flag()
        print(f"  ✓ Exposed flag cleared — password has been rotated")


def mode_audit(hosts, password, username="manager"):
    print(f"\n[AUDIT] Testing password against {len(hosts)} devices...")

    results = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(worker_audit, ip, hn, password, username): ip
            for ip, hn in hosts
        }
        done = 0
        for future in as_completed(futures):
            ip, hostname, status = future.result()
            results[ip] = {"hostname": hostname, "status": status}
            done += 1
            if done % 100 == 0 or done == len(hosts):
                print(f"  Progress: {done}/{len(hosts)}")

    successful = [(ip, d["hostname"]) for ip, d in results.items() if d["status"] == "SUCCESS"]

    revision = None
    if successful:
        revision = next_audit_revision()
        add_password_entry(revision, password)
        update_device_status(successful, revision)
        print(f"\n  {len(successful)} device(s) succeeded — recorded as revision {revision}")

    filename = write_results(results, revision if revision else "audit")

    total      = len(results)
    n_success  = len(successful)
    n_unreach  = sum(1 for d in results.values() if d["status"] == "UNREACHABLE")
    n_authfail = sum(1 for d in results.values() if d["status"] == "AUTH_FAILED")

    print(f"\n[DONE] Audit")
    print(f"  SUCCESS      : {n_success}/{total}")
    print(f"  UNREACHABLE  : {n_unreach}/{total}")
    print(f"  AUTH_FAILED  : {n_authfail}/{total}")
    print(f"  Results file : {filename}")


def mode_verify(hosts, username="manager"):
    print(f"\n[VERIFY] Checking recorded passwords against {len(hosts)} devices...")

    device_status = load_device_status()
    results = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(worker_verify, ip, hn, device_status, username): ip
            for ip, hn in hosts
        }
        done = 0
        for future in as_completed(futures):
            ip, hostname, status = future.result()
            results[ip] = {"hostname": hostname, "status": status}
            done += 1
            if done % 100 == 0 or done == len(hosts):
                print(f"  Progress: {done}/{len(hosts)}")

    # Mark drifted devices as UNKNOWN in device_status.db
    drifted = [(ip, d["hostname"]) for ip, d in results.items() if d["status"] == "DRIFTED"]
    if drifted:
        status_db = load_device_status()
        for ip, hostname in drifted:
            if ip in status_db:
                status_db[ip]["revision"] = None  # stored as UNKNOWN
        save_device_status(status_db)
        print(f"\n  {len(drifted)} device(s) marked as UNKNOWN in device_status.db")

    filename = write_results(results, "verify")

    total      = len(results)
    n_verified = sum(1 for d in results.values() if d["status"] == "VERIFIED")
    n_drifted  = sum(1 for d in results.values() if d["status"] == "DRIFTED")
    n_unreach  = sum(1 for d in results.values() if d["status"] == "UNREACHABLE")
    n_norecord = sum(1 for d in results.values() if d["status"] == "NO_RECORD")

    print(f"\n[DONE] Verify")
    print(f"  VERIFIED     : {n_verified}/{total}")
    print(f"  DRIFTED      : {n_drifted}/{total} (password changed externally, marked UNKNOWN)")
    print(f"  UNREACHABLE  : {n_unreach}/{total}")
    if n_norecord:
        print(f"  NO_RECORD    : {n_norecord}/{total}")
    print(f"  Results file : {filename}")


def mode_upgrade(hosts, username="manager"):
    """
    Find devices not on the latest revision and update them to the latest password.
    No user input required.
    """
    passwords = load_passwords_db()
    if not passwords:
        print("ERROR: passwords.db is empty. Run audit or change mode first.")
        return

    # Latest revision is the highest number overall
    latest = max(passwords, key=lambda r: r["revision"])
    latest_revision = latest["revision"]
    latest_password = latest["password"]

    device_status = load_device_status()
    hosts_by_ip   = {ip: hn for ip, hn in hosts}

    # Candidates: tracked devices whose revision is below latest, with a known password
    candidates = [
        (ip, data["hostname"] or hosts_by_ip.get(ip, ""), data["revision"])
        for ip, data in device_status.items()
        if data["revision"] is not None and data["revision"] < latest_revision
        and ip in hosts_by_ip
    ]

    if not candidates:
        print(f"\n[UPGRADE] All tracked devices are already at revision {latest_revision}. Nothing to do.")
        return

    print(f"\n[UPGRADE] Latest revision: {latest_revision}")
    print(f"  {len(candidates)} device(s) are behind — upgrading now...")

    results = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                worker_upgrade, ip, hostname, current_rev, latest_revision, latest_password, username
            ): ip
            for ip, hostname, current_rev in candidates
        }
        done = 0
        for future in as_completed(futures):
            ip, hostname, status = future.result()
            results[ip] = {"hostname": hostname, "status": status}
            done += 1
            if done % 100 == 0 or done == len(candidates):
                print(f"  Progress: {done}/{len(candidates)}")

    successful = [(ip, d["hostname"]) for ip, d in results.items() if d["status"] == "SUCCESS"]
    if successful:
        update_device_status(successful, latest_revision)

    filename = write_results(results, f"upgrade_{latest_revision}")

    total      = len(results)
    n_success  = len(successful)
    n_unreach  = sum(1 for d in results.values() if d["status"] == "UNREACHABLE")
    n_authfail = sum(1 for d in results.values() if d["status"] == "AUTH_FAILED")

    print(f"\n[DONE] Upgrade to revision {latest_revision}")
    print(f"  SUCCESS      : {n_success}/{total}")
    print(f"  UNREACHABLE  : {n_unreach}/{total}")
    print(f"  AUTH_FAILED  : {n_authfail}/{total}")
    print(f"  Results file : {filename}")


def mode_recover(hosts, username="manager"):
    """
    Try all known passwords against devices that have no entry in device_status.db.
    Passwords are tried newest first. Updates device_status.db on any match.
    """
    passwords = load_passwords_db()
    if not passwords:
        print("ERROR: passwords.db is empty. Run audit mode first.")
        return

    # Newest first
    passwords_by_revision = [
        (r["revision"], r["password"])
        for r in sorted(passwords, key=lambda r: r["revision"], reverse=True)
    ]

    device_status = load_device_status()
    hosts_by_ip   = {ip: hn for ip, hn in hosts}

    # Candidates: in hosts.txt but either not in device_status.db, or marked UNKNOWN (drifted)
    candidates = [
        (ip, hn)
        for ip, hn in hosts
        if ip not in device_status or device_status[ip]["revision"] is None
    ]

    if not candidates:
        print(f"\n[RECOVER] No candidates found. All hosts have a known password revision.")
        return

    n_missing = sum(1 for ip, _ in candidates if ip not in device_status)
    n_unknown = sum(1 for ip, _ in candidates if ip in device_status and device_status[ip]["revision"] is None)
    print(f"\n[RECOVER] Trying {len(passwords_by_revision)} password(s) against {len(candidates)} device(s)")
    print(f"  ({n_missing} never recorded, {n_unknown} marked UNKNOWN/drifted)...")

    results     = {}
    recovered   = []  # (ip, hostname, revision)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(worker_recover, ip, hn, passwords_by_revision, username): ip
            for ip, hn in candidates
        }
        done = 0
        for future in as_completed(futures):
            ip, hostname, status, matched_revision = future.result()
            results[ip] = {"hostname": hostname, "status": status}
            if status == "RECOVERED":
                recovered.append((ip, hostname, matched_revision))
            done += 1
            if done % 100 == 0 or done == len(candidates):
                print(f"  Progress: {done}/{len(candidates)}")

    # Update device_status.db grouped by matched revision
    if recovered:
        revision_groups = {}
        for ip, hostname, revision in recovered:
            revision_groups.setdefault(revision, []).append((ip, hostname))
        for revision, ip_hostname_list in revision_groups.items():
            update_device_status(ip_hostname_list, revision)
        print(f"\n  {len(recovered)} device(s) recovered and added to device_status.db")

    filename = write_results(results, "recover")

    total      = len(results)
    n_recovered = sum(1 for d in results.values() if d["status"] == "RECOVERED")
    n_unreach   = sum(1 for d in results.values() if d["status"] == "UNREACHABLE")
    n_authfail  = sum(1 for d in results.values() if d["status"] == "AUTH_FAILED")

    print(f"\n[DONE] Recover")
    print(f"  RECOVERED    : {n_recovered}/{total}")
    print(f"  UNREACHABLE  : {n_unreach}/{total}")
    print(f"  AUTH_FAILED  : {n_authfail}/{total} (no matching password found)")
    print(f"  Results file : {filename}")



def mode_status(hosts):
    """Print summary of device_status.db based on db contents only. No SSH connections."""
    current_status = load_device_status()
    removed_status = load_removed_status()
    seen_hosts     = load_seen_hosts()
    hosts_ips      = {ip for ip, _ in hosts}

    # Determine latest revision from passwords.db
    passwords = load_passwords_db()
    latest_revision = max((r["revision"] for r in passwords), default=None)

    n_known   = 0
    n_unknown = 0
    n_never   = 0
    n_latest  = 0
    n_behind  = 0

    for ip in hosts_ips:
        if ip in current_status:
            rev = current_status[ip]["revision"]
            if rev is None:
                n_unknown += 1
            else:
                n_known += 1
                if latest_revision is not None and rev == latest_revision:
                    n_latest += 1
                else:
                    n_behind += 1
        else:
            n_never += 1

    n_removed    = len(removed_status)
    total_active = len(hosts_ips)

    print(f"\n[STATUS] Device database summary")
    exposed = read_exposed_flag()
    if exposed:
        ts, user = exposed
        print(f"  {'─' * 38}")
        print(f"  ⚠  PASSWORD EXPOSED — rotation needed")
        print(f"     Looked up by: {user} at {ts}")
    print(f"  {'─' * 38}")
    print(f"  Active hosts in hosts.txt  : {total_active}")
    print(f"  {'─' * 38}")
    print(f"  KNOWN     (valid revision) : {n_known}")
    print(f"  UNKNOWN   (drifted/reset)  : {n_unknown}")
    print(f"  NO RECORD (never audited)  : {n_never}")
    print(f"  {'─' * 38}")
    if latest_revision is not None:
        print(f"  At latest rev ({latest_revision})      : {n_latest}")
        print(f"  Behind latest rev          : {n_behind}")
        print(f"  {'─' * 38}")
    print(f"  REMOVED   (ex-hosts.txt)   : {n_removed}")




def main():
    parser = argparse.ArgumentParser(
        description="MikroTik Bulk Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
hosts.txt format (one per line):
  192.168.1.1
  192.168.1.1:router-core-01

Examples:
  Change mode (push new password to all devices):
    python mikrotik_passmanager.py --mode change

  Audit mode (test a password, no changes made):
    python mikrotik_passmanager.py --mode audit --pass MyPassword123

  Verify mode (check recorded passwords still work):
    python mikrotik_passmanager.py --mode verify

  Status mode (summary of device db, no SSH connections):
    python mikrotik_passmanager.py --mode status

  Upgrade mode (bring all devices to the latest revision):
    python mikrotik_passmanager.py --mode upgrade

  Recover mode (try all passwords on untracked devices):
    python mikrotik_passmanager.py --mode recover

  Use custom hosts file or SSH username:
    python mikrotik_passmanager.py --mode change --hosts my_hosts.txt --username operator
        """
    )
    parser.add_argument("--mode",     required=True, choices=["change", "audit", "verify", "status", "upgrade", "recover"],
                        help="Operation mode: change, audit, verify, status, upgrade, or recover")
    parser.add_argument("--pass",     dest="password", default=None,
                        help="Password to test (audit mode only)")
    parser.add_argument("--hosts",    default="hosts.txt",
                        help="Path to hosts file (default: hosts.txt)")
    parser.add_argument("--username", default="manager",
                        help="SSH username (default: manager)")

    args = parser.parse_args()

    if args.mode == "audit" and not args.password:
        parser.error("--pass is required in audit mode")
    if args.mode in ("change", "verify", "status", "upgrade", "recover") and args.password:
        parser.error("--pass is not used in change/verify/status/upgrade/recover mode")

    if not os.path.exists(args.hosts):
        print(f"ERROR: Hosts file '{args.hosts}' not found.")
        sys.exit(1)

    hosts = load_hosts_file(args.hosts)

    if not hosts:
        print("ERROR: No hosts found in hosts file.")
        sys.exit(1)

    print(f"Loaded {len(hosts)} hosts from {args.hosts}")

    # Status mode reads db only — no reconcile or SSH needed
    if args.mode == "status":
        mode_status(hosts)
        return

    reconcile_hosts(hosts)

    if args.mode == "change":
        mode_change(hosts, username=args.username)
    elif args.mode == "audit":
        mode_audit(hosts, args.password, username=args.username)
    elif args.mode == "verify":
        mode_verify(hosts, username=args.username)
    elif args.mode == "upgrade":
        mode_upgrade(hosts, username=args.username)
    elif args.mode == "recover":
        mode_recover(hosts, username=args.username)


if __name__ == "__main__":
    main()

