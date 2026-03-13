# MikroTik Bulk Password Manager

A Python tool for managing SSH passwords across large fleets of MikroTik RouterOS devices. Designed for networks of hundreds to thousands of devices, it tracks password revisions, detects drift, and maintains a persistent audit trail. Includes a Telegram bot for on-demand password lookup in the field.

Authors: Claude (anthropic), silvije2
---

## Requirements

### Password Manager
- Python 3.7+
- [paramiko](https://www.paramiko.org/)

```bash
pip install paramiko --break-system-packages
```

### Telegram Bot
- [python-telegram-bot](https://python-telegram-bot.org/)

```bash
pip install python-telegram-bot --break-system-packages
```

---

## Quick Start

```bash
# 1. Create your hosts file
echo "192.168.1.1:router-core-01" >> hosts.txt
echo "192.168.1.2" >> hosts.txt

# 2. Discover existing passwords (bootstrap)
python mikrotik_passmanager.py --mode audit --pass CurrentPassword

# 3. Push a new password to all tracked devices
python mikrotik_passmanager.py --mode change

# 4. Verify passwords are still valid after a while
python mikrotik_passmanager.py --mode verify

# 5. Check database summary at any time
python mikrotik_passmanager.py --mode status
```

---

## Usage

```
python mikrotik_passmanager.py --mode <mode> [options]
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--mode` | Yes | Operation mode: `change`, `audit`, `verify`, `status`, `upgrade`, or `recover` |
| `--pass` | Audit only | Password to test against devices |
| `--hosts` | No | Path to hosts file (default: `hosts.txt`) |
| `--username` | No | SSH username (default: `manager`) |

---

## Modes

### `--mode audit`

Tests a given password against all devices in `hosts.txt`. No changes are made to any device. On success, the password is recorded in `passwords.db` with a new sub-1000 revision number and `device_status.db` is updated for all devices that accepted the login.

Use this mode to bootstrap the system — run it once (or several times with different candidate passwords) before using `change` mode.

```bash
python mikrotik_passmanager.py --mode audit --pass SomePassword
```

**Output statuses:** `SUCCESS`, `AUTH_FAILED`, `UNREACHABLE`

---

### `--mode change`

Pushes a new password to all tracked devices. The script will:

1. Prompt for the new password interactively
2. Auto-assign the next revision number (starting at 1000, incrementing by 1)
3. For each device, look up its current password from `passwords.db` via `device_status.db`
4. Connect with the old password, apply the new password via RouterOS command
5. Immediately reconnect with the new password to verify the change succeeded
6. Update `device_status.db` for all successful devices
7. Write a results file
8. Clear `password_exposed.flag` if set

Devices with no recorded password (`NO_RECORD`) are skipped with a warning. Run `audit` mode first to bring them into the system.

```bash
python mikrotik_passmanager.py --mode change
```

**Output statuses:** `SUCCESS`, `AUTH_FAILED`, `UNREACHABLE`, `NO_RECORD`

---

### `--mode verify`

Checks whether the currently recorded password for each device still works, without making any changes. Detects cases where a password was changed externally (e.g. by a local admin).

- `VERIFIED` — login succeeded, password record is still valid
- `DRIFTED` — device is reachable but login failed; the password was changed externally. The device's revision is set to `UNKNOWN` in `device_status.db`
- `UNREACHABLE` — device is down or not reachable; entry is left untouched
- `NO_RECORD` — device has no recorded password (never audited, or already marked UNKNOWN)

After running verify, use `audit` or `recover` mode to re-discover drifted devices.

```bash
python mikrotik_passmanager.py --mode verify
```

---

### `--mode status`

Prints a summary of the database state. No SSH connections are made — reads local db files only and returns instantly. Shows a warning if `password_exposed.flag` is set.

```bash
python mikrotik_passmanager.py --mode status
```

Example output (with exposed flag set):

```
[STATUS] Device database summary
  ──────────────────────────────────────
  ⚠  PASSWORD EXPOSED — rotation needed
     Looked up by: John (id:123456789) at 2024-06-01T14:32:00
  ──────────────────────────────────────
  Active hosts in hosts.txt  : 3000
  ──────────────────────────────────────
  KNOWN     (valid revision) : 2847
  UNKNOWN   (drifted/reset)  :   12
  NO RECORD (never audited)  :  141
  ──────────────────────────────────────
  At latest rev (1001)      : 2810
  Behind latest rev          :   37
  ──────────────────────────────────────
  REMOVED   (ex-hosts.txt)   :   47
```

---

### `--mode upgrade`

Finds all tracked devices not on the latest password revision and brings them up to date automatically. No user input required.

- Determines the highest revision in `passwords.db` as the target
- Skips devices with `UNKNOWN` revision or `NO_RECORD` (no known password to connect with)
- Connects using each device's currently recorded password, changes to latest, verifies by reconnecting
- Updates `device_status.db` for successful devices

Useful after a `change` run that had partial failures, or after a Telegram bot temp rotation to bring devices back to the fleet standard password.

```bash
python mikrotik_passmanager.py --mode upgrade
```

**Output statuses:** `SUCCESS`, `AUTH_FAILED`, `UNREACHABLE`

---

### `--mode recover`

Tries all known passwords against devices that have no working password on record — either never audited (`NO_RECORD`) or previously drifted (`UNKNOWN`). Passwords are tried newest first. Stops trying the moment one works for a given device. If a device is unreachable on the first attempt, no further passwords are tried for it.

```bash
python mikrotik_passmanager.py --mode recover
```

**Output statuses:** `RECOVERED`, `AUTH_FAILED`, `UNREACHABLE`

---

## Files

### Input

#### `hosts.txt`

One device per line. Hostname is optional. Lines starting with `#` are ignored.

```
# Lines starting with # are ignored
192.168.1.1
192.168.1.2:router-core-01
10.0.0.1:sw-access-floor3
```

---

### Database Files

All database files are CSV format with Unix line endings (`\n`).

#### `passwords.db`

Stores every password revision. Sorted by revision number ascending.

```
revision,password,timestamp
999,OldDefaultPass,2024-01-10T09:00:00
998,AnotherOldPass,2024-01-10T09:05:00
1000,FirstNewPass,2024-03-01T08:00:00
1001,SecondNewPass,2024-06-01T08:00:00
```

**Revision numbering:**
- `1000+` — assigned by `change` mode, auto-incremented
- `≤999` — assigned by `audit` mode and bot temp rotations, auto-decremented from 999 downward

#### `device_status.db`

Tracks the last known working password revision for each active device.

```
ip,hostname,last_successful_revision
10.0.0.1,router-core-01,1001
10.0.0.2,sw-access-01,UNKNOWN
10.0.0.3,,1001
```

`UNKNOWN` means the device was reachable during a verify run but the recorded password no longer worked.

#### `device_status_removed.db`

Same format as `device_status.db`. Contains entries for devices removed from `hosts.txt`. Preserved for audit history.

#### `hosts_seen.db`

Plain text, one IP per line. Records every IP that has ever appeared in `hosts.txt`. Used to detect new hosts on subsequent runs without re-announcing already-known devices.

#### `password_exposed.flag`

Written when a colleague looks up a password via the Telegram bot and the device was unreachable (fallback to DB password). Contains the timestamp and who triggered the lookup. Cleared automatically after a successful `change` run.

```
2024-06-01T14:32:00|John Smith (id:123456789)
```

---

### Output Files

#### `results_<revision>_<timestamp>.txt`

Created after every `change`, `audit`, or `upgrade` run.

```
ip,hostname,status
10.0.0.1,router-core-01,SUCCESS
10.0.0.2,sw-access-01,UNREACHABLE
10.0.0.3,,AUTH_FAILED
```

#### `results_verify_<timestamp>.txt`

Created after every `verify` run. Statuses: `VERIFIED`, `DRIFTED`, `UNREACHABLE`, `NO_RECORD`.

#### `results_recover_<timestamp>.txt`

Created after every `recover` run. Statuses: `RECOVERED`, `AUTH_FAILED`, `UNREACHABLE`.

---

## Hosts File Reconciliation

On every run (except `status`), the script compares `hosts.txt` against the database and reports:

- **New hosts** — IPs appearing for the first time; added to `hosts_seen.db`, will show as `NO_RECORD` until audited
- **Removed hosts** — IPs previously tracked but no longer in `hosts.txt`; moved from `device_status.db` to `device_status_removed.db`
- **Hostname updates** — if a hostname changes for an existing IP, `device_status.db` is silently updated

---

## Typical Workflows

### Initial Bootstrap (fresh deployment)

```bash
# Run audit with each candidate password until all devices are covered
python mikrotik_passmanager.py --mode audit --pass Password1
python mikrotik_passmanager.py --mode audit --pass Password2

# Check coverage
python mikrotik_passmanager.py --mode status

# Push a single unified password to all discovered devices
python mikrotik_passmanager.py --mode change
```

### Routine Password Rotation

```bash
python mikrotik_passmanager.py --mode change
# Enter new password when prompted
# Revision auto-increments (e.g. 1001 → 1002)
```

### Catching Up Devices That Missed a Change Run

```bash
python mikrotik_passmanager.py --mode upgrade
# Finds all devices below latest revision and upgrades them automatically
# Also restores devices that received a bot temp password back to fleet standard
```

### Detecting and Recovering External Password Changes

```bash
python mikrotik_passmanager.py --mode verify
# DRIFTED devices marked UNKNOWN

python mikrotik_passmanager.py --mode recover
# Tries all known passwords against UNKNOWN and NO_RECORD devices

python mikrotik_passmanager.py --mode change
# All recovered devices included in next rotation
```

### Adding New Devices Mid-Fleet

```bash
# Add IPs to hosts.txt, then run recover
python mikrotik_passmanager.py --mode recover
# Tries all known passwords automatically
```

---

## Configuration

Constants at the top of the script can be adjusted:

| Constant | Default | Description |
|----------|---------|-------------|
| `SSH_PORT` | `22` | SSH port |
| `SSH_TIMEOUT` | `10` | Connection timeout in seconds |
| `MAX_WORKERS` | `100` | Parallel SSH connections |
| `CHANGE_REVISION_START` | `1000` | First revision number for change mode |

---

## Telegram Bot

`mikrotik_bot.py` allows authorized colleagues to look up device passwords on demand from their phone — useful for field maintenance without VPN access. When a password is requested and the device is reachable, the bot sets a temporary password on the spot before returning it, so the credential is single-use per request. Periodic `--mode upgrade` runs restore devices to the fleet standard password.

### Bot Setup

**Step 1 — create the bot and get the token:**
Create a bot via `@BotFather` on Telegram.

**Step 2 — create the config file:**
Copy `telegram_bot.config.example` to `telegram_bot.config` and fill in your values:

```ini
BOT_TOKEN            = 123456:ABC-your-token-here
GROUP_CHAT_ID        = -1001234567890
SSH_USERNAME         = manager
USERS_PASSWORDS_FILE = /etc/freeradius/users
```

**Step 3 — find your group's chat ID:**
```bash
python mikrotik_bot.py --getgroupid
# Send any message in the group
# Bot prints: Add to telegram_bot.config: GROUP_CHAT_ID = -1001234567890
```

**Step 4 — collect colleague IDs via registration invite:**
```bash
python mikrotik_bot.py --register
```
The bot posts one message to the group with a button. Colleagues tap it, a private chat opens automatically, and their Telegram ID is written to `telegram_users.db` with a blank username field.

**Step 5 — authorize colleagues:**
Open `telegram_users.db` and fill in the `username` column for each person:

```
telegram_id,username
123456789,mhemen
987654321,jsmith
```

The username must match their entry in the `USERS_PASSWORDS_FILE`. Authorization is driven entirely by this file — users with a blank username are not yet authorized.

**Step 6 — run normally:**
```bash
python mikrotik_bot.py
```

---

### Bot Commands

| Command | Description |
|---------|-------------|
| `/pass <ip or hostname>` | Get current password for a device (with temp rotation if reachable) |
| `/mypass` | Get your personal system password from the RADIUS users file |
| `/help` | Show available commands |
| `/myid` | Show your Telegram user ID |

---

### `/pass` Behaviour (temp rotation)

When a colleague runs `/pass 10.0.0.1`:

1. Bot looks up the device's current password from `device_status.db` / `passwords.db`
2. Connects to the device using that password
3. If reachable — sets the temp password from `temp_manager.txt`, verifies by reconnecting, records a new sub-1000 revision in both DBs, sends the temp password to the user
4. If unreachable or auth fails — sends the current DB password as fallback and sets `password_exposed.flag`

The temp password in `temp_manager.txt` is a single line and is rotated weekly by a separate script. After field work, run `--mode upgrade` to restore all temp-rotated devices to the current fleet standard password.

---

### Bot Behaviour

- Responds only in private chats — passwords are never shown in the group
- All lookups logged to `bot_audit.log` with user ID, name, timestamp, and device queried
- Unauthorized users receive no response (silently ignored)
- All file paths resolved at startup — safe to run as a daemon
- Command menu registers automatically on bot startup

---

### Bot Files

| File | Description |
|------|-------------|
| `telegram_bot.config` | Bot token, group ID, SSH username, path to RADIUS users file |
| `telegram_users.db` | CSV: `telegram_id,username` — authorization and username mapping |
| `temp_manager.txt` | Single line — current temp password, rotated weekly |
| `bot_audit.log` | Log of every lookup: timestamp, user ID, device, result |
| `group_members_collected.log` | Raw registration log from `--register` flow |
| `password_exposed.flag` | Set when fallback password is sent, cleared after `change` run |

---

## Notes

- Passwords are stored in plaintext in `passwords.db`. Secure the directory appropriately.
- The script uses RouterOS command `/user set <username> password="<new>"` to change passwords.
- Paramiko transport-level errors (e.g. SSH banner errors on overloaded devices) are suppressed and treated as `UNREACHABLE`.
- All output files use Unix line endings (`\n`).
- `telegram_users.db` must have a header line: `telegram_id,username`
