#!/usr/bin/env python3
"""
MikroTik Password Manager — Telegram Bot
Allows authorized colleagues to look up device passwords on demand.

Authors: Claude (anthropic), silvije2

Setup:
  1. Create a bot via @BotFather on Telegram, get the token
  2. Set BOT_TOKEN in config below (or via env var MIKROTIK_BOT_TOKEN)
  3. Set DB_DIR to the directory containing passwords.db and device_status.db
  4. Set GROUP_CHAT_ID to your group's chat ID (see below)
  5. Run: python mikrotik_bot.py --register
     Bot posts a registration invite to the group with a button.
     Colleagues tap it, open private chat, IDs are collected automatically.
  6. Check group_members_collected.log, add usernames to telegram_users.db
  7. Run normally: python mikrotik_bot.py

Getting GROUP_CHAT_ID:
  Add the bot to your group, then send any message in the group.
  Run: python mikrotik_bot.py --getgroupid
  The bot will print the chat ID of the first group message it receives.

Commands:
  /pass <ip or hostname>  — returns the current password for that device
  /myid                      — returns your Telegram user ID (for setup)
  /help                      — shows available commands
"""

import os
import csv
import socket
import logging
import asyncio
import argparse
import daemon
from datetime import datetime
from pathlib import Path

try:
    from telegram import Update, BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
except ImportError:
    print("ERROR: python-telegram-bot is required.")
    print("Install with: pip install python-telegram-bot --break-system-packages")
    raise

try:
    import paramiko
    import socket
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except ImportError:
    print("ERROR: paramiko is required.")
    print("Install with: pip install paramiko --break-system-packages")
    raise

# ══════════════════════════════════════════════════════════════════════════════
# Configuration — loaded from telegram_bot.config (same dir as this script)
# ══════════════════════════════════════════════════════════════════════════════

CONFIG_FILE = Path(__file__).resolve().parent / "telegram_bot.config"

def load_config():
    """
    Load configuration from telegram_bot.config.
    Returns a dict with all settings. Exits with an error if the file is missing
    or required keys are absent.
    """
    if not CONFIG_FILE.exists():
        print(f"ERROR: Config file not found: {CONFIG_FILE}")
        print("Create telegram_bot.config next to this script. See telegram_bot.config.example for reference.")
        raise SystemExit(1)

    config = {}
    with open(CONFIG_FILE) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                print(f"ERROR: telegram_bot.config line {lineno}: expected key=value, got: {line!r}")
                raise SystemExit(1)
            key, _, value = line.partition("=")
            config[key.strip()] = value.strip()
    return config


_config = load_config()

# Script directory — resolved to absolute path at import time, survives daemonization
DB_DIR = Path(__file__).resolve().parent

BOT_TOKEN        = _config.get("BOT_TOKEN", "")
GROUP_CHAT_ID    = _config.get("GROUP_CHAT_ID", "")
BOT_SSH_USERNAME = _config.get("SSH_USERNAME", "manager")
USERS_PASSWORDS_FILE = Path(_config.get("USERS_PASSWORDS_FILE", ""))

if not BOT_TOKEN:
    print("ERROR: BOT_TOKEN is missing or empty in telegram_bot.config")
    raise SystemExit(1)

if not _config.get("USERS_PASSWORDS_FILE"):
    print("ERROR: USERS_PASSWORDS_FILE is missing in telegram_bot.config")
    raise SystemExit(1)

# Audit log file
AUDIT_LOG          = DB_DIR / "bot_audit.log"
COLLECT_LOG        = DB_DIR / "group_members_collected.log"
TEMP_MANAGER       = DB_DIR / "temp_manager.txt"
TELEGRAM_USERS_DB  = DB_DIR / "telegram_users.db"

# ── File paths (must match mikrotik_passmanager.py) ───────────────────────────
PASSWORDS_DB  = DB_DIR / "passwords.db"
DEVICE_STATUS = DB_DIR / "device_status.db"
EXPOSED_FLAG  = DB_DIR / "password_exposed.flag"

# ══════════════════════════════════════════════════════════════════════════════
# Logging
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# DB helpers (read-only, mirrors mikrotik_passmanager.py)
# ══════════════════════════════════════════════════════════════════════════════

def load_passwords_db():
    """Return dict {revision: password}."""
    result = {}
    if not PASSWORDS_DB.exists():
        return result
    with open(PASSWORDS_DB, newline="") as f:
        for row in csv.DictReader(f):
            result[int(row["revision"])] = row["password"]
    return result


def load_device_status():
    """Return dict {ip: {'hostname': str, 'revision': int or None}}."""
    status = {}
    if not DEVICE_STATUS.exists():
        return status
    with open(DEVICE_STATUS, newline="") as f:
        for row in csv.DictReader(f):
            raw = row["last_successful_revision"]
            status[row["ip"]] = {
                "hostname": row.get("hostname", ""),
                "revision": None if raw == "UNKNOWN" else int(raw),
            }
    return status


def lookup_device(query):
    """
    Look up a device by IP or hostname.
    Returns (ip, hostname, password) or (None, None, reason_string).
    """
    device_status = load_device_status()
    passwords     = load_passwords_db()

    # Try direct IP match first
    if query in device_status:
        entry = device_status[query]
        ip, hostname = query, entry["hostname"]
    else:
        # Try hostname match (case-insensitive)
        match = None
        for ip, data in device_status.items():
            if data["hostname"].lower() == query.lower():
                match = (ip, data)
                break
        if not match:
            return None, None, "Device not found. Check IP or hostname."
        ip, entry = match
        hostname = entry["hostname"]

    if entry["revision"] is None:
        return ip, hostname, "UNKNOWN — password was changed externally. Run recover or audit first."

    password = passwords.get(entry["revision"])
    if password is None:
        return ip, hostname, "Revision found but password missing from passwords.db."

    return ip, hostname, password


# ══════════════════════════════════════════════════════════════════════════════
# Temp password helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_temp_password():
    """Read current temp password from temp_manager.txt. Returns None if file missing."""
    if not TEMP_MANAGER.exists():
        return None
    with open(TEMP_MANAGER) as f:
        pw = f.read().strip()
    return pw if pw else None


def next_sub_revision():
    """Return next available sub-1000 revision (continues audit sequence downward)."""
    passwords = load_passwords_db()
    sub_revs  = [r for r in passwords if r < 1000]
    return min(sub_revs) - 1 if sub_revs else 999


def save_passwords_entry(revision, password):
    """Append a new revision to passwords.db if not already present."""
    passwords = load_passwords_db()
    if revision in passwords:
        return
    rows = []
    if PASSWORDS_DB.exists():
        import csv as _csv
        with open(PASSWORDS_DB, newline="") as f:
            rows = list(_csv.DictReader(f))
    rows.append({
        "revision":  revision,
        "password":  password,
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    })
    rows.sort(key=lambda r: int(r["revision"]))
    import csv as _csv
    with open(PASSWORDS_DB, "w", newline="") as f:
        writer = _csv.DictWriter(f, lineterminator="\n", fieldnames=["revision", "password", "timestamp"])
        writer.writeheader()
        writer.writerows(rows)


def save_device_revision(ip, hostname, revision):
    """Update device_status.db for a single device."""
    import csv as _csv
    rows = []
    if DEVICE_STATUS.exists():
        with open(DEVICE_STATUS, newline="") as f:
            rows = list(_csv.DictReader(f))
    updated = False
    for row in rows:
        if row["ip"] == ip:
            row["last_successful_revision"] = revision
            if hostname:
                row["hostname"] = hostname
            updated = True
            break
    if not updated:
        rows.append({"ip": ip, "hostname": hostname, "last_successful_revision": revision})
    rows.sort(key=lambda r: r["ip"])
    with open(DEVICE_STATUS, "w", newline="") as f:
        writer = _csv.DictWriter(f, lineterminator="\n",
                                 fieldnames=["ip", "hostname", "last_successful_revision"])
        writer.writeheader()
        writer.writerows(rows)


def ssh_try_connect(ip, username, password, timeout=10):
    """
    Try SSH login. Returns (client, None) on success or (None, error_string).
    error_string is 'AUTH_FAILED' or 'UNREACHABLE'.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        return client, None
    except paramiko.AuthenticationException:
        return None, "AUTH_FAILED"
    except (socket.timeout, socket.error, paramiko.SSHException, EOFError):
        return None, "UNREACHABLE"
    except Exception:
        return None, "UNREACHABLE"


def ssh_set_password(client, username, new_password):
    """Run RouterOS command to set a new password. Returns True on success."""
    try:
        stdin, stdout, stderr = client.exec_command(
            f'/user set {username} password="{new_password}"'
        )
        stdout.channel.recv_exit_status()
        return True
    except Exception:
        return False


def try_temp_rotation(ip, hostname, current_password, temp_password, username):
    """
    Connect with current_password, set temp_password, verify by reconnecting.
    Returns (success: bool, message: str).
    """
    client, err = ssh_try_connect(ip, username, current_password)
    if err:
        return False, err

    ssh_set_password(client, username, temp_password)
    client.close()

    # Verify
    client2, err2 = ssh_try_connect(ip, username, temp_password)
    if err2:
        return False, "VERIFY_FAILED"
    client2.close()
    return True, "OK"

def set_exposed_flag(user_display):
    """Write exposed flag with who triggered it and when."""
    with open(EXPOSED_FLAG, "w") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}|{user_display}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Audit / collect logs
# ══════════════════════════════════════════════════════════════════════════════

def audit_log(user_id, username, query, result_summary):
    """Append a lookup event to bot_audit.log."""
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    line = f"{ts} | user_id={user_id} | username={username} | query={query} | result={result_summary}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(line)
    logger.info(f"LOOKUP user_id={user_id} username={username} query={query} result={result_summary}")


def record_collected_member(user):
    """
    Add a registering user to telegram_users.db with empty username placeholder,
    and log to group_members_collected.log.
    """
    ts   = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    name = user.full_name or user.username or str(user.id)
    line = f"{ts} | id={user.id} | name={name} | username=@{user.username or 'not set'}\n"
    with open(COLLECT_LOG, "a") as f:
        f.write(line)

    # Add to telegram_users.db if not already present (username left blank for admin to fill)
    users = load_telegram_users()
    if user.id not in users:
        users[user.id] = ""
        save_telegram_users(users)

    print(f"  Registered: {user.id:>12}  {name:<30}  @{user.username or 'not set'}")


# ══════════════════════════════════════════════════════════════════════════════
# Authorization — telegram_users.db
# ══════════════════════════════════════════════════════════════════════════════

def load_telegram_users():
    """
    Load telegram_users.db.
    Returns dict {telegram_id (int): username (str)}.
    """
    users = {}
    if not TELEGRAM_USERS_DB.exists():
        return users
    with open(TELEGRAM_USERS_DB, newline="") as f:
        for row in csv.DictReader(f):
            try:
                tid = int(row["telegram_id"].strip())
                users[tid] = row["username"].strip()
            except (KeyError, ValueError):
                continue
    return users


def save_telegram_users(users):
    """Write telegram_users.db. users: {telegram_id (int): username (str)}"""
    with open(TELEGRAM_USERS_DB, "w", newline="") as f:
        writer = csv.DictWriter(f, lineterminator="\n", fieldnames=["telegram_id", "username"])
        writer.writeheader()
        for tid, uname in sorted(users.items()):
            writer.writerow({"telegram_id": tid, "username": uname})


def is_authorized(user_id):
    """Return True if telegram_id is in telegram_users.db."""
    return user_id in load_telegram_users()


def get_system_username(user_id):
    """Return system username for a telegram_id, or None if not found."""
    return load_telegram_users().get(user_id)


def load_user_password(system_username):
    """
    Look up password for system_username in USERS_PASSWORDS_FILE.
    File format (FreeRADIUS):  username Cleartext-Password := "password"
    Returns password string or None.
    """
    if not USERS_PASSWORDS_FILE.exists():
        return None
    with open(USERS_PASSWORDS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if not parts:
                continue
            if parts[0].lower() == system_username.lower():
                # Find quoted password after :=
                if ':=' in line:
                    after = line.split(':=', 1)[1].strip()
                    return after.strip('"').strip("'")
    return None


def user_display(update: Update):
    """Return a readable user label for logs and flag."""
    u = update.effective_user
    name = u.full_name or u.username or str(u.id)
    return f"{name} (id:{u.id})"


# ══════════════════════════════════════════════════════════════════════════════
# Command handlers
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /start — triggered when a user taps the deep link button from the group.
    Records their ID and name, replies with confirmation.
    Only works in private chat.
    """
    if update.effective_chat.type != "private":
        return

    user = update.effective_user
    record_collected_member(user)

    await update.message.reply_text(
        f"✅ Hi {user.full_name}!\n\n"
        f"Your ID has been recorded: <code>{user.id}</code>\n\n"
        f"The administrator will add you to the authorized list. "
        f"Once approved you can use /pass to look up device passwords.",
        parse_mode="HTML"
    )


async def cmd_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user

    # Private chat only
    if update.effective_chat.type != "private":
        return

    # Authorization check
    if not is_authorized(user.id):
        logger.warning(f"Unauthorized access attempt: user_id={user.id} username={user.username}")
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /pass <ip or hostname>\n"
            "Example: /pass 10.0.0.1\n"
            "Example: /pass router-core-01"
        )
        return

    query = context.args[0].strip()
    ip, hostname, result = lookup_device(query)

    if ip is None:
        await update.message.reply_text(f"❌ {result}")
        audit_log(user.id, user.username, query, f"NOT_FOUND: {result}")
        return

    if result.startswith("UNKNOWN") or result.endswith(".db."):
        await update.message.reply_text(f"⚠️ {ip} ({hostname}): {result}")
        audit_log(user.id, user.username, query, f"ERROR: {result}")
        return

    display  = f"{ip}" + (f" ({hostname})" if hostname else "")
    temp_pw  = load_temp_password()

    # ── Attempt temp rotation if temp_manager.txt is present ──────────────────
    if temp_pw:
        await update.message.reply_text(f"⏳ Connecting to {display}...")
        success, msg = await asyncio.get_event_loop().run_in_executor(
            None, try_temp_rotation, ip, hostname, result, temp_pw, BOT_SSH_USERNAME
        )

        if success:
            # Record new temp revision in both DBs
            revision = next_sub_revision()
            save_passwords_entry(revision, temp_pw)
            save_device_revision(ip, hostname, revision)

            await update.message.reply_text(
                f"🔑 {display}\n"
                f"<code>{temp_pw}</code>\n\n"
                f"<i>Temporary password set (rev {revision}). "
                f"Device will be restored to fleet password on next upgrade run.</i>",
                parse_mode="HTML"
            )
            audit_log(user.id, user.username, query, f"TEMP_ROTATED rev={revision}")
            return

        # Rotation failed — fall through to send current password as normal
        logger.info(f"Temp rotation failed for {ip}: {msg} — falling back to DB password")

    # ── Fallback: send current password from DB ────────────────────────────────
    await update.message.reply_text(f"🔑 {display}\n<code>{result}</code>", parse_mode="HTML")
    set_exposed_flag(user_display(update))
    audit_log(user.id, user.username, query, "PASSWORD_SENT")


async def cmd_myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Return the user's Telegram ID — useful during initial setup."""
    if update.effective_chat.type != "private":
        return
    user = update.effective_user
    await update.message.reply_text(
        f"Your Telegram user ID is: <code>{user.id}</code>\n"
        f"Name: {user.full_name}\n"
        f"Username: @{user.username or 'not set'}\n\n"
        f"Send this ID to the administrator to get access.",
        parse_mode="HTML"
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private":
        return
    if not is_authorized(update.effective_user.id):
        return
    await update.message.reply_text(
        "<b>MikroTik Password Bot</b>\n\n"
        "/pass &lt;ip or hostname&gt; — get current password for a device\n"
        "/mypass — get your personal system password\n"
        "/myid — show your Telegram user ID\n"
        "/help — show this message\n\n"
        "All lookups are logged for audit purposes.",
        parse_mode="HTML"
    )


async def cmd_mypass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Return the caller's personal password from the RADIUS users file."""
    if update.effective_chat.type != "private":
        return

    user = update.effective_user

    if not is_authorized(user.id):
        logger.warning(f"Unauthorized access attempt: user_id={user.id} username={user.username}")
        return

    system_username = get_system_username(user.id)

    if not system_username:
        await update.message.reply_text(
            "⚠️ Your account has no system username set yet.\n"
            "Contact the administrator to complete your profile in telegram_users.db."
        )
        audit_log(user.id, user.username, "mypass", "NO_USERNAME")
        return

    password = load_user_password(system_username)

    if password is None:
        await update.message.reply_text(
            f"⚠️ No password found for username <code>{system_username}</code>.\n"
            f"Contact the administrator.",
            parse_mode="HTML"
        )
        audit_log(user.id, user.username, "mypass", f"NOT_FOUND username={system_username}")
        return

    await update.message.reply_text(
        f"🔑 Your password for <code>{system_username}</code>:\n"
        f"<code>{password}</code>",
        parse_mode="HTML"
    )
    audit_log(user.id, user.username, "mypass", f"PASSWORD_SENT username={system_username}")


async def capture_group_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Temporary handler to print group chat ID — used with --getgroupid flag."""
    chat = update.effective_chat
    if chat.type in ("group", "supergroup"):
        print(f"\n  Group name : {chat.title}")
        print(f"  Chat ID    : {chat.id}")
        print(f"\n  Add to telegram_bot.config:  GROUP_CHAT_ID = {chat.id}")
        print("  Then restart with --register to post the invite.\n")


async def post_init(app):
    """Register the bot command menu shown to users when they tap /"""
    await app.bot.set_my_commands([
        BotCommand("help",   "Show available commands"),
        BotCommand("pass",   "Get device password — /pass <ip or hostname>"),
        BotCommand("mypass", "Your MikroTik pass"),
        BotCommand("myid",   "Show your Telegram user ID"),
    ])
    logger.info("Command menu registered with Telegram")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="MikroTik Password Bot")
    parser.add_argument(
        "--register",
        action="store_true",
        help="Post a registration invite to the group with a deep link button. "
             "Colleagues tap it to register their ID. Check group_members_collected.log afterwards."
    )
    parser.add_argument(
        "--getgroupid",
        action="store_true",
        help="Print the chat ID of the group the bot is in. Run once to find GROUP_CHAT_ID."
    )
    args = parser.parse_args()

    if not load_telegram_users():
        print("WARNING: telegram_users.db is empty — no one will be able to use the bot.")
        print("Run with --register to collect colleague IDs, then add usernames to telegram_users.db.")

    # ── --getgroupid mode ─────────────────────────────────────────────────────
    if args.getgroupid:
        print("Listening for group messages — send any message in the group to capture its ID.")
        print("Press Ctrl+C when done.\n")
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        app.add_handler(MessageHandler(filters.ChatType.GROUPS, capture_group_id))
        app.run_polling()
        return

    # ── --register mode ───────────────────────────────────────────────────────
    if args.register:
        if not GROUP_CHAT_ID:
            print("ERROR: GROUP_CHAT_ID is missing in telegram_bot.config.")
            print("Run with --getgroupid first to find your group's chat ID.")
            raise SystemExit(1)

        async def send_invite():
            app = ApplicationBuilder().token(BOT_TOKEN).build()
            bot_info     = await app.bot.get_me()
            bot_username = bot_info.username
            deep_link    = f"https://t.me/{bot_username}?start=register"
            keyboard     = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔑 Register for password access", url=deep_link)
            ]])
            await app.bot.send_message(
                chat_id=int(GROUP_CHAT_ID),
                text=(
                    "👋 <b>MikroTik Password Bot</b>\n\n"
                    "Tap the button below to register for on-demand device password access.\n"
                    "This opens a private chat with the bot — your ID will be sent to the administrator for approval."
                ),
                parse_mode="HTML",
                reply_markup=keyboard,
            )
            print(f"  Registration invite posted to group {GROUP_CHAT_ID}")
            print(f"  Now run normally and wait for colleagues to tap the button.")
            print(f"  Check {COLLECT_LOG} for collected IDs.")
            await app.shutdown()

        asyncio.run(send_invite())

        # Stay running to receive /start callbacks from colleagues tapping the button
        print("\nListening for registrations — press Ctrl+C when everyone has registered.\n")
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        app.add_handler(CommandHandler("start", cmd_start))
        app.run_polling()
        return

    # ── Normal mode ───────────────────────────────────────────────────────────
    logger.info(f"Starting bot. DB dir: {DB_DIR.resolve()}")
    logger.info(f"Config: {CONFIG_FILE}")
    logger.info(f"Authorized users: {list(load_telegram_users().keys())}")

    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start",         cmd_start))
    app.add_handler(CommandHandler("pass",       cmd_pass))
    app.add_handler(CommandHandler("mypass", cmd_mypass))
    app.add_handler(CommandHandler("myid",          cmd_myid))
    app.add_handler(CommandHandler("help",          cmd_help))

    logger.info("Bot is running. Press Ctrl+C to stop.")
    app.run_polling()


if __name__ == "__main__":
  with daemon.DaemonContext():
    main()

