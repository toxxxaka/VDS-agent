#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import socket
import shutil
import platform
import subprocess
import argparse
import ipaddress
import logging
import secrets
import tempfile
import base64
import hashlib
import hmac
import struct
from contextvars import ContextVar
from pathlib import Path
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None


# ===========================================================
# CONFIG
# ===========================================================
BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("MONITORINGBOT_STATE_DIR", str(BASE_DIR)))
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATUS_FILE = STATE_DIR / "server_status.json"
SSH_LOG_PATH = Path(os.environ.get("MONITORINGBOT_SSH_LOG", "/var/log/auth.log"))
SSH_STATE_FILE = STATE_DIR / "ssh_login_state.json"
SSH_ALLOWLIST_FILE = Path(os.environ.get(
    "MONITORINGBOT_SSH_ALLOWLIST", str(BASE_DIR / "ssh-allowlist.json")
))
ACTION_STATE_FILE = STATE_DIR / "pending_power_action.json"
AUTH_CONFIG_FILE = Path(os.environ.get("MONITORINGBOT_AUTH_CONFIG", "/etc/monitoringbot/auth.json"))
AUTH_STATE_FILE = STATE_DIR / "telegram_auth_state.json"
SSH_TERMINATION_STATE_FILE = STATE_DIR / "pending_ssh_termination.json"
SSH_SESSION_HELPER = Path("/usr/local/libexec/monitoringbot-ssh-session-helper")
REPLY_CHAT_ID = ContextVar("reply_chat_id", default=None)
CURRENT_USER_ID = ContextVar("current_user_id", default=None)
LOG = logging.getLogger("monitoringbot")
TELEGRAM_SEND_SESSION = requests.Session() if requests is not None else None
TELEGRAM_POLL_SESSION = requests.Session() if requests is not None else None
for _telegram_session in (TELEGRAM_SEND_SESSION, TELEGRAM_POLL_SESSION):
    if _telegram_session is not None:
        _telegram_session.trust_env = False

SERVERS = {
    "Сервер NL": "192.0.2.10",
    "Сервер FRA": "198.51.100.20"
}
SERVER_ALERTS_ENABLED = os.environ.get("MONITORINGBOT_SERVER_ALERTS", "0") == "1"

# ===========================================================
# TEMPERATURE LIMITS
# ===========================================================

CPU_TEMP_WARNING = 75
CPU_TEMP_CRITICAL = 85

HDD_TEMP_WARNING = 50
HDD_TEMP_CRITICAL = 52

# ===========================================================
# TELEGRAM
# ===========================================================

def telegram(method, payload=None, timeout=(5, 20)):
    """Call Telegram directly; proxy settings are deliberately never used."""
    if not BOT_TOKEN or not CHAT_ID:
        LOG.error("Telegram is not configured: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing")
        return None
    if requests is None:
        LOG.error("Python package requests is not installed")
        return None

    try:
        session = TELEGRAM_POLL_SESSION if method == "getUpdates" else TELEGRAM_SEND_SESSION
        response = session.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        payload_response = response.json()
        LOG.info("Telegram API %s completed: ok=%s", method, payload_response.get("ok"))
        return payload_response
    except Exception as exc:
        LOG.warning("Telegram API %s failed (%s)", method, type(exc).__name__)
        return None



BOT_COMMANDS = [
    {"command": "start", "description": "Start and authentication help"},
    {"command": "login", "description": "Sign in with a TOTP code"},
    {"command": "status", "description": "Full server status"},
    {"command": "daily", "description": "Daily report"},
    {"command": "ping", "description": "Check server availability"},
    {"command": "cpu", "description": "CPU usage"},
    {"command": "ram", "description": "RAM and swap"},
    {"command": "disk", "description": "Disk and SMART status"},
    {"command": "load", "description": "Load average"},
    {"command": "uptime", "description": "Server uptime"},
    {"command": "sessions", "description": "Active SSH sessions"},
    {"command": "sshlogins", "description": "Recent external SSH logins"},
    {"command": "killssh", "description": "Terminate SSH session by PID"},
    {"command": "incidents", "description": "List incidents"},
    {"command": "incident", "description": "Incident details by ID"},
    {"command": "ack", "description": "Acknowledge incident by ID"},
    {"command": "close", "description": "Close incident by ID"},
    {"command": "reboot", "description": "Reboot server with confirmation"},
    {"command": "shutdown", "description": "Shut down server with confirmation"},
    {"command": "logout", "description": "End authorization session"},
    {"command": "help", "description": "Show command help"},
]


def register_bot_commands():
    """Register Telegram's native slash-command menu; failure is non-fatal."""
    response = telegram("setMyCommands", {"commands": BOT_COMMANDS})
    if not response or not response.get("ok"):
        LOG.warning("Telegram command menu registration failed")
        return False
    LOG.info("Telegram command menu registered: %d commands", len(BOT_COMMANDS))
    return True

def send(text, chat_id=None):
    response = telegram("sendMessage", {
        "chat_id": chat_id or REPLY_CHAT_ID.get() or CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
        "parse_mode": "HTML",
    })
    delivered = bool(response and response.get("ok"))
    LOG.info("Telegram message delivery: %s", delivered)
    return delivered


# ===========================================================
# TELEGRAM USER AUTHENTICATION (ALLOWLIST + TOTP)
# ===========================================================

def auth_config():
    config = load_json(AUTH_CONFIG_FILE, {})
    allowed = {str(item) for item in config.get("allowed_user_ids", [])}
    secret = str(config.get("totp_secret", "")).replace(" ", "").upper()
    return {
        "allowed_user_ids": allowed,
        "totp_secret": secret,
        "session_seconds": int(config.get("session_seconds", 3600)),
        "max_failures": int(config.get("max_failures", 5)),
        "lockout_seconds": int(config.get("lockout_seconds", 900)),
    }


def totp_valid(secret, code, now=None):
    if not re.fullmatch(r"\d{6}", code):
        return False
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, base64.binascii.Error):
        return False
    current_step = int((time.time() if now is None else now) // 30)
    for step in (current_step - 1, current_step, current_step + 1):
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        candidate = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if secrets.compare_digest(f"{candidate:06d}", code):
            return True
    return False


def auth_state():
    state = load_json(AUTH_STATE_FILE, {})
    return state if isinstance(state, dict) else {}


def save_auth_state(state):
    save_json_atomic(AUTH_STATE_FILE, state)


def authenticated(user_id):
    config = auth_config()
    user_id = str(user_id)
    if user_id not in config["allowed_user_ids"] or not config["totp_secret"]:
        return False
    session = auth_state().get("sessions", {}).get(user_id, {})
    return session.get("expires_at", 0) > time.time()


def login(user_id, code):
    config = auth_config()
    user_id = str(user_id)
    state = auth_state()
    failures = state.setdefault("failures", {}).get(user_id, {"count": 0, "locked_until": 0})
    if user_id not in config["allowed_user_ids"] or not config["totp_secret"]:
        return False, "Access denied."
    if failures.get("locked_until", 0) > time.time():
        return False, "Too many failed attempts. Try again later."
    if not totp_valid(config["totp_secret"], code):
        failures["count"] = failures.get("count", 0) + 1
        if failures["count"] >= config["max_failures"]:
            failures = {"count": 0, "locked_until": time.time() + config["lockout_seconds"]}
        state.setdefault("failures", {})[user_id] = failures
        save_auth_state(state)
        return False, "Invalid authentication code."
    state.setdefault("sessions", {})[user_id] = {"expires_at": time.time() + config["session_seconds"]}
    state.setdefault("failures", {}).pop(user_id, None)
    save_auth_state(state)
    return True, f"Access granted for {config['session_seconds'] // 60} minutes."


def logout(user_id):
    state = auth_state()
    state.setdefault("sessions", {}).pop(str(user_id), None)
    save_auth_state(state)


def delete_login_message(chat_id, message_id):
    if message_id is not None:
        telegram("deleteMessage", {"chat_id": chat_id, "message_id": message_id})




# ===========================================================
# SUCCESSFUL SSH LOGIN MONITOR
# ===========================================================

SSH_ACCEPT_RE = re.compile(
    r"^(?P<timestamp>(?:\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+))\s+\S+\s+sshd\[\d+\]: Accepted "
    r"(?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\d+) ssh2(?:: (?P<fingerprint>.*))?$"
)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def save_json_atomic(path, value):
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def ssh_allowed_networks():
    config = load_json(SSH_ALLOWLIST_FILE, {"allowed_networks": []})
    raw_networks = config.get("allowed_networks", [])
    if not isinstance(raw_networks, list):
        LOG.error("SSH allowlist must contain an allowed_networks list: %s", SSH_ALLOWLIST_FILE)
        return []
    networks = []
    for raw_network in raw_networks:
        try:
            networks.append(ipaddress.ip_network(raw_network, strict=False))
        except ValueError:
            LOG.warning("Ignoring invalid SSH allowlist entry: %r", raw_network)
    return networks


def is_allowed_ssh_ip(address, networks=None):
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed_address in network for network in (networks or ssh_allowed_networks()))


def parse_successful_ssh_login(line):
    match = SSH_ACCEPT_RE.match(line.rstrip("\n"))
    return match.groupdict() if match else None


def ssh_alert(event):
    fingerprint = f"\nKey: {event['fingerprint']}" if event.get("fingerprint") else ""
    return (
        "SSH: successful login from an untrusted address\n"
        f"Host: {hostname()}\n"
        f"Time: {event['timestamp']}\n"
        f"User: {event['user']}\n"
        f"Method: {event['method']}\n"
        f"Source: {event['ip']}:{event['port']}"
        f"{fingerprint}"
    )


def check_ssh_logins(from_start=False):
    """Alert once for each non-allowlisted successful sshd login.

    The saved byte offset prevents repeated notifications. A first normal run starts
    at EOF, so historical logins do not create a burst of alerts.
    """
    state = load_json(SSH_STATE_FILE, {})
    alerts = []
    recent = state.get("recent_untrusted_logins", [])[-19:]
    networks = ssh_allowed_networks()
    try:
        # fstat() deliberately happens after opening the file. This makes the
        # saved identity agree with the bytes read even if logrotate runs here.
        with open(SSH_LOG_PATH, "rb") as handle:
            stat = os.fstat(handle.fileno())
            same_file = (
                state.get("inode") == stat.st_ino
                and state.get("device") == stat.st_dev
            )
            if from_start:
                offset = 0
            elif not state.get("initialized"):
                save_json_atomic(SSH_STATE_FILE, {
                    "initialized": True, "inode": stat.st_ino, "device": stat.st_dev,
                    "offset": stat.st_size, "recent_untrusted_logins": [],
                })
                return []
            elif same_file and 0 <= state.get("offset", 0) <= stat.st_size:
                offset = state["offset"]
            else:
                offset = 0

            processed_offset = offset
            handle.seek(offset)
            for raw_line in handle:
                line_end = handle.tell()
                event = parse_successful_ssh_login(raw_line.decode("utf-8", errors="replace"))
                if event and not is_allowed_ssh_ip(event["ip"], networks):
                    if not send(ssh_alert(event)):
                        LOG.error("SSH alert was not sent; the login will be retried on the next run")
                        break
                    alerts.append(event)
                    recent.append(event)
                    recent = recent[-20:]
                processed_offset = line_end
    except OSError as exc:
        LOG.error("Cannot read SSH log %s: %s", SSH_LOG_PATH, exc)
        return []

    save_json_atomic(SSH_STATE_FILE, {
        "initialized": True, "inode": stat.st_ino, "device": stat.st_dev, "offset": processed_offset,
        "recent_untrusted_logins": recent,
    })
    return alerts


# ===========================================================
# SYSTEM
# ===========================================================

def run(cmd):

    try:

        return subprocess.check_output(
            cmd,
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()

    except Exception:

        return ""


# ===========================================================
# PING
# ===========================================================

def ping(host):

    result = subprocess.run(
        [
            "ping",
            "-c",
            "1",
            "-W",
            "5",
            host
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

# PRIVILEGED POWER ACTIONS

POWER_ACTIONS = {"reboot", "poweroff"}
SERVERCTL = Path(os.environ.get("MONITORINGBOT_POWER_COMMAND", "/usr/bin/systemctl"))
SUDO = Path("/usr/bin/sudo")


def serverctl_is_safe():
    try:
        details = SERVERCTL.stat()
    except OSError:
        return False
    return details.st_uid == 0 and not (details.st_mode & 0o022) and SERVERCTL.is_file()


def request_power_action(action):
    if action not in POWER_ACTIONS:
        raise ValueError("Unsupported power action")
    token = secrets.token_urlsafe(6)
    save_json_atomic(ACTION_STATE_FILE, {
        "action": action,
        "token": token,
        "expires_at": time.time() + 60,
        "user_id": CURRENT_USER_ID.get(),
    })
    command = "/reboot" if action == "reboot" else "/shutdown"
    return f"Confirm {command}: {command} confirm {token} (valid for 60 seconds)"


def execute_power_action(action, token):
    pending = load_json(ACTION_STATE_FILE, {})
    if (
        action not in POWER_ACTIONS
        or pending.get("action") != action
        or not secrets.compare_digest(str(pending.get("token", "")), token)
        or pending.get("expires_at", 0) < time.time()
        or pending.get("user_id") != CURRENT_USER_ID.get()
    ):
        return False, "Confirmation is invalid or has expired."
    try:
        ACTION_STATE_FILE.unlink(missing_ok=True)
        if not serverctl_is_safe():
            return False, f"{SERVERCTL} is missing or has unsafe ownership/permissions."
        result = subprocess.run(
            [str(SUDO), "-n", str(SERVERCTL), action],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return True, "Command accepted."
        return False, "Privileged command was rejected or failed."
    except (OSError, subprocess.TimeoutExpired):
        return False, "Could not complete the privileged command."


def reboot():
    return request_power_action("reboot")


def shutdown():
    return request_power_action("poweroff")

# ===========================================================
# HOSTNAME
# ===========================================================

def hostname():

    return socket.gethostname()


# ===========================================================
# KERNEL
# ===========================================================

def kernel():

    return platform.release()


# ===========================================================
# UPTIME
# ===========================================================

def uptime():

    seconds = int(time.time() - psutil.boot_time())

    days = seconds // 86400
    seconds %= 86400

    hours = seconds // 3600
    seconds %= 3600

    minutes = seconds // 60

    if days:

        return f"{days}д {hours}ч {minutes}м"

    return f"{hours}ч {minutes}м"


# ===========================================================
# LOAD
# ===========================================================

def load():

    l = os.getloadavg()

    return (
        round(l[0], 2),
        round(l[1], 2),
        round(l[2], 2)
    )


# ===========================================================
# CPU USAGE
# ===========================================================

def cpu_usage():

    return psutil.cpu_percent(interval=1)


# ===========================================================
# CPU TEMPERATURE
# ===========================================================

def cpu_temperature():

    out = run(["sensors"])

    temps = []

    for line in out.splitlines():

        if "Core " in line:

            m = re.search(r"\+([\d.]+)", line)

            if m:

                temps.append(float(m.group(1)))

    if temps:

        return round(sum(temps) / len(temps), 1)

    m = re.search(r"temp1:\s+\+([\d.]+)", out)

    if m:

        return float(m.group(1))

    return None


# ===========================================================
# RAM
# ===========================================================

def ram():

    mem = psutil.virtual_memory()

    return {

        "total": round(mem.total / 1024 ** 3, 1),
        "used": round(mem.used / 1024 ** 3, 1),
        "free": round(mem.available / 1024 ** 3, 1),
        "percent": mem.percent
    }


# ===========================================================
# SWAP
# ===========================================================

def swap():

    s = psutil.swap_memory()

    return {

        "total": round(s.total / 1024 ** 3, 1),
        "used": round(s.used / 1024 ** 3, 1),
        "percent": s.percent
    }


# ===========================================================
# HDD
# ===========================================================

def disk():

    d = shutil.disk_usage("/")

    return {

        "total": round(d.total / 1024 ** 3, 1),
        "used": round(d.used / 1024 ** 3, 1),
        "free": round(d.free / 1024 ** 3, 1),
        "percent": round(d.used / d.total * 100)
    }


# ===========================================================
# SMART
# ===========================================================

def smart():

    # SMART helper is optional. Do not invoke sudo from the monitoring loop.
    out = ""

    result = {

        "health": "UNKNOWN",
        "temperature": None,
        "model": "",
        "power_on_hours": None

    }

    for line in out.splitlines():

        if "Model Family" in line:

            continue

        if "Device Model:" in line:

            result["model"] = line.split(":", 1)[1].strip()

        if "SMART overall-health" in line:

            if "PASSED" in line:

                result["health"] = "PASSED"

            else:

                result["health"] = "FAILED"

        if "SMART Health Status" in line:

            if "OK" in line:

                result["health"] = "PASSED"

        if "Temperature_Celsius" in line:

            try:

                temp = line.split("(")[0].split()[-1]

                result["temperature"] = int(temp)

            except Exception as e:

                print(e)

#        if "Temperature_Celsius" in line:
#
#            m = re.search(r"(\d+)\s*\(", line)
#
#            if m:
#
#                result["temperature"] = int(m.group(1))
#
        if "Power_On_Hours" in line:

            x = line.split()

            try:

                result["power_on_hours"] = int(x[-1])

            except:

                pass

    return result


# ===========================================================
# SERVER STATUS
# ===========================================================

def servers():

    data = {}

    for name, ip in SERVERS.items():

        data[name] = {

            "ip": ip,
            "alive": ping(ip)

        }

    return data


# ===========================================================
# BUILD STATUS MESSAGE
# ===========================================================

def build_status():

    cpu = cpu_usage()
    temp = cpu_temperature()

    memory = ram()
    sw = swap()
    hdd = disk()
    ld = load()
    sm = smart()

    text = []

    text.append(f"🖥 {hostname()}")
    text.append("")
    text.append(f"Kernel: {kernel()}")
    text.append(f"Uptime: {uptime()}")
    text.append("")
    text.append("CPU")
    text.append(f"  Usage : {cpu}%")
    text.append(f"  Load  : {ld[0]} {ld[1]} {ld[2]}")

    if temp:

        text.append(f"  Temp  : {temp}°C")

    text.append("")
    text.append("RAM")
    text.append(
        f"  {memory['used']} / {memory['total']} GB ({memory['percent']}%)"
    )

    text.append("")
    text.append("Swap")
    text.append(
        f"  {sw['used']} / {sw['total']} GB ({sw['percent']}%)"
    )

    text.append("")
    text.append("Disk")

    text.append(
        f"  {hdd['used']} / {hdd['total']} GB ({hdd['percent']}%)"
    )

    if sm["temperature"]:

        text.append(f"  Temp : {sm['temperature']}°C")

    text.append(f"  SMART: {sm['health']}")

    text.append("")

    text.append("Servers")

    for name, info in servers().items():

        icon = "🟢" if info["alive"] else "🔴"

        text.append(f"{icon} {name}")

    text.append("")
    text.append(datetime.now().strftime("%d.%m.%Y %H:%M"))

    return "\n".join(text)

# ===========================================================
# STATUS FILE
# ===========================================================

def load_status():

    if not os.path.exists(STATUS_FILE):
        return {}

    try:

        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return {}


def save_status(data):

    with open(STATUS_FILE, "w", encoding="utf-8") as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=4
        )


# ===========================================================
# SERVER CHECK
# ===========================================================

def check_servers():

    previous = load_status()

    current = {}

    for name, ip in SERVERS.items():

        alive = ping(ip)

        current[name] = alive

        was = previous.get(name)

        if was is None:

            continue

        if SERVER_ALERTS_ENABLED and was and not alive:

            send(
                f"🚨 {name}\n\n"
                f"{ip}\n\n"
                f"не отвечает."
            )

        elif SERVER_ALERTS_ENABLED and not was and alive:

            send(
                f"✅ {name}\n\n"
                f"{ip}\n\n"
                f"снова доступен."
            )

    save_status(current)


# ===========================================================
# COMMANDS
# ===========================================================

def help_text():
    return """📡 Мониторинг сервера

📊 Состояние
/status — полный статус
/daily — ежедневный отчёт
/ping — доступность серверов

🖥 Ресурсы
/cpu · /ram · /disk · /load · /uptime

🔐 Безопасность
/sessions — активные SSH-сессии
/sshlogins — недавние внешние SSH-входы
/killssh PID — завершить SSH-сессию
/logout — завершить авторизацию

⚙ Управление
/reboot · /shutdown — с подтверждением

/help — это меню"""


SSH_SESSION_RE = re.compile(r"^sshd:\s+(?P<user>[^@\s]+)@(?P<tty>\S+)$")


def active_ssh_sessions():
    """Read validated session leaves from the root helper; add remote sources when available."""
    try:
        result = subprocess.run(
            [str(SUDO), "-n", str(SSH_SESSION_HELPER), "list"],
            text=True, capture_output=True, timeout=5, check=False,
        )
        sessions = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    sources = {}
    try:
        for line in subprocess.run(["w", "-h", "-i"], text=True, capture_output=True, timeout=5).stdout.splitlines():
            parts = line.split(None, 6)
            if len(parts) == 7:
                match = re.search(r"sshd:\s+(\S+)@(\S+)$", parts[-1])
                if match:
                    sources[(match.group(1), match.group(2))] = parts[1]
    except (OSError, subprocess.TimeoutExpired):
        pass
    for item in sessions:
        item["source"] = sources.get((item["user"], item["tty"]), "unknown")
    return sessions


def ssh_sessions_text():
    sessions = active_ssh_sessions()
    if not sessions:
        return "No active SSH sessions found."
    lines = ["Active SSH sessions:", "PID | user | source | tty"]
    for session in sessions[:30]:
        lines.append(
            f"{session['pid']} | {session['user']} | {session['source']} | {session['tty']}"
        )
    if len(sessions) > 30:
        lines.append(f"Showing 30 of {len(sessions)} sessions.")
    lines.append("To terminate: /killssh PID")
    return "\n".join(lines)


def request_ssh_termination(pid):
    session = next((item for item in active_ssh_sessions() if item["pid"] == pid), None)
    if session is None:
        return False, "SSH session was not found. Use /sessions and choose a listed PID."
    token = secrets.token_urlsafe(6)
    save_json_atomic(SSH_TERMINATION_STATE_FILE, {
        "pid": pid, "session_id": session["id"], "token": token, "user_id": CURRENT_USER_ID.get(),
        "expires_at": time.time() + 60,
    })
    return True, f"Confirm termination: /killssh confirm {pid} {token} (valid for 60 seconds)"


def terminate_ssh_session(pid, token):
    pending = load_json(SSH_TERMINATION_STATE_FILE, {})
    if (
        pending.get("pid") != pid
        or pending.get("user_id") != CURRENT_USER_ID.get()
        or pending.get("expires_at", 0) < time.time()
        or not secrets.compare_digest(str(pending.get("token", "")), token)
    ):
        return False, "Confirmation is invalid or has expired."
    try:
        SSH_TERMINATION_STATE_FILE.unlink(missing_ok=True)
        result = subprocess.run(
            [str(SUDO), "-n", str(SSH_SESSION_HELPER), "terminate", pending["session_id"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "Could not complete the SSH termination request."
    if result.returncode == 0:
        return True, f"SSH session {pid} was terminated."
    return False, "SSH session was not terminated. It may already be closed."


def process_authenticated_command(text):
    raw_command = text.strip()
    cmd = raw_command.lower()
    LOG.info("Authenticated command started: %s", raw_command.split(maxsplit=1)[0])

    if cmd == "/status":
        send(build_status()); return
    if cmd == "/help":
        send(help_text()); return
    if cmd == "/uptime":
        send(f"⏱ <b>Аптайм</b>\n{uptime()}"); return
    if cmd == "/load":
        l = load(); send(f"⚙️ <b>Средняя нагрузка</b>\n1 мин: {l[0]}\n5 мин: {l[1]}\n15 мин: {l[2]}"); return
    if cmd == "/cpu":
        temp = cpu_temperature()
        lines = ["🧠 <b>Процессор</b>", f"Загрузка: {cpu_usage()}%"]
        if temp is not None: lines.append(f"Температура: {temp}°C")
        send("\n".join(lines)); return
    if cmd == "/ram":
        r, sw = ram(), swap()
        send(f"🧠 <b>Память</b>\nRAM: {r['used']} / {r['total']} ГБ ({r['percent']}%)\nSwap: {sw['used']} / {sw['total']} ГБ ({sw['percent']}%)"); return
    if cmd == "/disk":
        d, sm = disk(), smart()
        lines = ["💾 <b>Диск</b>", f"Занято: {d['used']} / {d['total']} ГБ ({d['percent']}%)", f"SMART: {sm['health']}"]
        if sm["temperature"] is not None: lines.append(f"Температура: {sm['temperature']}°C")
        send("\n".join(lines)); return
    if cmd == "/daily":
        send(build_daily_report()); return
    if cmd == "/sshlogins":
        recent = load_json(SSH_STATE_FILE, {}).get("recent_untrusted_logins", [])
        if not recent: send("🔐 Внешних успешных SSH-входов пока не обнаружено.")
        else:
            lines = ["🔐 <b>Последние внешние SSH-входы</b>"]
            for event in recent[-10:]: lines.append(f"{event['timestamp']} · {event['user']} · {event['method']} · {event['ip']}:{event['port']}")
            send("\n".join(lines))
        return
    if cmd == "/incidents":
        from v4.storage import rows
        data = rows("SELECT id,type,severity,status,started_at,last_seen_at,ack_by FROM incidents ORDER BY id DESC LIMIT 20")
        send("📋 <b>Incidents</b>\n" + ("\n".join(f"#{x['id']} · {x['severity']} · {x['type']} · {x['status']}" for x in data) if data else "Нет incidents.")); return
    if re.fullmatch(r"/incident\s+\d+", cmd):
        from v4.storage import rows
        iid=int(cmd.split()[1]); data=rows("SELECT * FROM incidents WHERE id=?",(iid,)); events=rows("SELECT event,time FROM incident_events WHERE incident_id=? ORDER BY time DESC LIMIT 10",(iid,))
        send((f"<b>Incident #{iid}</b>\n"+"\n".join(f"{k}: {v}" for k,v in data[0].items())+"\nEvents: "+", ".join(x['event'] for x in events)) if data else "Incident не найден."); return
    if re.fullmatch(r"/(ack|close)\s+\d+", cmd):
        from v4.incidents import ack, close
        action,iid=cmd[1:].split(); (ack if action=='ack' else close)(int(iid),CURRENT_USER_ID.get()); send(f"✅ Incident #{iid}: {action}"); return
    if cmd == "/sessions": send(ssh_sessions_text()); return
    if cmd == "/ping":
        rows = ["📡 <b>Проверка ICMP</b>"]
        for name, info in servers().items(): rows.append(f"{'🟢' if info['alive'] else '⚪️'} {name}: {'есть ответ' if info['alive'] else 'нет ICMP-ответа'}")
        rows.append("ℹ️ Нет ICMP-ответа не означает недоступность сервера.")
        send("\n".join(rows)); return
    if cmd == "/reboot": send("♻️ " + reboot()); return
    if cmd == "/shutdown": send("⛔ " + shutdown()); return
    if cmd.startswith("/reboot confirm ") or cmd.startswith("/shutdown confirm "):
        action = "reboot" if cmd.startswith("/reboot ") else "poweroff"
        ok, message = execute_power_action(action, raw_command.split(maxsplit=2)[2]); send(("✅ " if ok else "❌ ") + message); return
    if re.fullmatch(r"/killssh\s+\d+", cmd):
        ok, message = request_ssh_termination(int(cmd.split()[1])); send(("⚠️ " if ok else "❌ ") + message); return
    if cmd.startswith("/killssh confirm "):
        parts = raw_command.split(maxsplit=3)
        if len(parts) != 4 or not parts[2].isdigit(): send("Формат: /killssh confirm PID КОД"); return
        ok, message = terminate_ssh_session(int(parts[2]), parts[3]); send(("✅ " if ok else "❌ ") + message); return
    send("Неизвестная команда. Откройте /help.")


def process_command(text, user_id, chat_id, message_id):
    raw_command = text.strip()
    cmd = raw_command.lower()
    config = auth_config()
    if str(user_id) not in config["allowed_user_ids"]:
        LOG.warning("Telegram access denied: user_id=%s chat_id=%s", user_id, chat_id)
        send("Access denied.", chat_id=chat_id)
        return
    if cmd == "/start":
        send("Authentication required. Send: /login 123456", chat_id=chat_id)
        return
    if cmd == "/logout":
        logout(user_id)
        from v4.storage import audit
        audit(user_id, "logout")
        send("Authorization session ended.", chat_id=chat_id)
        return
    if cmd.startswith("/login "):
        parts = raw_command.split(maxsplit=1)
        code = parts[1].strip() if len(parts) == 2 else ""
        delete_login_message(chat_id, message_id)
        succeeded, message = login(user_id, code)
        from v4.storage import audit
        audit(user_id, "login", result="ok" if succeeded else "denied")
        send(("✅ " if succeeded else "❌ ") + message, chat_id=chat_id)
        return
    if not authenticated(user_id):
        send("Authentication required. Send: /login 123456", chat_id=chat_id)
        return
    process_authenticated_command(raw_command)


# ===========================================================
# TELEGRAM LONG POLLING
# ===========================================================

def poll(last_update):

    data = telegram(
        "getUpdates",
        {"timeout": 50, "offset": last_update + 1},
        timeout=(5, 65),
    )

    if not data:
        return last_update

    if not data.get("ok"):
        return last_update

    LOG.info("Telegram updates received: %d", len(data["result"]))
    for update in data["result"]:

        last_update = update["update_id"]

        message = update.get("message")

        if not message:
            continue

        sender = message.get("from", {})
        chat = message.get("chat", {})
        if chat.get("type") != "private" or chat.get("id") != sender.get("id"):
            LOG.warning("Ignoring non-private or mismatched Telegram update")
            continue

        text = message.get("text")
        if not text:
            continue

        chat_token = REPLY_CHAT_ID.set(str(chat["id"]))
        user_token = CURRENT_USER_ID.set(str(sender["id"]))
        try:
            LOG.info("Processing Telegram command from user_id=%s", sender["id"])
            process_command(text, str(sender["id"]), str(chat["id"]), message.get("message_id"))
        finally:
            CURRENT_USER_ID.reset(user_token)
            REPLY_CHAT_ID.reset(chat_token)

    return last_update

# ===========================================================
# DAILY REPORT
# ===========================================================

def daily_report():

    send(build_daily_report())

#def daily_report():
#
#    send(build_status())
#
# ===========================================================
# AVAILABLE UPDATES
# ===========================================================

def available_updates():
    try:
        out = run([
            "apt",
            "list",
            "--upgradable"
        ])
        lines = out.splitlines()
        # первая строка обычно:
        # Listing...
        return max(0, len(lines) - 1)
    except Exception:
        return 0
# ===========================================================
# DAILY REPORT
# ===========================================================

def build_daily_report():

    text = []

    #
    # Проверка серверов
    #

    srv = servers()

    failed = []

    for name, info in srv.items():

        if not info["alive"]:

            failed.append(name)

    if not failed:

        text.append("🟢 Все системы работают штатно")

    else:

        text.append("🔴 Обнаружены проблемы")

        for s in failed:

            text.append(f" • {s}")

    text.append("")

    #
    # Uptime
    #

    text.append(f"⏳ Аптайм: {uptime()}")

    #
    # RAM
    #

    r = ram()

    text.append(
        f"🧠 RAM: {r['used']} / {r['total']} GB ({r['percent']}%)"
    )
    #
    # CPU
    #
    temp = cpu_temperature()
    if temp is not None:
        text.append(f"🌡 CPU: {temp}°C")
    #
    # HDD
    #
    sm = smart()
    if sm["temperature"] is not None:
        text.append(
            f"💾 HDD: {sm['temperature']}°C"
        )
    #
    # Updates
    #
    updates = available_updates()
    text.append(
        f"📦 Доступно обновлений: {updates}"
    )
    #
    # Время
    #
    text.append("")
    text.append(datetime.now().strftime("%d.%m.%Y %H:%M"))
    return "\n".join(text)

# ===========================================================
# TEMPERATURE ALERTS
# ===========================================================

def check_temperatures():

    cpu = cpu_temperature()

    sm = smart()

    hdd = sm["temperature"]

    #
    # CPU
    #

    if cpu is not None:

        if cpu >= CPU_TEMP_CRITICAL:

            send(
                "🔥 КРИТИЧЕСКАЯ температура CPU!\n\n"
                f"{cpu}°C"
            )

        elif cpu >= CPU_TEMP_WARNING:

            send(
                "⚠ Повышенная температура CPU\n\n"
                f"{cpu}°C"
            )

    #
    # HDD
    #

    if hdd is not None:

        if hdd >= HDD_TEMP_CRITICAL:

            send(
                "🔥 КРИТИЧЕСКАЯ температура HDD!\n\n"
                f"{hdd}°C"
            )

        elif hdd >= HDD_TEMP_WARNING:

            send(
                "⚠ Повышенная температура HDD\n\n"
                f"{hdd}°C"
            )

# ===========================================================
# MAIN
# ===========================================================

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--daily-report", action="store_true")
    parser.add_argument(
        "--check-ssh-logins", action="store_true",
        help="Read new successful sshd logins and send alerts for non-allowlisted IPs.",
    )
    parser.add_argument(
        "--ssh-log-from-start", action="store_true",
        help="With --check-ssh-logins, inspect the complete current log (for a controlled test).",
    )
    parser.add_argument("--send-test-message", action="store_true")
    args = parser.parse_args()

    if args.ssh_log_from_start and not args.check_ssh_logins:
        parser.error("--ssh-log-from-start requires --check-ssh-logins")

    if args.send_test_message:
        if not BOT_TOKEN or not CHAT_ID or requests is None:
            parser.error("Test message requires TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID and requests")
        if not send(f"Monitoring bot test: {hostname()} is configured successfully."):
            raise SystemExit("Telegram test message was not accepted")
        print("Telegram test message accepted.")
        return

    if args.check_ssh_logins:
        if not BOT_TOKEN or not CHAT_ID or requests is None:
            parser.error("SSH monitoring requires TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID and requests")
        alerts = check_ssh_logins(from_start=args.ssh_log_from_start)
        print(f"Untrusted successful SSH logins alerted: {len(alerts)}")
        return

    if args.daily_report:
        daily_report()
        return

    if not BOT_TOKEN or not CHAT_ID:
        parser.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")
    if psutil is None or requests is None:
        parser.error("The full Telegram monitor requires Python packages psutil and requests")

    print("Telegram monitor started.")
    register_bot_commands()

    #
    # Первичная проверка серверов
    #
    check_servers()

    #
    # Чтобы после перезапуска не читать всю историю сообщений
    #
    last_update = 0

    data = telegram("getUpdates", {"timeout": 1})

    if data and data.get("ok") and data["result"]:

        last_update = data["result"][-1]["update_id"]

    #
    # Основной цикл
    #
    while True:

        try:

            #
            # Проверка серверов
            #
            check_servers()

            check_temperatures()

            #
            # Команды Telegram
            #
            last_update = poll(last_update)

            # getUpdates already blocks for up to 50 seconds; a short pause prevents
            # busy looping without adding visible command latency.
            time.sleep(1)

        except KeyboardInterrupt:

            print("Stopped.")

            break

        except Exception as e:

            LOG.exception("Main monitoring loop failed")
            time.sleep(15)


# ===========================================================
# ENTRY
# ===========================================================

if __name__ == "__main__":

    main()
