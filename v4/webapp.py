"""Authenticated Telegram Mini App backend for Monitoringbot v4."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from .incidents import ack, close, close_all
from .snapshots import overview
from .metrics import RANGES, latest as metric_latest, query as metric_query
from .backups import destinations as backup_destinations, history as backup_history, start as start_backup
from .library import content as library_content, download as library_download, info as library_info, issue_link as library_issue_link
from .storage import audit, connect, rows
from . import firewall
from . import external_tools
from . import ai
from . import self_monitoring
from .tasks import TASKS, get_run, list_runs, start_run

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
AUTH = Path(os.environ.get("MONITORINGBOT_AUTH_CONFIG", "/etc/monitoringbot-main/auth.json"))
TTL = 3600
PENDING_TTL = 60
V3 = None


def cfg():
    return json.loads(AUTH.read_text())


def load_v3():
    global V3
    if V3 is None:
        spec = spec_from_file_location("monitoringbot_v3", "/opt/monitoringbot/v3.py")
        V3 = module_from_spec(spec)
        spec.loader.exec_module(V3)
    return V3


def browser_principal(client_ip):
    """Return an IP-bound browser principal only for configured trusted networks."""
    try:
        address = ipaddress.ip_address(client_ip)
        permitted = [ipaddress.ip_network(value, strict=False) for value in cfg().get("web_allowed_ips", [])]
        if any(address in network for network in permitted):
            return f"browser:{address.compressed}"
    except ValueError:
        pass
    return None


def initdata_ok(raw):
    """Validate Telegram's signed initData and return an allow-listed user id."""
    try:
        query = urllib.parse.parse_qs(raw, strict_parsing=True)
        supplied_hash = query.pop("hash", [None])[0]
        data = {key: value[0] for key, value in query.items()}
        auth_date = int(data["auth_date"])
        user = json.loads(data["user"])
        check = "\n".join(f"{key}={data[key]}" for key in sorted(data))
        secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not supplied_hash or not hmac.compare_digest(supplied_hash, expected):
            return None
        if abs(time.time() - auth_date) > 300:
            return None
        if str(user["id"]) not in {str(item) for item in cfg()["allowed_user_ids"]}:
            return None
        return str(user["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None


def clear_expired(connection):
    connection.execute("DELETE FROM pending_actions WHERE expires_at < ?", (time.time(),))


def new_session(user):
    with connect() as connection:
        clear_expired(connection)
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            ("web_session", user, "", time.time() + TTL, "{}"),
        )
        return cursor.lastrowid


def cookie_session_id(header):
    try:
        cookie = SimpleCookie()
        cookie.load(header or "")
        return int(cookie["mbs"].value)
    except (KeyError, ValueError):
        return None


def web_user(header):
    session_id = cookie_session_id(header)
    if session_id is None:
        return None
    with connect() as connection:
        clear_expired(connection)
        row = connection.execute("SELECT user_id FROM pending_actions WHERE id=? AND kind='web_session'", (session_id,)).fetchone()
        return row["user_id"] if row else None


def create_confirmation(user, kind, target, data=None):
    with connect() as connection:
        clear_expired(connection)
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            (kind, user, target, time.time() + PENDING_TTL, json.dumps(data or {})),
        )
        return cursor.lastrowid


def consume_confirmation(user, action_id, allowed_kind):
    with connect() as connection:
        clear_expired(connection)
        row = connection.execute("SELECT * FROM pending_actions WHERE id=? AND user_id=? AND kind=?", (action_id, user, allowed_kind)).fetchone()
        if not row:
            return None
        connection.execute("DELETE FROM pending_actions WHERE id=?", (action_id,))
        return dict(row)


def command_result(command):
    """Execute an allow-listed existing monitor function without shell interpolation."""
    bot = load_v3()
    if command == "status":
        return {"title": "System status", "text": bot.build_status()}
    if command == "daily":
        return {"title": "Daily report", "text": bot.build_daily_report()}
    if command == "ping":
        data = bot.servers()
        text = ["Server availability"]
        for name, item in data.items():
            checks = ", ".join(f"{check['kind'].upper()}{('/' + str(check['port'])) if check.get('port') else ''}: {'ok' if check['ok'] else 'fail'}" for check in item["checks"])
            text.append(f"{item['status']}  {name}: {item['host']}\n{checks}")
        text.append("ICMP is diagnostic only. DOWN requires repeated failed configured TCP/HTTP checks.")
        return {"title": "Server availability", "text": "\n".join(text)}
    if command == "cpu":
        temperature = bot.cpu_temperature()
        text = f"CPU usage: {bot.cpu_usage()}%"
        if temperature is not None:
            text += f"\nTemperature: {temperature}°C"
        return {"title": "CPU", "text": text}
    if command == "ram":
        memory, swap = bot.ram(), bot.swap()
        return {"title": "Memory", "text": f"RAM: {memory['used']} / {memory['total']} GB ({memory['percent']}%)\nSwap: {swap['used']} / {swap['total']} GB ({swap['percent']}%)"}
    if command == "disk":
        disk, smart = bot.disk(), bot.smart()
        text = f"Used: {disk['used']} / {disk['total']} GB ({disk['percent']}%)\nSMART: {smart['health']}"
        if smart["temperature"] is not None:
            text += f"\nTemperature: {smart['temperature']}°C"
        return {"title": "Disk", "text": text}
    if command == "load":
        values = bot.load()
        return {"title": "Load average", "text": f"1 min: {values[0]}\n5 min: {values[1]}\n15 min: {values[2]}"}
    if command == "uptime":
        return {"title": "Uptime", "text": bot.uptime()}
    if command == "sshlogins":
        recent = bot.load_json(bot.SSH_STATE_FILE, {}).get("recent_untrusted_logins", [])
        if not recent:
            return {"title": "SSH logins", "text": "No untrusted successful SSH logins have been recorded."}
        text = ["Recent untrusted SSH logins"]
        for event in recent[-10:]:
            text.append(f"{event['timestamp']} | {event['user']} | {event['method']} | {event['ip']}:{event['port']}")
        return {"title": "SSH logins", "text": "\n".join(text)}
    if command == "sessions":
        return {"title": "SSH sessions", "text": "", "sessions": bot.active_ssh_sessions()}
    raise ValueError("Unsupported command")


def dashboard_payload():
    active = rows("SELECT * FROM incidents WHERE status='active' ORDER BY severity DESC,last_seen_at DESC LIMIT 8")
    counts = rows("SELECT status,COUNT(*) AS count FROM incidents GROUP BY status")
    return {
        "system": overview(),
        "active_incidents": active,
        "incident_counts": {row["status"]: row["count"] for row in counts},
        "runs": list_runs(5),
        "activity": rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8"),
        "self_monitoring": self_monitoring.report(),
    }


def metric_payload(period):
    # Legacy aliases retain compatibility with the previous statistics screen.
    period = {"hour": "1h", "day": "24h", "week": "7d"}.get(period, period)
    if period not in RANGES:
        raise ValueError("unsupported metric range")
    samples = metric_query(period)
    current = metric_latest()
    return {"period": period, "range": period, "samples": samples, "last_sample_at": current["time"] if current else None, "retention_days": 30, "refresh_seconds": 60}

def incident_payload(incident_id):
    incident = rows("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not incident:
        return None
    data = {"incident": incident[0], "events": rows("SELECT * FROM incident_events WHERE incident_id=? ORDER BY time DESC LIMIT 100", (incident_id,))}
    snapshot_id = incident[0].get("snapshot_id")
    if snapshot_id:
        snapshot = rows("SELECT * FROM snapshots WHERE id=?", (snapshot_id,))
        if snapshot:
            try:
                data["snapshot"] = json.loads(snapshot[0]["data"])
            except json.JSONDecodeError:
                data["snapshot"] = None
    return data


UI_DIR = Path(__file__).with_name("ui")
HTML = (UI_DIR / "index.html").read_text(encoding="utf-8")


def asset(name):
    """Return bundled UI assets only; no filesystem path comes from the request."""
    allowed = {"app.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8"}
    if name not in allowed:
        return None
    return (UI_DIR / name).read_bytes(), allowed[name]



class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload, headers=None):
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def auth(self):
        telegram_user = initdata_ok(self.headers.get("X-Telegram-InitData", ""))
        principal = telegram_user or browser_principal(self.headers.get("X-Real-IP", ""))
        return principal, web_user(self.headers.get("Cookie", ""))

    def body(self, limit=4096):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > limit:
                raise ValueError
            value = json.loads(self.rfile.read(size))
            return value if isinstance(value, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def authenticated_user(self):
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return None
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return None
        return telegram_user

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(HTML.encode())
            return
        if self.path in {"/static/app.css", "/static/app.js"}:
            item = asset(self.path.rsplit("/", 1)[1])
            if not item:
                self.reply(404, {"error": "asset not found"})
                return
            raw, content_type = item
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)
            return
        if re.fullmatch(r"/download/[A-Za-z0-9_-]{20,}", self.path):
            item=library_download(self.path.rsplit("/",1)[1])
            if not item:
                self.reply(404,{"error":"download link is invalid or expired"}); return
            filename,text=item; raw=text.encode()
            self.send_response(200); self.send_header("Content-Type","text/plain; charset=utf-8"); self.send_header("Content-Disposition",f'attachment; filename="{filename}"'); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw); return
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return
        if self.path == "/api/session":
            self.reply(200, {"totp": bool(session_user and session_user == telegram_user)})
            return
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return
        if self.path == "/api/dashboard":
            self.reply(200, dashboard_payload())
            return
        if self.path == "/api/self-monitoring":
            self.reply(200, self_monitoring.report())
            return
        if urllib.parse.urlparse(self.path).path == "/api/metrics":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            period = params.get("range", params.get("period", ["1h"]))[0]
            try:
                self.reply(200, metric_payload(period))
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
            return
        if self.path == "/api/backups":
            self.reply(200, {"backups": backup_history()})
            return
        if self.path == "/api/backups/destinations":
            try: self.reply(200, {"destinations": backup_destinations()})
            except RuntimeError as exc: self.reply(500, {"error": str(exc)})
            return
        if self.path == "/api/library":
            self.reply(200, {"scripts": library_info()})
            return
        if re.fullmatch(r"/api/library/[a-z0-9-]+", self.path):
            try:
                filename, text=library_content(self.path.rsplit("/",1)[1]); self.reply(200,{"filename":filename,"content":text})
            except ValueError as exc: self.reply(404,{"error":str(exc)})
            return
        if self.path.startswith("/api/incidents") and self.path.split("?", 1)[0] == "/api/incidents":
            filter_value = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("status", ["all"])[0]
            if filter_value == "open":
                query_sql, args = "SELECT * FROM incidents WHERE status='active' ORDER BY id DESC LIMIT 100", ()
            elif filter_value == "closed":
                query_sql, args = "SELECT * FROM incidents WHERE status!='active' ORDER BY id DESC LIMIT 100", ()
            elif filter_value == "all":
                query_sql, args = "SELECT * FROM incidents ORDER BY id DESC LIMIT 100", ()
            else:
                self.reply(400, {"error": "unsupported incident filter"})
                return
            self.reply(200, {"incidents": rows(query_sql, args), "filter": filter_value})
            return
        if re.fullmatch(r"/api/incidents/\d+", self.path):
            payload = incident_payload(int(self.path.rsplit("/", 1)[1]))
            self.reply(200, payload) if payload else self.reply(404, {"error": "incident not found"})
            return
        if self.path == "/api/audit":
            self.reply(200, {"audit": rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")})
            return
        if self.path == "/api/runs":
            self.reply(200, {"runs": list_runs(100)})
            return
        if re.fullmatch(r"/api/runs/[0-9a-f-]{36}", self.path):
            run = get_run(self.path.rsplit("/", 1)[1])
            self.reply(200, run) if run else self.reply(404, {"error": "run not found"})
            return
        if self.path == "/api/firewall":
            try: self.reply(200, firewall.state())
            except RuntimeError as exc: self.reply(503, {"error": str(exc)})
            return
        if self.path == "/api/settings":
            self.reply(200, {"settings": {"allowed_users": len(cfg()["allowed_user_ids"]), "session_seconds": TTL, "tasks": [spec.__dict__ for spec in TASKS.values()]}})
            return
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return
        if self.path == "/api/totp":
            data = self.body() or {}
            code = str(data.get("code", ""))
            if not re.fullmatch(r"\d{6}", code) or not load_v3().totp_valid(cfg()["totp_secret"], code):
                audit(telegram_user, "web_totp", result="denied")
                self.reply(403, {"error": "invalid TOTP"})
                return
            session_id = new_session(telegram_user)
            audit(telegram_user, "web_totp", result="ok")
            self.reply(200, {"ok": True}, {"Set-Cookie": f"mbs={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/"})
            return
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return
        if self.path == "/api/ai/chat":
            data = self.body(limit=32768) or {}
            try:
                messages = ai.validate_messages(data.get("messages"))
                ai.configured()
                stream = ai.stream(messages)
            except ai.AIError as error:
                self.reply(400, {"error": str(error)})
                return
            audit(telegram_user, "ai_chat", "timeweb-agent", "started", {"messages": len(messages)})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                for delta in stream:
                    self.wfile.write(("data: " + json.dumps({"delta": delta}, ensure_ascii=False) + "\n\n").encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                audit(telegram_user, "ai_chat", "timeweb-agent", "ok", {"messages": len(messages)})
            except (BrokenPipeError, ConnectionResetError):
                audit(telegram_user, "ai_chat", "timeweb-agent", "cancelled")
            except ai.AIError as error:
                try:
                    self.wfile.write(("data: " + json.dumps({"error": str(error)}) + "\n\n").encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                audit(telegram_user, "ai_chat", "timeweb-agent", "failed")
            return
        if self.path == "/api/tools/password":
            self.reply(200,{"password":external_tools.password()}); return
        if self.path == "/api/tools/ssl":
            try:self.reply(200,external_tools.ssl_check(str((self.body() or {}).get("host",""))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/checkhost":
            data=self.body() or {}
            try:self.reply(200,external_tools.checkhost(str(data.get("host","")),str(data.get("kind","http"))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/cheburcheck":
            try:self.reply(200,{"url":external_tools.cheburcheck_url(str((self.body() or {}).get("host","")))})
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/preview":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try: self.reply(200, firewall.preview(str(data.get("profile","")),ip,bool(data.get("keep_webui"))))
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/request":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try:
                result=firewall.request_apply(str(data.get("profile","")),ip,bool(data.get("keep_webui"))); audit(telegram_user,"firewall_request",str(data.get("profile","")),"pending",{"ip":ip}); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/confirm":
            try: result=firewall.confirm(str((self.body() or {}).get("token",""))); audit(telegram_user,"firewall_apply","","ok" if result.get("ok") else "failed"); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/keep":
            try: self.reply(200,firewall._bridge({"action":"firewall_keep","token":str((self.body() or {}).get("token",""))}))
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/rollback":
            try: self.reply(200,firewall.rollback()); audit(telegram_user,"firewall_rollback")
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/backups":
            data=self.body() or {}
            try: self.reply(202,start_backup(telegram_user,data.get("source",""),data.get("destination",""),data.get("label","")))
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if re.fullmatch(r"/api/library/[a-z0-9-]+/link", self.path):
            try: self.reply(200,library_issue_link(telegram_user,self.path.split("/")[-2]))
            except ValueError as exc: self.reply(404,{"error":str(exc)})
            return
        if self.path == "/api/runs":
            command = str((self.body() or {}).get("command", ""))
            try:
                self.reply(202, start_run(telegram_user, command, command_result))
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
            return
        if self.path.startswith("/api/commands/"):
            command = self.path.rsplit("/", 1)[1]
            try:
                result = command_result(command)
                audit(telegram_user, "web_command", command, "ok")
                self.reply(200, result)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                audit(telegram_user, "web_command", command, "failed")
                self.reply(500, {"error": f"command failed: {type(error).__name__}"})
            return
        if self.path == "/api/actions/ssh":
            pid = (self.body() or {}).get("pid")
            if not isinstance(pid, int) or pid < 2:
                self.reply(400, {"error": "invalid SSH session"})
                return
            session = next((item for item in load_v3().active_ssh_sessions() if item["pid"] == pid), None)
            if not session:
                self.reply(404, {"error": "SSH session was not found"})
                return
            confirmation_id = create_confirmation(telegram_user, "web_ssh_terminate", session["id"], {"pid": pid})
            audit(telegram_user, "killssh_request", str(pid), "pending")
            self.reply(200, {"confirmation_id": confirmation_id, "expires_in": PENDING_TTL})
            return
        if self.path == "/api/actions/power":
            action = (self.body() or {}).get("action")
            if action not in {"reboot", "poweroff"}:
                self.reply(400, {"error": "invalid power action"})
                return
            confirmation_id = create_confirmation(telegram_user, "web_power", action)
            audit(telegram_user, f"{action}_request", result="pending")
            self.reply(200, {"confirmation_id": confirmation_id, "expires_in": PENDING_TTL})
            return
        if re.fullmatch(r"/api/actions/confirm/\d+", self.path):
            action_id = int(self.path.rsplit("/", 1)[1])
            pending = consume_confirmation(telegram_user, action_id, "web_ssh_terminate")
            if pending:
                try:
                    result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/local/libexec/monitoringbot-ssh-session-helper", "terminate", pending["target"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    ok = result.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
                audit(telegram_user, "killssh", pending["target"], "ok" if ok else "failed")
                self.reply(200, {"ok": ok, "message": "SSH session terminated." if ok else "SSH session was not terminated; it may already be closed."})
                return
            pending = consume_confirmation(telegram_user, action_id, "web_power")
            if pending:
                action = pending["target"]
                try:
                    result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/systemctl", action], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    ok = result.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
                audit(telegram_user, action, "server", "ok" if ok else "failed")
                self.reply(200, {"ok": ok, "message": "Command accepted." if ok else "Privileged command was rejected or failed."})
                return
            self.reply(404, {"error": "confirmation is invalid or has expired"})
            return
        if self.path == "/api/logout":
            session_id = cookie_session_id(self.headers.get("Cookie", ""))
            if session_id is not None:
                with connect() as connection:
                    connection.execute("DELETE FROM pending_actions WHERE id=? AND kind='web_session' AND user_id=?", (session_id, telegram_user))
            audit(telegram_user, "web_logout")
            self.reply(200, {"ok": True}, {"Set-Cookie": "mbs=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"})
            return
        if self.path == "/api/incidents/close-all":
            self.reply(200, {"closed": close_all(telegram_user), "warning": "active alerts can open again while their condition persists"})
            return
        if re.fullmatch(r"/api/incidents/\d+/(ack|close)", self.path):
            _, _, _, incident_id, action = self.path.split("/")
            (ack if action == "ack" else close)(int(incident_id), telegram_user)
            self.reply(200, {"ok": True})
            return
        self.reply(404, {"error": "not found"})

    def log_message(self, *_args):
        pass


def main():
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MONITORINGBOT_WEB_PORT", "8787"))), Handler).serve_forever()


if __name__ == "__main__":
    main()
