"""Public demonstration WebUI with short-lived owner-issued credentials.

This server never accepts TOTP or Telegram initData and explicitly denies every
host-changing endpoint.  It is intended to run beside, never in place of, the
normal authenticated WebUI so nginx can be switched back in one change.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import demo_access
from . import webapp as core

UI_DIR = Path(__file__).with_name("demo_ui")
HTML = (UI_DIR / "index.html").read_text(encoding="utf-8")
ASSETS = {"app.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8", "demo-login.js": "application/javascript; charset=utf-8", "favicon.svg": "image/svg+xml"}
DENIED_PREFIXES = ("/api/actions/power", "/api/firewall", "/api/backups")


def _cookie(header: str, name: str) -> str:
    for item in header.split(";"):
        key, _, value = item.strip().partition("=")
        if key == name:
            return value
    return ""


def _session_token() -> str:
    return secrets.token_urlsafe(32)


class DemoHandler(core.Handler):
    def auth(self):
        token = _cookie(self.headers.get("Cookie", ""), "vds_demo")
        with core.connect() as connection:
            row = connection.execute("SELECT target,expires_at FROM pending_actions WHERE kind='demo_session' AND user_id=?", (token,)).fetchone()
        if not row or float(row["expires_at"]) <= time.time():
            return None, None
        account = demo_access.active_request(int(row["target"]))
        if not account:
            return None, None
        principal = f"demo:{account['id']}"
        return principal, principal

    def _html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def _asset(self, name: str):
        content_type = ASSETS.get(name)
        path = UI_DIR / name
        if not content_type or not path.is_file():
            self.reply(404, {"error": "asset not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._html(); return
        if path.startswith("/static/"):
            self._asset(path.rsplit("/", 1)[1]); return
        if path == "/api/demo-access/status":
            request_token = _cookie(self.headers.get("Cookie", ""), "vds_demo_request")
            self.reply(200, demo_access.status(request_token, reveal=True)); return
        if path == "/api/session":
            user, _ = self.auth()
            self.reply(200, {"totp": bool(user), "demo": True}); return
        if path.startswith(DENIED_PREFIXES):
            self.reply(404, {"error": "not available on the public demo"}); return
        user, session_user = self.auth()
        if not user:
            self.reply(401, {"error": "demo login required"}); return
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/demo-access/request":
            source_ip = self.headers.get("X-Real-IP", self.client_address[0])
            result = demo_access.request_access(source_ip)
            if not result["ok"]:
                self.reply(429, {"error": "A request was already sent from this network. Try again later.", "retry_after": result["retry_after"]}, {"Retry-After": str(result["retry_after"])}); return
            delivered = demo_access.notify_owner(result["label"])
            headers = {"Set-Cookie": f"vds_demo_request={result['token']}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"}
            self.reply(202, {"ok": True, "request": result["label"], "owner_notified": delivered}, headers); return
        if path == "/api/demo-access/login":
            data = self.body() or {}
            username, password = str(data.get("username", "")), str(data.get("password", ""))
            if not re.fullmatch(r"[A-Za-z]{6,9}", username) or not re.fullmatch(r"[A-Za-z]{9,15}", password):
                self.reply(400, {"error": "Login and password contain Latin letters only."}); return
            account = demo_access.verify(username, password)
            if not account:
                self.reply(403, {"error": "Invalid or expired demo credentials."}); return
            token = _session_token()
            # A separate session table is unnecessary: the signed random token is
            # bound to the account by a server-side pending row in normal storage.
            with core.connect() as connection:
                connection.execute("INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)", ("demo_session", token, str(account["id"]), account["expires_at"], "{}"))
            self.reply(200, {"ok": True, "expires_at": account["expires_at"]}, {"Set-Cookie": f"vds_demo={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"}); return
        if path == "/api/logout":
            token = _cookie(self.headers.get("Cookie", ""), "vds_demo")
            with core.connect() as connection:
                connection.execute("DELETE FROM pending_actions WHERE kind='demo_session' AND user_id=?", (token,))
            self.reply(200, {"ok": True}, {"Set-Cookie": "vds_demo=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"}); return
        if path.startswith(DENIED_PREFIXES) or path == "/api/totp":
            self.reply(404, {"error": "not available on the public demo"}); return
        user, session_user = self.auth()
        if not user:
            self.reply(401, {"error": "demo login required"}); return
        super().do_POST()


def main():
    port = int(os.environ.get("MONITORINGBOT_WEB_PORT", "8788"))
    ThreadingHTTPServer(("127.0.0.1", port), DemoHandler).serve_forever()


if __name__ == "__main__":
    main()
