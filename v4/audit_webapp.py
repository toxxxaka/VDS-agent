"""Isolated authenticated-audit WebUI entry point.

This module is not used by the normal WebUI unit.  It keeps Telegram initData,
TOTP, session and confirmation checks active while replacing confirmed power
side effects with an audited simulation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import struct
import time
from http.server import ThreadingHTTPServer

from . import webapp as core


def _attempt_table(connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS web_totp_attempts("
        "user_id TEXT PRIMARY KEY,failures INTEGER NOT NULL DEFAULT 0,"
        "locked_until REAL NOT NULL DEFAULT 0,updated_at REAL NOT NULL)"
    )


def _policy() -> tuple[int, int]:
    config = core.cfg()
    return (
        max(1, min(int(config.get("max_failures", 5)), 100)),
        max(1, min(int(config.get("lockout_seconds", 900)), 86400)),
    )


def retry_after(user: str, now: float | None = None) -> int:
    current = time.time() if now is None else now
    with core.connect() as connection:
        _attempt_table(connection)
        row = connection.execute("SELECT locked_until FROM web_totp_attempts WHERE user_id=?", (str(user),)).fetchone()
    if not row:
        return 0
    return max(0, int(float(row["locked_until"]) - current + 0.999))


def record_failure(user: str, now: float | None = None) -> int:
    current = time.time() if now is None else now
    maximum, lockout = _policy()
    with core.connect() as connection:
        _attempt_table(connection)
        row = connection.execute("SELECT failures,locked_until FROM web_totp_attempts WHERE user_id=?", (str(user),)).fetchone()
        if row and float(row["locked_until"]) > current:
            return max(1, int(float(row["locked_until"]) - current + 0.999))
        failures = (int(row["failures"]) if row else 0) + 1
        locked_until = current + lockout if failures >= maximum else 0
        connection.execute(
            "INSERT INTO web_totp_attempts(user_id,failures,locked_until,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at",
            (str(user), 0 if locked_until else failures, locked_until, current),
        )
    return max(0, int(locked_until - current + 0.999))


def clear_failures(user: str) -> None:
    with core.connect() as connection:
        _attempt_table(connection)
        connection.execute("DELETE FROM web_totp_attempts WHERE user_id=?", (str(user),))


def valid_totp_step(secret: str, code: str, now: float | None = None) -> int | None:
    if not re.fullmatch(r"\d{6}", code):
        return None
    current = time.time() if now is None else now
    normalized = secret.replace(" ", "").upper()
    try:
        key = base64.b32decode(normalized + "=" * (-len(normalized) % 8))
    except (ValueError, base64.binascii.Error):
        return None
    for step in range(int(current // 30) - 1, int(current // 30) + 2):
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        candidate = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{candidate:06d}", code):
            return step
    return None


def configured_role(user: str) -> str:
    roles = core.cfg().get("roles", {})
    if isinstance(roles, dict):
        role = roles.get(str(user))
        if role in {"viewer", "operator", "admin"}:
            return role
        if roles:
            return "viewer"
    return "admin"


def _is_admin(session: dict | None) -> bool:
    return bool(session and session.get("recovery_role") == "admin")


class AuditHandler(core.Handler):
    """Normal handler with enforced TOTP throttling and simulated power actions."""

    def _require_admin(self, user: str, session: dict | None) -> bool:
        if _is_admin(session):
            return True
        core.audit(user, "audit_rbac", self.path, "denied", {"required": "admin"})
        self.reply(403, {"error": "admin role is required"})
        return False

    def _totp(self, user: str) -> None:
        locked = retry_after(user)
        if locked:
            core.audit(user, "web_totp", result="rate_limited")
            self.reply(429, {"error": "TOTP attempts temporarily locked"}, {"Retry-After": str(locked)})
            return
        code = str((self.body() or {}).get("code", ""))
        step = valid_totp_step(str(core.cfg().get("totp_secret", "")), code)
        if step is None:
            locked = record_failure(user)
            core.audit(user, "web_totp", result="rate_limited" if locked else "denied")
            if locked:
                self.reply(429, {"error": "TOTP attempts temporarily locked"}, {"Retry-After": str(locked)})
            else:
                self.reply(403, {"error": "invalid TOTP"})
            return
        if not core.consume_initdata(self.headers.get("X-Telegram-InitData", ""), user) or not core.consume_totp_step(user, step):
            core.audit(user, "web_totp", result="denied", details={"reason": "replay"})
            self.reply(403, {"error": "authentication replay rejected"})
            return
        clear_failures(user)
        session_id = core.new_session(user, configured_role(user))
        core.audit(user, "web_totp", result="ok")
        self.reply(200, {"ok": True, "role": configured_role(user)}, {"Set-Cookie": f"mbs={session_id}; HttpOnly; Secure; SameSite=None; Path=/"})

    def do_POST(self):
        user, session_user = self.auth()
        if not user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return
        if self.path == "/api/totp":
            self._totp(user)
            return
        session = core.web_session(self.headers.get("Cookie", ""))
        if not session_user or session_user != user:
            self.reply(403, {"error": "TOTP required"})
            return
        admin_paths = {
            "/api/actions/ssh", "/api/actions/power", "/api/firewall/request",
            "/api/firewall/confirm", "/api/firewall/keep", "/api/firewall/rollback",
            "/api/backups",
        }
        if self.path in admin_paths or re.fullmatch(r"/api/actions/confirm/\d+", self.path):
            if not self._require_admin(user, session):
                return
        if re.fullmatch(r"/api/actions/confirm/\d+", self.path):
            if not core.web_recent_totp(self.headers.get("Cookie", ""), user):
                core.audit(user, "web_step_up", result="denied", details={"reason": "stale_totp"})
                self.reply(403, {"error": "fresh TOTP required; sign in again with a new code"})
                return
            action_id = int(self.path.rsplit("/", 1)[1])
            with core.connect() as connection:
                row = connection.execute("SELECT kind FROM pending_actions WHERE id=? AND user_id=?", (action_id, user)).fetchone()
            if row and row["kind"] == "web_power":
                pending = core.consume_confirmation(user, action_id, "web_power")
                action = pending["target"]
                core.audit(user, "audit_dummy_power", action, "simulated", {"mode": "audit-dummy"})
                self.reply(200, {"ok": True, "simulated": True, "message": "Audit dummy: confirmation accepted; no host action was executed."})
                return
        super().do_POST()


def main():
    core.recover_pending(core.command_result)
    port = int(os.environ.get("MONITORINGBOT_WEB_PORT", "8788"))
    ThreadingHTTPServer(("127.0.0.1", port), AuditHandler).serve_forever()


if __name__ == "__main__":
    main()
