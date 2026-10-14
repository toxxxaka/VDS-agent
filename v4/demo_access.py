"""Short-lived credential workflow for the public VDS Agent demo.

The demo database is intentionally separate from the normal monitoring state.
Only a hash of a browser request token is stored.  Credentials are generated
by the owner through an authenticated Telegram callback and are available to
the requesting browser once, for at most 24 hours.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import string
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import storage

DEMO_DB = Path(os.environ.get("MONITORINGBOT_DEMO_DB", "/var/lib/monitoringbot-demo/demo.db"))
TTL_SECONDS = 24 * 60 * 60
REQUEST_COOLDOWN_SECONDS = 15 * 60
SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_access_requests(
 id INTEGER PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE, source_digest TEXT NOT NULL,
 requested_at REAL NOT NULL, status TEXT NOT NULL CHECK(status IN ('waiting','generated','shared','deleted','expired')),
 username TEXT, password_salt TEXT, password_digest TEXT, revealed_password TEXT,
 expires_at REAL, revealed_at REAL, delivered_at REAL
);
CREATE INDEX IF NOT EXISTS ix_demo_access_source_time ON demo_access_requests(source_digest,requested_at DESC);
CREATE INDEX IF NOT EXISTS ix_demo_access_token ON demo_access_requests(token_digest);
"""


def _connect(path: Path = DEMO_DB) -> sqlite3.Connection:
    connection = storage.connect(path)
    connection.executescript(SCHEMA)
    return connection


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _letters(length: int) -> str:
    alphabet = string.ascii_letters
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _password_record(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("ascii"), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def _password_matches(password: str, salt: str, digest: str) -> bool:
    try:
        calculated = hashlib.scrypt(password.encode("ascii"), salt=base64.b64decode(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(calculated, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def request_access(source_ip: str, now: float | None = None) -> dict:
    """Create one browser-bound request, rate-limited by a non-reversible IP hash."""
    current = time.time() if now is None else now
    source = _digest(source_ip or "unknown")
    with _connect() as connection:
        recent = connection.execute(
            "SELECT requested_at FROM demo_access_requests WHERE source_digest=? ORDER BY id DESC LIMIT 1", (source,)
        ).fetchone()
        if recent and current - float(recent["requested_at"]) < REQUEST_COOLDOWN_SECONDS:
            retry_after = int(REQUEST_COOLDOWN_SECONDS - (current - float(recent["requested_at"])))
            return {"ok": False, "retry_after": max(1, retry_after)}
        token = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO demo_access_requests(token_digest,source_digest,requested_at,status) VALUES(?,?,?,?)",
            (_digest(token), source, current, "waiting"),
        )
        request_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    return {"ok": True, "token": token, "id": request_id, "label": request_label(request_id, current)}


def request_label(request_id: int, created_at: float) -> str:
    return f"{request_id}-{datetime.fromtimestamp(created_at, timezone.utc):%d-%m}"


def _row_by_token(token: str) -> dict | None:
    if not token:
        return None
    with _connect() as connection:
        row = connection.execute("SELECT * FROM demo_access_requests WHERE token_digest=?", (_digest(token),)).fetchone()
    return dict(row) if row else None


def status(token: str, reveal: bool = False, now: float | None = None) -> dict:
    current = time.time() if now is None else now
    row = _row_by_token(token)
    if not row:
        return {"status": "missing"}
    if row.get("expires_at") and current >= float(row["expires_at"]) and row["status"] not in {"deleted", "expired"}:
        with _connect() as connection:
            connection.execute("UPDATE demo_access_requests SET status='expired',revealed_password=NULL WHERE id=?", (row["id"],))
        row["status"] = "expired"
    result = {"status": row["status"], "id": row["id"], "expires_at": row.get("expires_at")}
    if reveal and row["status"] == "shared" and row.get("revealed_password") and not row.get("delivered_at"):
        result.update({"username": row["username"], "password": row["revealed_password"]})
        with _connect() as connection:
            connection.execute("UPDATE demo_access_requests SET delivered_at=?,revealed_password=NULL WHERE id=?", (current, row["id"]))
    return result


def active_request(request_id: int, now: float | None = None) -> dict | None:
    """Return a non-secret active account record for an authenticated session."""
    current = time.time() if now is None else now
    with _connect() as connection:
        row = connection.execute("SELECT id,status,username,expires_at FROM demo_access_requests WHERE id=?", (request_id,)).fetchone()
    if not row or row["status"] != "shared" or float(row["expires_at"] or 0) <= current:
        return None
    return dict(row)


def generate(request_id: int, now: float | None = None) -> dict | None:
    current = time.time() if now is None else now
    username = _letters(secrets.randbelow(4) + 6)
    password = _letters(secrets.randbelow(7) + 9)
    salt, digest = _password_record(password)
    expires_at = current + TTL_SECONDS
    with _connect() as connection:
        row = connection.execute("SELECT status FROM demo_access_requests WHERE id=?", (request_id,)).fetchone()
        if not row or row["status"] != "waiting":
            return None
        connection.execute(
            "UPDATE demo_access_requests SET status='generated',username=?,password_salt=?,password_digest=?,revealed_password=?,expires_at=? WHERE id=?",
            (username, salt, digest, password, expires_at, request_id),
        )
    return {"id": request_id, "username": username, "password": password, "expires_at": expires_at}


def share(request_id: int, now: float | None = None) -> dict | None:
    current = time.time() if now is None else now
    with _connect() as connection:
        row = connection.execute("SELECT * FROM demo_access_requests WHERE id=?", (request_id,)).fetchone()
        if not row or row["status"] != "generated" or float(row["expires_at"] or 0) <= current:
            return None
        connection.execute("UPDATE demo_access_requests SET status='shared',revealed_at=? WHERE id=?", (current, request_id))
    return {"id": request_id, "username": row["username"], "password": row["revealed_password"], "expires_at": row["expires_at"]}


def delete(request_id: int) -> bool:
    with _connect() as connection:
        result = connection.execute(
            "UPDATE demo_access_requests SET status='deleted',revealed_password=NULL,password_digest=NULL,password_salt=NULL WHERE id=? AND status NOT IN ('deleted','expired')",
            (request_id,),
        )
    return bool(result.rowcount)


def verify(username: str, password: str, now: float | None = None) -> dict | None:
    current = time.time() if now is None else now
    if not username.isascii() or not password.isascii() or not username.isalpha() or not password.isalpha():
        return None
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM demo_access_requests WHERE username=? AND status='shared' AND expires_at>?", (username, current)
        ).fetchone()
    if not row or not _password_matches(password, row["password_salt"], row["password_digest"]):
        return None
    return {"id": row["id"], "username": row["username"], "expires_at": row["expires_at"]}


def notify_owner(label: str) -> bool:
    token, chat_id = os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False
    payload = json.dumps({
        "chat_id": chat_id,
        "text": f"Demo access request <b>{label}</b>\nGenerate temporary credentials?",
        "parse_mode": "HTML",
        "reply_markup": {"inline_keyboard": [[{"text": "Generate credentials", "callback_data": f"demo:generate:{label.split('-', 1)[0]}"}]]},
    }).encode("utf-8")
    request = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return 200 <= response.status < 300
    except OSError:
        return False


def owner_action(data: str) -> tuple[str, dict | None] | None:
    """Return a Telegram message and optional inline keyboard for owner callbacks."""
    try:
        action, raw_id = data.rsplit(":", 1)
        request_id = int(raw_id)
    except (ValueError, AttributeError):
        return None
    if action == "demo:generate":
        record = generate(request_id)
        if not record:
            return ("Demo request is no longer waiting.", None)
        expires = datetime.fromtimestamp(record["expires_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        buttons = {"inline_keyboard": [[
            {"text": "Share", "callback_data": f"demo:share:{request_id}"},
            {"text": "Delete now", "callback_data": f"demo:delete:{request_id}"},
        ]]}
        return (f"Demo credentials generated\nLogin: <code>{record['username']}</code>\nPassword: <code>{record['password']}</code>\nExpires: {expires}", buttons)
    if action == "demo:share":
        record = share(request_id)
        return (("Credentials shared with the requester for one display." if record else "Demo request cannot be shared."), None)
    if action == "demo:delete":
        return (("Demo credentials deleted." if delete(request_id) else "Demo request was already removed."), None)
    return None
