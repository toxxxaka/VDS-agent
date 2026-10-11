"""SQLite notification outbox, intentionally transport-agnostic and opt-in."""
from __future__ import annotations

import json
import time
import uuid
from typing import Callable

from .storage import connect, rows

MAX_ATTEMPTS = 8


def enqueue(channel: str, payload: dict, idempotency_key: str) -> dict:
    if channel not in {"telegram", "webhook", "email", "ntfy", "matrix"}:
        raise ValueError("unsupported notification channel")
    if not isinstance(payload, dict) or not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
        raise ValueError("invalid notification payload")
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > 128_000:
        raise ValueError("notification payload is too large")
    now = time.time()
    with connect() as connection:
        existing = connection.execute("SELECT * FROM notification_outbox WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if existing is not None:
            return dict(existing)
        identifier = str(uuid.uuid4())
        connection.execute("INSERT INTO notification_outbox(id,channel,payload,status,idempotency_key,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (identifier, channel, encoded, "queued", idempotency_key, 0, now, now, now))
        return dict(connection.execute("SELECT * FROM notification_outbox WHERE id=?", (identifier,)).fetchone())


def claim_due(now: float | None = None) -> dict | None:
    now = time.time() if now is None else now
    with connect() as connection:
        row = connection.execute("SELECT * FROM notification_outbox WHERE status='queued' AND next_attempt_at<=? ORDER BY created_at LIMIT 1", (now,)).fetchone()
        if row is None:
            return None
        connection.execute("UPDATE notification_outbox SET status='sending',updated_at=? WHERE id=? AND status='queued'", (now, row["id"]))
        claimed = connection.execute("SELECT * FROM notification_outbox WHERE id=?", (row["id"],)).fetchone()
        return dict(claimed) if claimed and claimed["status"] == "sending" else None


def delivered(identifier: str, now: float | None = None) -> None:
    with connect() as connection:
        connection.execute("UPDATE notification_outbox SET status='delivered',updated_at=?,last_error='' WHERE id=? AND status='sending'", (time.time() if now is None else now, identifier))


def failed(identifier: str, error: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    with connect() as connection:
        row = connection.execute("SELECT attempts FROM notification_outbox WHERE id=? AND status='sending'", (identifier,)).fetchone()
        if row is None:
            return
        attempts = int(row["attempts"]) + 1
        status = "failed" if attempts >= MAX_ATTEMPTS else "queued"
        delay = min(3600, 2 ** attempts)
        connection.execute("UPDATE notification_outbox SET status=?,attempts=?,next_attempt_at=?,updated_at=?,last_error=? WHERE id=?", (status, attempts, now + delay, now, str(error)[:1000], identifier))


def dispatch_one(deliver: Callable[[str, dict], bool], now: float | None = None) -> bool:
    item = claim_due(now)
    if item is None:
        return False
    try:
        payload = json.loads(item["payload"])
        if not deliver(item["channel"], payload):
            raise RuntimeError("transport rejected notification")
    except Exception as error:
        failed(item["id"], type(error).__name__, now)
        return True
    delivered(item["id"], now)
    return True


def pending(limit: int = 50) -> list[dict]:
    return rows("SELECT * FROM notification_outbox WHERE status IN ('queued','sending','failed') ORDER BY created_at DESC LIMIT ?", (max(1, min(int(limit), 100)),))
