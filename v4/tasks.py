"""Durable, allow-listed task execution for bounded diagnostic work.

Task metadata and every lifecycle transition are committed before the next step.
Only idempotent read-only diagnostics are eligible for automatic retry.  A
controlled action must use its own confirmation flow and is never replayed.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from .storage import audit, connect, rows


@dataclass(frozen=True)
class TaskSpec:
    command: str
    title: str
    description: str
    category: str
    timeout_seconds: int
    retryable: bool = True
    max_attempts: int = 2


TASKS: dict[str, TaskSpec] = {
    "status": TaskSpec("status", "System status", "Complete status summary", "Monitoring", 20),
    "daily": TaskSpec("daily", "Daily report", "Extended daily report", "Monitoring", 30),
    "ping": TaskSpec("ping", "Server availability", "ICMP with a configured TCP fallback", "Monitoring", 15),
    "cpu": TaskSpec("cpu", "CPU", "CPU usage and temperature", "Resources", 10),
    "ram": TaskSpec("ram", "Memory", "RAM and swap", "Resources", 10),
    "disk": TaskSpec("disk", "Disk", "Disk capacity and SMART summary", "Resources", 10),
    "load": TaskSpec("load", "Load average", "One, five and fifteen minute load", "Resources", 10),
    "uptime": TaskSpec("uptime", "Uptime", "Server uptime", "Resources", 10),
    "sessions": TaskSpec("sessions", "SSH sessions", "Active authenticated SSH sessions", "Security", 10),
    "sshlogins": TaskSpec("sshlogins", "SSH logins", "Recent external successful SSH logins", "Security", 10),
}


def _event(connection, run_id: str, event: str, details=None, now=None) -> None:
    connection.execute(
        "INSERT INTO task_events(run_id,time,event,details) VALUES(?,?,?,?)",
        (run_id, time.time() if now is None else now, event, json.dumps(details or {}, sort_keys=True)),
    )


def serialize_run(row: dict) -> dict:
    row = dict(row)
    for key in ("details",):
        try:
            row[key] = json.loads(row.get(key) or "{}")
        except json.JSONDecodeError:
            row[key] = {}
    return row


def list_runs(limit: int = 30) -> list[dict]:
    return [serialize_run(row) for row in rows("SELECT * FROM command_runs ORDER BY started_at DESC LIMIT ?", (max(1, min(int(limit), 100)),))]


def get_run(run_id: str) -> dict | None:
    result = rows("SELECT * FROM command_runs WHERE id=?", (run_id,))
    return serialize_run(result[0]) if result else None


def task_events(run_id: str, limit: int = 100) -> list[dict]:
    return rows("SELECT * FROM task_events WHERE run_id=? ORDER BY id DESC LIMIT ?", (run_id, max(1, min(int(limit), 100))))


def cancel_run(user_id: str, run_id: str) -> dict | None:
    now = time.time()
    with connect() as connection:
        row = connection.execute("SELECT status,user_id FROM command_runs WHERE id=?", (run_id,)).fetchone()
        if row is None or str(row["user_id"]) != str(user_id):
            return None
        if row["status"] in {"completed", "failed", "timeout", "cancelled"}:
            return serialize_run(dict(connection.execute("SELECT * FROM command_runs WHERE id=?", (run_id,)).fetchone()))
        if row["status"] == "queued":
            connection.execute("UPDATE command_runs SET status='cancelled',finished_at=?,updated_at=? WHERE id=?", (now, now, run_id))
            _event(connection, run_id, "cancelled", {"before_start": True}, now)
        else:
            connection.execute("UPDATE command_runs SET cancel_requested_at=?,updated_at=? WHERE id=?", (now, now, run_id))
            _event(connection, run_id, "cancel_requested", {}, now)
    audit(user_id, "command_run_cancel", run_id)
    return get_run(run_id)


def start_run(user_id: str, command: str, handler: Callable[[str], dict], idempotency_key: str | None = None) -> dict:
    spec = TASKS.get(command)
    if not spec:
        raise ValueError("Unsupported command")
    return start_custom_run(user_id, spec, handler, idempotency_key=idempotency_key)


def start_custom_run(user_id: str, spec: TaskSpec, handler: Callable[[str], dict], details=None, idempotency_key: str | None = None) -> dict:
    if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128):
        raise ValueError("invalid idempotency key")
    now = time.time()
    meta = {"category": spec.category, "timeout_seconds": spec.timeout_seconds, "retryable": spec.retryable, **(details or {})}
    with connect() as connection:
        if idempotency_key:
            existing = connection.execute(
                "SELECT * FROM command_runs WHERE user_id=? AND command=? AND idempotency_key=?",
                (str(user_id), spec.command, idempotency_key),
            ).fetchone()
            if existing is not None:
                return serialize_run(dict(existing))
        run_id = str(uuid.uuid4())
        attempts = max(1, min(int(spec.max_attempts), 3)) if spec.retryable else 1
        connection.execute(
            "INSERT INTO command_runs(id,command,title,status,user_id,started_at,details,idempotency_key,attempts,max_attempts,next_attempt_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, spec.command, spec.title, "queued", str(user_id), now, json.dumps(meta, sort_keys=True), idempotency_key, 0, attempts, now, now),
        )
        _event(connection, run_id, "queued", {"max_attempts": attempts}, now)
    audit(user_id, "command_run", spec.command, "queued", {"run_id": run_id})
    _spawn(run_id, str(user_id), spec.command, handler)
    return get_run(run_id)


def _spawn(run_id: str, user_id: str, command: str, handler: Callable[[str], dict]) -> None:
    threading.Thread(target=_execute, args=(run_id, user_id, command, handler), daemon=True, name=f"monitorbot-task-{command}").start()


def _cancelled(run_id: str) -> bool:
    record = get_run(run_id)
    return not record or record["status"] == "cancelled" or record.get("cancel_requested_at") is not None


def _execute(run_id: str, user_id: str, command: str, handler: Callable[[str], dict]) -> None:
    started = time.monotonic()
    now = time.time()
    with connect() as connection:
        row = connection.execute("SELECT status,attempts,max_attempts,cancel_requested_at FROM command_runs WHERE id=?", (run_id,)).fetchone()
        if row is None or row["status"] != "queued" or row["cancel_requested_at"] is not None:
            return
        attempt = int(row["attempts"]) + 1
        connection.execute("UPDATE command_runs SET status='running',attempts=?,updated_at=? WHERE id=?", (attempt, now, run_id))
        _event(connection, run_id, "started", {"attempt": attempt}, now)
    if _cancelled(run_id):
        return
    try:
        result = handler(command)
        stdout = str(result.get("text", ""))
        details = {key: value for key, value in result.items() if key not in {"text", "title", "stderr", "exit_code"}}
        status = "completed" if int(result.get("exit_code", 0)) == 0 else "failed"
        stderr, exit_code = str(result.get("stderr", "")), int(result.get("exit_code", 0))
    except Exception as exc:  # The WebUI worker must survive every task failure.
        stdout, details, status, stderr, exit_code = "", {}, "failed", f"{type(exc).__name__}: {exc}", 1
    duration_ms = int((time.monotonic() - started) * 1000)
    now = time.time()
    with connect() as connection:
        row = connection.execute("SELECT attempts,max_attempts,cancel_requested_at,details FROM command_runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            return
        if row["cancel_requested_at"] is not None:
            status = "cancelled"
        retryable = bool(json.loads(row["details"] or "{}").get("retryable"))
        should_retry = status == "failed" and retryable and int(row["attempts"]) < int(row["max_attempts"])
        if should_retry:
            delay = min(30, 2 ** int(row["attempts"]))
            connection.execute("UPDATE command_runs SET status='queued',next_attempt_at=?,stderr=?,updated_at=? WHERE id=?", (now + delay, stderr[:12000], now, run_id))
            _event(connection, run_id, "retry_scheduled", {"delay_seconds": delay}, now)
        else:
            connection.execute(
                "UPDATE command_runs SET status=?,finished_at=?,duration_ms=?,exit_code=?,stdout=?,stderr=?,details=?,updated_at=? WHERE id=?",
                (status, now, duration_ms, exit_code, stdout[:120000], stderr[:12000], json.dumps(details, sort_keys=True), now, run_id),
            )
            _event(connection, run_id, status, {"duration_ms": duration_ms, "exit_code": exit_code}, now)
    audit(user_id, "command_run", command, "retry" if should_retry else status, {"run_id": run_id, "duration_ms": duration_ms})
    if should_retry:
        timer = threading.Timer(delay, _spawn, args=(run_id, user_id, command, handler))
        timer.daemon = True
        timer.start()


def recover_pending(handler: Callable[[str], dict], limit: int = 20) -> int:
    """Resume queued idempotent diagnostics after a service restart.

    Running tasks are marked failed rather than replayed because their side
    effects cannot be known after an abrupt process death.
    """
    now = time.time()
    with connect() as connection:
        interrupted = connection.execute("SELECT id FROM command_runs WHERE status='running'").fetchall()
        for row in interrupted:
            connection.execute("UPDATE command_runs SET status='failed',finished_at=?,stderr='worker restarted before completion',updated_at=? WHERE id=?", (now, now, row["id"]))
            _event(connection, row["id"], "interrupted", {}, now)
        queued = connection.execute("SELECT id,user_id,command,details FROM command_runs WHERE status='queued' AND COALESCE(next_attempt_at,0)<=? ORDER BY started_at LIMIT ?", (now, max(1, min(limit, 100)))).fetchall()
        runnable = []
        for row in queued:
            try:
                retryable = bool(json.loads(row["details"] or "{}").get("retryable"))
            except json.JSONDecodeError:
                retryable = False
            if retryable:
                runnable.append(row)
            else:
                connection.execute("UPDATE command_runs SET status='failed',finished_at=?,stderr='worker restarted before task began',updated_at=? WHERE id=?", (now, now, row["id"]))
                _event(connection, row["id"], "interrupted", {"replayed": False}, now)
    for row in runnable:
        _spawn(row["id"], str(row["user_id"]), row["command"], handler)
    return len(runnable)
