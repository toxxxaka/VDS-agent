"""Persistent, allow-listed asynchronous read-only task runner."""
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


def serialize_run(row: dict) -> dict:
    row = dict(row)
    try:
        row["details"] = json.loads(row.get("details") or "{}")
    except json.JSONDecodeError:
        row["details"] = {}
    return row


def list_runs(limit: int = 30) -> list[dict]:
    return [serialize_run(row) for row in rows("SELECT * FROM command_runs ORDER BY started_at DESC LIMIT ?", (limit,))]


def get_run(run_id: str) -> dict | None:
    result = rows("SELECT * FROM command_runs WHERE id=?", (run_id,))
    return serialize_run(result[0]) if result else None


def start_run(user_id: str, command: str, handler: Callable[[str], dict]) -> dict:
    spec = TASKS.get(command)
    if not spec:
        raise ValueError("Unsupported command")
    return start_custom_run(user_id, spec, handler)


def start_custom_run(user_id: str, spec: TaskSpec, handler: Callable[[str], dict], details=None) -> dict:
    run_id = str(uuid.uuid4())
    now = time.time()
    meta = {"category": spec.category, "timeout_seconds": spec.timeout_seconds, **(details or {})}
    with connect() as connection:
        connection.execute("INSERT INTO command_runs(id,command,title,status,user_id,started_at,details) VALUES(?,?,?,?,?,?,?)", (run_id, spec.command, spec.title, "queued", str(user_id), now, json.dumps(meta)))
    audit(user_id, "command_run", spec.command, "queued", {"run_id": run_id})
    threading.Thread(target=_execute, args=(run_id, str(user_id), spec.command, handler), daemon=True, name=f"monitorbot-task-{spec.command}").start()
    return get_run(run_id)


def _execute(run_id: str, user_id: str, command: str, handler: Callable[[str], dict]) -> None:
    started = time.monotonic()
    with connect() as connection:
        connection.execute("UPDATE command_runs SET status='running' WHERE id=? AND status='queued'", (run_id,))
    try:
        result = handler(command)
        stdout = str(result.get("text", ""))
        details = {key: value for key, value in result.items() if key not in {"text", "title", "stderr", "exit_code"}}
        status, stderr, exit_code = ("completed" if int(result.get("exit_code", 0)) == 0 else "failed"), str(result.get("stderr", "")), int(result.get("exit_code", 0))
    except Exception as exc:  # The task must never terminate the WebUI worker.
        stdout, details = "", {}
        status, stderr, exit_code = "failed", f"{type(exc).__name__}: {exc}", 1
    duration_ms = int((time.monotonic() - started) * 1000)
    with connect() as connection:
        connection.execute(
            "UPDATE command_runs SET status=?,finished_at=?,duration_ms=?,exit_code=?,stdout=?,stderr=?,details=? WHERE id=?",
            (status, time.time(), duration_ms, exit_code, stdout[:120000], stderr[:12000], json.dumps(details), run_id),
        )
    audit(user_id, "command_run", command, status, {"run_id": run_id, "duration_ms": duration_ms})
