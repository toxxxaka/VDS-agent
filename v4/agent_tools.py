"""Bounded diagnostics and controlled actions shared by MCP and Telegram AI.

No function accepts a shell command.  Arguments are validated before fixed argv
subprocess calls, output is capped and potentially secret-looking values are redacted.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil

from . import external_tools
from .metrics import latest as metric_latest, query as metric_query
from .self_monitoring import report as self_monitoring_report
from .snapshots import overview
from .storage import audit, connect, rows

MAX_OUTPUT = 12_000
MAX_LOG_LINES = 100
PENDING_TTL = 90
UNIT_RE = re.compile(r"[A-Za-z0-9@_.-]{1,120}\.service")
LOG_UNITS = {"monitoringbot.service", "monitorbot-web.service", "monitorbot-health.service", "monitorbot-oom.service", "monitorbot-snapshot.service", "nginx.service", "ssh.service", "docker.service"}
DIAGNOSTIC_HELPER = Path("/usr/local/libexec/monitoringbot-diagnostic-helper")
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
SECRET_RE = re.compile(r"(?i)(?:authorization|bearer|token|password|secret|api[_-]?key)\\s*[:=]\\s*[^\\s,;]+")


class ToolError(ValueError):
    """A safe, user-displayable tool error."""


def _redact(value: str) -> str:
    return SECRET_RE.sub("[redacted]", value)


def _run(argv: list[str], timeout: int = 8, limit: int = MAX_OUTPUT) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "command timed out"}
    except OSError as error:
        return {"ok": False, "error": f"command unavailable: {type(error).__name__}"}
    text = _redact(result.stdout[-limit:])
    return {"ok": result.returncode == 0, "exit_code": result.returncode, "output": text}


def _unit(value: Any) -> str:
    if not isinstance(value, str) or not UNIT_RE.fullmatch(value):
        raise ToolError("invalid systemd unit")
    return value


def _host(value: Any) -> str:
    if not isinstance(value, str):
        raise ToolError("host is required")
    host = value.strip().rstrip(".")
    if not HOST_RE.fullmatch(host) or ".." in host:
        raise ToolError("invalid host")
    return host


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ToolError("invalid TCP port") from error
    if not 1 <= port <= 65535:
        raise ToolError("invalid TCP port")
    return port


def server_status(_: dict[str, Any] | None = None) -> dict[str, Any]:
    """Current local CPU, memory, disks, network and uptime overview."""
    return overview()


def diagnose_load(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect compact CPU, RAM, I/O and top process evidence."""
    limit = min(max(int((arguments or {}).get("limit", 10)), 1), 25)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    io = psutil.disk_io_counters()
    processes = []
    for process in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
        try:
            info = process.info
            processes.append({
                "pid": info["pid"], "name": info.get("name") or "?", "user": info.get("username") or "?",
                "cpu_percent": round(float(info.get("cpu_percent") or 0), 1),
                "memory_percent": round(float(info.get("memory_percent") or 0), 1),
                "status": info.get("status") or "?",
            })
        except (psutil.Error, OSError):
            continue
    processes.sort(key=lambda item: (item["cpu_percent"], item["memory_percent"]), reverse=True)
    return {
        "load_average": dict(zip(("1m", "5m", "15m"), (round(value, 2) for value in os.getloadavg()))),
        "cpu_percent": round(psutil.cpu_percent(interval=1.0), 1),
        "cpu_count": psutil.cpu_count() or 1,
        "memory": {"used": memory.used, "available": memory.available, "percent": memory.percent, "swap_percent": swap.percent},
        "disk_io": {"read_bytes": io.read_bytes if io else 0, "write_bytes": io.write_bytes if io else 0},
        "top_processes": processes[:limit],
    }


def process_inspect(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return selected process metadata, sorted by CPU or memory."""
    arguments = arguments or {}
    limit = min(max(int(arguments.get("limit", 15)), 1), 50)
    sort = arguments.get("sort", "cpu")
    if sort not in {"cpu", "memory"}:
        raise ToolError("sort must be cpu or memory")
    requested_pid = arguments.get("pid")
    if requested_pid is not None:
        try:
            requested_pid = int(requested_pid)
        except (TypeError, ValueError) as error:
            raise ToolError("invalid process id") from error
        if requested_pid < 1:
            raise ToolError("invalid process id")
    items = []
    iterator = [psutil.Process(requested_pid)] if requested_pid else psutil.process_iter()
    for process in iterator:
        try:
            with process.oneshot():
                items.append({
                    "pid": process.pid, "name": process.name(), "user": process.username(),
                    "status": process.status(), "cpu_percent": round(process.cpu_percent(interval=None), 1),
                    "memory_percent": round(process.memory_percent(), 1), "threads": process.num_threads(),
                    "created_at": process.create_time(),
                })
        except (psutil.Error, OSError):
            continue
    field = "cpu_percent" if sort == "cpu" else "memory_percent"
    items.sort(key=lambda item: item[field], reverse=True)
    return {"sort": sort, "processes": items[:limit]}


def service_status(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read bounded state for explicitly named systemd service units."""
    arguments = arguments or {}
    units = arguments.get("units") or [
        "monitoringbot.service", "monitorbot-web.service", "monitorbot-health.service", "nginx.service", "ssh.service",
    ]
    if not isinstance(units, list) or not 1 <= len(units) <= 12:
        raise ToolError("provide between one and twelve service units")
    result = []
    for raw in units:
        unit = _unit(raw)
        state = _run(["/usr/bin/systemctl", "is-active", unit], timeout=4)
        enabled = _run(["/usr/bin/systemctl", "is-enabled", unit], timeout=4)
        result.append({"unit": unit, "active": state.get("output", "unknown").strip(), "enabled": enabled.get("output", "unknown").strip()})
    return {"services": result}


def service_logs(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read recent, redacted journal entries of one explicit service only."""
    arguments = arguments or {}
    unit = _unit(arguments.get("unit", "monitoringbot.service"))
    lines = min(max(int(arguments.get("lines", 40)), 1), MAX_LOG_LINES)
    minutes = min(max(int(arguments.get("minutes", 60)), 1), 24 * 60)
    if unit not in LOG_UNITS:
        raise ToolError("journal access is limited to VDS-Agent and core service units")
    if DIAGNOSTIC_HELPER.is_file():
        result = _run(["/usr/bin/sudo", "-n", str(DIAGNOSTIC_HELPER), "journal", unit, str(lines), str(minutes)], timeout=12)
    else:
        result = _run([
            "/usr/bin/journalctl", "--no-pager", "--output=short-iso", "--unit", unit,
            "--since", f"{minutes} minutes ago", "--lines", str(lines),
        ], timeout=10)
    return {"unit": unit, "minutes": minutes, "available": result["ok"], "log": result.get("output", result.get("error", ""))}


def metrics_query(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Current telemetry plus bounded history for an allowed range."""
    period = (arguments or {}).get("range", "1h")
    if period not in {"1h", "6h", "24h", "7d", "30d"}:
        raise ToolError("unsupported metric range")
    samples = metric_query(period)
    return {"range": period, "latest": metric_latest(), "samples": samples}


def incidents_query(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read active or historical incidents without exposing database internals."""
    status = (arguments or {}).get("status", "active")
    if status not in {"active", "closed", "all"}:
        raise ToolError("status must be active, closed or all")
    where = "status='active'" if status == "active" else "status!='active'" if status == "closed" else "1=1"
    return {"status": status, "incidents": rows(f"SELECT id,type,severity,status,started_at,last_seen_at,recovered_at,closed_at,peak,threshold FROM incidents WHERE {where} ORDER BY id DESC LIMIT 50")}


def _public_addresses(host: str) -> list[str]:
    try:
        values = {row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ToolError("DNS lookup failed") from error
    public = []
    for value in values:
        address = ipaddress.ip_address(value)
        if address.is_global:
            public.append(value)
    if not public:
        raise ToolError("host must resolve to a public address")
    return sorted(public)


def network_diagnostics(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bounded DNS, TCP, optional HTTPS and ICMP diagnostics for a public host."""
    arguments = arguments or {}
    host = _host(arguments.get("host"))
    port = _port(arguments.get("port", 443))
    addresses = _public_addresses(host)
    tcp = False
    error = None
    try:
        with socket.create_connection((host, port), timeout=4):
            tcp = True
    except OSError as exc:
        error = type(exc).__name__
    result: dict[str, Any] = {"host": host, "addresses": addresses, "tcp": {"port": port, "reachable": tcp, "error": error}}
    if bool(arguments.get("https", False)):
        try:
            result["https"] = external_tools.ssl_check(f"{host}:{port}")
        except Exception as exc:
            result["https"] = {"ok": False, "error": type(exc).__name__}
    if bool(arguments.get("icmp", False)):
        probe = _run(["/usr/bin/ping", "-c", "1", "-W", "2", host], timeout=3, limit=2000)
        result["icmp"] = {"reachable": probe["ok"], "detail": probe.get("output", probe.get("error", ""))}
    return result


def monitoring_health(_: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read VDS-Agent service, metric freshness and SQLite health summary."""
    return self_monitoring_report()


ADMIN_ACTIONS = {
    "restart_monitoringbot": ["/usr/bin/systemctl", "restart", "monitoringbot.service"],
    "restart_web": ["/usr/bin/systemctl", "restart", "monitorbot-web.service"],
    "restart_health": ["/usr/bin/systemctl", "restart", "monitorbot-health.service"],
    "reboot": ["/usr/bin/systemctl", "reboot"],
    "poweroff": ["/usr/bin/systemctl", "poweroff"],
}


def _create_pending(actor: str, action: str) -> int:
    token = secrets.token_urlsafe(18)
    with connect() as connection:
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            ("agent_admin", actor, action, time.time() + PENDING_TTL, json.dumps({"token": token})),
        )
        return cursor.lastrowid


def _consume_pending(actor: str, confirmation_id: Any) -> str | None:
    try:
        confirmation_id = int(confirmation_id)
    except (TypeError, ValueError):
        return None
    with connect() as connection:
        row = connection.execute(
            "SELECT target FROM pending_actions WHERE id=? AND kind='agent_admin' AND user_id=? AND expires_at>=?",
            (confirmation_id, actor, time.time()),
        ).fetchone()
        if not row:
            return None
        connection.execute("DELETE FROM pending_actions WHERE id=?", (confirmation_id,))
        return row["target"]


def admin_action(arguments: dict[str, Any] | None = None, actor: str = "mcp") -> dict[str, Any]:
    """Prepare or execute one explicitly allow-listed high-risk action.

    The first call returns a short-lived confirmation id. A second call from the
    same actor with that id is required. The root-owned bridge is intentionally
    absent until its separate deployment step has been reviewed and installed.
    """
    arguments = arguments or {}
    action = arguments.get("action")
    if action not in ADMIN_ACTIONS:
        raise ToolError("unsupported administrative action")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is None:
        pending_id = _create_pending(actor, action)
        audit(actor, "agent_admin_request", action, "pending", {"confirmation_id": pending_id})
        return {"ok": False, "confirmation_required": True, "confirmation_id": pending_id, "expires_in_seconds": PENDING_TTL, "action": action}
    approved = _consume_pending(actor, confirmation_id)
    if approved != action:
        raise ToolError("confirmation is invalid, expired or belongs to a different action")
    helper = Path("/usr/local/libexec/monitoringbot-admin-helper")
    if not helper.is_file():
        audit(actor, "agent_admin", action, "unavailable")
        return {"ok": False, "error": "controlled admin bridge is not installed"}
    result = _run(["/usr/bin/sudo", "-n", str(helper), action], timeout=15, limit=2000)
    audit(actor, "agent_admin", action, "ok" if result["ok"] else "failed")
    return {"ok": result["ok"], "action": action, "detail": result.get("output", result.get("error", ""))}


TOOLS = {
    "server_status": server_status,
    "diagnose_load": diagnose_load,
    "process_inspect": process_inspect,
    "service_status": service_status,
    "service_logs": service_logs,
    "metrics_query": metrics_query,
    "incidents_query": incidents_query,
    "network_diagnostics": network_diagnostics,
    "monitoring_health": monitoring_health,
    "admin_action": admin_action,
}


def execute(name: str, arguments: dict[str, Any] | None = None, actor: str = "mcp") -> dict[str, Any]:
    """Execute exactly one named allow-listed tool and audit its outcome."""
    function = TOOLS.get(name)
    if function is None:
        raise ToolError("unknown tool")
    try:
        value = admin_action(arguments, actor) if name == "admin_action" else function(arguments)
    except ToolError:
        audit(actor, "agent_tool", name, "denied")
        raise
    except Exception as error:
        audit(actor, "agent_tool", name, "failed", {"error": type(error).__name__})
        raise ToolError(f"{name} is currently unavailable") from error
    audit(actor, "agent_tool", name, "ok")
    return value
