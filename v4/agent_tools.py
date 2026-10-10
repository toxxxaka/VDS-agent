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
LOG_UNITS = {"monitoringbot.service", "monitorbot-web.service", "monitorbot-health.service", "monitorbot-oom.service", "monitorbot-snapshot.service", "monitorbot-infrad.service", "monitorbot-backupd.service", "nginx.service", "ssh.service", "docker.service"}
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


def _process_items(requested_pid: int | None = None, sample_seconds: float = 0.5) -> list[dict[str, Any]]:
    """Take one short real CPU interval and return bounded process evidence."""
    try:
        processes = [psutil.Process(requested_pid)] if requested_pid else list(psutil.process_iter())
    except psutil.Error:
        return []
    for process in processes:
        try:
            process.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            pass
    time.sleep(max(0.1, min(sample_seconds, 1.0)))
    now = time.time()
    items = []
    for process in processes:
        try:
            with process.oneshot():
                memory = process.memory_info()
                io = process.io_counters() if hasattr(process, "io_counters") else None
                command = " ".join(process.cmdline()) or process.name()
                items.append({
                    "pid": process.pid,
                    "name": process.name(),
                    "user": process.username(),
                    "status": process.status(),
                    "cpu_percent": round(process.cpu_percent(interval=None), 1),
                    "memory_percent": round(process.memory_percent(), 2),
                    "rss_bytes": memory.rss,
                    "rss_mib": round(memory.rss / (1024 * 1024), 1),
                    "cmd": _redact(command)[:240],
                    "elapsed_seconds": max(0, int(now - process.create_time())),
                    "threads": process.num_threads(),
                    "io_read_bytes": getattr(io, "read_bytes", None),
                    "io_write_bytes": getattr(io, "write_bytes", None),
                })
        except (psutil.Error, OSError):
            continue
    return items


def _atop_evidence() -> dict[str, Any]:
    """Expose only a bounded recent atop excerpt; absence is an explicit limitation."""
    directory = Path("/var/log/atop")
    try:
        files = sorted((item for item in directory.glob("atop_*") if item.is_file()), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        files = []
    if not files:
        return {"available": False, "reason": "no atop archive available"}
    archive = files[0]
    result = _run(["/usr/bin/atop", "-r", str(archive), "-1"], timeout=8, limit=6000)
    return {"available": result["ok"], "archive": archive.name, "excerpt": result.get("output", result.get("error", ""))[-5000:]}


def diagnose_load(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect evidence for CPU/RAM/I/O pressure, not cumulative counters alone."""
    limit = min(max(int((arguments or {}).get("limit", 5)), 1), 25)
    cpu_times = psutil.cpu_times_percent(interval=0.5)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    io = psutil.disk_io_counters()
    processes = _process_items(sample_seconds=0.5)
    processes.sort(key=lambda item: (item["cpu_percent"], item["rss_bytes"]), reverse=True)
    return {
        "measurement_window_seconds": 1.0,
        "load_average": dict(zip(("1m", "5m", "15m"), (round(value, 2) for value in os.getloadavg()))),
        "cpu": {"percent": round(psutil.cpu_percent(interval=None), 1), "cores": psutil.cpu_count() or 1, "user": round(getattr(cpu_times, "user", 0.0), 1), "system": round(getattr(cpu_times, "system", 0.0), 1), "iowait": round(getattr(cpu_times, "iowait", 0.0), 1), "steal": round(getattr(cpu_times, "steal", 0.0), 1)},
        "memory": {"used_bytes": memory.used, "available_bytes": memory.available, "percent": memory.percent, "swap_percent": swap.percent},
        "disk_io_cumulative_bytes": {"read": io.read_bytes if io else 0, "write": io.write_bytes if io else 0},
        "top_processes": processes[:limit],
        "atop": _atop_evidence(),
    }


def process_inspect(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return top processes with sampled CPU, RSS, cmd and elapsed time."""
    arguments = arguments or {}
    limit = min(max(int(arguments.get("limit", 5)), 1), 50)
    sort = arguments.get("sort", "cpu")
    if sort not in {"cpu", "memory", "io"}:
        raise ToolError("sort must be cpu, memory or io")
    requested_pid = arguments.get("pid")
    if requested_pid is not None:
        try:
            requested_pid = int(requested_pid)
        except (TypeError, ValueError) as error:
            raise ToolError("invalid process id") from error
        if requested_pid < 1:
            raise ToolError("invalid process id")
    items = _process_items(requested_pid)
    fields = {
        "cpu": lambda item: (item["cpu_percent"], item["rss_bytes"]),
        "memory": lambda item: (item["rss_bytes"], item["cpu_percent"]),
        "io": lambda item: ((item["io_read_bytes"] or 0) + (item["io_write_bytes"] or 0), item["cpu_percent"]),
    }
    items.sort(key=fields[sort], reverse=True)
    return {"sort": sort, "measurement_window_seconds": 0.5, "processes": items[:limit]}


def socket_inspect(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """List local listening sockets from a fixed ss invocation."""
    arguments = arguments or {}
    sort = arguments.get("sort", "port")
    if sort not in {"port", "name"}:
        raise ToolError("sort must be port or name")
    result = _run(["/usr/bin/ss", "-H", "-l", "-t", "-u", "-p", "-n"], timeout=6, limit=10000)
    lines = [line for line in result.get("output", "").splitlines() if line.strip()]
    lines.sort(key=str.lower if sort == "name" else lambda line: int(re.search(r":(\d+)(?:\s|$)", line).group(1)) if re.search(r":(\d+)(?:\s|$)", line) else 0)
    return {"available": result["ok"], "sort": sort, "sockets": lines[:100], "detail": "" if result["ok"] else result.get("error", "")}


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
    # Connect to a validated address, not a second DNS lookup of untrusted input.
    try:
        with socket.create_connection((addresses[0], port), timeout=4):
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
    "socket_inspect": socket_inspect,
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
