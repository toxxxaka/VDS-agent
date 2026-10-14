"""Bounded diagnostics and controlled actions shared by MCP and Telegram AI.

No function accepts a shell command.  Arguments are validated before fixed argv
subprocess calls, output is capped and potentially secret-looking values are redacted.
"""
from __future__ import annotations

import hashlib
import hmac
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
LOG_UNITS = {"monitoringbot.service", "monitorbot-web.service", "monitorbot-health.service", "monitorbot-oom.service", "monitorbot-snapshot.service", "monitorbot-infrad.service", "monitorbot-backupd.service", "monitorbot-mcp.service", "nginx.service", "ssh.service", "docker.service", "fail2ban.service"}
DIAGNOSTIC_HELPER = Path("/usr/local/libexec/monitoringbot-diagnostic-helper")
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
SECRET_RE = re.compile(r"(?i)(?:authorization|bearer|token|password|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+")
ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class ToolError(ValueError):
    """A safe, user-displayable tool error."""


def _redact(value: str) -> str:
    return SECRET_RE.sub("[redacted]", value)


def sanitize_untrusted(value: Any, limit: int = MAX_OUTPUT) -> str:
    """Bound terminal, journal and process text before it reaches a user or model."""
    text = ANSI_RE.sub("", str(value))
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return _redact(text[-max(0, limit):])


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
    text = sanitize_untrusted(result.stdout, limit)
    return {"ok": result.returncode == 0, "exit_code": result.returncode, "output": text, "untrusted": True}


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
                    "cmd": sanitize_untrusted(command, 240),
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
    cpu_percent = round(max(0.0, min(100.0, 100.0 - float(getattr(cpu_times, "idle", 0.0)))), 1)
    return {
        "measurement_window_seconds": 1.0,
        "load_average": dict(zip(("1m", "5m", "15m"), (round(value, 2) for value in os.getloadavg()))),
        "cpu": {"percent": cpu_percent, "cores": psutil.cpu_count() or 1, "user": round(getattr(cpu_times, "user", 0.0), 1), "system": round(getattr(cpu_times, "system", 0.0), 1), "iowait": round(getattr(cpu_times, "iowait", 0.0), 1), "steal": round(getattr(cpu_times, "steal", 0.0), 1)},
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
    direct = os.environ.get("MONITORINGBOT_JOURNAL_DIRECT") == "1"
    if direct or not DIAGNOSTIC_HELPER.is_file():
        # WebUI runs with adm and keeps NoNewPrivileges enabled.
        result = _run([
            "/usr/bin/journalctl", "--no-pager", "--output=short-iso", "--unit", unit,
            "--since", f"{minutes} minutes ago", "--lines", str(lines),
        ], timeout=10)
    else:
        # Telegram retains its existing narrow root-owned journal helper.
        result = _run(["/usr/bin/sudo", "-n", str(DIAGNOSTIC_HELPER), "journal", unit, str(lines), str(minutes)], timeout=12)
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


def service_pack(arguments=None):
    from .stage78 import packs
    return packs((arguments or {}).get("pack", "all"))

def weekly_report(_: dict | None = None):
    from .stage78 import report
    return {"html": report()}

def monitoring_health(_: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read VDS-Agent service, metric freshness and SQLite health summary."""
    return self_monitoring_report()


def incident_investigate(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return bounded evidence and a labelled timeline for one incident."""
    try:
        incident_id = int((arguments or {}).get("incident_id"))
    except (TypeError, ValueError) as error:
        raise ToolError("incident_id must be a positive integer") from error
    if incident_id < 1:
        raise ToolError("incident_id must be a positive integer")
    from .intelligence import incident_evidence
    evidence = incident_evidence(incident_id)
    if evidence is None:
        raise ToolError("incident was not found")
    return evidence


def forensics_export(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an anonymized, bounded incident evidence bundle for postmortem use."""
    try:
        incident_id = int((arguments or {}).get("incident_id"))
    except (TypeError, ValueError) as error:
        raise ToolError("incident_id must be a positive integer") from error
    from .intelligence import forensics_export as build_export
    result = build_export(incident_id)
    if result is None:
        raise ToolError("incident was not found")
    return result


def patch_status(_: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read patch, reboot-required, needrestart and unattended-upgrades status."""
    from .intelligence import patch_status as collect_patch_status
    return collect_patch_status()


def security_detect(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run explicitly detect-only listener baseline and IOC inventory checks."""
    mode = (arguments or {}).get("mode", "all")
    if mode not in {"all", "listeners", "ioc"}:
        raise ToolError("mode must be all, listeners or ioc")
    from .intelligence import ioc_checks, listener_baseline
    result: dict[str, Any] = {"detect_only": True}
    if mode in {"all", "listeners"}: result["listeners"] = listener_baseline()
    if mode in {"all", "ioc"}: result["ioc"] = ioc_checks()
    return result


def historical_query(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fetch explicitly historical raw metrics around a caller-supplied epoch."""
    arguments = arguments or {}
    try:
        at = float(arguments.get("at"))
        window = int(arguments.get("window_seconds", 1800))
    except (TypeError, ValueError) as error:
        raise ToolError("at and window_seconds must be numeric") from error
    if at < 1:
        raise ToolError("at must be a Unix timestamp")
    from .intelligence import historical_metrics
    return historical_metrics(at, window)


ADMIN_ACTIONS = {
    "restart_monitoringbot": ["/usr/bin/systemctl", "restart", "monitoringbot.service"],
    "restart_web": ["/usr/bin/systemctl", "restart", "monitorbot-web.service"],
    "restart_health": ["/usr/bin/systemctl", "restart", "monitorbot-health.service"],
    "reboot": ["/usr/bin/systemctl", "reboot"],
    "poweroff": ["/usr/bin/systemctl", "poweroff"],
}


def _confirmation_digest(actor: str, action: str) -> str:
    """Bind a one-time approval to its caller and exact allow-listed action."""
    payload = json.dumps({"actor": actor, "action": action}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _create_pending(actor: str, action: str) -> int:
    digest = _confirmation_digest(actor, action)
    with connect() as connection:
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            ("agent_admin", actor, action, time.time() + PENDING_TTL, json.dumps({"digest": digest})),
        )
        return cursor.lastrowid


def _consume_pending(actor: str, action: str, confirmation_id: Any) -> bool:
    try:
        confirmation_id = int(confirmation_id)
    except (TypeError, ValueError):
        return False
    with connect() as connection:
        row = connection.execute(
            "SELECT target,data FROM pending_actions WHERE id=? AND kind='agent_admin' AND user_id=? AND expires_at>=?",
            (confirmation_id, actor, time.time()),
        ).fetchone()
        if not row or row["target"] != action:
            return False
        try:
            stored = json.loads(row["data"]).get("digest", "")
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(stored, str) or not hmac.compare_digest(stored, _confirmation_digest(actor, action)):
            return False
        connection.execute("DELETE FROM pending_actions WHERE id=?", (confirmation_id,))
        return True


def admin_action(arguments: dict[str, Any] | None = None, actor: str = "mcp") -> dict[str, Any]:
    """Prepare or execute one explicitly allow-listed high-risk action.

    The first call returns a short-lived confirmation id. A second call from the
    same actor with that id is required. The root-owned bridge is intentionally
    absent until its separate deployment step has been reviewed and installed.
    """
    arguments = arguments or {}
    if actor.startswith("mcp"):
        audit(actor, "agent_admin", "", "denied", {"reason": "mcp_read_only"})
        raise ToolError("MCP is read-only; administrative actions require Telegram or WebUI confirmation")
    action = arguments.get("action")
    if action not in ADMIN_ACTIONS:
        raise ToolError("unsupported administrative action")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is None:
        pending_id = _create_pending(actor, action)
        audit(actor, "agent_admin_request", action, "pending", {"confirmation_id": pending_id})
        return {"ok": False, "confirmation_required": True, "confirmation_id": pending_id, "expires_in_seconds": PENDING_TTL, "action": action}
    if not _consume_pending(actor, action, confirmation_id):
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
    "service_pack": service_pack,
    "weekly_report": weekly_report,
    "monitoring_health": monitoring_health,
    "incident_investigate": incident_investigate,
    "forensics_export": forensics_export,
    "patch_status": patch_status,
    "security_detect": security_detect,
    "historical_query": historical_query,
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

# Safe-console diagnostic groups. Every branch below has fixed arguments; no
# browser-provided value is ever made part of a shell command or a file path.
def console_diagnostic(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    topic = arguments.get("topic")
    option = arguments.get("option", "")
    allowed = {
        "pressure": {""}, "oom": {"history"},
        "swap": {"usage", "activity", "pressure"}, "kernel": {"reclaim", "allocfail", "hung-tasks", "oops"},
        "network": {"summary", "top", "interfaces", "errors", "connections", "listen", "syn", "dns", "routes"},
        "services": {"failed", "restart-count"}, "service": LOG_UNITS | {f"deps:{unit}" for unit in LOG_UNITS} | {f"restarts:{unit}" for unit in LOG_UNITS},
        "logs": {"errors", "kernel", "ssh", "journal-size", "rotate"}, "timers": {""}, "boot": {"analyze"},
        "apt": {"health", "pending-security"}, "time": {"sync"}, "limits": {"fd", "conntrack"},
        "fail2ban": {"jails", "bans"}, "ssh": {"sessions", "last-logins"},
        "security": {"overview", "ssh", "fail2ban", "firewall", "ports", "updates"},
        "disk": {"usage", "inodes", "health", "growth"}, "backup": {"status", "verify"},
        "monitoring": {"health", "collectors", "alerts"}, "incidents": {"recent"},
        "diagnose": {"cpu", "memory", "io", "disk", "network", "oom", "server", "nginx", "docker"},
        "compare": {"cpu"}, "changes": {"24h"}, "report": {"24h"},
    }
    if topic not in allowed or option not in allowed[topic]:
        raise ToolError("unsupported console diagnostic")

    if topic == "pressure":
        values: dict[str, Any] = {}
        for name in ("cpu", "memory", "io"):
            try:
                line = Path(f"/proc/pressure/{name}").read_text().splitlines()[0]
                values[name] = dict(re.findall(r"(avg10|avg60|avg300|total)=([0-9.]+)", line))
            except OSError:
                values[name] = {"available": False}
        return {"pressure": values}
    if topic in {"swap", "kernel"}:
        try:
            vmstat = {key: int(value) for key, value in (line.split()[:2] for line in Path("/proc/vmstat").read_text().splitlines())}
        except (OSError, ValueError):
            vmstat = {}
        if topic == "swap":
            swap = psutil.swap_memory()
            if option == "usage":
                return {"swap": {"total_bytes": swap.total, "used_bytes": swap.used, "free_bytes": swap.free, "percent": swap.percent}}
            if option == "activity":
                return {"swap_activity": {"page_in": vmstat.get("pswpin", 0), "page_out": vmstat.get("pswpout", 0), "unit": "pages since boot"}}
            try:
                line = Path("/proc/pressure/memory").read_text().splitlines()[0]
                pressure = dict(re.findall(r"(avg10|avg60|avg300|total)=([0-9.]+)", line))
            except OSError:
                pressure = {"available": False}
            return {"swap_pressure": pressure, "note": "memory PSI; elevated sustained values can indicate reclaim or swap pressure"}
        if option == "reclaim":
            return {"kernel_reclaim": {key: vmstat.get(key, 0) for key in ("pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct", "pgfault", "pgmajfault")}, "unit": "events since boot"}
        if option == "allocfail":
            return {"kernel_allocfail": {key: vmstat.get(key, 0) for key in ("allocstall", "allocstall_dma", "allocstall_dma32", "allocstall_normal", "pgmajfault", "oom_kill")}, "unit": "events since boot"}
        if option == "hung-tasks":
            return {"journal": _journal_fixed(["-k", "--grep", "blocked for more than|task .* blocked", "--since", "30 days ago", "--lines", "80"])}
        return {"journal": _journal_fixed(["-k", "--grep", "Oops|BUG:|general protection fault", "--since", "30 days ago", "--lines", "80"])}
    if topic == "oom":
        return {"oom": _journal_fixed(["-k", "--grep", "Out of memory|Killed process", "--since", "30 days ago", "--lines", "80"])}
    if topic == "network":
        io = psutil.net_io_counters(pernic=True)
        if option == "summary":
            return {"interfaces": {name: {"up": bool(getattr(psutil.net_if_stats().get(name), "isup", False)), "rx_bytes": item.bytes_recv, "tx_bytes": item.bytes_sent, "errors": item.errin + item.errout, "drops": item.dropin + item.dropout} for name, item in io.items()}}
        if option == "interfaces":
            stats, addresses = psutil.net_if_stats(), psutil.net_if_addrs()
            return {"interfaces": {name: {"up": item.isup, "speed_mbps": item.speed, "addresses": [row.address for row in addresses.get(name, []) if row.family in {socket.AF_INET, socket.AF_INET6}]} for name, item in stats.items()}}
        if option == "errors":
            return {"interfaces": {name: {"errors_in": item.errin, "errors_out": item.errout, "drops_in": item.dropin, "drops_out": item.dropout} for name, item in io.items()}}
        if option in {"connections", "top", "syn"}:
            try:
                conns = psutil.net_connections(kind="tcp")
            except psutil.Error:
                conns = []
            if option == "syn":
                return {"syn_recv": sum(1 for item in conns if item.status == "SYN_RECV")}
            if option == "connections":
                states: dict[str, int] = {}
                for item in conns: states[item.status or "UNKNOWN"] = states.get(item.status or "UNKNOWN", 0) + 1
                return {"tcp_states": states, "total": len(conns)}
            peers: dict[str, int] = {}
            for item in conns:
                if item.raddr: peers[str(item.raddr.ip)] = peers.get(str(item.raddr.ip), 0) + 1
            return {"connections_by_peer": sorted(({"peer": key, "connections": value} for key, value in peers.items()), key=lambda item: item["connections"], reverse=True)[:20]}
        if option == "listen": return socket_inspect({"sort": "port"})
        if option == "dns":
            try: lines = [line.strip() for line in Path("/etc/resolv.conf").read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
            except OSError: lines = []
            return {"resolver": lines[:20]}
        if option == "routes": return {"routes": _run(["/usr/sbin/ip", "route", "show"], limit=6000)}
    if topic == "services":
        if option == "failed": return {"failed": _run(["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"], limit=6000)}
        rows_out = []
        for unit in sorted(LOG_UNITS):
            rows_out.append({"unit": unit, "restart_count": _run(["/usr/bin/systemctl", "show", unit, "--property", "NRestarts", "--value"], limit=100).get("output", "unknown").strip()})
        return {"restart_counts": rows_out}
    if topic == "service":
        if ":" in option:
            mode, unit = option.split(":", 1)
            if mode == "deps":
                return {"service": unit, "dependencies": _run(["/usr/bin/systemctl", "show", unit, "--property", "After,Requires,Wants", "--no-pager"], timeout=8, limit=7000)}
            return {"service": unit, "restarts": _run(["/usr/bin/systemctl", "show", unit, "--property", "NRestarts,ActiveEnterTimestamp,ExecMainStatus", "--no-pager"], timeout=8, limit=3000)}
        return {"service": option, "status": _run(["/usr/bin/systemctl", "status", option, "--no-pager", "--lines", "20"], timeout=8, limit=7000)}
    if topic == "logs":
        if option == "journal-size":
            return {"journal_size": _run(["/usr/bin/journalctl", "--disk-usage"], timeout=8, limit=1000)}
        if option == "rotate":
            status_path = Path("/var/lib/logrotate/status")
            try:
                stat = status_path.stat()
                return {"logrotate": {"state_file_present": True, "state_file_mtime": int(stat.st_mtime)}}
            except OSError:
                return {"logrotate": {"state_file_present": False}}
        args = {"errors": ["--priority", "err", "--since", "1 hour ago", "--lines", "80"], "kernel": ["-k", "--priority", "warning", "--since", "2 hours ago", "--lines", "80"], "ssh": ["--unit", "ssh.service", "--since", "24 hours ago", "--lines", "80"]}[option]
        return {"journal": _journal_fixed(args)}
    if topic == "timers": return {"timers": _run(["/usr/bin/systemctl", "list-timers", "--all", "--no-pager"], limit=8000)}
    if topic == "boot": return {"boot": _run(["/usr/bin/systemd-analyze", "blame"], timeout=12, limit=8000)}
    if topic == "apt":
        if option == "health":
            return {"dpkg_audit": _run(["/usr/bin/dpkg", "--audit"], timeout=10, limit=4000), "note": "An empty dpkg audit result means no packages are awaiting configuration."}
        return {"upgradable": _run(["/usr/bin/apt", "list", "--upgradable"], timeout=12, limit=5000), "note": "This is the local APT catalogue; update it separately before relying on it."}
    if topic == "time":
        return {"time_sync": _run(["/usr/bin/timedatectl", "show", "--property", "NTPSynchronized,NTPSync,Timezone", "--no-pager"], timeout=8, limit=2000)}
    if topic == "limits":
        names = {"fd": ("/proc/sys/fs/file-nr", "file_nr"), "conntrack": ("/proc/sys/net/netfilter/nf_conntrack_count", "conntrack_count")}
        path, key = names[option]
        try:
            current = Path(path).read_text().strip()
        except OSError:
            current = "unavailable"
        if option == "conntrack":
            try:
                maximum = Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip()
            except OSError:
                maximum = "unavailable"
            return {key: current, "conntrack_max": maximum}
        return {key: current, "format": "allocated unused maximum"}
    if topic == "fail2ban":
        argv = ["/usr/bin/fail2ban-client", "status"] if option == "jails" else ["/usr/bin/fail2ban-client", "status", "sshd"]
        return {"fail2ban": _run(argv, timeout=8, limit=5000), "scope": "all jails" if option == "jails" else "sshd jail when configured"}
    if topic == "ssh":
        argv = ["/usr/bin/who"] if option == "sessions" else ["/usr/bin/last", "-w", "-n", "10"]
        return {"ssh": _run(argv, timeout=8, limit=5000)}
    if topic == "security":
        if option == "overview": return {"ports": socket_inspect({"sort": "port"}), "failed_units": _run(["/usr/bin/systemctl", "--failed", "--no-legend"], limit=3000)}
        if option == "ssh": return {"ssh": _journal_fixed(["--unit", "ssh.service", "--since", "24 hours ago", "--lines", "100"])}
        if option == "fail2ban": return {"fail2ban": _run(["/usr/bin/fail2ban-client", "status"], limit=4000)}
        if option == "firewall":
            try:
                from . import firewall
                return {"firewall": firewall.state()}
            except Exception as error: return {"available": False, "error": type(error).__name__}
        if option == "ports": return socket_inspect({"sort": "port"})
        if option == "updates": return {"updates": _run(["/usr/bin/apt", "list", "--upgradable"], timeout=12, limit=5000)}
    if topic == "disk":
        if option == "usage": return {"filesystems": [{"mount": part.mountpoint, "used": psutil.disk_usage(part.mountpoint).used, "total": psutil.disk_usage(part.mountpoint).total, "percent": psutil.disk_usage(part.mountpoint).percent} for part in psutil.disk_partitions(all=False)]}
        if option == "inodes":
            return {"inodes": [{"mount": part.mountpoint, "used": max(0, os.statvfs(part.mountpoint).f_files - os.statvfs(part.mountpoint).f_ffree), "total": os.statvfs(part.mountpoint).f_files} for part in psutil.disk_partitions(all=False)]}
        if option == "health":
            smartctl = Path("/usr/sbin/smartctl")
            if not smartctl.is_file():
                return {"text": "SMART/NVMe health is unavailable: smartmontools is not installed and this virtual server may not expose a physical disk."}
            result = _run([str(smartctl), "--scan-open"], timeout=10, limit=4000)
            if not result.get("ok"):
                return {"text": "SMART/NVMe health is unavailable: the virtual disk is not exposed to the guest OS.", "detail": result.get("output", result.get("error", ""))}
            return {"health": result}
        if option == "growth": return {"metrics": metric_query("30d")}
    if topic == "backup":
        report = self_monitoring_report()
        return {"backup": report.get("backups", {}), "checks": {"backups": report.get("checks", {}).get("backups")}}
    if topic == "monitoring":
        report = self_monitoring_report()
        if option == "health": return report
        if option == "collectors": return {"metrics": report.get("metrics", {}), "services": [item for item in report.get("services", []) if "monitor" in item.get("unit", "")]}
        return {"active_incidents": incidents_query({"status": "active"}), "health": report.get("checks", {})}
    if topic == "incidents": return incidents_query({"status": "all"})
    if topic == "diagnose":
        # Each command deliberately returns its own evidence. A generic snapshot
        # makes CPU, memory and I/O diagnostics indistinguishable.
        if option == "cpu":
            evidence = diagnose_load({"limit": 5})
            return {"focus": "cpu", "measurement_window_seconds": evidence["measurement_window_seconds"], "cpu": evidence["cpu"], "load_average": evidence["load_average"], "top_processes": evidence["top_processes"]}
        if option == "memory":
            evidence = diagnose_load({"limit": 5})
            processes = process_inspect({"limit": 5, "sort": "memory"})
            return {"focus": "memory", "measurement_window_seconds": evidence["measurement_window_seconds"], "memory": evidence["memory"], "top_processes": processes["processes"]}
        if option == "io":
            evidence = diagnose_load({"limit": 5})
            processes = process_inspect({"limit": 5, "sort": "io"})
            return {"focus": "io", "measurement_window_seconds": evidence["measurement_window_seconds"], "disk_io_cumulative_bytes": evidence["disk_io_cumulative_bytes"], "top_processes": processes["processes"], "io_scope": "per-process counters are cumulative since process start"}
        if option == "disk":
            evidence = diagnose_load({"limit": 5})
            return {"focus": "disk", "filesystems": console_diagnostic({"topic": "disk", "option": "usage"}), "disk_io_cumulative_bytes": evidence["disk_io_cumulative_bytes"], "top_processes": process_inspect({"limit": 5, "sort": "io"})["processes"], "io_scope": "per-process counters are cumulative since process start"}
        if option == "network":
            return {"focus": "network", "summary": console_diagnostic({"topic": "network", "option": "summary"}), "errors": console_diagnostic({"topic": "network", "option": "errors"}), "connections": console_diagnostic({"topic": "network", "option": "connections"}), "dns": console_diagnostic({"topic": "network", "option": "dns"}), "routes": console_diagnostic({"topic": "network", "option": "routes"})}
        if option == "oom":
            evidence = diagnose_load({"limit": 5})
            return {"focus": "oom", "memory": evidence["memory"], "top_processes": process_inspect({"limit": 5, "sort": "memory"})["processes"], "oom_history": console_diagnostic({"topic": "oom", "option": "history"})}
        if option == "server":
            return {"focus": "server", "status": server_status({}), "health": self_monitoring_report()}
        if option == "nginx": return {"service": service_status({"units": ["nginx.service"]}), "logs": service_logs({"unit": "nginx.service", "lines": 30, "minutes": 120}), "connections": console_diagnostic({"topic": "network", "option": "connections"})}
        if option == "docker": return {"service": service_status({"units": ["docker.service"]}), "status": _run(["/usr/bin/docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], timeout=8, limit=6000)}
    if topic == "compare":
        first, second = metric_query("1h"), metric_query("24h")
        def average(rows: list[dict[str, Any]]) -> float | None:
            values = [float(row["cpu"]) for row in rows if isinstance(row.get("cpu"), (int, float))]
            return round(sum(values) / len(values), 2) if values else None
        return {"cpu": {"1h_average": average(first), "24h_average": average(second)}}
    if topic == "changes": return {"audit": rows("SELECT time,user_id,action,target,result FROM audit_log WHERE time>=? ORDER BY time DESC LIMIT 100", (time.time() - 86400,))}
    if topic == "report": return {"health": self_monitoring_report(), "incidents": incidents_query({"status": "all"})}
    raise ToolError("unsupported console diagnostic")


def _journal_fixed(arguments: list[str]) -> dict[str, Any]:
    if os.environ.get("MONITORINGBOT_JOURNAL_DIRECT") != "1":
        return {"available": False, "error": "system journal is available in the WebUI console only"}
    return _run(["/usr/bin/journalctl", "--no-pager", "--output=short-iso", *arguments], timeout=12, limit=10000)

TOOLS["console_diagnostic"] = console_diagnostic
