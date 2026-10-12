"""Bounded incident intelligence and detect-only host evidence.

This module deliberately uses fixed commands and capped local reads.  It never
changes a service, firewall, account or process.  Its output is evidence for
incidents, operators and the optional AI layer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil

from .storage import connect, rows

MAX_ITEMS = 20
MAX_TEXT = 12_000
_BASELINE_PORTS = "listener-baseline-v1"
_BASELINE_IOC = "ioc-baseline-v1"
_RE_IP = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_RE_NUMBER = re.compile(r"\b\d{2,}\b")
_RE_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)


def _run(argv: list[str], timeout: int = 8, limit: int = MAX_TEXT) -> dict[str, Any]:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=timeout,
                                check=False)
    except subprocess.TimeoutExpired:
        return {"available": False, "error": "timed out"}
    except OSError as error:
        return {"available": False, "error": type(error).__name__}
    text = "".join(char for char in result.stdout if char in "\n\t" or ord(char) >= 32)
    return {"available": result.returncode == 0, "output": text[-limit:], "exit_code": result.returncode}


def _unit_for_pid(pid: int) -> str | None:
    try:
        values = Path(f"/proc/{pid}/cgroup").read_text(errors="replace").splitlines()
    except OSError:
        return None
    for value in values:
        match = re.search(r"(?:^|/)([A-Za-z0-9@_.-]+\.service)(?:$|/)", value)
        if match:
            return match.group(1)
    return None


def _processes() -> list[dict[str, Any]]:
    processes = list(psutil.process_iter())
    for process in processes:
        try:
            process.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(0.25)
    result = []
    now = time.time()
    for process in processes:
        try:
            with process.oneshot():
                memory = process.memory_info()
                io = process.io_counters() if hasattr(process, "io_counters") else None
                cmd = " ".join(process.cmdline()) or process.name()
                result.append({
                    "pid": process.pid,
                    "user": process.username(),
                    "name": process.name(),
                    "cpu_percent": round(process.cpu_percent(None), 1),
                    "rss_bytes": memory.rss,
                    "rss_mib": round(memory.rss / (1024 * 1024), 1),
                    "io_bytes": int(getattr(io, "read_bytes", 0) or 0) + int(getattr(io, "write_bytes", 0) or 0),
                    "cmd": cmd[:300],
                    "elapsed_seconds": max(0, int(now - process.create_time())),
                    "unit": _unit_for_pid(process.pid),
                })
        except (psutil.Error, OSError):
            continue
    return result


def top_processes(limit: int = 8) -> dict[str, list[dict[str, Any]]]:
    """Sample once and rank the same bounded process set three ways."""
    items = _processes()
    amount = max(1, min(int(limit), MAX_ITEMS))
    return {
        "cpu": sorted(items, key=lambda item: (item["cpu_percent"], item["rss_bytes"]), reverse=True)[:amount],
        "rss": sorted(items, key=lambda item: (item["rss_bytes"], item["cpu_percent"]), reverse=True)[:amount],
        "io_cumulative": sorted(items, key=lambda item: (item["io_bytes"], item["cpu_percent"]), reverse=True)[:amount],
    }


def tcp_connections(limit: int = 100) -> dict[str, Any]:
    result = _run(["/usr/bin/ss", "-H", "-t", "-n", "-p"], timeout=6, limit=10_000)
    lines = [line for line in result.get("output", "").splitlines() if line.strip()]
    return {"available": bool(result.get("available")), "connections": lines[:max(1, min(limit, 100))], "detail": result.get("error", "")}


def unit_restarts(units: list[str]) -> list[dict[str, Any]]:
    answer = []
    for unit in sorted({item for item in units if re.fullmatch(r"[A-Za-z0-9@_.-]{1,120}\.service", item)}):
        result = _run(["/usr/bin/systemctl", "show", unit, "--property=NRestarts", "--value"], timeout=4, limit=100)
        value = result.get("output", "").strip()
        answer.append({"unit": unit, "restart_count": int(value) if value.isdigit() else None, "available": bool(result.get("available"))})
    return answer


def failed_units() -> list[str]:
    result = _run(["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"], timeout=5, limit=6000)
    units = []
    for line in result.get("output", "").splitlines():
        field = line.split(maxsplit=1)[0] if line.split() else ""
        if re.fullmatch(r"[A-Za-z0-9@_.-]{1,120}\.service", field):
            units.append(field)
    return units[:MAX_ITEMS]


def _journal(arguments: list[str], limit: int = 8000) -> str:
    return _run(["/usr/bin/journalctl", "--no-pager", "--output=short-iso", *arguments], timeout=10, limit=limit).get("output", "")


def _pattern(line: str) -> str:
    line = _RE_IP.sub("<ip>", line)
    line = _RE_HEX.sub("<hex>", line)
    return _RE_NUMBER.sub("<n>", line)[:360]


def log_intelligence(since_seconds: int = 3600, incident_id: int | None = None) -> dict[str, Any]:
    """Group bounded warning/error journal rows; first-seen patterns are recorded."""
    seconds = max(60, min(int(since_seconds), 7 * 86400))
    text = _journal(["--priority", "warning", "--since", f"@{int(time.time() - seconds)}", "--lines", "240"], limit=16_000)
    groups: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        signature = _pattern(line)
        if not signature:
            continue
        item = groups.setdefault(signature, {"pattern": signature, "count": 0, "example": line[:500]})
        item["count"] += 1
    output = sorted(groups.values(), key=lambda item: item["count"], reverse=True)[:MAX_ITEMS]
    now = time.time()
    with connect() as connection:
        for item in output:
            digest = hashlib.sha256(item["pattern"].encode()).hexdigest()
            prior = connection.execute("SELECT first_seen,count FROM log_patterns WHERE signature=?", (digest,)).fetchone()
            item["new"] = prior is None
            connection.execute(
                "INSERT INTO log_patterns(signature,pattern,first_seen,last_seen,count,example) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(signature) DO UPDATE SET last_seen=excluded.last_seen,count=log_patterns.count+excluded.count,example=excluded.example",
                (digest, item["pattern"], now, now, item["count"], item["example"]),
            )
            if incident_id:
                connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (incident_id, now, "log_pattern", json.dumps({"signature": digest[:12], "count": item["count"], "new": item["new"]})))
    return {"since_seconds": seconds, "patterns": output}


def _baseline_get(name: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT data FROM intelligence_baselines WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["data"])
    except (TypeError, json.JSONDecodeError):
        return None


def _baseline_put(name: str, data: dict[str, Any]) -> None:
    with connect() as connection:
        connection.execute("INSERT INTO intelligence_baselines(name,updated_at,data) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET updated_at=excluded.updated_at,data=excluded.data", (name, time.time(), json.dumps(data, separators=(",", ":"))))


def listeners() -> list[str]:
    output = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.Error:
        connections = []
    for item in connections:
        if item.status != psutil.CONN_LISTEN or not item.laddr:
            continue
        host = getattr(item.laddr, "ip", item.laddr[0])
        port = getattr(item.laddr, "port", item.laddr[1])
        process = ""
        if item.pid:
            try:
                process = psutil.Process(item.pid).name()
            except psutil.Error:
                process = "unknown"
        output.append(f"{item.type}:{host}:{port}:{process}")
    return sorted(set(output))[:200]


def listener_baseline() -> dict[str, Any]:
    current = listeners()
    previous = _baseline_get(_BASELINE_PORTS)
    if previous is None:
        _baseline_put(_BASELINE_PORTS, {"listeners": current})
        return {"mode": "baseline_created", "listeners": current, "new_listeners": []}
    old = set(previous.get("listeners", []))
    new = sorted(set(current) - old)
    missing = sorted(old - set(current))
    _baseline_put(_BASELINE_PORTS, {"listeners": current})
    return {"mode": "detect_only", "listeners": current, "new_listeners": new, "missing_listeners": missing}


def _ioc_inventory() -> dict[str, list[str]]:
    suspicious_processes, deleted = [], []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(process.info.get("cmdline") or [])
            if cmd.startswith("/tmp/") or cmd.startswith("/dev/shm/"):
                suspicious_processes.append(f"{process.pid}:{process.info.get('name', '?')}:{cmd[:180]}")
            executable = os.readlink(f"/proc/{process.pid}/exe")
            if executable.endswith(" (deleted)"):
                deleted.append(f"{process.pid}:{executable[:220]}")
        except (psutil.Error, OSError):
            continue
    suid = []
    for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        try:
            for path in Path(directory).iterdir():
                try:
                    if path.is_file() and path.stat().st_mode & 0o4000:
                        suid.append(str(path))
                except OSError:
                    continue
        except OSError:
            continue
    cron = []
    for path in (Path("/etc/crontab"), *Path("/etc/cron.d").glob("*")):
        try:
            if path.is_file(): cron.append(f"{path}:{path.stat().st_mtime_ns}:{path.stat().st_size}")
        except OSError:
            continue
    units = []
    for directory in (Path("/etc/systemd/system"),):
        try:
            for path in directory.glob("*.service"):
                if path.is_file(): units.append(f"{path.name}:{path.stat().st_mtime_ns}:{path.stat().st_size}")
        except OSError:
            continue
    users = []
    try:
        for line in Path("/etc/passwd").read_text(errors="replace").splitlines():
            fields = line.split(":")
            if len(fields) >= 3 and fields[2].isdigit() and int(fields[2]) >= 1000:
                users.append(f"{fields[0]}:{fields[2]}")
    except OSError:
        pass
    return {"tmp_or_shm_processes": sorted(suspicious_processes)[:MAX_ITEMS], "deleted_executables": sorted(deleted)[:MAX_ITEMS], "suid": sorted(suid)[:500], "cron": sorted(cron)[:200], "units": sorted(units)[:300], "users": sorted(users)[:200]}


def ioc_checks() -> dict[str, Any]:
    """Detect-only IOC inventory. A first scan only establishes a baseline."""
    current = _ioc_inventory()
    previous = _baseline_get(_BASELINE_IOC)
    if previous is None:
        _baseline_put(_BASELINE_IOC, current)
        return {"mode": "baseline_created", "findings": {"tmp_or_shm_processes": current["tmp_or_shm_processes"], "deleted_executables": current["deleted_executables"]}, "new": {}}
    changed = {key: sorted(set(value) - set(previous.get(key, [])))[:MAX_ITEMS] for key, value in current.items()}
    _baseline_put(_BASELINE_IOC, current)
    return {"mode": "detect_only", "findings": {"tmp_or_shm_processes": current["tmp_or_shm_processes"], "deleted_executables": current["deleted_executables"]}, "new": {key: value for key, value in changed.items() if value}}


def patch_status() -> dict[str, Any]:
    updates = _run(["/usr/bin/apt", "list", "--upgradable"], timeout=15, limit=6000)
    lines = [line for line in updates.get("output", "").splitlines() if line and not line.startswith("Listing")]
    reboot = Path("/var/run/reboot-required").exists()
    needrestart = _run(["/usr/sbin/needrestart", "-b", "-r", "l"], timeout=15, limit=4000) if Path("/usr/sbin/needrestart").exists() else {"available": False, "error": "not installed"}
    unattended = _run(["/usr/bin/systemctl", "is-active", "unattended-upgrades.service"], timeout=4, limit=100)
    return {"security_updates": lines[:100], "security_update_count": len(lines), "reboot_required": reboot, "needrestart": needrestart.get("output", needrestart.get("error", ""))[-1000:], "unattended_upgrades": unattended.get("output", "unknown").strip()}


def tracked_etc_changes() -> list[dict[str, Any]]:
    paths = [Path("/etc/ssh/sshd_config"), Path("/etc/nginx"), Path("/etc/systemd/system"), Path("/etc/cron.d"), Path("/etc/crontab")]
    entries = []
    for root in paths:
        try:
            candidates = list(root.rglob("*"))[:200] if root.is_dir() else [root]
        except OSError:
            candidates = []
        for path in candidates:
            try:
                if path.is_file():
                    stat = path.stat()
                    entries.append(f"{path}:{stat.st_mtime_ns}:{stat.st_size}")
            except OSError:
                continue
    key = "etc-baseline-v1"
    current = {"entries": sorted(entries)[:600]}
    previous = _baseline_get(key)
    _baseline_put(key, current)
    if previous is None:
        return []
    old = set(previous.get("entries", [])); new = set(current["entries"])
    return [{"kind": "etc_changed", "path": item.split(":", 1)[0]} for item in sorted((new - old) | (old - new))[:MAX_ITEMS]]


def timeline(start_at: float, end_at: float | None = None, limit: int = 120) -> list[dict[str, Any]]:
    """Merge bounded local sources into a time-ordered, labelled timeline."""
    end = time.time() if end_at is None else end_at
    start = max(0, min(float(start_at), end))
    events: list[dict[str, Any]] = []
    sources = {
        "systemd": _journal(["--since", f"@{int(start)}", "--until", f"@{int(end)}", "--grep", "Started|Stopped|Restarted|Failed", "--lines", "80"]),
        "ssh": _journal(["--unit", "ssh.service", "--since", f"@{int(start)}", "--until", f"@{int(end)}", "--lines", "80"]),
        "kernel": _journal(["-k", "--since", f"@{int(start)}", "--until", f"@{int(end)}", "--grep", "Out of memory|Killed process|oom", "--lines", "80"]),
    }
    for source, text in sources.items():
        for line in text.splitlines():
            events.append({"source": source, "time": None, "message": line[:700]})
    for row in rows("SELECT time,action,target,result FROM audit_log WHERE time BETWEEN ? AND ? ORDER BY time DESC LIMIT 60", (start, end)):
        events.append({"source": "agent_audit", "time": row["time"], "message": f"{row['action']} {row['target']} ({row['result']})"})
    try:
        dpkg = Path("/var/log/dpkg.log").read_text(errors="replace").splitlines()[-400:]
        for line in dpkg:
            events.append({"source": "dpkg", "time": None, "message": line[:700]})
    except OSError:
        pass
    events.extend(tracked_etc_changes())
    return events[-max(1, min(limit, 200)):]


def deep_snapshot(kind: str, flight_recorder: dict | None = None) -> dict[str, Any]:
    failed = failed_units()
    process = top_processes(8)
    units = [item.get("unit") for group in process.values() for item in group if item.get("unit")]
    units.extend(failed)
    result = {
        "kind": kind,
        "captured_at": time.time(),
        "processes": process,
        "tcp_connections": tcp_connections(),
        "failed_units": failed,
        "unit_restarts": unit_restarts(units),
        "log_intelligence": log_intelligence(3600),
        "patch_status": patch_status(),
        "ioc": ioc_checks(),
    }
    if flight_recorder is not None:
        result["flight_recorder"] = flight_recorder
    return result


def incident_evidence(incident_id: int) -> dict[str, Any] | None:
    incident_rows = rows("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not incident_rows:
        return None
    incident = incident_rows[0]
    snapshot = None
    if incident.get("snapshot_id"):
        saved = rows("SELECT data FROM snapshots WHERE id=?", (incident["snapshot_id"],))
        if saved:
            try: snapshot = json.loads(saved[0]["data"])
            except (TypeError, json.JSONDecodeError): pass
    return {"incident": incident, "events": rows("SELECT time,event,details FROM incident_events WHERE incident_id=? ORDER BY time ASC LIMIT 200", (incident_id,)), "snapshot": snapshot, "timeline": timeline(incident["started_at"], incident.get("closed_at") or time.time()), "patch_status": patch_status()}


def _anonymize(value: Any) -> Any:
    if isinstance(value, str):
        return _RE_IP.sub(lambda match: "ip-" + hashlib.sha256(match.group(0).encode()).hexdigest()[:10], value)
    if isinstance(value, list): return [_anonymize(item) for item in value]
    if isinstance(value, dict): return {str(key): _anonymize(item) for key, item in value.items()}
    return value


def forensics_export(incident_id: int) -> dict[str, Any] | None:
    evidence = incident_evidence(incident_id)
    if evidence is None:
        return None
    return {"format": "vds-agent-evidence-v1", "generated_at": time.time(), "anonymized": True, "evidence": _anonymize(evidence)}


def historical_metrics(at: float, window_seconds: int = 1800) -> dict[str, Any]:
    """Return explicitly labelled raw historical samples around one timestamp."""
    point = float(at)
    window = max(300, min(int(window_seconds), 24 * 3600))
    samples = rows(
        "SELECT time,cpu,load1,mem_used,mem_cached,mem_available,rx,tx,read_bytes,write_bytes FROM metric_samples WHERE sample_version=2 AND time BETWEEN ? AND ? ORDER BY time ASC LIMIT 720",
        (point - window, point + window),
    )
    return {"kind": "historical_raw_samples", "at": point, "window_seconds": window, "samples": samples, "sample_count": len(samples)}
