"""Cached, bounded health model for VDS-Agent itself."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from .config import load as load_settings
from .metrics import latest
from .storage import DB, rows

UNITS = (
    "monitoringbot.service",
    "monitorbot-web.service",
    "monitorbot-mcp.service",
    "monitorbot-health.service",
    "monitorbot-snapshot.timer",
    "monitorbot-oom.service",
    "monitorbot-infrad.service",
    "monitorbot-backupd.service",
)
CACHE = Path(os.environ.get("MONITORINGBOT_SELF_MONITORING_STATE", "/var/lib/monitoringbot/self_monitoring.json"))
CACHE_MAX_AGE = 180


def _run(argv: list[str], timeout: int = 3) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, "unknown"
    return getattr(result, "returncode", 0) == 0, getattr(result, "stdout", "").strip()


def _write_cache(payload: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_cache(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _cache_path(path: Path, cache: Path) -> Path:
    return path.parent / cache.name if cache == CACHE and path != DB else cache


def collect(now: float | None = None, path: Path = DB, cache: Path = CACHE) -> dict:
    """Collect bounded local health once; no external requests or diagnostics."""
    now = time.time() if now is None else now
    cache = _cache_path(path, cache)
    services = []
    for unit in UNITS:
        _ok, state = _run(["/usr/bin/systemctl", "is-active", unit])
        services.append({"unit": unit, "state": state or "unknown", "healthy": state in {"active", "waiting"}})
    _failed_ok, failed_units = _run(["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"], timeout=4)
    failed_unit_lines = [line for line in failed_units.splitlines() if line.strip() and line.strip() not in {"active", "unknown"}]
    current = latest(path)
    metric_age = None if not current else max(0.0, now - float(current["time"]))
    database = {"ok": False, "size_bytes": 0, "wal_bytes": 0}
    try:
        database["size_bytes"] = path.stat().st_size
        wal = Path(str(path) + "-wal")
        database["wal_bytes"] = wal.stat().st_size if wal.exists() else 0
        with sqlite3.connect(path, timeout=3) as connection:
            database["ok"] = connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    except (OSError, sqlite3.Error):
        pass
    failures = rows(
        "SELECT command,status,started_at FROM command_runs WHERE status IN ('failed','timeout') AND started_at>=? ORDER BY started_at DESC LIMIT 10",
        (now - 86400,),
        path=path,
    )
    backups = rows(
        "SELECT finished_at,details FROM command_runs WHERE command='backup' AND status='completed' ORDER BY finished_at DESC LIMIT 1",
        path=path,
    )
    backup_age = None if not backups or backups[0]["finished_at"] is None else max(0.0, now - float(backups[0]["finished_at"]))
    upstream_ok, _ = _run(["/usr/bin/systemctl", "is-active", "monitorbot-web.service"])
    database["soft_limit_bytes"] = load_settings().telemetry.database_soft_limit_mib * 1024 * 1024
    database["within_soft_limit"] = database["size_bytes"] + database["wal_bytes"] <= database["soft_limit_bytes"]
    checks = {
        "services": all(item["healthy"] for item in services),
        "failed_units": _failed_ok and not bool(failed_unit_lines),
        "metrics": metric_age is not None and metric_age <= CACHE_MAX_AGE,
        "database": database["ok"],
        "database_size": database["within_soft_limit"],
        # No completed backup is "not configured/unknown", not a broken service.
        "backups": backup_age is None or backup_age <= 604800,
        "components": not failures,
        "web_upstream": upstream_ok,
    }
    payload = {
        "time": now,
        "healthy": all(checks.values()),
        "checks": checks,
        "services": services,
        "failed_units": failed_unit_lines[-20:],
        "metrics": {"last_sample_at": current["time"] if current else None, "age_seconds": metric_age, "max_age_seconds": CACHE_MAX_AGE},
        "backups": {"last_success_at": backups[0]["finished_at"] if backups else None, "age_seconds": backup_age, "max_age_seconds": 604800, "configured_or_unknown": backup_age is None},
        "database": database,
        "component_failures": failures,
    }
    _write_cache(payload, cache)
    return payload


def report(now: float | None = None, path: Path = DB, cache: Path = CACHE) -> dict:
    """Return a fresh cached health report; collect only when no cache exists."""
    now = time.time() if now is None else now
    cache = _cache_path(path, cache)
    cached = _read_cache(cache)
    if cached and isinstance(cached.get("time"), (int, float)):
        cached["cache_age_seconds"] = max(0.0, now - float(cached["time"]))
        cached["cached"] = True
        return cached
    payload = collect(now=now, path=path, cache=cache)
    payload["cache_age_seconds"] = 0.0
    payload["cached"] = False
    return payload
