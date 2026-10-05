"""Bounded, non-secret checks of Monitoringbot's own health."""
import sqlite3
import subprocess
import time
from pathlib import Path
from .metrics import latest
from .storage import DB, rows

UNITS = ("monitoringbot.service", "monitorbot-web.service", "monitorbot-health.service", "monitorbot-snapshot.timer", "monitorbot-oom.service", "monitorbot-infrad.service")

def report(now=None, path=DB):
    now = time.time() if now is None else now
    units = []
    for unit in UNITS:
        try:
            state = subprocess.run(["/usr/bin/systemctl", "is-active", unit], stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=3, check=False).stdout.strip()
        except (OSError, subprocess.TimeoutExpired): state = "unknown"
        units.append({"unit": unit, "state": state, "healthy": state in {"active", "waiting"}})
    current = latest(path); age = None if not current else max(0, now-current["time"])
    db = {"ok": False, "size_bytes": 0, "wal_bytes": 0}
    try:
        db["size_bytes"] = path.stat().st_size; wal = Path(str(path)+"-wal"); db["wal_bytes"] = wal.stat().st_size if wal.exists() else 0
        with sqlite3.connect(path, timeout=3) as c: db["ok"] = c.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    except (OSError, sqlite3.Error): pass
    failed = rows("SELECT command,status,started_at FROM command_runs WHERE status IN ('failed','timeout') AND started_at>=? ORDER BY started_at DESC LIMIT 10", (now-86400,), path=path)
    backups = rows("SELECT finished_at FROM command_runs WHERE command='backup' AND status='completed' ORDER BY finished_at DESC LIMIT 1", path=path)
    backup_age = None if not backups or backups[0]["finished_at"] is None else max(0, now-backups[0]["finished_at"])
    checks = {"services": all(x["healthy"] for x in units), "metrics": age is not None and age <= 180, "database": db["ok"], "backups": backup_age is not None and backup_age <= 604800, "components": not failed}
    return {"time": now, "healthy": all(checks.values()), "checks": checks, "services": units, "metrics": {"last_sample_at": current["time"] if current else None, "age_seconds": age, "max_age_seconds": 180}, "backups": {"last_success_at": backups[0]["finished_at"] if backups else None, "age_seconds": backup_age, "max_age_seconds": 604800}, "database": db, "component_failures": failed}
