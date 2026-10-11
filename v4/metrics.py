"""Lightweight local telemetry, retention and bounded peak-preserving queries."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import psutil

from .config import load as load_settings
from .storage import DB, connect, rows

RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
SAMPLE_VERSION = 2
CPU_INTERVAL_SECONDS = 1.0
ROLLUP_5M = 300
ROLLUP_1H = 3600
# Compatibility constant for callers and existing tests. Runtime policy lives in config.
RETENTION_SECONDS = 30 * 86400


def cpu_percent(interval=CPU_INTERVAL_SECONDS):
    """Use a meaningful system-wide interval, never a scheduler burst."""
    return psutil.cpu_percent(interval=interval)


def _pressure() -> dict:
    result = {}
    for name in ("cpu", "memory", "io"):
        try:
            fields = Path(f"/proc/pressure/{name}").read_text(encoding="utf-8").splitlines()[0].split()
            values = dict(item.split("=", 1) for item in fields[1:] if "=" in item)
            result[name] = float(values.get("avg10", 0.0))
        except (OSError, ValueError, IndexError):
            result[name] = None
    return result


def _inodes() -> dict:
    try:
        usage = os.statvfs("/")
        total = usage.f_files
        used = total - usage.f_ffree if total else 0
        return {"used": used, "total": total, "percent": round((used * 100 / total), 3) if total else None}
    except OSError:
        return {"used": None, "total": None, "percent": None}


def collect(cpu_interval=CPU_INTERVAL_SECONDS):
    """Read only cheap local counters; no services or remote checks per point."""
    cpu = cpu_percent(cpu_interval)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    network = psutil.net_io_counters()
    io = psutil.disk_io_counters()
    return {
        "time": time.time(), "cpu": cpu, "load1": os.getloadavg()[0],
        "mem_used": memory.used, "mem_cached": getattr(memory, "cached", 0),
        "mem_available": memory.available, "disk_used": disk.used, "disk_total": disk.total,
        "rx": network.bytes_recv, "tx": network.bytes_sent,
        "read": io.read_bytes if io else 0, "write": io.write_bytes if io else 0,
        "pressure": _pressure(), "inodes": _inodes(),
    }


def _rate(first, last, field, seconds):
    """Counter resets after reboot/interface reset are zero, never negative."""
    return max(0.0, (last[field] - first[field]) / max(seconds, 1.0))


def _bucket(group):
    def rate(field):
        return max((_rate(group[index - 1], item, field, item["time"] - group[index - 1]["time"])
                    for index, item in enumerate(group) if index), default=0.0)
    last = group[-1]
    try:
        extra = json.loads(last.get("extra") or "{}")
    except (AttributeError, json.JSONDecodeError):
        extra = {}
    return {
        "time": last["time"], "cpu": max(item["cpu"] for item in group),
        "load1": max(item["load1"] for item in group), "mem_used": last["mem_used"],
        "mem_cached": last["mem_cached"], "mem_available": last["mem_available"],
        "disk_used": last["disk_used"], "disk_total": last["disk_total"],
        "rx": rate("rx"), "tx": rate("tx"), "read": rate("read_bytes"), "write": rate("write_bytes"),
        "pressure": extra.get("pressure", {}), "inodes": extra.get("inodes", {}),
    }


def _refresh_rollup(connection, resolution: int, now: float) -> None:
    bucket_at = now - (now % resolution)
    group = [dict(row) for row in connection.execute(
        "SELECT * FROM metric_samples WHERE sample_version=? AND time>=? AND time<? ORDER BY time",
        (SAMPLE_VERSION, bucket_at, bucket_at + resolution),
    )]
    if not group:
        return
    if len(group) == 1:
        before = connection.execute(
            "SELECT * FROM metric_samples WHERE sample_version=? AND time<? ORDER BY time DESC LIMIT 1",
            (SAMPLE_VERSION, group[0]["time"]),
        ).fetchone()
        if before is not None:
            group.insert(0, dict(before))
    payload = _bucket(group)
    connection.execute(
        "INSERT INTO metric_rollups(resolution_seconds,bucket_at,data) VALUES(?,?,?) "
        "ON CONFLICT(resolution_seconds,bucket_at) DO UPDATE SET data=excluded.data",
        (resolution, bucket_at, json.dumps(payload, separators=(",", ":"))),
    )


def _retention(connection, now: float) -> None:
    settings = load_settings().telemetry
    deleted = connection.execute("DELETE FROM metric_samples WHERE time < ?", (now - settings.raw_retention_days * 86400,)).rowcount
    connection.execute("DELETE FROM metric_rollups WHERE resolution_seconds=? AND bucket_at < ?", (ROLLUP_5M, now - settings.rollup_5m_retention_days * 86400))
    connection.execute("DELETE FROM metric_rollups WHERE resolution_seconds=? AND bucket_at < ?", (ROLLUP_1H, now - settings.rollup_1h_retention_days * 86400))
    if deleted:
        # No-op unless incremental auto-vacuum was enabled when the DB was created.
        connection.execute("PRAGMA incremental_vacuum(32)")


def record(sample=None, now=None, path=DB):
    """Persist one sample and update the two tiny rollup windows transactionally."""
    sample = sample or collect()
    now = now if now is not None else sample["time"]
    extra = {"pressure": sample.get("pressure", {}), "inodes": sample.get("inodes", {})}
    values = (now, sample["cpu"], sample["load1"], sample["mem_used"], sample["mem_cached"],
              sample["mem_available"], sample["disk_used"], sample["disk_total"], sample["rx"],
              sample["tx"], sample["read"], sample["write"], SAMPLE_VERSION, json.dumps(extra, separators=(",", ":")))
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO metric_samples(time,cpu,load1,mem_used,mem_cached,mem_available,"
            "disk_used,disk_total,rx,tx,read_bytes,write_bytes,sample_version,extra) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
        _refresh_rollup(connection, ROLLUP_5M, now)
        _refresh_rollup(connection, ROLLUP_1H, now)
        _retention(connection, now)


def latest(path=DB):
    values = rows("SELECT * FROM metric_samples WHERE sample_version=? ORDER BY time DESC LIMIT 1", (SAMPLE_VERSION,), path)
    return values[0] if values else None


def _raw(period: str, now: float, path: Path) -> list[dict]:
    return rows("SELECT * FROM metric_samples WHERE sample_version=? AND time >= ? ORDER BY time", (SAMPLE_VERSION, now - RANGES[period]), path)


def _rollup(period: str, now: float, path: Path) -> list[dict]:
    resolution = ROLLUP_5M if period == "7d" else ROLLUP_1H
    values = rows("SELECT data FROM metric_rollups WHERE resolution_seconds=? AND bucket_at>=? ORDER BY bucket_at", (resolution, now - RANGES[period]), path)
    output = []
    for row in values:
        try:
            payload = json.loads(row["data"])
            if isinstance(payload, dict):
                output.append(payload)
        except json.JSONDecodeError:
            continue
    return output


def query(period="1h", limit=360, now=None, path=DB):
    """Return bounded samples. Long ranges prefer stored rollups and preserve peaks."""
    if period not in RANGES:
        raise ValueError("unsupported metric range")
    now = time.time() if now is None else now
    limit = max(2, min(int(limit), 720))
    raw = _rollup(period, now, path) if period in {"7d", "30d"} else _raw(period, now, path)
    if len(raw) < 2:
        raw = _raw(period, now, path)
    if len(raw) < 2:
        return []
    bucket_size = max(1, (len(raw) + limit - 1) // limit)
    output = []
    for index in range(0, len(raw), bucket_size):
        group = raw[index:index + bucket_size]
        if len(group) == 1:
            group = [raw[index - 1] if index else group[0], group[0]]
        # rollups already contain rates, so preserve their peak values directly.
        if "read_bytes" not in group[0]:
            result = dict(group[-1])
            for key in ("cpu", "load1", "rx", "tx", "read", "write"):
                result[key] = max(float(item.get(key, 0)) for item in group)
            output.append(result)
        else:
            output.append(_bucket(group))
    return output
