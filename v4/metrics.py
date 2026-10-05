"""Lightweight local telemetry collection and bounded chart payloads."""
import os
import time

import psutil

from .storage import DB, connect, rows

RETENTION_SECONDS = 30 * 86400
RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
SAMPLE_VERSION = 2
CPU_INTERVAL_SECONDS = 1.0


def cpu_percent(interval=CPU_INTERVAL_SECONDS):
    """Use a meaningful one-second system-wide interval, not a volatile 100ms burst."""
    return psutil.cpu_percent(interval=interval)


def collect(cpu_interval=CPU_INTERVAL_SECONDS):
    """Read cheap local counters; service and network checks do not run per point."""
    # CPU is measured over an interval while monotonic counters continue accumulating.
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
    }


def record(sample=None, now=None, path=DB):
    """Persist one raw counter sample and keep a bounded, versioned history."""
    sample = sample or collect()
    now = now if now is not None else sample["time"]
    values = (now, sample["cpu"], sample["load1"], sample["mem_used"], sample["mem_cached"],
              sample["mem_available"], sample["disk_used"], sample["disk_total"], sample["rx"],
              sample["tx"], sample["read"], sample["write"], SAMPLE_VERSION)
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO metric_samples(time,cpu,load1,mem_used,mem_cached,mem_available,"
            "disk_used,disk_total,rx,tx,read_bytes,write_bytes,sample_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
        connection.execute("DELETE FROM metric_samples WHERE time < ?", (now - RETENTION_SECONDS,))


def _rate(first, last, field, seconds):
    """Counter resets after reboot/interface reset become zero, never negative."""
    return max(0.0, (last[field] - first[field]) / max(seconds, 1.0))


def _bucket(group):
    def rate(field):
        return max(_rate(group[index - 1], item, field, item["time"] - group[index - 1]["time"])
                   for index, item in enumerate(group) if index)
    last = group[-1]
    return {
        "time": last["time"], "cpu": max(item["cpu"] for item in group),
        "load1": max(item["load1"] for item in group), "mem_used": last["mem_used"],
        "mem_cached": last["mem_cached"], "mem_available": last["mem_available"],
        "disk_used": last["disk_used"], "disk_total": last["disk_total"],
        "rx": rate("rx"), "tx": rate("tx"), "read": rate("read_bytes"), "write": rate("write_bytes"),
    }


def latest(path=DB):
    values = rows("SELECT * FROM metric_samples WHERE sample_version=? ORDER BY time DESC LIMIT 1", (SAMPLE_VERSION,), path)
    return values[0] if values else None


def query(period="1h", limit=360, now=None, path=DB):
    """Return bounded peak-preserving v2 telemetry for a supported period."""
    if period not in RANGES:
        raise ValueError("unsupported metric range")
    now = time.time() if now is None else now
    raw = rows("SELECT * FROM metric_samples WHERE sample_version=? AND time >= ? ORDER BY time", (SAMPLE_VERSION, now - RANGES[period]), path)
    if len(raw) < 2:
        return []
    bucket_size = max(1, (len(raw) + limit - 1) // limit)
    output = []
    for index in range(0, len(raw), bucket_size):
        group = raw[index:index + bucket_size]
        if len(group) == 1:
            group = [raw[index - 1] if index else group[0], group[0]]
        output.append(_bucket(group))
    return output
