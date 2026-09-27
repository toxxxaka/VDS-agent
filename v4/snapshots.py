"""Low-overhead current system facts and incident snapshots."""
import json
import os
import subprocess
import time

import psutil

from .storage import connect

SERVICE_NAMES = ("nginx", "ssh", "docker", "fail2ban", "mariadb", "mysql", "redis-server")


def service_states():
    states = []
    for name in SERVICE_NAMES:
        try:
            result = subprocess.run(["/usr/bin/systemctl", "is-active", name], stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=2, check=False)
            value = result.stdout.strip()
            states.append({"name": name, "state": value if value in {"active", "inactive", "failed"} else "unknown"})
        except (OSError, subprocess.TimeoutExpired):
            states.append({"name": name, "state": "unknown"})
    return states


def overview():
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    io = psutil.disk_io_counters()
    return {
        "time": time.time(),
        "hostname": os.uname().nodename,
        "cpu": {"percent": psutil.cpu_percent(interval=0.1), "cores": psutil.cpu_count() or 0, "load": list(os.getloadavg())},
        "memory": {"total": memory.total, "available": memory.available, "used": memory.used, "cached": getattr(memory, "cached", 0), "percent": memory.percent, "swap_percent": swap.percent},
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free, "percent": disk.percent},
        "network": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv, "packets_sent": net.packets_sent, "packets_recv": net.packets_recv, "errin": net.errin, "errout": net.errout, "dropin": net.dropin, "dropout": net.dropout},
        "disk_io": {"read_bytes": io.read_bytes if io else 0, "write_bytes": io.write_bytes if io else 0},
        "services": service_states(),
    }


def capture(kind):
    data = overview()
    data["kind"] = kind
    processes = []
    for process in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info"]):
        try:
            processes.append({"pid": process.info["pid"], "name": process.info["name"], "user": process.info["username"], "cpu": process.info["cpu_percent"], "rss": process.info["memory_info"].rss})
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    data["top_cpu"] = sorted(processes, key=lambda item: item["cpu"], reverse=True)[:10]
    data["top_rss"] = sorted(processes, key=lambda item: item["rss"], reverse=True)[:10]
    with connect() as connection:
        cursor = connection.execute("INSERT INTO snapshots(time,kind,data) VALUES(?,?,?)", (time.time(), kind, json.dumps(data)))
        return cursor.lastrowid, data


def record_metric():
    data = overview()
    with connect() as connection:
        cursor = connection.execute("INSERT INTO snapshots(time,kind,data) VALUES(?,?,?)", (time.time(), "periodic", json.dumps(data)))
        return cursor.lastrowid
