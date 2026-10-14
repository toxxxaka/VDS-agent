"""Synthetic telemetry for the public product demonstration.

It intentionally never reads the host collector or production metrics database.
"""
from __future__ import annotations

import math
import time
from pathlib import Path

from . import metrics


def ensure(path: Path, now: float | None = None) -> None:
    """Seed a bounded 24-hour history and append one demo point per minute."""
    current = time.time() if now is None else now
    latest = metrics.latest(path=path)
    if latest and current - float(latest["time"]) < 55:
        return
    start = current - 24 * 3600 if not latest else float(latest["time"]) + 60
    for timestamp in range(int(start // 60 * 60), int(current // 60 * 60) + 1, 60):
        phase = timestamp / 1800
        cpu = 23 + 13 * math.sin(phase) + 5 * math.sin(phase * 2.7)
        available = int((1.25 + .18 * math.cos(phase / 2)) * 1024**3)
        metrics.record({
            "time": timestamp,
            "cpu": round(max(4, min(72, cpu)), 2),
            "load1": round(max(.04, cpu / 100), 2),
            "mem_used": int(0.72 * 1024**3),
            "mem_cached": int(.22 * 1024**3),
            "mem_available": available,
            "disk_used": int(13.8 * 1024**3),
            "disk_total": int(30 * 1024**3),
            "rx": timestamp * 1200,
            "tx": timestamp * 540,
            "read": timestamp * 140,
            "write": timestamp * 90,
            "pressure": {"cpu": 0.0, "memory": 0.0, "io": 0.0},
            "inodes": {"used": 100000, "total": 1000000, "percent": 10.0},
        }, path=path)
