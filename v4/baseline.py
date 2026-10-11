"""Adaptive, shadow-only baselines from local telemetry.

The module never changes alert state itself. Callers must keep it in shadow mode
for at least seven days and explicitly enable enforcement in a later release.
"""
from __future__ import annotations

import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .metrics import SAMPLE_VERSION
from .storage import DB, rows

MIN_SAMPLES = 7
MAD_MULTIPLIER = 6.0


def hourly_profile(field: str, now: float | None = None, path: Path = DB, days: int = 7) -> dict[int, dict]:
    if field not in {"cpu", "load1"}:
        raise ValueError("unsupported baseline field")
    now = time.time() if now is None else now
    values = rows("SELECT time," + field + " AS value FROM metric_samples WHERE sample_version=? AND time>=? ORDER BY time", (SAMPLE_VERSION, now - days * 86400), path)
    grouped: dict[int, list[float]] = {hour: [] for hour in range(24)}
    for row in values:
        grouped[datetime.fromtimestamp(float(row["time"]), timezone.utc).hour].append(float(row["value"]))
    result = {}
    for hour, samples in grouped.items():
        if len(samples) < MIN_SAMPLES:
            continue
        median = statistics.median(samples)
        mad = statistics.median(abs(item - median) for item in samples)
        result[hour] = {"samples": len(samples), "median": median, "mad": mad, "upper": median + MAD_MULTIPLIER * max(mad, 0.1)}
    return result


def shadow(field: str, value: float, now: float | None = None, path: Path = DB) -> dict:
    now = time.time() if now is None else now
    hour = datetime.fromtimestamp(now, timezone.utc).hour
    profile = hourly_profile(field, now, path)
    baseline = profile.get(hour)
    return {"field": field, "value": value, "hour_utc": hour, "ready": baseline is not None, "baseline": baseline, "would_alert": bool(baseline and value > baseline["upper"])}
