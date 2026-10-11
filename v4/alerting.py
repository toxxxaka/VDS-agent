"""Deterministic alert state machine used by lightweight collectors."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlertPolicy:
    for_samples: int = 3
    recovery_samples: int = 1
    reminder_seconds: int = 900
    severity: str = "high"
    quiet: bool = False


def threshold(value: float, trigger: float, clear: float, was_active: bool) -> bool:
    """Apply hysteresis: an open alert clears only below its lower boundary."""
    return value >= (clear if was_active else trigger)


def advance(record: dict | None, active: bool, policy: AlertPolicy, now: float) -> tuple[dict, str | None]:
    record = dict(record or {})
    record.setdefault("count", 0)
    record.setdefault("recovery_count", 0)
    record.setdefault("active", False)
    record.setdefault("last_sent", 0.0)
    record.setdefault("reminders", 0)
    if active:
        record["count"] += 1
        record["recovery_count"] = 0
        if not record["active"] and record["count"] >= policy.for_samples:
            record.update({"active": True, "reminders": 0, "last_sent": now})
            return record, "opened"
        if record["active"]:
            wait = policy.reminder_seconds * min(16, 2 ** record["reminders"])
            if now - float(record["last_sent"]) >= wait:
                record["last_sent"] = now
                record["reminders"] += 1
                return record, "reminder"
        return record, None
    record["count"] = 0
    if not record["active"]:
        return record, None
    record["recovery_count"] += 1
    if record["recovery_count"] >= policy.recovery_samples:
        record.update({"active": False, "recovery_count": 0, "reminders": 0, "last_sent": now})
        return record, "recovered"
    return record, None
