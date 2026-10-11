"""Bounded in-memory pre-trigger telemetry buffer.

It is intentionally process-local: retained evidence is persisted only when an
incident opens, avoiding continuous high-frequency writes to SQLite.
"""
from __future__ import annotations

import json
import time
from collections import deque


class FlightRecorder:
    def __init__(self, interval_seconds: int = 5, window_seconds: int = 300, max_bytes: int = 512_000):
        self.interval_seconds = interval_seconds
        self.max_bytes = max_bytes
        self.samples = deque(maxlen=max(1, window_seconds // interval_seconds))
        self.bytes = 0
        self.dropped = 0

    def append(self, sample: dict) -> None:
        payload = json.dumps(sample, separators=(",", ":"), ensure_ascii=False)
        size = len(payload.encode())
        if size > self.max_bytes:
            self.dropped += 1
            return
        while self.samples and self.bytes + size > self.max_bytes:
            self.bytes -= len(json.dumps(self.samples.popleft(), separators=(",", ":"), ensure_ascii=False).encode())
            self.dropped += 1
        self.samples.append(sample)
        self.bytes += size

    def snapshot(self, kind: str, now: float | None = None) -> dict:
        return {
            "kind": kind,
            "captured_at": time.time() if now is None else now,
            "interval_seconds": self.interval_seconds,
            "sample_count": len(self.samples),
            "estimated_bytes": self.bytes,
            "dropped": self.dropped,
            "samples": list(self.samples),
        }
