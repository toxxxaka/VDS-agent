from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import alerting, config, flight_recorder, metrics, tasks
from v4.storage import connect, rows


class ConfigTests(unittest.TestCase):
    def test_feature_flags_and_invalid_values_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"telemetry": {"flight_recorder_enabled": True}, "features": {"telegram_outbox": True}}))
            settings = config.load(path)
            self.assertTrue(settings.telemetry.flight_recorder_enabled)
            self.assertTrue(settings.features.telegram_outbox)
            path.write_text('{"telemetry":{"raw_retention_days":0}}')
            with self.assertRaises(ValueError):
                config.load(path)


class AlertStateTests(unittest.TestCase):
    def test_for_window_hysteresis_and_recovery_window(self):
        self.assertTrue(alerting.threshold(91, 90, 80, False))
        self.assertTrue(alerting.threshold(85, 90, 80, True))
        self.assertFalse(alerting.threshold(79, 90, 80, True))
        policy = alerting.AlertPolicy(for_samples=2, recovery_samples=2, reminder_seconds=60)
        record, event = alerting.advance({}, True, policy, 10)
        self.assertIsNone(event)
        record, event = alerting.advance(record, True, policy, 11)
        self.assertEqual(event, "opened")
        record, event = alerting.advance(record, False, policy, 12)
        self.assertIsNone(event)
        _record, event = alerting.advance(record, False, policy, 13)
        self.assertEqual(event, "recovered")


class FlightRecorderTests(unittest.TestCase):
    def test_ring_buffer_is_bounded_and_preserves_recent_samples(self):
        recorder = flight_recorder.FlightRecorder(interval_seconds=5, window_seconds=10, max_bytes=1000)
        recorder.append({"n": 1})
        recorder.append({"n": 2})
        recorder.append({"n": 3})
        snap = recorder.snapshot("CPU", now=20)
        self.assertEqual(snap["sample_count"], 2)
        self.assertEqual([item["n"] for item in snap["samples"]], [2, 3])
        self.assertLessEqual(snap["estimated_bytes"], 1000)


class DurableTaskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"
        self.connect = patch.object(tasks, "connect", lambda: connect(self.db))
        self.rows = patch.object(tasks, "rows", lambda query, args=(): rows(query, args, self.db))
        self.audit = patch.object(tasks, "audit", lambda *args, **kwargs: None)
        self.connect.start(); self.rows.start(); self.audit.start()

    def tearDown(self):
        self.connect.stop(); self.rows.stop(); self.audit.stop(); self.temp.cleanup()

    def test_idempotency_returns_existing_task(self):
        spec = tasks.TaskSpec("test", "Test", "", "Tests", 1, retryable=False)
        first = tasks.start_custom_run("u", spec, lambda _command: {"text": "ok"}, idempotency_key="abcdefgh")
        second = tasks.start_custom_run("u", spec, lambda _command: {"text": "new"}, idempotency_key="abcdefgh")
        self.assertEqual(first["id"], second["id"])
        deadline = time.monotonic() + 2
        while tasks.get_run(first["id"])["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(tasks.get_run(first["id"])["status"], "completed")

    def test_cancelled_queued_task_never_runs(self):
        spec = tasks.TaskSpec("test", "Test", "", "Tests", 1, retryable=False)
        # Insert directly to avoid a racing worker and exercise durable cancellation.
        now = time.time()
        with connect(self.db) as connection:
            connection.execute("INSERT INTO command_runs(id,command,title,status,user_id,started_at,details,attempts,max_attempts,next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("run", "test", "Test", "queued", "u", now, '{"retryable":false}', 0, 1, now))
        result = tasks.cancel_run("u", "run")
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(rows("SELECT count(*) AS n FROM task_events WHERE run_id='run'", path=self.db)[0]["n"], 1)


class RollupTests(unittest.TestCase):
    def test_long_range_queries_prefer_stored_rollups(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "monitoring.db"
            for offset in (0, 60, 120):
                metrics.record({"time": 1000 + offset, "cpu": 10 + offset, "load1": 1, "mem_used": 1, "mem_cached": 0, "mem_available": 1, "disk_used": 1, "disk_total": 2, "rx": offset, "tx": offset, "read": offset, "write": offset}, path=db)
            self.assertGreater(rows("SELECT count(*) AS n FROM metric_rollups", path=db)[0]["n"], 0)
            # Existing raw data remains a correct fallback while a new range's
            # rollup history is being built after an upgrade.
            self.assertTrue(metrics.query("7d", now=1120, path=db))


if __name__ == "__main__":
    unittest.main()

class OutboxTests(unittest.TestCase):
    def setUp(self):
        from v4 import outbox
        self.outbox = outbox
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"
        self.connect = patch.object(outbox, "connect", lambda: connect(self.db))
        self.rows = patch.object(outbox, "rows", lambda query, args=(): rows(query, args, self.db))
        self.connect.start(); self.rows.start()

    def tearDown(self):
        self.connect.stop(); self.rows.stop(); self.temp.cleanup()

    def test_delivery_is_idempotent_and_retries_after_failure(self):
        first = self.outbox.enqueue("telegram", {"text": "alert"}, "notification-key")
        second = self.outbox.enqueue("telegram", {"text": "duplicate"}, "notification-key")
        self.assertEqual(first["id"], second["id"])
        item = self.outbox.claim_due(now=10**11)
        self.outbox.failed(item["id"], "timeout", now=10**11)
        row = rows("SELECT * FROM notification_outbox WHERE id=?", (item["id"],), self.db)[0]
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["attempts"], 1)
