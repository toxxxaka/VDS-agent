from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel import vds_agent_sentinel as sentinel


CONFIG = {
    "schema": 1,
    "failure_threshold": 3,
    "recovery_threshold": 2,
    "targets": [{"name": "release", "url": "https://vds-agent.0x870x4k3r.tech/", "expected_status": [200, 399], "timeout_seconds": 8}],
}


class SentinelConfigTests(unittest.TestCase):
    def test_config_accepts_https_target_and_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel.json"
            path.write_text(json.dumps({"targets": CONFIG["targets"]}))
            config = sentinel.load_config(path)
        self.assertEqual(config["failure_threshold"], 3)
        self.assertEqual(config["recovery_threshold"], 2)
        self.assertEqual(config["targets"][0]["name"], "release")

    def test_config_rejects_http_and_duplicate_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel.json"
            path.write_text(json.dumps({"targets": [
                {"name": "one", "url": "http://example.test/"},
                {"name": "one", "url": "https://second.test/"},
            ]}))
            with self.assertRaisesRegex(ValueError, "only absolute https"):
                sentinel.load_config(path)


class SentinelStateTests(unittest.TestCase):
    def test_down_requires_three_failures_and_recovery_requires_two_successes(self):
        state: dict[str, object] = {}
        failed = sentinel.ProbeResult(False, "tcp", "connection refused")
        success = sentinel.ProbeResult(True, "https", "HTTP 200", 200)
        for counter in range(1, 3):
            state, event = sentinel.transition(state, failed, 3, 2, f"t{counter}")
            self.assertIsNone(event)
            self.assertNotEqual(state["availability"], "down")
        state, event = sentinel.transition(state, failed, 3, 2, "t3")
        self.assertEqual(event, "down")
        self.assertEqual(state["availability"], "down")
        state, event = sentinel.transition(state, success, 3, 2, "t4")
        self.assertIsNone(event)
        state, event = sentinel.transition(state, success, 3, 2, "t5")
        self.assertEqual(event, "recovered")
        self.assertEqual(state["availability"], "up")

    def test_run_once_sends_only_transition_notifications_and_writes_state(self):
        messages: list[str] = []
        results = iter([
            sentinel.ProbeResult(False, "dns", "not found"),
            sentinel.ProbeResult(False, "dns", "not found"),
            sentinel.ProbeResult(False, "dns", "not found"),
            sentinel.ProbeResult(True, "https", "HTTP 200", 200),
            sentinel.ProbeResult(True, "https", "HTTP 200", 200),
        ])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            for index in range(5):
                final, _ = sentinel.run_once(
                    CONFIG,
                    path,
                    probe=lambda _: next(results),
                    notify=lambda _, message: messages.append(message),
                    now=f"2026-10-14T00:00:0{index}+00:00",
                )
            stored = json.loads(path.read_text())
        self.assertEqual(final["targets"]["release"]["availability"], "up")
        self.assertEqual(stored["targets"]["release"]["availability"], "up")
        self.assertEqual(len(messages), 2)
        self.assertIn("unavailable", messages[0])
        self.assertIn("recovered", messages[1])


    def test_notification_failure_still_persists_down_state(self):
        results = iter([sentinel.ProbeResult(False, "dns", "not found")] * 3)

        def rejected_notification(_config, _message):
            raise RuntimeError("Telegram HTTP 400")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            for index in range(3):
                final, events = sentinel.run_once(
                    CONFIG,
                    path,
                    probe=lambda _: next(results),
                    notify=rejected_notification,
                    now=f"2026-10-14T00:00:0{index}+00:00",
                )
            stored = json.loads(path.read_text())
        self.assertEqual(events, [("down", "release")])
        self.assertEqual(final["targets"]["release"]["availability"], "down")
        self.assertEqual(stored["targets"]["release"]["availability"], "down")


class SentinelProbeTests(unittest.TestCase):
    @patch("sentinel.vds_agent_sentinel.socket.getaddrinfo", side_effect=OSError("NXDOMAIN"))
    def test_probe_identifies_dns_failure(self, _getaddrinfo):
        result = sentinel.probe_target(CONFIG["targets"][0])
        self.assertFalse(result.ok)
        self.assertEqual(result.stage, "dns")


if __name__ == "__main__":
    unittest.main()
