import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import incidents, metrics
from v4.storage import connect, rows
from v4.webapp import metric_payload


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"

    def tearDown(self):
        self.temp.cleanup()

    def sample(self, clock, rx=0, tx=0, read=0, write=0, cpu=10):
        return {"time": clock, "cpu": cpu, "load1": 0.5, "mem_used": 10, "mem_cached": 5,
                "mem_available": 20, "disk_used": 30, "disk_total": 100, "rx": rx, "tx": tx,
                "read": read, "write": write}

    def test_ranges_and_counter_reset_never_return_negative_rate(self):
        metrics.record(self.sample(1000, rx=10_000, read=20_000), path=self.db)
        metrics.record(self.sample(1060, rx=70_000, read=80_000), path=self.db)
        metrics.record(self.sample(1120, rx=1_000, read=2_000), path=self.db)  # reboot/reset
        points = metrics.query("1h", now=1120, path=self.db)
        self.assertEqual(len(points), 3)
        self.assertTrue(all(point["rx"] >= 0 and point["read"] >= 0 for point in points))
        self.assertIn("30d", metrics.RANGES)
        with self.assertRaises(ValueError):
            metrics.query("forever", now=1120, path=self.db)

    def test_downsampling_keeps_cpu_peak_and_is_bounded(self):
        for index in range(800):
            metrics.record(self.sample(2000 + index, rx=index * 10, cpu=99 if index == 333 else 2), path=self.db)
        points = metrics.query("1h", limit=100, now=2800, path=self.db)
        self.assertLessEqual(len(points), 100)
        self.assertEqual(max(point["cpu"] for point in points), 99)

    def test_retention_removes_old_points(self):
        old = 2_000_000
        metrics.record(self.sample(old), now=old, path=self.db)
        metrics.record(self.sample(old + metrics.RETENTION_SECONDS + 1), now=old + metrics.RETENTION_SECONDS + 1, path=self.db)
        self.assertEqual(len(rows("SELECT * FROM metric_samples", path=self.db)), 1)


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"
        self.connect_patch = patch.object(incidents, "connect", lambda: connect(self.db))
        self.audit_patch = patch.object(incidents, "audit", lambda *args, **kwargs: None)
        self.connect_patch.start(); self.audit_patch.start()

    def tearDown(self):
        self.connect_patch.stop(); self.audit_patch.stop(); self.temp.cleanup()

    def test_recovery_auto_closes_and_repeat_opens_new_incident(self):
        first, event = incidents.observe("CPU", "high", True, 95, 90)
        self.assertEqual(event, "opened")
        recovered, event = incidents.observe("CPU", "high", False, 20, 90)
        self.assertEqual((recovered, event), (first, "recovered"))
        record = rows("SELECT * FROM incidents WHERE id=?", (first,), self.db)[0]
        self.assertEqual(record["status"], "closed")
        self.assertIsNotNone(record["recovered_at"])
        second, event = incidents.observe("CPU", "high", True, 96, 90)
        self.assertEqual(event, "opened")
        self.assertNotEqual(first, second)

    def test_close_all_closes_active_only(self):
        incidents.observe("CPU", "high", True, 95, 90)
        incidents.observe("Traffic", "high", True, 99, 90)
        self.assertEqual(incidents.close_all("42"), 2)
        self.assertEqual(rows("SELECT count(*) AS n FROM incidents WHERE status='active'", path=self.db)[0]["n"], 0)


class ApiContractTests(unittest.TestCase):
    def test_metric_payload_uses_ranges_and_keeps_legacy_aliases(self):
        with patch("v4.webapp.metric_query", return_value=[{"time": 1}]) as query, patch("v4.webapp.metric_latest", return_value=None):
            self.assertEqual(metric_payload("hour")["range"], "1h")
            query.assert_called_with("1h")
        with self.assertRaises(ValueError):
            metric_payload("bad")


if __name__ == "__main__":
    unittest.main()

class HttpApiTests(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        from v4 import webapp
        self.webapp = webapp
        self.auth = patch.object(webapp.Handler, "auth", lambda _handler: ("test-user", "test-user"))
        self.auth.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.auth.stop()

    def request(self, path, method="GET"):
        from urllib.request import Request, urlopen
        with urlopen(Request(f"http://127.0.0.1:{self.server.server_port}{path}", method=method), timeout=3) as response:
            return response.status, response.read().decode()

    def test_metrics_and_bulk_close_api_contracts(self):
        with patch.object(self.webapp, "metric_payload", return_value={"range": "1h", "samples": []}):
            status, body = self.request("/api/metrics?range=1h")
            self.assertEqual(status, 200)
            self.assertIn('"range": "1h"', body)
        with patch.object(self.webapp, "close_all", return_value=3):
            status, body = self.request("/api/incidents/close-all", "POST")
            self.assertEqual(status, 200)
            self.assertIn('"closed": 3', body)

class CollectorTests(MetricsTests):
    def test_collector_uses_cpu_measurement_and_records_version_two(self):
        with patch("v4.metrics.cpu_percent", return_value=17.5), \
             patch("v4.metrics.psutil.virtual_memory") as memory, \
             patch("v4.metrics.psutil.disk_usage") as disk, \
             patch("v4.metrics.psutil.net_io_counters") as network, \
             patch("v4.metrics.psutil.disk_io_counters") as io:
            memory.return_value = type("M", (), {"used": 1, "cached": 2, "available": 3})()
            disk.return_value = type("D", (), {"used": 4, "total": 5})()
            network.return_value = type("N", (), {"bytes_recv": 6, "bytes_sent": 7})()
            io.return_value = type("I", (), {"read_bytes": 8, "write_bytes": 9})()
            sample = metrics.collect()
        self.assertEqual(sample["cpu"], 17.5)

    def test_legacy_samples_are_retained_but_excluded(self):
        with connect(self.db) as connection:
            connection.execute("INSERT INTO metric_samples(time,cpu,load1,mem_used,mem_cached,mem_available,disk_used,disk_total,rx,tx,read_bytes,write_bytes,sample_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (1000, 100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1))
        metrics.record(self.sample(1060, cpu=10), path=self.db)
        metrics.record(self.sample(1120, cpu=20), path=self.db)
        points = metrics.query("1h", now=1120, path=self.db)
        self.assertEqual(max(point["cpu"] for point in points), 20)
        self.assertEqual(rows("SELECT count(*) AS n FROM metric_samples", path=self.db)[0]["n"], 3)

    def test_latest_timestamp_is_freshest_version_two_sample(self):
        metrics.record(self.sample(1000), path=self.db)
        metrics.record(self.sample(1060), path=self.db)
        self.assertEqual(metrics.latest(self.db)["time"], 1060)


class AIProxyTests(unittest.TestCase):
    def test_rejects_bad_history_without_contacting_upstream(self):
        from v4 import ai
        with self.assertRaises(ai.AIError):
            ai.validate_messages([{"role": "system", "content": "secret"}])
        with self.assertRaises(ai.AIError):
            ai.validate_messages([{"role": "user", "content": ""}])

    def test_stream_parses_openai_sse_without_exposing_token(self):
        from v4 import ai
        class Response:
            status_code = 200
            def iter_lines(self, decode_unicode=True):
                return iter(['data: {"choices":[{"delta":{"content":"Hello"}}]}', '', 'data: {"choices":[{"delta":{"content":" world"}}]}', '', 'data: [DONE]'])
        with patch.dict("os.environ", {"TIMEWEB_AI_OPENAI_URL": "https://example.test/chat/completions", "TIMEWEB_AI_API_TOKEN": "private"}, clear=False), patch("v4.ai.requests.post", return_value=Response()) as post:
            self.assertEqual(''.join(ai.stream([{"role":"user", "content":"Hi"}])), "Hello world")
            self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer private")
