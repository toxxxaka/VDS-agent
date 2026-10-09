import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import agent_tools, availability, telegram_ai
from v4.storage import connect


class AvailabilityTests(unittest.TestCase):
    def server(self, ports=(22,), url=None):
        return {"name": "node", "host": "203.0.113.10", "tcp_ports": list(ports), "http_url": url}

    def test_icmp_blocked_tcp_available_is_up(self):
        with patch.object(availability, "_icmp", return_value=False), patch.object(availability, "_tcp", return_value=True):
            result = availability.probe(self.server())
        self.assertEqual(result["candidate"], "UP")
        self.assertFalse(result["icmp_reachable"])

    def test_partial_service_failure_is_degraded(self):
        with patch.object(availability, "_icmp", return_value=True), patch.object(availability, "_tcp", side_effect=[True, False, True, False]):
            result = availability.probe(self.server((22, 443)))
        self.assertEqual(result["candidate"], "DEGRADED")

    def test_full_outage_needs_failure_threshold_before_down(self):
        result = {"candidate": "DOWN", "name": "node", "host": "203.0.113.10", "checks": [], "icmp_reachable": False}
        first = availability.stabilise(result, {}, 2, 1)
        second = availability.stabilise(result, {"status": first["status"], "failure_streak": first["failure_streak"]}, 2, 1)
        self.assertEqual(first["status"], "DEGRADED")
        self.assertEqual(second["status"], "DOWN")

    def test_without_service_check_icmp_timeout_is_unknown(self):
        with patch.object(availability, "_icmp", return_value=False):
            result = availability.probe(self.server(ports=()))
        self.assertEqual(result["candidate"], "UNKNOWN")


class AgentToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "monitoring.db"
        self.connect = patch.object(agent_tools, "connect", lambda: connect(self.db))
        self.audit = patch.object(agent_tools, "audit", lambda *args, **kwargs: None)
        self.connect.start(); self.audit.start()

    def tearDown(self):
        self.connect.stop(); self.audit.stop(); self.tmp.cleanup()

    def test_rejects_unsafe_service_name(self):
        with self.assertRaises(agent_tools.ToolError):
            agent_tools.service_status({"units": ["ssh.service; whoami"]})

    def test_accepts_allowed_systemd_unit_name(self):
        self.assertEqual(agent_tools._unit("monitoringbot.service"), "monitoringbot.service")

    def test_admin_action_requires_second_owner_bound_confirmation(self):
        with patch.object(agent_tools, "_run", return_value={"ok": False, "error": "bridge unavailable"}):
            first = agent_tools.admin_action({"action": "restart_web"}, actor="telegram:42")
            self.assertTrue(first["confirmation_required"])
            with self.assertRaises(agent_tools.ToolError):
                agent_tools.admin_action({"action": "restart_web", "confirmation_id": first["confirmation_id"]}, actor="telegram:43")
            second = agent_tools.admin_action({"action": "restart_web", "confirmation_id": first["confirmation_id"]}, actor="telegram:42")
        self.assertFalse(second["ok"])
        self.assertIn("bridge", second.get("detail", second.get("error", "")))

    def test_network_rejects_private_resolution(self):
        with patch.object(agent_tools.socket, "getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]):
            with self.assertRaises(agent_tools.ToolError):
                agent_tools.network_diagnostics({"host": "localhost"})


class TelegramAITests(unittest.TestCase):
    def test_uses_bounded_tools_and_escapes_provider_output(self):
        with patch.object(telegram_ai, "execute", return_value={"cpu": 5}), patch.object(telegram_ai.ai, "stream", return_value=iter(["<unsafe> report"])):
            reply = telegram_ai.ask("42", "Почему сервер тормозит? Проверь процессы")
        self.assertIn("&lt;unsafe&gt;", reply.text)

    def test_confirmation_requires_owner(self):
        with patch.object(telegram_ai, "execute", return_value={"confirmation_required": True, "confirmation_id": 9, "expires_in_seconds": 90}):
            reply = telegram_ai.request_action("42", "restart_web")
        self.assertEqual(reply.confirmation_id, 9)


class McpAuthTests(unittest.TestCase):
    def test_bearer_token_is_compared_exactly(self):
        with patch.dict("os.environ", {"MONITORINGBOT_MCP_TOKEN": "test-token"}, clear=False):
            self.assertTrue(__import__("v4.mcp_http", fromlist=["_"])._token_valid("Bearer test-token"))
            self.assertFalse(__import__("v4.mcp_http", fromlist=["_"])._token_valid("Bearer wrong"))


if __name__ == "__main__":
    unittest.main()

class SelfMonitoringTests(unittest.TestCase):
    def test_self_monitoring_reports_fresh_metrics_and_healthy_components(self):
        from types import SimpleNamespace
        from v4 import metrics, self_monitoring

        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "monitoring.db"
            now = 10_000.0
            metrics.record({
                "time": now, "cpu": 5, "load1": 0.1, "mem_used": 1, "mem_cached": 1,
                "mem_available": 1, "disk_used": 1, "disk_total": 2, "rx": 1, "tx": 1,
                "read": 1, "write": 1,
            }, now=now, path=db)
            with connect(db) as connection:
                connection.execute("INSERT INTO command_runs(id,command,title,status,user_id,started_at,finished_at,details) VALUES(?,?,?,?,?,?,?,?)", ("backup", "backup", "Backup", "completed", "42", now - 20, now - 10, "{}"))
            with patch.object(self_monitoring.subprocess, "run", return_value=SimpleNamespace(stdout="active\n")):
                report = self_monitoring.report(now=now + 30, path=db)
            self.assertTrue(report["checks"]["metrics"])
            self.assertTrue(report["checks"]["database"])
            self.assertTrue(report["checks"]["backups"])
            self.assertTrue(report["healthy"])
