#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("monitoring_v3", Path(__file__).with_name("v3.py"))
bot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bot)


class SSHLoginMonitorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.log = root / "auth.log"
        self.state = root / "state.json"
        self.allowlist = root / "allowlist.json"
        self.log.write_text("")
        self.allowlist.write_text(json.dumps({"allowed_networks": ["192.0.2.10/32", "198.51.100.20/32", "203.0.113.10/32"]}))
        self.old_paths = bot.SSH_LOG_PATH, bot.SSH_STATE_FILE, bot.SSH_ALLOWLIST_FILE
        bot.SSH_LOG_PATH, bot.SSH_STATE_FILE, bot.SSH_ALLOWLIST_FILE = self.log, self.state, self.allowlist
        self.sent = []
        self.old_send = bot.send
        bot.send = lambda message: self.sent.append(message) or True

    def tearDown(self):
        bot.SSH_LOG_PATH, bot.SSH_STATE_FILE, bot.SSH_ALLOWLIST_FILE = self.old_paths
        bot.send = self.old_send
        self.directory.cleanup()

    def test_alerts_only_for_new_untrusted_successes(self):
        self.log.write_text("Sep 24 16:00:00 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2\n")
        self.assertEqual(bot.check_ssh_logins(), [])  # initial run starts at EOF
        with self.log.open("a") as handle:
            handle.write("2026-09-24T16:01:00+00:00 host sshd[2]: Failed password for root from 8.8.8.8 port 23 ssh2\n")
            handle.write("Sep 24 16:02:00 host sshd[3]: Accepted publickey for ai from 198.51.100.20 port 24 ssh2: ED25519 SHA256:test\n")
            handle.write("Sep 24 16:03:00 host sshd[4]: Accepted password for root from 8.8.8.8 port 25 ssh2\n")
        alerts = bot.check_ssh_logins()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "8.8.8.8")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(bot.check_ssh_logins(), [])  # offset prevents duplicates

    def test_allowed_networks_and_power_confirmation(self):
        self.assertTrue(bot.is_allowed_ssh_ip("192.0.2.10"))
        self.assertFalse(bot.is_allowed_ssh_ip("192.0.2.11"))
        old_state, old_serverctl = bot.ACTION_STATE_FILE, bot.SERVERCTL
        bot.ACTION_STATE_FILE, bot.SERVERCTL = Path(self.directory.name) / "action.json", Path("/missing-serverctl")
        try:
            message = bot.request_power_action("reboot")
            token = message.split(" confirm ", 1)[1].split(" ", 1)[0]
            ok, reason = bot.execute_power_action("reboot", token)
            self.assertFalse(ok)
            self.assertIn("missing", reason)
        finally:
            bot.ACTION_STATE_FILE, bot.SERVERCTL = old_state, old_serverctl

    def test_totp_login_session(self):
        old_config, old_state, old_totp = bot.AUTH_CONFIG_FILE, bot.AUTH_STATE_FILE, bot.totp_valid
        bot.AUTH_CONFIG_FILE = Path(self.directory.name) / "auth.json"
        bot.AUTH_STATE_FILE = Path(self.directory.name) / "auth-state.json"
        bot.AUTH_CONFIG_FILE.write_text(json.dumps({"allowed_user_ids": ["TGID"], "totp_secret": "TEST", "session_seconds": 3600}))
        bot.totp_valid = lambda secret, code: secret == "TEST" and code == "123456"
        try:
            ok, _ = bot.login("TGID", "123456")
            self.assertTrue(ok)
            self.assertTrue(bot.authenticated("TGID"))
            bot.logout("TGID")
            self.assertFalse(bot.authenticated("TGID"))
        finally:
            bot.AUTH_CONFIG_FILE, bot.AUTH_STATE_FILE, bot.totp_valid = old_config, old_state, old_totp

    def test_power_confirmation_preserves_case(self):
        old_execute, old_send = bot.execute_power_action, bot.send
        received = []
        try:
            bot.execute_power_action = lambda action, token: (received.extend([action, token]) or (True, "Command accepted."))
            bot.send = lambda message: True
            bot.process_authenticated_command("/reboot confirm AbC_XyZ")
            self.assertEqual(received, ["reboot", "AbC_XyZ"])
        finally:
            bot.execute_power_action, bot.send = old_execute, old_send
    def test_ai_command_uses_existing_authenticated_dispatch(self):
        old_send = bot.send
        messages = []
        try:
            bot.send = lambda message, **kwargs: messages.append((message, kwargs)) or True
            with patch("v4.telegram_ai.ask") as ask:
                ask.return_value = type("Reply", (), {"text": "safe AI report"})()
                token = bot.CURRENT_USER_ID.set("TGID")
                try:
                    bot.process_authenticated_command("/ai Why is the server slow?")
                finally:
                    bot.CURRENT_USER_ID.reset(token)
            ask.assert_called_once_with("TGID", "Why is the server slow?")
            self.assertIn("safe AI report", messages[0][0])
        finally:
            bot.send = old_send


class ServerAvailabilityTests(unittest.TestCase):
    def test_tcp_fallback_confirms_a_live_host_when_icmp_is_filtered(self):
        with patch.object(bot, "ping", return_value=False), patch.object(bot, "tcp_reachable", return_value=22):
            result = bot.probe_server("203.0.113.42")
        self.assertTrue(result["alive"])
        self.assertEqual(result["method"], "TCP")
        self.assertEqual(result["port"], 22)

    def test_unconfirmed_is_not_reported_as_no_icmp(self):
        with patch.object(bot, "ping", return_value=False), patch.object(bot, "tcp_reachable", return_value=None):
            result = bot.probe_server("203.0.113.42")
        self.assertFalse(result["alive"])
        self.assertEqual(result["method"], "unconfirmed")

    def test_configured_tcp_ports_are_validated(self):
        with patch.dict(bot.os.environ, {"MONITORINGBOT_SERVER_TCP_PORTS": "22, 443, 0, bad, 443, 70000"}):
            self.assertEqual(bot.server_tcp_ports(), (22, 443))


if __name__ == "__main__":
    unittest.main()
