import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from unittest.mock import patch

from v4 import webapp


class SupportNotificationTests(unittest.TestCase):
    def test_support_notification_is_bounded_and_html_escaped(self):
        sent = []
        sender = type("Sender", (), {"send": lambda _self, value: sent.append(value) or True})()
        with patch.object(webapp, "load_v3", return_value=sender):
            self.assertTrue(webapp.notify_support("demo:<one>", "Need <reply@example.test>"))
        self.assertIn("&lt;one&gt;", sent[0])
        self.assertIn("&lt;reply@example.test&gt;", sent[0])

    def test_support_notification_rejects_empty_or_oversized_messages(self):
        with self.assertRaises(ValueError):
            webapp.notify_support("demo:1", "  ")
        with self.assertRaises(ValueError):
            webapp.notify_support("demo:1", "x" * 2001)

    def test_authenticated_api_sends_request_to_owner_channel(self):
        with patch.object(webapp.Handler, "auth", lambda _handler: ("demo:7", "demo:7")), \
             patch.object(webapp, "notify_support", return_value=True) as notify, \
             patch.object(webapp, "audit"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                payload = json.dumps({"message": "Reply: test@example.test"}).encode()
                request = Request(f"http://127.0.0.1:{server.server_port}/api/support", data=payload, method="POST", headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=3) as response:
                    self.assertEqual(response.status, 202)
                    self.assertTrue(json.loads(response.read())["ok"])
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)
        notify.assert_called_once_with("demo:7", "Reply: test@example.test")
