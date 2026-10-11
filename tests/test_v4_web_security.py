"""Security contract tests for the WebUI HTTP surface."""
from __future__ import annotations

import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from v4 import webapp


# These are the only unauthenticated GET resources intentionally served by the
# Python app. nginx still applies its browser IP allow-list before this layer.
PUBLIC_GET_PATHS = {
    "/": {200},
    "/static/app.css": {200},
    "/static/app.js": {200},
    "/static/favicon.svg": {200},
    "/download/aaaaaaaaaaaaaaaaaaaa": {404},
}

AUTH_GET_PATHS = {
    "/api/session",
    "/api/dashboard",
    "/api/self-monitoring",
    "/api/metrics?range=1h",
    "/api/backups",
    "/api/backups/destinations",
    "/api/library",
    "/api/library/example",
    "/api/incidents",
    "/api/incidents/1",
    "/api/audit",
    "/api/runs",
    "/api/runs/00000000-0000-0000-0000-000000000000",
    "/api/firewall",
    "/api/settings",
    "/api/not-registered",
}

AUTH_POST_PATHS = {
    "/api/totp",
    "/api/ai/chat",
    "/api/console",
    "/api/tools/password",
    "/api/tools/ssl",
    "/api/tools/checkhost",
    "/api/tools/cheburcheck",
    "/api/firewall/preview",
    "/api/firewall/request",
    "/api/firewall/confirm",
    "/api/firewall/keep",
    "/api/firewall/rollback",
    "/api/backups",
    "/api/runs",
    "/api/commands/status",
    "/api/actions/ssh",
    "/api/actions/power",
    "/api/logout",
    "/api/incidents/close-all",
    "/api/not-registered",
}


class WebDenyByDefaultTests(unittest.TestCase):
    def setUp(self):
        self.auth = patch.object(webapp.Handler, "auth", lambda _handler: (None, None))
        self.download = patch.object(webapp, "library_download", return_value=None)
        self.auth.start()
        self.download.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.download.stop()
        self.auth.stop()

    def request_status(self, path: str, method: str = "GET") -> int:
        request = Request(f"http://127.0.0.1:{self.server.server_port}{path}", method=method)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status
        except HTTPError as error:
            return error.code

    def test_only_explicit_public_get_resources_bypass_authentication(self):
        for path, accepted in PUBLIC_GET_PATHS.items():
            with self.subTest(path=path):
                self.assertIn(self.request_status(path), accepted)

    def test_every_registered_get_api_path_denies_anonymous_access(self):
        for path in AUTH_GET_PATHS:
            with self.subTest(path=path):
                self.assertIn(self.request_status(path), {401, 403})

    def test_every_registered_post_api_path_denies_anonymous_access(self):
        for path in AUTH_POST_PATHS:
            with self.subTest(path=path):
                self.assertIn(self.request_status(path, "POST"), {401, 403})


if __name__ == "__main__":
    unittest.main()
