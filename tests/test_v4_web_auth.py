import hashlib
import hmac
import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from v4 import storage, webapp


class WebAuthReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = Path(self.directory.name) / "monitoring.db"
        self.connect = patch.object(webapp, "connect", lambda: storage.connect(self.db))
        self.connect.start()

    def tearDown(self):
        self.connect.stop()
        self.directory.cleanup()

    def test_initdata_is_single_use_until_expiry(self):
        self.assertTrue(webapp.consume_initdata("signed-init-data", "42", now=1000))
        self.assertFalse(webapp.consume_initdata("signed-init-data", "42", now=1001))
        self.assertTrue(webapp.consume_initdata("signed-init-data", "42", now=1301))

    def test_totp_time_step_is_single_use_per_principal(self):
        self.assertTrue(webapp.consume_totp_step("42", 100, now=1000))
        self.assertFalse(webapp.consume_totp_step("42", 100, now=1001))
        self.assertTrue(webapp.consume_totp_step("42", 101, now=1030))
        self.assertTrue(webapp.consume_totp_step("43", 100, now=1030))

    def test_duplicate_initdata_keys_are_rejected_before_signature_check(self):
        self.assertIsNone(webapp.initdata_ok("hash=one&hash=two&auth_date=1&user=%7B%7D"))

    def test_initdata_validation_accepts_reordered_pairs_and_rejects_bad_inputs(self):
        token = "unit-test-token"
        user = json.dumps({"id": 42}, separators=(",", ":"))
        values = {"auth_date": "1000", "user": user}
        check = "\n".join(f"{key}={values[key]}" for key in sorted(values))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        digest = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        raw = urllib.parse.urlencode([("user", user), ("hash", digest), ("auth_date", "1000")])
        with patch.object(webapp, "TOKEN", token), patch.object(webapp, "cfg", return_value={"allowed_user_ids": [42]}), patch.object(webapp.time, "time", return_value=1001):
            self.assertEqual(webapp.initdata_ok(raw), "42")
            self.assertIsNone(webapp.initdata_ok(raw.replace(digest, "0" * 64)))
            self.assertIsNone(webapp.initdata_ok(urllib.parse.urlencode([("auth_date", "1000"), ("user", user)])))
        with patch.object(webapp, "TOKEN", token), patch.object(webapp, "cfg", return_value={"allowed_user_ids": [99]}), patch.object(webapp.time, "time", return_value=1001):
            self.assertIsNone(webapp.initdata_ok(raw))
        with patch.object(webapp, "TOKEN", token), patch.object(webapp, "cfg", return_value={"allowed_user_ids": [42]}), patch.object(webapp.time, "time", return_value=1401):
            self.assertIsNone(webapp.initdata_ok(raw))

    def test_web_step_up_expires_after_sixty_seconds(self):
        with patch.object(webapp.time, "time", return_value=1000):
            session_id = webapp.new_session("42")
        cookie = f"mbs={session_id}"
        with patch.object(webapp.time, "time", return_value=1059):
            self.assertTrue(webapp.web_recent_totp(cookie, "42", now=1059))
        with patch.object(webapp.time, "time", return_value=1061):
            self.assertFalse(webapp.web_recent_totp(cookie, "42", now=1061))


if __name__ == "__main__":
    unittest.main()
