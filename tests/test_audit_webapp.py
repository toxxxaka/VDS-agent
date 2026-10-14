import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import audit_webapp, storage, webapp


class AuditWebTotpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "audit.db"
        self.connection = patch.object(webapp, "connect", lambda: storage.connect(self.db))
        self.config = patch.object(webapp, "cfg", lambda: {"max_failures": 3, "lockout_seconds": 60})
        self.connection.start()
        self.config.start()

    def tearDown(self):
        self.config.stop()
        self.connection.stop()
        self.temp.cleanup()

    def test_totp_lockout_is_per_principal_and_clears_after_success(self):
        self.assertEqual(audit_webapp.record_failure("viewer", now=1000), 0)
        self.assertEqual(audit_webapp.record_failure("viewer", now=1001), 0)
        self.assertEqual(audit_webapp.record_failure("viewer", now=1002), 60)
        self.assertEqual(audit_webapp.retry_after("viewer", now=1003), 59)
        self.assertEqual(audit_webapp.retry_after("admin", now=1003), 0)
        audit_webapp.clear_failures("viewer")
        self.assertEqual(audit_webapp.retry_after("viewer", now=1003), 0)

    def test_explicit_roles_do_not_promote_unknown_user(self):
        with patch.object(webapp, "cfg", lambda: {"roles": {"viewer": "viewer", "admin": "admin"}}):
            self.assertEqual(audit_webapp.configured_role("viewer"), "viewer")
            self.assertEqual(audit_webapp.configured_role("admin"), "admin")
            self.assertEqual(audit_webapp.configured_role("unknown"), "viewer")


if __name__ == "__main__":
    unittest.main()
