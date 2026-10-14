import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import demo_access, storage


class DemoAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "demo.db"
        def connect():
            connection = storage.connect(self.db)
            connection.executescript(demo_access.SCHEMA)
            return connection
        self.connect = patch.object(demo_access, "_connect", connect)
        self.connect.start()

    def tearDown(self):
        self.connect.stop()
        self.temp.cleanup()

    def test_owner_issues_and_shares_one_time_credentials(self):
        request = demo_access.request_access("198.51.100.7", now=100)
        self.assertTrue(request["ok"])
        record = demo_access.generate(request["id"], now=101)
        self.assertRegex(record["username"], r"^[A-Za-z]{6,9}$")
        self.assertRegex(record["password"], r"^[A-Za-z]{9,15}$")
        self.assertIsNotNone(demo_access.share(request["id"], now=102))
        credentials = demo_access.status(request["token"], reveal=True, now=103)
        self.assertEqual(credentials["username"], record["username"])
        self.assertEqual(credentials["password"], record["password"])
        self.assertNotIn("password", demo_access.status(request["token"], reveal=True, now=104))
        self.assertIsNotNone(demo_access.verify(record["username"], record["password"], now=105))

    def test_three_requests_are_allowed_per_source_per_day_and_deleted_account_cannot_sign_in(self):
        request = demo_access.request_access("198.51.100.8", now=100)
        self.assertTrue(demo_access.request_access("198.51.100.8", now=101)["ok"])
        self.assertTrue(demo_access.request_access("198.51.100.8", now=102)["ok"])
        rejected = demo_access.request_access("198.51.100.8", now=103)
        self.assertFalse(rejected["ok"])
        self.assertGreater(rejected["retry_after"], 0)
        self.assertTrue(demo_access.request_access("198.51.100.8", now=100 + 24 * 60 * 60)["ok"])
        account = demo_access.generate(request["id"], now=104)
        demo_access.share(request["id"], now=103)
        self.assertTrue(demo_access.delete(request["id"]))
        self.assertIsNone(demo_access.verify(account["username"], account["password"], now=104))


if __name__ == "__main__":
    unittest.main()
