import tempfile
import unittest
from pathlib import Path

from v4 import demo_metrics, metrics


class DemoMetricsTests(unittest.TestCase):
    def test_seeds_demo_history_without_host_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.db"
            demo_metrics.ensure(path, now=1_800_000_000)
            values = metrics.query("1h", path=path, now=1_800_000_000)
            self.assertGreaterEqual(len(values), 2)
            self.assertTrue(all(0 <= item["cpu"] <= 100 for item in values))


if __name__ == "__main__":
    unittest.main()
