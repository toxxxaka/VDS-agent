import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("monitorbot_infrad", Path(__file__).parents[1] / "systemd" / "monitorbot-infrad.py")
infrad = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(infrad)


class FirewallRollbackTests(unittest.TestCase):
    def test_state_never_exposes_host_wide_ruleset(self):
        with patch.object(infrad, "_managed_table", return_value="table inet monitoringbot {}"):
            state = infrad.state()
        self.assertEqual(state["managed"], "table inet monitoringbot {}")
        self.assertNotIn("ruleset", state)

    def test_restore_replaces_only_saved_managed_table(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            previous = base / "previous.nft"
            metadata = base / "previous.json"
            previous.write_text("table inet monitoringbot { chain input {} }\n")
            metadata.write_text(json.dumps({"table_existed": True, "backup": str(previous)}))
            calls = []

            def fake_run(*args, **_kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch.object(infrad, "ACTIVE_PREVIOUS", previous), patch.object(infrad, "ACTIVE_META", metadata), patch.object(infrad, "run", side_effect=fake_run):
                result = infrad.restore_previous()
            self.assertTrue(result["restored"])
            self.assertIn(("/usr/sbin/nft", "delete", "table", "inet", "monitoringbot"), calls)
            self.assertIn(("/usr/sbin/nft", "-c", "-f", str(previous)), calls)
            self.assertIn(("/usr/sbin/nft", "-f", str(previous)), calls)
            self.assertFalse(any("ruleset" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
