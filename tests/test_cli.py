from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from v4 import cli


REPORT = {
    "healthy": True,
    "checks": {"services": True, "database": True},
    "metrics": {"age_seconds": 12},
    "database": {"ok": True, "size_bytes": 1024},
    "services": [{"unit": "monitorbot-web.service", "state": "active"}],
    "failed_units": [],
    "component_failures": [],
}


class CliTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(list(args))
        return code, output.getvalue()

    def test_status_prints_human_readable_health(self):
        with patch.object(cli.self_monitoring, "report", return_value=REPORT):
            code, output = self.invoke("status")
        self.assertEqual(code, 0)
        self.assertIn("VDS Agent: healthy", output)
        self.assertIn("monitorbot-web.service: active", output)

    def test_status_json_is_machine_readable_and_unhealthy_is_nonzero(self):
        report = {**REPORT, "healthy": False}
        with patch.object(cli.self_monitoring, "report", return_value=report):
            code, output = self.invoke("status", "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(output)["healthy"])

    def test_doctor_combines_config_and_runtime_checks(self):
        with patch.object(cli, "validate", return_value={"features": {}}), patch.object(cli.self_monitoring, "report", return_value=REPORT):
            code, output = self.invoke("doctor")
        self.assertEqual(code, 0)
        self.assertIn("OK    configuration", output)
        self.assertIn("Overall: healthy", output)

    def test_doctor_reports_invalid_configuration(self):
        with patch.object(cli, "validate", side_effect=ValueError("bad config")), patch.object(cli.self_monitoring, "report", return_value=REPORT):
            code, output = self.invoke("doctor", "--json")
        self.assertEqual(code, 1)
        result = json.loads(output)
        self.assertFalse(result["healthy"])
        self.assertEqual(result["checks"][0]["status"], "error")
