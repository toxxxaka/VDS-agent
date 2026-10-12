import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from v4 import intelligence, runbooks
from v4.storage import audit, connect, rows


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.db = Path(self.temp.name) / 'monitoring.db'
        self.patch = patch.object(intelligence, 'connect', lambda: connect(self.db)); self.patch.start()
    def tearDown(self): self.patch.stop(); self.temp.cleanup()
    @patch.object(intelligence, 'listeners', return_value=['1:0.0.0.0:22:sshd'])
    def test_listener_first_sample_creates_baseline_then_detects_change(self, listeners):
        self.assertEqual(intelligence.listener_baseline()['mode'], 'baseline_created')
        listeners.return_value = ['1:0.0.0.0:22:sshd', '1:0.0.0.0:443:nginx']
        self.assertIn('1:0.0.0.0:443:nginx', intelligence.listener_baseline()['new_listeners'])
    @patch.object(intelligence, '_ioc_inventory', return_value={'tmp_or_shm_processes': [], 'deleted_executables': [], 'suid': [], 'cron': [], 'units': [], 'users': []})
    def test_ioc_baseline_is_detect_only(self, inventory):
        self.assertEqual(intelligence.ioc_checks()['mode'], 'baseline_created')
        inventory.return_value = {**inventory.return_value, 'users': ['new:1000']}
        self.assertEqual(intelligence.ioc_checks()['new']['users'], ['new:1000'])


class RunbookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.db=Path(self.temp.name)/'monitoring.db'; self.runbooks=Path(self.temp.name)/'runbooks'; self.runbooks.mkdir()
        (self.runbooks/'test-book.yaml').write_text('id: test-book\ntitle: Test\ndiagnostics:\n  - tool: server_status\n    arguments: {}\ncooldown_seconds: 1\nmax_attempts: 2\n')
        self.cp=patch.object(runbooks, 'connect', lambda: connect(self.db)); self.ap=patch.object(runbooks, 'audit', lambda *args, **kwargs: audit(*args, path=self.db, **kwargs)); self.rows=patch.object(runbooks, 'rows', lambda query, args=(): rows(query, args, self.db)); self.rp=patch.object(runbooks, 'RUNBOOK_DIR', self.runbooks); self.ep=patch.object(runbooks, 'execute', return_value={'ok': True}); self.cp.start(); self.ap.start(); self.rows.start(); self.rp.start(); self.ep.start()
    def tearDown(self): self.ep.stop(); self.rp.stop(); self.rows.stop(); self.ap.stop(); self.cp.stop(); self.temp.cleanup()
    def test_dry_run_uses_only_allowlisted_diagnostics(self):
        result=runbooks.dry_run('test-book','42',{'allowed_user_ids':['42']})
        self.assertEqual(result['status'],'dry_run'); self.assertEqual(result['evidence'][0]['tool'],'server_status')
