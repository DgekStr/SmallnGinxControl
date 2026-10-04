import tempfile
from datetime import date
from pathlib import Path
from unittest.mock import Mock

from django.test import SimpleTestCase

from .log_retention import rotate_and_prune_host_logs


class LogRetentionTests(SimpleTestCase):
    def test_rotates_host_data_log_and_prunes_expired_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / 'example.test-data.log'
            active.write_text('active log data\n')
            expired = root / 'old.test-data.log.20260901-030000'
            expired.write_text('expired\n')
            retained = root / 'recent.test-data.log.20261002-030000'
            retained.write_text('retained\n')
            unrelated = root / 'nginx-access.log.20260901-030000'
            unrelated.write_text('do not touch\n')
            reopen = Mock()

            result = rotate_and_prune_host_logs(root, 7, today=date(2026, 10, 4), reopen=reopen)

            self.assertEqual(result, {'rotated': 1, 'deleted': 1})
            self.assertEqual(active.read_text(), '')
            self.assertEqual(len(list(root.glob('example.test-data.log.20261004-*'))), 1)
            self.assertFalse(expired.exists())
            self.assertTrue(retained.exists())
            self.assertTrue(unrelated.exists())
            reopen.assert_called_once_with()