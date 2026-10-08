from concurrent.futures import Future
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from .metrics import collect_completed, enable_sqlite_wal, local_uptime


class MetricCollectorTests(SimpleTestCase):
    def test_local_uptime_prefers_proc_uptime_over_host_boot_time(self):
        with patch('panel.metrics.Path.read_text', return_value='14996.45 14996.45'), patch('panel.metrics.psutil.boot_time', return_value=1):
            self.assertEqual(local_uptime(), 14996.45)

    def test_local_uptime_falls_back_when_proc_uptime_is_unavailable(self):
        with patch('panel.metrics.Path.read_text', side_effect=OSError), patch('panel.metrics.time.time', return_value=1000), patch('panel.metrics.psutil.boot_time', return_value=250):
            self.assertEqual(local_uptime(), 750)

    def test_enable_sqlite_wal_for_file_database(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = sqlite3.connect(Path(directory) / 'panel.sqlite3')
            try:
                self.assertTrue(enable_sqlite_wal(connection))
                self.assertEqual(connection.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
            finally:
                connection.close()

    def test_failed_future_is_removed_and_scheduled_for_retry(self):
        future = Future()
        future.set_exception(RuntimeError('database is locked'))
        pending = {'local': future}
        previous = {'local': ({'rx_bytes': 100}, 10)}
        due = {}

        with self.assertLogs('panel.metrics', level='ERROR'):
            collect_completed(pending, previous, due, 15)

        self.assertEqual(pending, {})
        self.assertNotIn('local', previous)
        self.assertEqual(due, {'local': 45})

    def test_successful_future_updates_previous_sample(self):
        sample = ({'rx_bytes': 200}, 20)
        future = Future()
        future.set_result((sample, True))
        pending = {'local': future}
        previous = {}
        due = {}

        collect_completed(pending, previous, due, 25)

        self.assertEqual(pending, {})
        self.assertEqual(previous, {'local': sample})
        self.assertEqual(due, {'local': 25})
