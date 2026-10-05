from concurrent.futures import Future
import sqlite3
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .metrics import collect_completed, enable_sqlite_wal


class MetricCollectorTests(SimpleTestCase):
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
