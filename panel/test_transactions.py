import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from panel.transactions import OperationError, apply_transaction, atomic_write


class TransactionTests(unittest.TestCase):
    def test_invalid_configuration_rolls_back_without_reload(self):
        change, rollback, reload_service = Mock(), Mock(), Mock()
        validate = Mock(side_effect=OperationError('invalid config'))
        with self.assertRaises(OperationError):
            apply_transaction(change, rollback, validate, reload_service)
        change.assert_called_once()
        rollback.assert_called_once()
        reload_service.assert_not_called()

    def test_reload_failure_restores_and_reloads_previous_configuration(self):
        rollback = Mock()
        validate = Mock(return_value='ok')
        reload_service = Mock(side_effect=[OperationError('reload failed'), None])
        with self.assertRaisesRegex(OperationError, 'previous configuration restored'):
            apply_transaction(Mock(), rollback, validate, reload_service)
        rollback.assert_called_once()
        self.assertEqual(reload_service.call_count, 2)
        self.assertEqual(validate.call_count, 2)

    def test_partial_change_failure_is_rolled_back(self):
        rollback, validate = Mock(), Mock()
        with self.assertRaises(OSError):
            apply_transaction(Mock(side_effect=OSError('disk full')), rollback, validate, Mock())
        rollback.assert_called_once()
        validate.assert_not_called()

    def test_success_does_not_rollback(self):
        rollback = Mock()
        self.assertEqual(apply_transaction(Mock(), rollback, lambda: 'valid', Mock()), 'valid')
        rollback.assert_not_called()

    def test_atomic_write_replaces_content(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'site.conf'
            atomic_write(target, b'old')
            atomic_write(target, b'new')
            self.assertEqual(target.read_bytes(), b'new')
            self.assertEqual(list(Path(directory).iterdir()), [target])