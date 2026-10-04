import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from panel.transactions import OperationError, apply_transaction, atomic_write, configure_host_access_logs


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

    def test_per_host_access_logs_cover_server_and_location_off(self):
        content = (
            'server {\n'
            '    server_name alpha.test www.alpha.test;\n'
            '    access_log off;\n'
            '    location /private/ { access_log off; }\n'
            '    location /custom/ { access_log /var/log/nginx/old.log combined; }\n'
            '}\n'
            'server {\n'
            '    server_name beta.test;\n'
            '}\n'
        )
        rendered, changed = configure_host_access_logs(content, 'fallback', '/var/log/nginx')
        text = rendered.decode()
        self.assertEqual(changed, ['alpha.test', 'beta.test'])
        self.assertNotIn('access_log off;', text)
        self.assertIn('access_log /var/log/nginx/alpha.test-data.log;', text)
        self.assertIn('access_log /var/log/nginx/beta.test-data.log;', text)
        self.assertIn('access_log /var/log/nginx/old.log combined;', text)
        rerendered, changed_again = configure_host_access_logs(rendered, 'fallback', '/var/log/nginx')
        self.assertEqual(rerendered, rendered)
        self.assertEqual(changed_again, [])

    def test_per_host_log_name_is_bounded_for_long_server_name(self):
        host = 'a' * 220 + '.example.test'
        content = f'server {{\n server_name {host};\n}}\n'
        rendered, changed = configure_host_access_logs(content, 'fallback', '/var/log/nginx')
        log_path = next(token for token in rendered.decode().split() if token.startswith('/var/log/nginx/'))
        self.assertLess(len(Path(log_path).name), 255)
        self.assertEqual(len(changed), 1)