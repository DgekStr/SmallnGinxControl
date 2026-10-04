import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from panel.transactions import OperationError, access_log_traffic_totals, apply_transaction, atomic_write, certificate_days_remaining, configure_host_access_logs, ensure_traffic_log_format, issue_webroot_certificate, validate_certificate_request


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
        self.assertIn('access_log /var/log/nginx/alpha.test-data.log smallnginxcontrol_traffic;', text)
        self.assertIn('access_log /var/log/nginx/beta.test-data.log smallnginxcontrol_traffic;', text)
        self.assertIn('access_log /var/log/nginx/old.log combined;', text)
        rerendered, changed_again = configure_host_access_logs(rendered, 'fallback', '/var/log/nginx')
        self.assertEqual(rerendered, rendered)
        self.assertEqual(changed_again, [])

    def test_traffic_log_format_is_added_to_http_context_once(self):
        initial = 'events {}\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n}\n'
        updated, changed = ensure_traffic_log_format(initial)
        self.assertTrue(changed)
        self.assertIn('log_format smallnginxcontrol_traffic', updated.decode())
        self.assertLess(updated.decode().index('log_format smallnginxcontrol_traffic'), updated.decode().index('include /etc/nginx/conf.d'))
        repeated, changed_again = ensure_traffic_log_format(updated)
        self.assertFalse(changed_again)
        self.assertEqual(repeated, updated)

    def test_access_log_traffic_reports_download_and_upload_when_format_has_request_length(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'access.log'
            log.write_text('127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 345 712 "-" "test"\n')
            totals = access_log_traffic_totals([str(log)], [root])
            self.assertEqual(totals, {'downloaded_bytes': 345, 'uploaded_bytes': 712, 'uploaded_complete': True})

    def test_access_log_traffic_marks_upload_unknown_for_combined_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'access.log'
            log.write_text('127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 345 "-" "test"\n')
            totals = access_log_traffic_totals([str(log)], [root])
            self.assertEqual(totals, {'downloaded_bytes': 345, 'uploaded_bytes': None, 'uploaded_complete': False})

    def test_access_log_traffic_marks_mixed_request_sizes_as_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'access.log'
            log.write_text(
                '127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET /old HTTP/1.1" 200 345 "-" "test"\n'
                '127.0.0.1 - - [04/Oct/2026:12:00:01 +0000] "POST /new HTTP/1.1" 200 200 712 "-" "test"\n'
            )
            totals = access_log_traffic_totals([str(log)], [root])
            self.assertEqual(totals, {'downloaded_bytes': 545, 'uploaded_bytes': 712, 'uploaded_complete': False})

    def test_per_host_log_name_is_bounded_for_long_server_name(self):
        host = 'a' * 220 + '.example.test'
        content = f'server {{\n server_name {host};\n}}\n'
        rendered, changed = configure_host_access_logs(content, 'fallback', '/var/log/nginx')
        log_path = next(token for token in rendered.decode().split() if token.startswith('/var/log/nginx/'))
        self.assertLess(len(Path(log_path).name), 255)
        self.assertEqual(len(changed), 1)

    def test_existing_per_host_combined_log_is_upgraded_to_traffic_format(self):
        content = 'server { server_name alpha.test; access_log /var/log/nginx/alpha.test-data.log combined; }\n'
        updated, changed = configure_host_access_logs(content, 'fallback', '/var/log/nginx')
        self.assertEqual(changed, ['alpha.test'])
        self.assertIn('access_log /var/log/nginx/alpha.test-data.log smallnginxcontrol_traffic;', updated.decode())

    def test_existing_per_host_default_log_format_is_upgraded(self):
        content = 'server { server_name alpha.test; access_log /var/log/nginx/alpha.test-data.log; }\n'
        updated, changed = configure_host_access_logs(content, 'fallback', '/var/log/nginx')
        self.assertEqual(changed, ['alpha.test'])
        self.assertIn('access_log /var/log/nginx/alpha.test-data.log smallnginxcontrol_traffic;', updated.decode())

    def test_certificate_days_remaining_returns_earliest_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / 'first.crt'
            second = Path(directory) / 'second.crt'
            first.write_text('certificate')
            second.write_text('certificate')
            responses = [
                Mock(returncode=0, stdout='', stderr='notAfter=Oct 20 00:00:00 2026 GMT'),
                Mock(returncode=0, stdout='', stderr='notAfter=Oct 14 00:00:00 2026 GMT'),
            ]
            with patch('panel.transactions.subprocess.run', side_effect=responses):
                remaining = certificate_days_remaining([str(first), str(second)], datetime(2026, 10, 4, tzinfo=timezone.utc))
            self.assertEqual(remaining, 10)

    def test_certificate_request_requires_public_dns_and_valid_contact(self):
        self.assertEqual(validate_certificate_request('app.example.com', 'ops@example.com'), ('app.example.com', 'ops@example.com'))
        for domain in ['192.0.2.5', '*.example.com', 'localhost', 'invalid_host.example.com']:
            with self.subTest(domain=domain), self.assertRaises(OperationError):
                validate_certificate_request(domain, 'ops@example.com')
        with self.assertRaises(OperationError):
            validate_certificate_request('app.example.com', 'bad-email')

    def test_certbot_webroot_invocation_uses_argv_and_checks_keypair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certbot = root / 'certbot'
            certbot.write_text('placeholder')
            webroot = root / 'webroot'
            webroot.mkdir()
            live = root / 'live' / 'app.example.com'
            live.mkdir(parents=True)
            (live / 'fullchain.pem').write_text('public cert')
            (live / 'privkey.pem').write_text('private key')
            with patch('panel.transactions.subprocess.run') as run:
                run.return_value = Mock(returncode=0, stdout='issued', stderr='')
                result = issue_webroot_certificate(certbot, webroot, root / 'live', 'app.example.com', 'ops@example.com')
            self.assertEqual(result, (live / 'fullchain.pem', live / 'privkey.pem'))
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[0], str(certbot))
            self.assertIn('--webroot', arguments)
            self.assertEqual(arguments[arguments.index('--deploy-hook') + 1], 'systemctl reload nginx')
            self.assertEqual(run.call_args.kwargs['timeout'], 300)