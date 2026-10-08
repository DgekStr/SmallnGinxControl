import tempfile
import ipaddress
import os
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from django.test import SimpleTestCase, override_settings

from .panel_tls import generate_local_certificate, install_panel_tls, panel_tls_status, replace_panel_certificate, validate_certificate_pair
from .transactions import OperationError


class PanelTlsTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.nginx_root = self.root / 'nginx'
        (self.nginx_root / 'conf.d').mkdir(parents=True)
        (self.nginx_root / 'nginx.conf').write_text('events {}\nhttp { include conf.d/*.conf; }\n')
        self.override = override_settings(
            SNC_MODE='local', SNC_SERVER='192.0.2.15', SNC_PORT=7445,
            STATE_DIR=self.root / 'state', NGINX_ROOT=self.nginx_root,
        )
        self.override.enable()
        self.addCleanup(self.override.disable)

    def test_local_certificate_contains_panel_ip_and_matches_private_key(self):
        certificate_pem, private_key_pem = generate_local_certificate()
        certificate, private_key = validate_certificate_pair(certificate_pem, private_key_pem)

        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(names.get_values_for_type(x509.IPAddress), [ipaddress.IPv4Address('192.0.2.15')])
        self.assertEqual(names.get_values_for_type(x509.DNSName), ['localhost'])
        self.assertEqual(certificate.public_key().public_numbers(), private_key.public_key().public_numbers())

    @patch('panel.panel_tls.NginxManager')
    def test_install_creates_tls_vhost_and_keeps_private_key_private(self, manager_type):
        result = install_panel_tls()
        directory, certificate_path, key_path, config_path = (
            self.root / 'state' / 'panel-tls',
            self.root / 'state' / 'panel-tls' / 'panel.crt',
            self.root / 'state' / 'panel-tls' / 'panel.key',
            self.nginx_root / 'conf.d' / 'smallnginxcontrol-panel.conf',
        )

        self.assertTrue(result['installed'])
        self.assertTrue(result['self_signed'])
        if os.name != 'nt':
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(certificate_path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertIn('listen 0.0.0.0:7444 ssl', config_path.read_text())
        self.assertIn('proxy_pass http://127.0.0.1:7445;', config_path.read_text())
        self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', config_path.read_text())
        self.assertEqual(panel_tls_status()['fingerprint'], result['fingerprint'])
        manager_type.return_value.validate.assert_called_once()
        manager_type.return_value.reload.assert_called_once()

    @patch('panel.panel_tls.NginxManager')
    def test_failed_nginx_validation_restores_tls_files(self, manager_type):
        manager_type.return_value.validate.side_effect = OperationError('invalid nginx config')

        with self.assertRaisesRegex(OperationError, 'invalid nginx config'):
            install_panel_tls()

        self.assertFalse((self.nginx_root / 'conf.d' / 'smallnginxcontrol-panel.conf').exists())
        self.assertFalse((self.root / 'state' / 'panel-tls' / 'panel.crt').exists())
        self.assertFalse((self.root / 'state' / 'panel-tls' / 'panel.key').exists())
        manager_type.return_value.reload.assert_not_called()

    @patch('panel.panel_tls.NginxManager')
    def test_failed_nginx_reload_restores_previous_certificate(self, manager_type):
        install_panel_tls()
        certificate_path = self.root / 'state' / 'panel-tls' / 'panel.crt'
        key_path = self.root / 'state' / 'panel-tls' / 'panel.key'
        original_certificate = certificate_path.read_bytes()
        original_key = key_path.read_bytes()
        replacement = generate_local_certificate()
        manager_type.return_value.reload.side_effect = [OperationError('reload failed'), None]

        with self.assertRaisesRegex(OperationError, 'previous configuration restored'):
            replace_panel_certificate(*replacement)

        self.assertEqual(certificate_path.read_bytes(), original_certificate)
        self.assertEqual(key_path.read_bytes(), original_key)

    def test_certificate_with_mismatched_key_is_rejected(self):
        certificate_pem, _ = generate_local_certificate()
        _, different_key = generate_local_certificate()

        with self.assertRaisesRegex(OperationError, 'не соответствует'):
            replace_panel_certificate(certificate_pem, different_key)