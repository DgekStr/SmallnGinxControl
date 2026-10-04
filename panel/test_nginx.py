import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from .nginx import NginxManager
from .transactions import OperationError, render_maintenance_config


class NginxTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        (root / 'conf.d').mkdir()
        (root / 'sites-available').mkdir()
        (root / 'sites-enabled').mkdir()
        (root / 'logs').mkdir()
        self.maintenance_root = root / 'maintenance'
        self.maintenance_root.mkdir()
        (self.maintenance_root / 'maitenance.html').write_text('maintenance')
        (root / 'nginx.conf').write_text('events {}\nhttp {}\n')
        self.override = override_settings(NGINX_ROOT=root, NGINX_LOG_ROOT=root / 'logs', STATE_DIR=root, SNC_MODE='demo')
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.manager = NginxManager(maintenance_root=self.maintenance_root)

    def test_create_inventory_disable_enable(self):
        self.manager.create({'name': 'example.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80})
        item = self.manager.inventory()['items'][0]
        self.assertEqual(item['kind'], 'proxy')
        self.assertTrue(item['enabled'])
        original = self.manager.read(item['id'])['content'].encode()
        self.manager.toggle(item['id'], False, item['revision'])
        item = self.manager.inventory()['items'][0]
        self.assertFalse(item['enabled'])
        self.assertTrue(item['maintenance'])
        self.assertIn('return 503;', self.manager.read(item['id'])['content'])
        self.assertEqual(self.manager.maintenance_backup(item['id']).read_bytes(), original)
        self.manager.toggle(item['id'], True, item['revision'])
        item = self.manager.inventory()['items'][0]
        self.assertTrue(item['enabled'])
        self.assertFalse(item['maintenance'])
        self.assertEqual(self.manager.read(item['id'])['content'].encode(), original)
        self.assertFalse(self.manager.maintenance_backup(item['id']).exists())

    def test_ssl_site_renders_http_challenge_redirect_and_tls_server(self):
        data = {'name': 'secure.example.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80, 'ssl_email': 'ops@example.test'}
        _, _, challenge = self.manager.render_site(data, challenge=True)
        _, _, https = self.manager.render_site(data, https=True)
        self.assertIn('/.well-known/acme-challenge/', challenge)
        self.assertNotIn('return 301 https://', challenge)
        self.assertIn('return 301 https://$host$request_uri;', https)
        self.assertIn('listen 443 ssl;', https)
        self.assertIn('/etc/letsencrypt/live/secure.example.test/fullchain.pem', https)
        self.assertIn('proxy_pass http://127.0.0.1:3000;', https)

    def test_demo_cannot_request_real_ssl_certificate(self):
        data = {'name': 'secure.example.test', 'kind': 'host', 'target': '/var/www/html', 'port': 80, 'issue_ssl': True, 'ssl_email': 'ops@example.test'}
        with self.assertRaisesRegex(OperationError, 'рабочем nginx'):
            self.manager.create(data)

    def test_ssl_create_switches_http_host_to_tls_after_certbot(self):
        self.manager.demo = False
        data = {'name': 'issued.example.test', 'kind': 'host', 'target': '/var/www/html', 'port': 80, 'issue_ssl': True, 'ssl_email': 'ops@example.test'}
        with patch.object(self.manager, 'validate', return_value='ok'), patch.object(self.manager, 'reload'), patch('panel.nginx.issue_webroot_certificate') as issue:
            result = self.manager.create(data)
        self.assertIn('SSL сертификат выпущен', result)
        issue.assert_called_once()
        config = self.manager.read('conf.d/issued.example.test.conf')['content']
        self.assertIn('listen 443 ssl;', config)
        self.assertIn('return 301 https://$host$request_uri;', config)

    def test_ssl_create_removes_temporary_http_host_if_certbot_fails(self):
        self.manager.demo = False
        data = {'name': 'failed.example.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80, 'issue_ssl': True, 'ssl_email': 'ops@example.test'}
        with patch.object(self.manager, 'validate', return_value='ok'), patch.object(self.manager, 'reload'), patch('panel.nginx.issue_webroot_certificate', side_effect=OperationError('DNS validation failed')):
            with self.assertRaisesRegex(OperationError, 'временный HTTP-хост удалён'):
                self.manager.create(data)
        self.assertFalse((self.manager.root / 'conf.d/failed.example.test.conf').exists())

    def test_static_host_uses_legacy_disable(self):
        self.manager.create({'name': 'static.test', 'kind': 'host', 'target': '/var/www/html', 'port': 80})
        item = self.manager.inventory()['items'][0]
        self.manager.toggle(item['id'], False, item['revision'])
        item = self.manager.inventory()['items'][0]
        self.assertFalse(item['enabled'])
        self.assertFalse(item['maintenance'])
        self.assertTrue((self.manager.root / 'conf.d' / 'static.test.conf.disabled').is_file())

    def test_delete_requires_disabled_host_and_removes_disabled_config(self):
        self.manager.create({'name': 'delete.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80})
        item = self.manager.inventory()['items'][0]
        with self.assertRaisesRegex(OperationError, 'Сначала отключите'):
            self.manager.delete(item['id'], item['revision'])
        self.assertTrue((self.manager.root / item['id']).is_file())
        self.manager.toggle(item['id'], False, item['revision'])
        item = self.manager.inventory()['items'][0]
        result = self.manager.delete(item['id'], item['revision'])
        self.assertIn('удалён из nginx', result)
        self.assertEqual(self.manager.inventory()['items'], [])
        self.assertTrue(list((self.manager.state / 'backups').glob('*.bak')))

    def test_delete_maintenance_proxy_clears_saved_original(self):
        self.manager.create({'name': 'maintenance-delete.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80})
        item = self.manager.inventory()['items'][0]
        self.manager.toggle(item['id'], False, item['revision'])
        item = self.manager.inventory()['items'][0]
        stored = self.manager.maintenance_backup(item['id'])
        self.assertTrue(stored.is_file())
        self.manager.delete(item['id'], item['revision'])
        self.assertFalse(stored.exists())
        self.assertEqual(self.manager.inventory()['items'], [])

    def test_delete_rolls_back_when_validation_fails(self):
        self.manager.create({'name': 'rollback-delete.test', 'kind': 'host', 'target': '/var/www/html', 'port': 80})
        item = self.manager.inventory()['items'][0]
        self.manager.toggle(item['id'], False, item['revision'])
        item = self.manager.inventory()['items'][0]
        with patch.object(self.manager, 'validate', side_effect=OperationError('invalid config')):
            with self.assertRaisesRegex(OperationError, 'invalid config'):
                self.manager.delete(item['id'], item['revision'])
        self.assertTrue((self.manager.root / item['id']).is_file())
        self.assertEqual(len(self.manager.inventory()['items']), 1)

    def test_proxy_maintenance_requires_page(self):
        self.manager.create({'name': 'missing.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000', 'port': 80})
        item = self.manager.inventory()['items'][0]
        self.maintenance_page = self.maintenance_root / 'maitenance.html'
        self.maintenance_page.unlink()
        with self.assertRaisesRegex(OperationError, 'Страница обслуживания'):
            self.manager.toggle(item['id'], False, item['revision'])
        self.assertTrue(self.manager.inventory()['items'][0]['enabled'])

    def test_proxy_maintenance_reuses_existing_handler(self):
        content = (
            'server {\n'
            '    include /etc/nginx/snippets/maintenance_all.conf;\n'
            '    server_name proxy.test;\n'
            '    location / { proxy_pass http://127.0.0.1:3000; }\n'
            '}\n'
        )
        rendered = render_maintenance_config(content, self.maintenance_root).decode()
        self.assertIn('if ($uri != /maitenance.html)', rendered)
        self.assertNotIn('/__smallnginxcontrol_maintenance.html', rendered)

    def test_save_conflict_and_rollback(self):
        config = self.manager.read('nginx.conf')
        with self.assertRaisesRegex(OperationError, 'уже изменён'):
            self.manager.save('nginx.conf', 'events {}', 'stale')
        with patch.object(self.manager, 'validate', side_effect=OperationError('nginx -t failed')):
            with self.assertRaises(OperationError):
                self.manager.save('nginx.conf', 'events {}', config['revision'])
        self.assertEqual(self.manager.read('nginx.conf')['content'], config['content'])

    def test_two_servers_keep_identical_host_names_isolated(self):
        other_root = self.manager.root / 'second-server'
        other_root.mkdir()
        (other_root / 'conf.d').mkdir()
        (other_root / 'nginx.conf').write_text('events {}\nhttp {}\n')
        other = NginxManager(root=other_root, logs_root=other_root / 'logs', state=other_root, demo=True)
        data = {'name': 'shared.test', 'kind': 'proxy', 'target': 'http://127.0.0.1:3000'}
        self.manager.create(data)
        other.create(data)
        item = self.manager.inventory()['items'][0]
        self.manager.toggle(item['id'], False, item['revision'])
        self.assertFalse(self.manager.inventory()['items'][0]['enabled'])
        self.assertTrue(other.inventory()['items'][0]['enabled'])
        self.assertNotEqual(self.manager.state, other.state)

    def test_path_traversal_is_blocked(self):
        for identifier in ['../secret', '/etc/passwd', 'conf.d/../../secret', '.secret', 'conf.d\\secret']:
            with self.subTest(identifier=identifier), self.assertRaises(OperationError):
                self.manager.read(identifier)

    def test_directive_injection_is_blocked(self):
        for target in ['http://localhost;include /etc/passwd', 'http://localhost/\n}', 'http://user:pass@localhost', 'file:///etc/passwd']:
            with self.subTest(target=target), self.assertRaises(OperationError):
                self.manager.create({'name': 'test.local', 'kind': 'proxy', 'target': target})

    def test_logs_are_bounded_and_confined(self):
        path = self.manager.logs_root / 'access.log'
        path.write_text('\n'.join(str(number) for number in range(1000)))
        log = self.manager.logs(lines=10)['content']
        self.assertIn('999', log)
        self.assertNotIn('\n989\n', log)
        config = self.manager.root / 'conf.d' / 'unsafe.conf'
        config.write_text('server { access_log /etc/passwd; }')
        self.assertIn('вне разрешённого', self.manager.logs('conf.d/unsafe.conf')['content'])

    def test_logs_read_from_configured_extra_root(self):
        extra_root = self.manager.root / 'http'
        host_logs = extra_root / 'example.test'
        host_logs.mkdir(parents=True)
        (host_logs / 'access.log').write_text('127.0.0.1 GET / 200\n')
        config = self.manager.root / 'conf.d' / 'host-logs.conf'
        config.write_text(f'server {{ access_log {host_logs}/access.log; server_name example.test; }}')
        manager = NginxManager(extra_log_roots=[extra_root])
        result = manager.logs('conf.d/host-logs.conf', 'access')
        self.assertIn('GET / 200', result['content'])
        self.assertEqual(result['sources'], [str(host_logs / 'access.log')])

    def test_access_log_off_is_reported_as_disabled(self):
        config = self.manager.root / 'conf.d' / 'access-off.conf'
        config.write_text('server { server_name disabled.test; access_log off; }')
        result = self.manager.logs('conf.d/access-off.conf', 'access')
        self.assertEqual(result['sources'], [])
        self.assertIn('access_log off', result['content'])
        self.assertNotIn('Просмотр недоступен', result['content'])

    def test_error_log_off_is_reported_as_non_file_destination(self):
        config = self.manager.root / 'conf.d' / 'error-off.conf'
        config.write_text('server { server_name disabled.test; error_log off; }')
        result = self.manager.logs('conf.d/error-off.conf', 'error')
        self.assertEqual(result['sources'], [])
        self.assertIn('error_log off', result['content'])
        self.assertNotIn('Просмотр недоступен', result['content'])

    def test_traffic_top_ranks_active_vhosts_by_access_log_bytes(self):
        logs_root = self.manager.root / 'http'
        logs_root.mkdir()
        entries = {'alpha.test': [900, 500], 'beta.test': [200], 'gamma.test': [700]}
        for name, byte_counts in entries.items():
            log = logs_root / name / 'access.log'
            log.parent.mkdir()
            log.write_text(''.join(f'127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 {size} {size + 10} "-" "test"\n' for size in byte_counts))
            config = self.manager.root / 'conf.d' / f'{name}.conf'
            config.write_text(f'server {{ listen 80; server_name {name}; access_log {log}; location / {{ proxy_pass http://127.0.0.1:3000; }} }}')
        disabled = self.manager.root / 'conf.d' / 'disabled.test.conf'
        disabled.write_text(f'server {{ listen 80; server_name disabled.test; access_log {logs_root / "alpha.test" / "access.log"}; }}')
        disabled_item = next(item for item in self.manager.inventory()['items'] if item['id'] == 'conf.d/disabled.test.conf')
        self.manager.toggle(disabled_item['id'], False, disabled_item['revision'])
        manager = NginxManager(extra_log_roots=[logs_root])
        result = manager.traffic_top()
        self.assertEqual([item['name'] for item in result['items']], ['alpha.test', 'gamma.test', 'beta.test'])
        self.assertEqual([item['bytes'] for item in result['items']], [1400, 700, 200])
        self.assertEqual(result['hosts']['conf.d/alpha.test.conf'], {'downloaded_bytes': 1400, 'uploaded_bytes': 1420, 'uploaded_complete': True})

    def test_enable_host_logging_updates_enabled_and_disabled_configs(self):
        active = self.manager.root / 'conf.d' / 'active.test.conf'
        disabled = self.manager.root / 'conf.d' / 'disabled.test.conf.disabled'
        active.write_text('server { server_name active.test; access_log off; }\n')
        disabled.write_text('server { server_name disabled.test; }\n')
        preview = self.manager.enable_host_logging(dry_run=True)
        self.assertEqual(preview['files'], 3)
        self.assertIn('access_log off', active.read_text())
        self.assertNotIn('active.test-data.log', active.read_text())
        with patch.object(self.manager, 'validate', return_value='ok'), patch.object(self.manager, 'reload'):
            applied = self.manager.enable_host_logging(dry_run=False)
        self.assertEqual(applied, preview)
        self.assertNotIn('access_log off', active.read_text())
        self.assertIn('active.test-data.log', active.read_text())
        self.assertIn('disabled.test-data.log', disabled.read_text())
        self.assertIn('smallnginxcontrol_traffic', active.read_text())
        self.assertIn('log_format smallnginxcontrol_traffic', (self.manager.root / 'nginx.conf').read_text())