from contextlib import nullcontext
import tempfile
import json
import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from django.test import TestCase, override_settings

from .nginx import NginxManager
from .models import AuditEvent, MetricSample, Server
from .servers import ServerForm, initialize_demo, manager_for, public_server, selected_server
from .transactions import OperationError
from .remote_worker import RemoteWorker
from .ssh import PinnedHostKey, SSHManager, key_fingerprint, worker_command
from .metrics import local_raw, snapshot, sample_from_raw


class ServerTests(TestCase):
    def test_secret_is_encrypted_and_never_serialized(self):
        server = Server.objects.create(name='Remote', host='192.0.2.10', mode='ssh')
        server.set_secret('test-secret-never-return')
        server.save()
        server.refresh_from_db()
        self.assertNotIn('test-secret', server.encrypted_secret)
        self.assertEqual(server.get_secret(), 'test-secret-never-return')
        self.assertNotIn('secret', public_server(server))
        self.assertNotIn('encrypted_secret', public_server(server))
        self.assertTrue(public_server(server)['has_secret'])

    def test_unknown_server_never_falls_back_to_default(self):
        with self.assertRaises(OperationError):
            selected_server('not-a-server')

    def test_demo_primary_cannot_use_production_roots(self):
        server = Server.objects.get(pk='local')
        server.mode = 'demo'
        with override_settings(SNC_MODE='local', NGINX_ROOT=Path('/etc/nginx')):
            with self.assertRaises(OperationError):
                manager_for(server)

    def test_ssh_requires_valid_host_and_pinned_fingerprint(self):
        form = ServerForm({'name': 'Remote', 'host': 'host;id', 'mode': 'ssh', 'port': 22, 'username': 'root', 'auth_method': 'agent', 'nginx_root': '/etc/nginx', 'log_root': '/var/log/nginx'})
        self.assertFalse(form.is_valid())
        self.assertIn('host', form.errors)
        self.assertIn('fingerprint', form.errors)

    def test_added_demo_is_isolated_from_primary(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(STATE_DIR=Path(directory)):
            server = Server.objects.create(name='Second', host='192.0.2.11', mode='demo')
            initialize_demo(server)
            manager = manager_for(server)
            self.assertEqual(len(manager.inventory()['items']), 2)
            self.assertEqual(manager.state, Path(directory) / 'servers' / server.pk)

    def test_changed_ssh_key_is_rejected(self):
        key = Mock()
        key.asbytes.return_value = b'test-public-host-key'
        PinnedHostKey(key_fingerprint(key)).missing_host_key(None, 'example.test', key)
        with self.assertRaises(OperationError):
            PinnedHostKey('SHA256:' + 'x' * 43).missing_host_key(None, 'example.test', key)

    def test_remote_worker_reads_without_creating_remote_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nginx.conf').write_text('events {}')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            self.assertEqual(worker.dispatch('read', {'id': 'nginx.conf'})['content'], 'events {}')
            self.assertFalse((root / 'state').exists())
            with self.assertRaises(OperationError):
                worker.dispatch('read', {'id': '../outside'})
            with self.assertRaises(OperationError):
                worker.dispatch('shell', {'command': 'id'})

    def test_remote_worker_new_host_registers_traffic_log_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            (root / 'nginx.conf').write_text('events {}\nhttp {}\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            data = {'id': 'conf.d/alpha.example.com.conf', 'content': 'server { listen 80; server_name alpha.example.com; access_log /var/log/nginx/alpha.example.com-data.log smallnginxcontrol_traffic; }\n'}
            with patch.object(worker, 'lock', return_value=nullcontext()), patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'):
                worker.dispatch('create', data)
            self.assertIn('log_format smallnginxcontrol_traffic', (root / 'nginx.conf').read_text())
            self.assertIn('smallnginxcontrol_traffic', (root / data['id']).read_text())

    def test_ssh_manager_sends_challenge_and_final_tls_configs(self):
        manager = SSHManager.__new__(SSHManager)
        manager.server = Mock(log_root='/var/log/nginx', nginx_root='/etc/nginx')
        manager.parser = NginxManager(demo=True)
        data = {'name': 'secure.example.com', 'kind': 'proxy', 'port': 80, 'target': 'http://127.0.0.1:3000', 'issue_ssl': True, 'ssl_email': 'ops@example.com'}
        with patch.object(manager, 'inventory', return_value={'items': []}), patch.object(manager, 'rpc', return_value='ok') as rpc:
            manager.create(data)
        payload = rpc.call_args.args[1]
        self.assertIn('include /etc/nginx/snippets/maintenance_all.conf;', payload['content'])
        self.assertIn('include /etc/nginx/snippets/maintenance_all.conf;', payload['https_content'])
        self.assertTrue(payload['issue_ssl'])
        self.assertIn('/.well-known/acme-challenge/', payload['content'])
        self.assertIn('return 301 https://$host$request_uri;', payload['https_content'])
        self.assertIn('listen 443 ssl;', payload['https_content'])
        self.assertEqual(payload['ssl_email'], 'ops@example.com')

    def test_remote_worker_certbot_success_switches_challenge_to_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            challenge = 'server { listen 80; server_name secure.example.com; }\n'
            https = 'server { listen 443 ssl; server_name secure.example.com; }\n'
            data = {'id': 'conf.d/secure.example.com.conf', 'content': challenge, 'issue_ssl': True, 'ssl_domain': 'secure.example.com', 'ssl_email': 'ops@example.com', 'https_content': https}
            with patch.object(worker, 'lock', return_value=nullcontext()), patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'), patch('panel.remote_worker.issue_webroot_certificate') as issue:
                worker.dispatch('create', data)
            issue.assert_called_once_with('/usr/bin/certbot', '/var/www/html', '/etc/letsencrypt/live', 'secure.example.com', 'ops@example.com')
            self.assertEqual((root / data['id']).read_text(), https)

    def test_remote_worker_removes_challenge_if_certbot_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            data = {'id': 'conf.d/secure.example.com.conf', 'content': 'server { listen 80; }\n', 'issue_ssl': True, 'ssl_domain': 'secure.example.com', 'ssl_email': 'ops@example.com', 'https_content': 'server { listen 443 ssl; }\n'}
            with patch.object(worker, 'lock', return_value=nullcontext()), patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'), patch('panel.remote_worker.issue_webroot_certificate', side_effect=OperationError('ACME failed')):
                with self.assertRaisesRegex(OperationError, 'temporary HTTP host was removed'):
                    worker.dispatch('create', data)
            self.assertFalse((root / data['id']).exists())

    def test_remote_worker_reads_logs_from_configured_extra_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extra_root = root / 'http'
            host_logs = extra_root / 'example.test'
            host_logs.mkdir(parents=True)
            log = host_logs / 'access.log'
            log.write_text('GET / 200\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state', log_roots=[extra_root])
            result = worker.logs([str(log)], 10)
            self.assertIn('GET / 200', result['content'])
            denied = worker.logs(['/etc/passwd'], 10)
            self.assertIn('outside allowed root', denied['content'])

    def test_remote_worker_traffic_top_ranks_active_vhosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            extra_root = root / 'http'
            configs = []
            for name, sent in [('alpha.test', 900), ('beta.test', 300)]:
                log = extra_root / name / 'access.log'
                log.parent.mkdir(parents=True)
                log.write_text(f'127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 {sent} {sent + 50} "-" "test"\n')
                path = root / 'conf.d' / f'{name}.conf'
                content = f'server {{\n    listen 80;\n    server_name {name};\n    access_log {log};\n    location / {{\n        proxy_pass http://127.0.0.1:3000;\n    }}\n}}\n'
                path.write_text(content)
                configs.append({'id': f'conf.d/{name}.conf', 'content': content, 'enabled': True, 'maintenance': False})
            worker = RemoteWorker(root, root / 'logs', root / 'state', log_roots=[extra_root])
            with patch.object(worker, 'inventory', return_value={'configs': configs, 'warnings': []}):
                result = worker.traffic_top()
            self.assertEqual([item['name'] for item in result['items']], ['alpha.test', 'beta.test'])
            self.assertEqual([item['bytes'] for item in result['items']], [900, 300])
            self.assertEqual(result['hosts']['conf.d/alpha.test.conf'], {'downloaded_bytes': 900, 'uploaded_bytes': 950, 'uploaded_complete': True})

    def test_remote_worker_deletes_only_disabled_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            path = root / 'conf.d' / 'unused.conf.disabled'
            path.write_text('server { listen 80; server_name unused.test; }\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            config = {'id': 'conf.d/unused.conf.disabled', 'toggleable': True, 'enabled': False}
            with patch.object(worker, 'inventory', return_value={'configs': [config], 'warnings': []}), patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'):
                result = worker.edit('delete', {'id': config['id'], 'revision': worker.read(config['id'])['revision']})
            self.assertIn('deleted from nginx', result)
            self.assertFalse(path.exists())
            self.assertTrue(list((root / 'state' / 'backups').glob('*.bak')))

    def test_remote_worker_deletes_enabled_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            path = root / 'conf.d' / 'active.conf'
            path.write_text('server { listen 80; server_name active.test; }\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            config = {'id': 'conf.d/active.conf', 'toggleable': True, 'enabled': True}
            with patch.object(worker, 'inventory', return_value={'configs': [config], 'warnings': []}), patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'):
                result = worker.edit('delete', {'id': config['id'], 'revision': worker.read(config['id'])['revision']})
            self.assertIn('deleted from nginx', result)
            self.assertFalse(path.exists())
            self.assertTrue(list((root / 'state' / 'backups').glob('*.bak')))

    def test_remote_worker_protects_management_host_from_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            path = root / 'conf.d' / 'panel.conf'
            path.write_text('server { listen 443 ssl; server_name panel.test; location / { proxy_pass http://127.0.0.1:7444; } }\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            config = {'id': 'conf.d/panel.conf', 'toggleable': True, 'enabled': True}
            with patch.object(worker, 'inventory', return_value={'configs': [config], 'warnings': []}):
                with self.assertRaisesRegex(OperationError, 'Cannot delete the configuration serving'):
                    worker.edit('delete', {'id': config['id'], 'revision': worker.read(config['id'])['revision']})
            self.assertTrue(path.is_file())

    def test_remote_worker_reverts_failed_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'nginx.conf'
            config.write_text('events {}')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            original = worker.read('nginx.conf')
            with patch.object(worker, 'validate', side_effect=OperationError('invalid')), patch.object(worker, 'reload') as reload_service:
                with self.assertRaises(OperationError):
                    worker.edit('save', {**original, 'content': 'events { invalid; }'})
                reload_service.assert_not_called()
            self.assertEqual(worker.read('nginx.conf'), original)
            self.assertEqual(len(list((root / 'state' / 'backups').iterdir())), 1)

    def test_remote_worker_maintenance_proxy_restores_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            (root / 'nginx.conf').write_text('events {}')
            maintenance_root = root / 'maintenance'
            maintenance_root.mkdir()
            (maintenance_root / 'maitenance.html').write_text('maintenance')
            path = root / 'conf.d' / 'proxy.conf'
            path.write_text('server { listen 80; server_name proxy.test; location / { proxy_pass http://127.0.0.1:3000; } }\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state', maintenance_root)
            original = worker.read('conf.d/proxy.conf')
            with patch.object(worker, 'validate', return_value='ok'), patch.object(worker, 'reload'):
                worker.edit('toggle', {**original, 'enabled': False})
                self.assertIn('return 503;', path.read_text())
                maintenance = worker.read('conf.d/proxy.conf')
                worker.edit('toggle', {**maintenance, 'enabled': True})
            self.assertEqual(worker.read('conf.d/proxy.conf'), original)

    def test_remote_command_contains_no_connection_secrets(self):
        command = worker_command()
        self.assertTrue(command.startswith('python3 -c '))
        self.assertNotIn('password=', command)
        self.assertNotIn('192.168.', command)

    def test_standalone_worker_executes_read_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nginx.conf').write_text('events {}')
            payload = {'root': str(root), 'log_root': str(root / 'logs'), 'operation': 'read', 'data': {'id': 'nginx.conf'}}
            process = subprocess.run([sys.executable, '-c', shlex.split(worker_command())[2]], input=json.dumps(payload), capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['result']['content'], 'events {}')

    def test_changed_destination_requires_password_again(self):
        server = Server.objects.create(name='Remote', host='192.0.2.10', mode='ssh', auth_method='password', fingerprint='SHA256:' + 'x' * 43)
        server.set_secret('old-host-password')
        server.save()
        data = {**public_server(server), 'host': '192.0.2.11'}
        form = ServerForm(data, instance=server)
        self.assertFalse(form.is_valid())
        self.assertIn('secret', form.errors)

    def test_changed_destination_resets_metric_history(self):
        from django.contrib.auth import get_user_model
        self.client.force_login(get_user_model().objects.create_user('operator', is_staff=True))
        with tempfile.TemporaryDirectory() as directory, override_settings(STATE_DIR=Path(directory)):
            server = Server.objects.create(name='Demo', host='192.0.2.10', mode='demo')
            MetricSample.objects.create(server=server, cpu=90, memory=50, rx_rate=10, tx_rate=5, rx_mb=100, tx_mb=50, uptime=1000)
            response = self.client.post('/api/servers/', {**public_server(server), 'action': 'update', 'host': '192.0.2.11'}, content_type='application/json')
            self.assertEqual(response.status_code, 200, response.content)
            self.assertFalse(MetricSample.objects.filter(server=server).exists())

    def test_metrics_and_audit_are_server_scoped(self):
        from django.contrib.auth import get_user_model
        self.client.force_login(get_user_model().objects.create_user('operator', is_staff=True))
        primary = Server.objects.get(pk='local')
        secondary = Server.objects.create(name='Other', host='192.0.2.9', mode='demo')
        data = dict(cpu=90, memory=50, rx_rate=10, tx_rate=5, rx_mb=100, tx_mb=50, uptime=1000)
        MetricSample.objects.create(server=primary, **data)
        MetricSample.objects.create(server=secondary, **{**data, 'cpu': 12})
        AuditEvent.objects.create(server=primary, actor='operator', action='test', target='primary-only')
        self.assertEqual(snapshot(secondary)['peaks']['cpu'], 12)
        response = self.client.get('/api/audit/', {'server': secondary.pk})
        self.assertNotContains(response, 'primary-only')
        self.assertEqual(self.client.get('/api/hosts/', {'server': 'deleted'}).status_code, 400)

    def test_network_counter_reset_is_not_negative(self):
        raw = dict(cpu_total=100, cpu_idle=50, memory=20, disk_used_bytes=400, disk_total_bytes=1000, rx_bytes=500, tx_bytes=100, uptime=10)
        previous = ({**raw, 'cpu_total': 200, 'rx_bytes': 900, 'uptime': 100}, 5)
        sample = sample_from_raw(raw, previous, 10)
        self.assertEqual(sample['rx_rate'], 0)
        self.assertEqual(sample['cpu'], 0)
        self.assertEqual(sample['disk_used_bytes'], 400)
        self.assertEqual(sample['disk_total_bytes'], 1000)

    def test_local_raw_reports_root_disk_usage(self):
        raw = local_raw('')
        self.assertGreater(raw['disk_total_bytes'], 0)
        self.assertGreaterEqual(raw['disk_used_bytes'], 0)
        self.assertLessEqual(raw['disk_used_bytes'], raw['disk_total_bytes'])

    def test_stale_profile_cannot_run_nginx_operation(self):
        from django.contrib.auth import get_user_model
        self.client.force_login(get_user_model().objects.create_user('operator', is_staff=True))
        server = Server.objects.get(pk='local')
        previous_revision = server.updated_at.isoformat()
        server.host = '192.0.2.99'
        server.save()
        with patch('panel.views.manager_for') as manager:
            response = self.client.post('/api/service/?' + urlencode({'server': 'local', 'server_revision': previous_revision}), {'action': 'reload'}, content_type='application/json')
            self.assertEqual(response.status_code, 400)
            manager.assert_not_called()

    def test_server_crud_and_default_protection(self):
        from django.contrib.auth import get_user_model
        self.client.force_login(get_user_model().objects.create_user('operator', is_staff=True))
        with tempfile.TemporaryDirectory() as directory, override_settings(STATE_DIR=Path(directory)):
            response = self.client.post('/api/servers/', {'action': 'create', 'name': 'Second', 'host': '192.0.2.12', 'mode': 'demo'}, content_type='application/json')
            self.assertEqual(response.status_code, 200, response.content)
            server = response.json()['server']
            response = self.client.get('/api/hosts/', {'server': server['id']})
            self.assertEqual(len(response.json()['items']), 2)
            deleted = self.client.post('/api/servers/', {'action': 'delete', 'id': server['id'], 'revision': server['revision']}, content_type='application/json')
            self.assertEqual(deleted.status_code, 200)
        primary = public_server(Server.objects.get(pk='local'))
        response = self.client.post('/api/servers/', {'action': 'delete', 'id': primary['id'], 'revision': primary['revision']}, content_type='application/json')
        self.assertEqual(response.status_code, 400)