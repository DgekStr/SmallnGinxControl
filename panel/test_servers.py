import tempfile
import json
import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from django.test import TestCase, override_settings

from .models import AuditEvent, MetricSample, Server
from .servers import ServerForm, initialize_demo, manager_for, public_server, selected_server
from .transactions import OperationError
from .remote_worker import RemoteWorker
from .ssh import PinnedHostKey, key_fingerprint, worker_command
from .metrics import snapshot, sample_from_raw


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

    def test_remote_worker_refuses_delete_of_enabled_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conf.d').mkdir()
            path = root / 'conf.d' / 'active.conf'
            path.write_text('server { listen 80; server_name active.test; }\n')
            worker = RemoteWorker(root, root / 'logs', root / 'state')
            config = {'id': 'conf.d/active.conf', 'toggleable': True, 'enabled': True}
            with patch.object(worker, 'inventory', return_value={'configs': [config], 'warnings': []}):
                with self.assertRaisesRegex(OperationError, 'Disable the host'):
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
        raw = dict(cpu_total=100, cpu_idle=50, memory=20, rx_bytes=500, tx_bytes=100, uptime=10)
        previous = ({**raw, 'cpu_total': 200, 'rx_bytes': 900, 'uptime': 100}, 5)
        sample = sample_from_raw(raw, previous, 10)
        self.assertEqual(sample['rx_rate'], 0)
        self.assertEqual(sample['cpu'], 0)

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