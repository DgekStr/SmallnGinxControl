import base64
import hashlib
import hmac
import json
import socket
import zlib
from functools import lru_cache
from pathlib import Path
from pathlib import PurePosixPath

import paramiko
from cryptography.fernet import InvalidToken
from django.conf import settings

from .nginx import NginxManager, configured_log_paths, describe_configuration
from .transactions import ACCESS_LOG_SAMPLE_DEFAULT_BYTES, OperationError


def key_fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        if not hmac.compare_digest(self.expected, key_fingerprint(key)):
            raise OperationError('SSH-ключ сервера не совпадает с сохранённым отпечатком. Подключение заблокировано.')


def probe_fingerprint(host, port):
    try:
        with socket.create_connection((host, port), timeout=6) as connection:
            transport = paramiko.Transport(connection)
            try:
                transport.start_client(timeout=6)
                key = transport.get_remote_server_key()
                return {'fingerprint': key_fingerprint(key), 'algorithm': key.get_name()}
            finally:
                transport.close()
    except (OSError, paramiko.SSHException) as error:
        raise OperationError('Не удалось получить SSH-ключ: ' + str(error)) from error


@lru_cache(maxsize=1)
def worker_command():
    folder = Path(__file__).parent
    source = (folder / 'transactions.py').read_text(encoding='utf-8') + '\n' + (folder / 'remote_worker.py').read_text(encoding='utf-8')
    encoded = base64.b64encode(zlib.compress(source.encode(), 9)).decode()
    return 'python3 -c \'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("' + encoded + '")),"<smallnginxcontrol>","exec"))\''


class SSHManager:
    demo = False

    def __init__(self, server):
        self.server = server
        directory = settings.STATE_DIR / 'servers' / server.pk
        directory.mkdir(parents=True, exist_ok=True)
        self.parser = NginxManager(state=directory, demo=True)

    def rpc(self, operation, data=None):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(PinnedHostKey(self.server.fingerprint))
        try:
            secret = self.server.get_secret() or None
            client.connect(
                hostname=self.server.host, port=self.server.port, username=self.server.username,
                password=secret if self.server.auth_method == 'password' else None,
                key_filename=self.server.key_path if self.server.auth_method == 'key' else None,
                passphrase=secret if self.server.auth_method == 'key' else None,
                allow_agent=self.server.auth_method == 'agent', look_for_keys=False,
                timeout=6, banner_timeout=6, auth_timeout=8,
            )
            stdin, stdout, stderr = client.exec_command(worker_command(), timeout=90)
            stdin.write(json.dumps({
                'root': self.server.nginx_root,
                'log_root': self.server.log_root,
                'log_roots': [str(path) for path in settings.SNC_LOG_EXTRA_ROOTS],
                'certbot_bin': settings.SNC_CERTBOT_BIN,
                'acme_webroot': str(settings.SNC_ACME_WEBROOT),
                'certbot_live_root': str(settings.SNC_CERTBOT_LIVE_ROOT),
                'management_host': settings.SNC_SERVER,
                'management_port': settings.SNC_PORT,
                'management_https_port': int(settings.SNC_PORT) + 1,
                'operation': operation,
                'data': data or {},
            }, ensure_ascii=True))
            stdin.flush()
            stdin.channel.shutdown_write()
            output = stdout.read(6 * 1024 * 1024 + 1)
            if len(output) > 6 * 1024 * 1024:
                raise OperationError('Ответ SSH-сервера превышает 6 МБ.')
            if not output:
                raise OperationError('SSH-исполнитель не запустился. Проверьте Python 3 и права пользователя. ' + stderr.read(2000).decode('utf-8', errors='replace'))
            result = json.loads(output)
            if not result.get('ok'):
                raise OperationError(result.get('error', 'Ошибка nginx на SSH-сервере.'))
            return result['result']
        except paramiko.AuthenticationException as error:
            raise OperationError('Ошибка аутентификации SSH. Проверьте пользователя и способ входа.') from error
        except InvalidToken as error:
            raise OperationError('SSH-секрет не расшифрован. Введите его повторно в настройках сервера.') from error
        except (OSError, paramiko.SSHException, ValueError) as error:
            raise OperationError('Ошибка подключения SSH: ' + str(error)) from error
        finally:
            client.close()

    def status(self):
        return self.rpc('status')

    def raw_metrics(self):
        return self.rpc('metrics', {'interface': self.server.interface})

    def inventory(self):
        result = self.rpc('inventory')
        items, warnings = [], result['warnings']
        for config in result['configs']:
            try:
                nodes = self.parser.syntax(config['content'])
                item = describe_configuration(nodes, config['id'], config['revision'], config['enabled'], config['toggleable'], config.get('maintenance', False), config.get('certificate_days'), config.get('certificate'), config.get('nonpayment', False))
                if item:
                    items.append(item)
            except OperationError as error:
                warnings.append(config['id'] + ': ' + str(error))
        return {'items': items, 'warnings': warnings}

    def read(self, identifier):
        return self.rpc('read', {'id': identifier})

    def save(self, identifier, content, expected_revision):
        if not isinstance(content, str) or len(content.encode('utf-8')) > 256 * 1024:
            raise OperationError('Размер конфигурации не должен превышать 256 КБ.')
        self.parser.syntax(content)
        return self.rpc('save', {'id': identifier, 'content': content, 'revision': expected_revision})

    def create(self, data):
        issue_ssl = data.get('issue_ssl', False)
        if type(issue_ssl) is not bool:
            raise OperationError('Признак выпуска SSL должен быть boolean.')
        maintenance_include = str(PurePosixPath(self.server.nginx_root) / 'snippets' / 'maintenance_all.conf')
        name, filename, content = self.parser.render_site(data, log_root=self.server.log_root, challenge=issue_ssl, maintenance_include=maintenance_include)
        if any(name in item['domains'] for item in self.inventory()['items']):
            raise OperationError('Такой домен уже есть в конфигурации сервера.')
        payload = {'id': 'conf.d/' + filename, 'content': content}
        if issue_ssl:
            _, _, https_content = self.parser.render_site(data, log_root=self.server.log_root, https=True, maintenance_include=maintenance_include)
            payload.update({
                'issue_ssl': True,
                'ssl_domain': name,
                'ssl_email': data.get('ssl_email'),
                'https_content': https_content,
            })
        return self.rpc('create', payload)

    def toggle(self, identifier, enabled, expected_revision):
        return self.rpc('toggle', {'id': identifier, 'enabled': enabled, 'revision': expected_revision})

    def toggle_nonpayment(self, identifier, enabled, expected_revision, contact_text):
        return self.rpc('toggle_nonpayment', {
            'id': identifier, 'enabled': enabled, 'revision': expected_revision,
            'contact_text': contact_text,
        })

    def update_nonpayment_contact(self, contact_text):
        return self.rpc('update_nonpayment_contact', {'contact_text': contact_text})

    def delete(self, identifier, expected_revision):
        return self.rpc('delete', {'id': identifier, 'revision': expected_revision})

    def traffic_top(self, sample_size=ACCESS_LOG_SAMPLE_DEFAULT_BYTES):
        return self.rpc('traffic', {'sample_size': sample_size})

    def service(self, action):
        if action not in {'test', 'reload', 'restart'}:
            raise OperationError('Неизвестное действие.')
        return self.rpc(action)

    def validate_traffic_maintenance_page(self, page_path):
        return self.rpc('validate_traffic_maintenance_page', {'page_path': page_path})['path']

    def set_traffic_maintenance(self, enabled, page_path):
        return self.rpc('traffic_maintenance', {'enabled': enabled, 'page_path': page_path})

    def logs(self, identifier='', kind='access', lines=150):
        if kind not in {'access', 'error'}:
            raise OperationError('Неизвестный журнал.')
        if identifier:
            config = self.read(identifier)
            nodes = self.parser.syntax(config['content'])
            paths, has_off = configured_log_paths(nodes, kind)
            if not paths and has_off:
                note = 'Запись access-лога выключена директивой access_log off.' if kind == 'access' else 'Директива error_log off не задаёт файловый путь к журналу.'
                return {'content': note, 'sources': [], 'note': note}
        else:
            paths = [self.server.log_root.rstrip('/') + '/' + kind + '.log']
        return self.rpc('logs', {'paths': paths, 'lines': max(1, min(500, lines))})