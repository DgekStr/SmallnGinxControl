import ipaddress
import re
from pathlib import Path

from django import forms
from django.conf import settings

from .models import Server
from .nginx import NginxManager
from .transactions import OperationError, atomic_write


def validate_host(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', value):
            raise forms.ValidationError('Укажите IP-адрес или DNS-имя без схемы и пути.')


class AddressForm(forms.Form):
    host = forms.CharField(max_length=253, validators=[validate_host])
    port = forms.IntegerField(min_value=1, max_value=65535, initial=22)


class ServerForm(forms.ModelForm):
    secret = forms.CharField(required=False, max_length=4096, strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_auth = self.instance.auth_method

    class Meta:
        model = Server
        fields = ['name', 'host', 'mode', 'port', 'username', 'auth_method', 'key_path', 'fingerprint', 'nginx_root', 'log_root', 'interface']

    def clean(self):
        values = super().clean()
        mode = values.get('mode')
        if mode == 'local' and not self.instance.is_default:
            self.add_error('mode', 'Дополнительные серверы подключаются по SSH или работают в деморежиме.')
        if self.instance.is_default and mode != self.instance.mode:
            self.add_error('mode', 'Режим основного сервера задаётся при запуске панели.')
        try:
            validate_host(values.get('host', ''))
        except forms.ValidationError as error:
            self.add_error('host', error)
        if mode == 'ssh':
            if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]*\$?', values.get('username', '')):
                self.add_error('username', 'Некорректное имя SSH-пользователя.')
            if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', values.get('fingerprint', '')):
                self.add_error('fingerprint', 'Нужен проверенный SHA256-отпечаток ключа SSH-сервера.')
            for field in ['nginx_root', 'log_root']:
                value = values.get(field, '')
                if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', value) or '..' in value.split('/') or value == '/':
                    self.add_error(field, 'Укажите абсолютный Linux-путь к каталогу.')
            auth = values.get('auth_method')
            destination_changed = any(getattr(self.instance, field) != values.get(field) for field in ['host', 'port', 'username'])
            if auth == 'password' and not values.get('secret') and (not self.instance.encrypted_secret or destination_changed or self.instance.auth_method != auth):
                self.add_error('secret', 'Введите SSH-пароль для этого сервера.')
            if auth == 'key' and not Path(values.get('key_path') or '.').is_absolute():
                self.add_error('key_path', 'Укажите абсолютный путь к приватному ключу на машине панели.')
        if values.get('interface') and not re.fullmatch(r'[a-zA-Z0-9_.:-]+', values['interface']):
            self.add_error('interface', 'Некорректное имя интерфейса.')
        return values

    def save(self, commit=True):
        server = super().save(commit=False)
        secret = self.cleaned_data.get('secret')
        if secret:
            server.set_secret(secret)
        elif server.auth_method != self.original_auth:
            server.set_secret('')
        if server.mode != 'ssh' or server.auth_method == 'agent':
            server.set_secret('')
        if commit:
            server.save()
        return server


def public_server(server):
    fields = ['id', 'name', 'host', 'mode', 'is_default', 'port', 'username', 'auth_method', 'key_path', 'fingerprint', 'nginx_root', 'log_root', 'interface', 'last_seen', 'last_error']
    return {**{field: getattr(server, field) for field in fields}, 'has_secret': bool(server.encrypted_secret), 'revision': server.updated_at.isoformat()}


def selected_server(identifier=None):
    try:
        return Server.objects.get(pk='local' if identifier is None else identifier)
    except (Server.DoesNotExist, ValueError, TypeError):
        raise OperationError('Сервер не найден. Выберите существующий профиль.')


def local_manager(server):
    if server.is_default:
        if server.mode != settings.SNC_MODE:
            raise OperationError('Режим основного профиля не совпадает с режимом панели. Не переносите демобазу в рабочее окружение.')
        return NginxManager(demo=server.mode == 'demo')
    directory = settings.STATE_DIR / 'servers' / server.pk
    return NginxManager(root=directory / 'nginx', logs_root=directory / 'logs', state=directory, demo=True)


def manager_for(server):
    if server.mode == 'ssh':
        from .ssh import SSHManager
        return SSHManager(server)
    return local_manager(server)


def initialize_demo(server):
    if server.mode != 'demo' or server.is_default:
        return
    manager = local_manager(server)
    for directory in [manager.root / 'conf.d', manager.root / 'sites-available', manager.root / 'sites-enabled', manager.logs_root]:
        directory.mkdir(parents=True, exist_ok=True)
    if (manager.root / 'nginx.conf').exists():
        return
    atomic_write(manager.root / 'nginx.conf', b'worker_processes auto;\nevents { worker_connections 1024; }\nhttp { include conf.d/*.conf; include sites-enabled/*; }\n')
    manager.create({'name': 'welcome.demo', 'kind': 'host', 'target': '/var/www/html', 'port': 80})
    manager.create({'name': 'api.demo', 'kind': 'proxy', 'target': 'http://127.0.0.1:8000', 'port': 80})
    atomic_write(manager.logs_root / 'access.log', b'127.0.0.1 - - "GET / HTTP/1.1" 200 512\n')
    atomic_write(manager.logs_root / 'error.log', b'')