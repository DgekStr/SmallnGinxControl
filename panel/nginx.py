import hashlib
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import crossplane
import portalocker
from django.conf import settings

from .transactions import (
    OperationError, access_log_traffic_bytes, apply_transaction, atomic_write,
    certificate_days_remaining, configure_host_access_logs, delete_config_transaction,
    issue_webroot_certificate, validate_certificate_request,
    has_proxy_server, is_allowed_log_path,
    is_maintenance_config, maintenance_backup_path, render_maintenance_config,
)


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.get('block', []))


def configured_log_paths(nodes, kind):
    directives = [node for node in walk(nodes) if node['directive'] == kind + '_log' and node['args']]
    has_off = any(node['args'][0].lower() == 'off' for node in directives)
    paths = [node['args'][0] for node in directives if node['args'][0].lower() != 'off']
    return list(dict.fromkeys(paths)), has_off


def revision(content):
    return hashlib.sha256(content).hexdigest()


def describe_configuration(nodes, identifier, content_revision, enabled, toggleable, maintenance=False, certificate_days=None):
    directives = list(walk(nodes))
    servers = sum(node['directive'] == 'server' and 'block' in node for node in directives)
    if not servers:
        return None
    domains = [value for node in directives if node['directive'] == 'server_name' for value in node['args']]
    upstreams = [node['args'][0] for node in directives if node['directive'] in {'proxy_pass', 'fastcgi_pass', 'grpc_pass', 'uwsgi_pass', 'scgi_pass'} and node['args']]
    roots = [node['args'][0] for node in directives if node['directive'] == 'root' and node['args']]
    listens = [' '.join(node['args']) for node in directives if node['directive'] == 'listen']
    return {
        'id': identifier, 'name': domains[0] if domains else Path(identifier).stem,
        'domains': domains, 'kind': 'proxy' if upstreams else 'host',
        'target': ', '.join(dict.fromkeys(upstreams or roots)) or 'Конфигурация сервера',
        'listen': ', '.join(dict.fromkeys(listens)) or '80',
        'tls': any('ssl' in node['args'] for node in directives if node['directive'] == 'listen'),
        'enabled': enabled, 'maintenance': maintenance, 'certificate_days': certificate_days, 'servers': servers, 'toggleable': toggleable, 'revision': content_revision,
    }


class NginxManager:
    def __init__(self, *, root=None, logs_root=None, state=None, demo=None, maintenance_root=None, extra_log_roots=None):
        self.root = Path(root if root is not None else settings.NGINX_ROOT).resolve()
        self.logs_root = Path(logs_root if logs_root is not None else settings.NGINX_LOG_ROOT).resolve()
        self.demo = settings.SNC_MODE == 'demo' if demo is None else demo
        self.state = Path(state if state is not None else settings.STATE_DIR)
        self.maintenance_root = Path(maintenance_root if maintenance_root is not None else settings.SNC_MAINTENANCE_ROOT)
        self.maintenance_page = self.maintenance_root / 'maitenance.html'
        configured_log_roots = settings.SNC_LOG_EXTRA_ROOTS if extra_log_roots is None else extra_log_roots
        self.allowed_log_roots = tuple(dict.fromkeys([self.logs_root, *(Path(root).resolve() for root in configured_log_roots)]))

    def lock(self):
        return portalocker.Lock(str(self.state / 'nginx.lock'), timeout=15)

    def path(self, identifier):
        if not isinstance(identifier, str) or not identifier or '\\' in identifier:
            raise OperationError('Недопустимый путь конфигурации.')
        relative = Path(identifier)
        if relative.is_absolute() or '..' in relative.parts or any(part.startswith('.') for part in relative.parts):
            raise OperationError('Недопустимый путь конфигурации.')
        path = self.root / relative
        if not path.resolve().is_relative_to(self.root):
            raise OperationError('Конфигурация находится за пределами каталога nginx.')
        if path.is_symlink():
            raise OperationError('Редактируйте исходный файл, а не символическую ссылку.')
        return path

    def parse(self, path):
        result = crossplane.parse(str(path), single=True, check_ctx=False, check_args=False)
        if result['status'] != 'ok':
            errors = '; '.join(str(error.get('error', error)) for error in result.get('errors', []))
            raise OperationError(f'Ошибка синтаксиса: {errors[:1500]}')
        return result['config'][0]['parsed']

    def syntax(self, content):
        descriptor, temporary = tempfile.mkstemp(suffix='.nginx', dir=self.state)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
                stream.write(content)
            return self.parse(Path(temporary))
        finally:
            os.unlink(temporary)

    def command(self, arguments, timeout=20):
        try:
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OperationError(str(error)) from error
        output = (result.stdout + result.stderr).strip()
        if result.returncode:
            raise OperationError(output[:3000] or f'Код завершения: {result.returncode}')
        return output

    def validate(self):
        if self.demo:
            self.parse(self.root / 'nginx.conf')
            for item in self.inventory()['items']:
                if item['enabled'] or item.get('maintenance'):
                    self.parse(self.path(item['id']))
            return 'Демо: синтаксис Crossplane корректен. nginx -t выполняется только в рабочем режиме.'
        return self.command([settings.NGINX_BIN, '-t', '-c', str(self.root / 'nginx.conf')])

    def reload(self):
        if not self.demo:
            self.command(['/usr/bin/systemctl', 'reload', 'nginx'])

    def service(self, action):
        if action not in {'test', 'reload', 'restart'}:
            raise OperationError('Неизвестное действие.')
        with self.lock():
            output = self.validate()
            if action == 'reload':
                self.reload()
            elif action == 'restart' and not self.demo:
                self.command(['/usr/bin/systemctl', 'restart', 'nginx'])
            return output

    def status(self):
        if self.demo:
            return {'active': True, 'version': 'nginx/1.24.0', 'system': 'Ubuntu · демо'}
        try:
            version = self.command([settings.NGINX_BIN, '-v'])
            self.command(['/usr/bin/systemctl', 'is-active', 'nginx'])
            active = True
        except OperationError:
            version, active = 'nginx', False
        import platform
        try:
            system = platform.freedesktop_os_release().get('PRETTY_NAME', 'Linux')
        except OSError:
            system = platform.system()
        return {'active': active, 'version': version.replace('nginx version: ', ''), 'system': system}

    def inventory(self):
        files, warnings, active_files = set(), [], set()
        for folder, pattern in [('sites-available', '*'), ('sites-enabled', '*'), ('conf.d', '*.conf'), ('conf.d', '*.conf.disabled')]:
            for path in (self.root / folder).glob(pattern):
                if path.is_file() and not path.name.startswith('.'):
                    if path.resolve().is_relative_to(self.root):
                        files.add(path.resolve())
                    else:
                        warnings.append(f'Внешняя конфигурация вне каталога nginx: {path}')
        if not self.demo and (self.root / 'nginx.conf').exists():
            payload = crossplane.parse(str(self.root / 'nginx.conf'), check_ctx=False, check_args=False)
            for config in payload.get('config', []):
                path = Path(config['file']).resolve()
                active_files.add(path)
                if path != self.root / 'nginx.conf':
                    if path.is_relative_to(self.root):
                        files.add(path)
                    else:
                        warnings.append(f'Внешний include: {path}')
            if payload['status'] != 'ok':
                warnings.append('Включаемые файлы разобраны не полностью. Проверьте nginx -t.')
        items = []
        for path in sorted(files):
            identifier = path.relative_to(self.root).as_posix()
            try:
                content = path.read_bytes()
                maintenance = is_maintenance_config(content)
                nodes = self.parse(path)
                links = self.links(path)
                standard_conf = path.parent == self.root / 'conf.d'
                standard_site = path.parent == self.root / 'sites-available'
                enabled = bool(links) or (standard_conf and path.suffix == '.conf') or path.parent == self.root / 'sites-enabled'
                if not self.demo:
                    enabled = path in active_files
                if maintenance:
                    enabled = False
                certificates = [node['args'][0] for node in walk(nodes) if node['directive'] == 'ssl_certificate' and node['args']]
                certificate_days = certificate_days_remaining(certificates) if any('ssl' in node['args'] for node in walk(nodes) if node['directive'] == 'listen') else None
                item = describe_configuration(nodes, identifier, revision(content), enabled, standard_site or standard_conf, maintenance, certificate_days)
                if item:
                    items.append(item)
            except (OperationError, OSError, UnicodeError) as error:
                warnings.append(f'{identifier}: {error}')
        return {'items': items, 'warnings': warnings}

    def links(self, path):
        return [link for link in (self.root / 'sites-enabled').glob('*') if link.is_symlink() and link.resolve() == path.resolve()]

    def read(self, identifier):
        path = self.path(identifier)
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            raise OperationError('Файл отсутствует или превышает 256 КБ.')
        content = path.read_bytes()
        return {'id': identifier, 'content': content.decode('utf-8'), 'revision': revision(content)}

    def backup(self, identifier, content):
        directory = self.state / 'backups'
        directory.mkdir(exist_ok=True)
        name = f'{time.time_ns()}-{Path(identifier).name}.bak'
        atomic_write(directory / name, content)

    def maintenance_backup(self, identifier):
        return maintenance_backup_path(self.state, identifier)

    def require_maintenance_page(self):
        if not self.maintenance_page.is_file():
            raise OperationError(f'Страница обслуживания {self.maintenance_page} не найдена.')

    def save(self, identifier, content, expected_revision):
        if not isinstance(content, str) or len(content.encode('utf-8')) > 256 * 1024:
            raise OperationError('Размер конфигурации не должен превышать 256 КБ.')
        self.syntax(content)
        with self.lock():
            path = self.path(identifier)
            old = path.read_bytes()
            if revision(old) != expected_revision:
                raise OperationError('Файл уже изменён. Откройте его заново перед сохранением.')
            self.backup(identifier, old)
            return apply_transaction(lambda: atomic_write(path, content.encode('utf-8')), lambda: atomic_write(path, old), self.validate, self.reload)

    def toggle(self, identifier, enabled, expected_revision):
        with self.lock():
            path = self.path(identifier)
            current = path.read_bytes()
            if revision(current) != expected_revision:
                raise OperationError('Конфигурация изменилась. Обновите список.')
            stored = self.maintenance_backup(identifier)
            if is_maintenance_config(current):
                if not enabled:
                    return 'Режим обслуживания уже включён.'
                if not stored.is_file():
                    raise OperationError('Исходная конфигурация для восстановления не найдена.')
                original = stored.read_bytes()
                self.backup(identifier, current)
                result = apply_transaction(
                    lambda: atomic_write(path, original),
                    lambda: atomic_write(path, current),
                    self.validate, self.reload,
                )
                stored.unlink(missing_ok=True)
                return result
            active = (path.parent == self.root / 'sites-available' and bool(self.links(path))) or (path.parent == self.root / 'conf.d' and path.suffix == '.conf')
            if not enabled and active and has_proxy_server(current):
                self.require_maintenance_page()
                if stored.exists():
                    raise OperationError('Сохранённая исходная конфигурация уже существует. Сначала восстановите сайт вручную.')
                maintenance = render_maintenance_config(current, self.maintenance_root)
                self.backup(identifier, current)

                def change():
                    stored.parent.mkdir(parents=True, exist_ok=True)
                    atomic_write(stored, current)
                    atomic_write(path, maintenance)

                def rollback():
                    atomic_write(path, current)
                    stored.unlink(missing_ok=True)

                return apply_transaction(change, rollback, self.validate, self.reload)
            if path.parent == self.root / 'sites-available':
                links = self.links(path)
                link = self.root / 'sites-enabled' / path.name
                if enabled and not links:
                    if os.path.lexists(link):
                        raise OperationError('Имя в sites-enabled уже занято.')
                    change = lambda: link.symlink_to(path)
                    rollback = lambda: link.unlink(missing_ok=True)
                elif not enabled and links:
                    targets = {item: os.readlink(item) for item in links}
                    def change():
                        for item in links:
                            item.unlink()
                    def rollback():
                        for item, target in targets.items():
                            if not os.path.lexists(item):
                                item.symlink_to(target)
                else:
                    return 'Состояние уже установлено.'
            elif path.parent == self.root / 'conf.d':
                if enabled == (path.suffix == '.conf'):
                    return 'Состояние уже установлено.'
                destination = path.with_name(path.name.removesuffix('.disabled') if enabled else path.name + '.disabled')
                if destination.exists():
                    raise OperationError('Целевое имя уже занято.')
                change = lambda: path.rename(destination)
                def rollback():
                    if destination.exists():
                        destination.rename(path)
            else:
                raise OperationError('Для нестандартного include измените nginx.conf вручную.')
            self.backup(identifier, current)
            return apply_transaction(change, rollback, self.validate, self.reload)

    def delete(self, identifier, expected_revision):
        with self.lock():
            path = self.path(identifier)
            if not path.is_file():
                raise OperationError('Файл конфигурации не найден.')
            current = path.read_bytes()
            if revision(current) != expected_revision:
                raise OperationError('Конфигурация изменилась. Обновите список.')
            standard_site = path.parent == self.root / 'sites-available'
            standard_conf = path.parent == self.root / 'conf.d' and (path.name.endswith('.conf') or path.name.endswith('.conf.disabled'))
            if not standard_site and not standard_conf:
                raise OperationError('Удалять можно только стандартные конфигурации сайтов.')
            item = next((item for item in self.inventory()['items'] if item['id'] == identifier), None)
            if item is None or not item['toggleable']:
                raise OperationError('Конфигурация не является управляемым виртуальным хостом.')
            if item['enabled']:
                raise OperationError('Сначала отключите хост. Активные конфигурации удалять нельзя.')
            links = self.links(path) if standard_site else []
            stored = self.maintenance_backup(identifier)
            self.backup(identifier, current)
            if stored.is_file():
                self.backup(identifier, stored.read_bytes())
            delete_config_transaction(path, links, self.validate, self.reload)
            if stored.is_file():
                stored.unlink()
            return 'Хост удалён из nginx. Резервная копия конфигурации сохранена.'

    def enable_host_logging(self, *, dry_run=True):
        with self.lock():
            plans, hosts = {}, set()
            for item in self.inventory()['items']:
                if not item['toggleable']:
                    continue
                identifier = item['id']
                path = self.path(identifier)
                original = path.read_bytes()
                updated, changed_hosts = configure_host_access_logs(original, path.stem, self.logs_root)
                if updated != original:
                    self.syntax(updated.decode('utf-8'))
                    plans[path] = (identifier, original, updated)
                    hosts.update(changed_hosts)
                if item['maintenance']:
                    stored = self.maintenance_backup(identifier)
                    if stored.is_file():
                        stored_original = stored.read_bytes()
                        stored_updated, stored_hosts = configure_host_access_logs(stored_original, path.stem, self.logs_root)
                        if stored_updated != stored_original:
                            self.syntax(stored_updated.decode('utf-8'))
                            plans[stored] = (identifier + '.maintenance-original', stored_original, stored_updated)
                            hosts.update(stored_hosts)
            summary = {'files': len(plans), 'hosts': len(hosts), 'host_names': sorted(hosts)}
            if dry_run or not plans:
                return summary
            for identifier, original, _ in plans.values():
                self.backup(identifier, original)

            def change():
                for path, (_, _, updated) in plans.items():
                    atomic_write(path, updated)

            def rollback():
                for path, (_, original, _) in plans.items():
                    atomic_write(path, original)

            self.validate()
            apply_transaction(change, rollback, self.validate, self.reload)
            return summary

    def render_site(self, data, log_root=None, *, challenge=False, https=False):
        name = data.get('name', '').strip().lower()
        if len(name) > 190 or not re.fullmatch(r'(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name):
            raise OperationError('Введите корректное доменное имя (IDN в punycode).')
        try:
            port = int(data.get('port', 80))
        except (ValueError, TypeError):
            raise OperationError('Некорректный порт.')
        if not 1 <= port <= 65535:
            raise OperationError('Порт должен быть от 1 до 65535.')
        if https:
            validate_certificate_request(name, data.get('ssl_email'))
            if port != 80:
                raise OperationError('Для HTTP-01 SSL challenge у нового хоста должен быть порт 80.')
        kind, target = data.get('kind'), data.get('target', '').strip()
        if kind == 'proxy':
            parsed = urlsplit(target)
            try:
                parsed.port
            except ValueError:
                raise OperationError('Некорректный порт upstream.')
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or re.search(r'[\s;{}#"\x00-\x1f\\$]', target):
                raise OperationError('Upstream должен быть HTTP(S)-адресом без специальных символов.')
            location = f'proxy_pass {target};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_http_version 1.1;'
        elif kind == 'host':
            if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', target) or '..' in Path(target).parts:
                raise OperationError('Укажите абсолютный путь к каталогу сайта.')
            location = f'root {target};\n        index index.html;\n        try_files $uri $uri/ =404;'
        else:
            raise OperationError('Неизвестный тип хоста.')
        filename = name.replace('*', 'wildcard') + '.conf'
        log_root = self.logs_root.as_posix() if log_root is None else log_root.rstrip('/')
        log_name = name.replace('*', 'wildcard')
        access_log = f'{log_root}/{log_name}-data.log'
        error_log = f'{log_root}/{filename}.error.log'
        acme_root = PurePosixPath(str(settings.SNC_ACME_WEBROOT).replace('\\', '/'))
        if not acme_root.is_absolute() or '..' in acme_root.parts or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', acme_root.as_posix()):
            raise OperationError('Некорректный ACME webroot path.')
        challenge_location = f'    location ^~ /.well-known/acme-challenge/ {{\n        root {acme_root.as_posix()};\n        try_files $uri =404;\n    }}\n'
        if https:
            cert_root = PurePosixPath(str(settings.SNC_CERTBOT_LIVE_ROOT).replace('\\', '/'))
            if not cert_root.is_absolute() or '..' in cert_root.parts or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', cert_root.as_posix()):
                raise OperationError('Некорректный каталог live-сертификатов.')
            cert_dir = cert_root / name
            http_block = (
                f'server {{\n    listen 80;\n    listen [::]:80;\n    server_name {name};\n'
                f'    access_log {access_log};\n    error_log {error_log} warn;\n\n'
                f'{challenge_location}\n'
                '    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n'
            )
            https_block = (
                f'\nserver {{\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name {name};\n'
                f'    ssl_certificate {cert_dir}/fullchain.pem;\n'
                f'    ssl_certificate_key {cert_dir}/privkey.pem;\n'
                '    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_tickets off;\n'
                f'    access_log {access_log};\n    error_log {error_log} warn;\n\n'
                f'    location / {{\n        {location}\n    }}\n}}\n'
            )
            content = http_block + https_block
        else:
            challenge_block = challenge_location + '\n' if challenge else ''
            content = f'server {{\n    listen {port};\n    server_name {name};\n    access_log {access_log};\n    error_log {error_log} warn;\n\n{challenge_block}    location / {{\n        {location}\n    }}\n}}\n'
        self.syntax(content)
        return name, filename, content

    def create(self, data):
        issue_ssl = data.get('issue_ssl', False)
        if type(issue_ssl) is not bool:
            raise OperationError('Признак выпуска SSL должен быть boolean.')
        if issue_ssl and self.demo:
            raise OperationError('Выпуск SSL доступен только на рабочем nginx-сервере.')
        if issue_ssl:
            name, filename, content = self.render_site(data, challenge=True)
            _, _, https_content = self.render_site(data, https=True)
        else:
            name, filename, content = self.render_site(data)
        with self.lock():
            path = self.path('conf.d/' + filename)
            if path.exists() or path.with_name(filename + '.disabled').exists():
                raise OperationError('Конфигурация с таким именем уже существует.')
            for item in self.inventory()['items']:
                if name in item['domains']:
                    raise OperationError('Такой домен уже есть в конфигурации.')
            result = apply_transaction(lambda: atomic_write(path, content.encode()), lambda: path.unlink(missing_ok=True), self.validate, self.reload)
            if not issue_ssl:
                return result
            try:
                issue_webroot_certificate(settings.SNC_CERTBOT_BIN, settings.SNC_ACME_WEBROOT, settings.SNC_CERTBOT_LIVE_ROOT, name, data.get('ssl_email'))
            except OperationError as error:
                try:
                    apply_transaction(lambda: path.unlink(missing_ok=True), lambda: atomic_write(path, content.encode()), self.validate, self.reload)
                except Exception as cleanup_error:
                    raise OperationError(f'Certbot failed ({error}); temporary HTTP host rollback failed ({cleanup_error}).') from error
                raise OperationError(f'Certbot не выпустил сертификат; временный HTTP-хост удалён: {error}') from error
            self.backup('conf.d/' + filename, content.encode())
            result = apply_transaction(
                lambda: atomic_write(path, https_content.encode()),
                lambda: atomic_write(path, content.encode()),
                self.validate, self.reload,
            )
            return 'Хост создан, SSL сертификат выпущен и HTTPS включён. ' + str(result)

    def traffic_top(self, limit=5):
        totals = []
        for item in self.inventory()['items']:
            if not item['enabled'] or item['maintenance']:
                continue
            try:
                nodes = self.parse(self.path(item['id']))
            except (OperationError, OSError, UnicodeError):
                continue
            paths, _ = configured_log_paths(nodes, 'access')
            total = sum(access_log_traffic_bytes(path, self.allowed_log_roots) for path in paths)
            if total:
                totals.append({'name': item['name'], 'kind': item['kind'], 'bytes': total})
        totals.sort(key=lambda entry: (-entry['bytes'], entry['name'].casefold()))
        return {'items': totals[:max(1, min(5, limit))], 'sample_bytes_per_log': 128 * 1024}

    def logs(self, identifier='', kind='access', lines=150):
        if kind not in {'access', 'error'}:
            raise OperationError('Неизвестный журнал.')
        candidates = []
        disabled = False
        if identifier:
            nodes = self.parse(self.path(identifier))
            candidates, has_off = configured_log_paths(nodes, kind)
        else:
            candidates = [str(self.logs_root / (kind + '.log'))]
            has_off = False
        off_note = ''
        if has_off:
            off_note = 'Запись access-лога выключена директивой access_log off.' if kind == 'access' else 'Директива error_log off не задаёт файловый путь к журналу.'
        if not candidates:
            if off_note:
                return {'content': off_note, 'sources': [], 'note': off_note}
            return {'content': '', 'sources': [], 'note': 'В файле не задан отдельный журнал. Смотрите общий журнал nginx.'}
        output, sources = ([off_note] if off_note else []), []
        for candidate in dict.fromkeys(candidates):
            path = Path(candidate)
            if not is_allowed_log_path(candidate, self.allowed_log_roots):
                output.append(f'[{candidate}] Просмотр недоступен: путь вне разрешённого каталога или динамический журнал.')
                continue
            sources.append(str(path))
            if not path.is_file():
                output.append(f'[{path.name}] Журнал ещё не создан.')
                continue
            with path.open('rb') as stream:
                stream.seek(max(0, path.stat().st_size - 128 * 1024))
                output.append(f'[{path.name}]\n' + '\n'.join(stream.read().decode('utf-8', errors='replace').splitlines()[-lines:]))
        return {'content': '\n\n'.join(output), 'sources': sources, 'note': ''}