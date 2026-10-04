import contextlib
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

if __package__:
    from .transactions import (
        OperationError, access_log_traffic_bytes, apply_transaction, atomic_write,
        delete_config_transaction, has_proxy_server, is_allowed_log_path,
        is_maintenance_config, maintenance_backup_path, render_maintenance_config,
    )


class RemoteWorker:
    def __init__(self, root, log_root, state='/var/lib/smallnginxcontrol-ssh', maintenance_root='/var/www/html', log_roots=None):
        self.root = Path(root).resolve()
        self.log_root = Path(log_root).resolve()
        self.state = Path(state)
        self.maintenance_root = Path(maintenance_root)
        self.maintenance_page = self.maintenance_root / 'maitenance.html'
        self.allowed_log_roots = tuple(dict.fromkeys([self.log_root, *(Path(root).resolve() for root in (log_roots or ['/var/http']))]))

    def path(self, identifier):
        if not isinstance(identifier, str) or not identifier or '\\' in identifier:
            raise OperationError('Invalid configuration path')
        relative = Path(identifier)
        if relative.is_absolute() or '..' in relative.parts or any(part.startswith('.') for part in relative.parts):
            raise OperationError('Invalid configuration path')
        path = self.root / relative
        if not path.resolve().is_relative_to(self.root) or path.is_symlink():
            raise OperationError('Edit the original configuration inside nginx root')
        return path

    def command(self, arguments, check=True):
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=20)
        if check and result.returncode:
            raise OperationError((result.stdout + result.stderr).strip()[:3000])
        return result

    def validate(self):
        result = self.command(['/usr/sbin/nginx', '-t', '-c', str(self.root / 'nginx.conf')])
        return (result.stdout + result.stderr).strip()

    def reload(self):
        self.command(['/usr/bin/systemctl', 'reload', 'nginx'])

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.state / 'nginx.lock').open('a') as stream:
            deadline = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OperationError('Another nginx operation is in progress')
                    time.sleep(.05)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def read(self, identifier):
        path = self.path(identifier)
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            raise OperationError('Configuration missing or larger than 256 KB')
        content = path.read_bytes()
        return {'id': identifier, 'content': content.decode('utf-8'), 'revision': hashlib.sha256(content).hexdigest()}

    def inventory(self):
        result = self.command(['/usr/sbin/nginx', '-T', '-c', str(self.root / 'nginx.conf')], check=False)
        active = {Path(name).resolve() for name in re.findall(r'^# configuration file (.+):$', result.stdout, re.MULTILINE)}
        warnings = [] if result.returncode == 0 else ['nginx -T: ' + result.stderr[-2000:]]
        files = active - {self.root / 'nginx.conf'}
        for folder, pattern in [('sites-available', '*'), ('sites-enabled', '*'), ('conf.d', '*.conf'), ('conf.d', '*.conf.disabled')]:
            files.update(path.resolve() for path in (self.root / folder).glob(pattern) if path.is_file() and not path.name.startswith('.'))
        configs = []
        total = 0
        for path in sorted(files):
            if not path.is_relative_to(self.root):
                warnings.append('External include: ' + str(path))
                continue
            identifier = path.relative_to(self.root).as_posix()
            try:
                config = self.read(identifier)
                total += len(config['content'].encode())
                if total > 4 * 1024 * 1024:
                    raise OperationError('Configuration inventory exceeds 4 MB')
                maintenance = is_maintenance_config(config['content'])
                configs.append({**config, 'enabled': path in active and not maintenance, 'maintenance': maintenance, 'toggleable': path.parent in [self.root / 'conf.d', self.root / 'sites-available']})
            except (OSError, UnicodeError, OperationError) as error:
                warnings.append(identifier + ': ' + str(error))
        return {'configs': configs, 'warnings': warnings}

    def backup(self, identifier, content):
        directory = self.state / 'backups'
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(directory / f'{time.time_ns()}-{Path(identifier).name}.bak', content)

    def maintenance_backup(self, identifier):
        return maintenance_backup_path(self.state, identifier)

    def require_maintenance_page(self):
        if not self.maintenance_page.is_file():
            raise OperationError('Maintenance page is missing: ' + str(self.maintenance_page))

    def edit(self, action, data):
        path = self.path(data['id'])
        if action == 'create':
            if path.parent != self.root / 'conf.d' or path.suffix != '.conf':
                raise OperationError('New hosts must be conf.d/*.conf')
            if path.exists() or path.with_name(path.name + '.disabled').exists():
                raise OperationError('Configuration already exists')
            content = data['content'].encode('utf-8')
            if len(content) > 256 * 1024:
                raise OperationError('Configuration too large')
            return apply_transaction(lambda: atomic_write(path, content), lambda: path.unlink(missing_ok=True), self.validate, self.reload)
        old = path.read_bytes()
        if hashlib.sha256(old).hexdigest() != data.get('revision'):
            raise OperationError('Configuration changed; reload it before saving')
        if action == 'save':
            content = data['content'].encode('utf-8')
            if len(content) > 256 * 1024:
                raise OperationError('Configuration too large')
            self.backup(data['id'], old)
            return apply_transaction(lambda: atomic_write(path, content), lambda: atomic_write(path, old), self.validate, self.reload)
        if action == 'delete':
            return self.delete(data['id'], path, old)
        if action != 'toggle' or type(data.get('enabled')) is not bool:
            raise OperationError('Invalid operation')
        self.backup(data['id'], old)
        enabled = data['enabled']
        stored = self.maintenance_backup(data['id'])
        if is_maintenance_config(old):
            if not enabled:
                return 'Maintenance mode is already enabled'
            if not stored.is_file():
                raise OperationError('Original configuration for restoration is missing')
            original = stored.read_bytes()
            self.backup(data['id'], old)
            result = apply_transaction(
                lambda: atomic_write(path, original),
                lambda: atomic_write(path, old),
                self.validate, self.reload,
            )
            stored.unlink(missing_ok=True)
            return result
        active = (path.parent == self.root / 'sites-available' and any(link.is_symlink() and link.resolve() == path for link in (self.root / 'sites-enabled').glob('*'))) or (path.parent == self.root / 'conf.d' and path.suffix == '.conf')
        if not enabled and active and has_proxy_server(old):
            self.require_maintenance_page()
            if stored.exists():
                raise OperationError('Original maintenance backup already exists; restore the site manually first')
            maintenance = render_maintenance_config(old, self.maintenance_root)
            self.backup(data['id'], old)

            def change():
                stored.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                atomic_write(stored, old)
                atomic_write(path, maintenance)

            def rollback():
                atomic_write(path, old)
                stored.unlink(missing_ok=True)

            return apply_transaction(change, rollback, self.validate, self.reload)
        if path.parent == self.root / 'conf.d':
            if enabled == (path.suffix == '.conf'):
                return 'State unchanged'
            destination = path.with_name(path.name.removesuffix('.disabled') if enabled else path.name + '.disabled')
            if destination.exists():
                raise OperationError('Destination already exists')
            change = lambda: path.rename(destination)
            def rollback():
                if destination.exists():
                    destination.rename(path)
        elif path.parent == self.root / 'sites-available':
            links = [link for link in (self.root / 'sites-enabled').glob('*') if link.is_symlink() and link.resolve() == path]
            if bool(links) == enabled:
                return 'State unchanged'
            link = self.root / 'sites-enabled' / path.name
            if enabled:
                if os.path.lexists(link):
                    raise OperationError('Enabled site name already occupied')
                change = lambda: link.symlink_to(path)
                rollback = lambda: link.unlink(missing_ok=True)
            else:
                targets = {item: os.readlink(item) for item in links}
                def change():
                    for item in links:
                        item.unlink()
                def rollback():
                    for item, target in targets.items():
                        if not os.path.lexists(item):
                            item.symlink_to(target)
        else:
            raise OperationError('Custom includes must be edited in nginx.conf')
        return apply_transaction(change, rollback, self.validate, self.reload)

    def delete(self, identifier, path, content):
        standard_site = path.parent == self.root / 'sites-available'
        standard_conf = path.parent == self.root / 'conf.d' and (path.name.endswith('.conf') or path.name.endswith('.conf.disabled'))
        if not standard_site and not standard_conf:
            raise OperationError('Only standard virtual host configurations can be deleted')
        config = next((item for item in self.inventory()['configs'] if item['id'] == identifier), None)
        if config is None or not config['toggleable']:
            raise OperationError('Configuration is not a manageable virtual host')
        if config['enabled']:
            raise OperationError('Disable the host before deleting it; active configurations cannot be deleted')
        links = [link for link in (self.root / 'sites-enabled').glob('*') if link.is_symlink() and link.resolve() == path] if standard_site else []
        stored = self.maintenance_backup(identifier)
        self.backup(identifier, content)
        if stored.is_file():
            self.backup(identifier, stored.read_bytes())
        delete_config_transaction(path, links, self.validate, self.reload)
        if stored.is_file():
            stored.unlink()
        return 'Host deleted from nginx; a configuration backup was saved'

    def traffic_top(self, limit=5):
        totals = []
        for config in self.inventory()['configs']:
            if not config['enabled'] or config.get('maintenance'):
                continue
            content = re.sub(r'(?m)^\s*#.*$', '', config['content'])
            raw_paths = re.findall(r'(?m)^\s*access_log\s+(?:"([^"]+)"|\'([^\']+)\'|([^;\s]+))', content)
            paths = list(dict.fromkeys(next(value for value in match if value) for match in raw_paths))
            paths = [path for path in paths if path.lower() != 'off']
            total = sum(access_log_traffic_bytes(path, self.allowed_log_roots) for path in paths)
            if not total:
                continue
            names = re.findall(r'(?m)^\s*server_name\s+([^;]+);', content)
            name = names[0].split()[0] if names else Path(config['id']).stem
            kind = 'proxy' if re.search(r'\bproxy_pass\b', content) else 'host'
            totals.append({'name': name, 'kind': kind, 'bytes': total})
        totals.sort(key=lambda entry: (-entry['bytes'], entry['name'].casefold()))
        return {'items': totals[:max(1, min(5, limit))], 'sample_bytes_per_log': 128 * 1024}

    def logs(self, candidates, lines):
        output, sources = [], []
        for candidate in dict.fromkeys(candidates):
            path = Path(candidate)
            if not is_allowed_log_path(candidate, self.allowed_log_roots):
                output.append(f'[{candidate}] Log path outside allowed root or dynamic log')
                continue
            sources.append(str(path))
            if not path.is_file():
                output.append(f'[{path.name}] Log not created yet')
                continue
            with path.open('rb') as stream:
                stream.seek(max(0, path.stat().st_size - 128 * 1024))
                output.append(f'[{path.name}]\n' + '\n'.join(stream.read().decode('utf-8', errors='replace').splitlines()[-max(1, min(500, lines)):]))
        return {'content': '\n\n'.join(output), 'sources': sources, 'note': '' if candidates else 'В файле не задан отдельный журнал. Смотрите общий журнал nginx.'}

    def status(self):
        version = self.command(['/usr/sbin/nginx', '-v'], check=False)
        active = self.command(['/usr/bin/systemctl', 'is-active', 'nginx'], check=False).returncode == 0
        return {'active': active, 'version': (version.stdout + version.stderr).strip().replace('nginx version: ', ''), 'system': platform.freedesktop_os_release().get('PRETTY_NAME', 'Linux')}

    def raw_metrics(self, interface):
        cpu = [int(value) for value in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        memory = {parts[0].rstrip(':'): int(parts[1]) for line in Path('/proc/meminfo').read_text().splitlines() if len(parts := line.split()) >= 2}
        counters = {}
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            name, values = line.split(':', 1)
            numbers = values.split()
            counters[name.strip()] = (int(numbers[0]), int(numbers[8]))
        if interface:
            if interface not in counters:
                raise OperationError('Network interface not found: ' + interface)
            names = [interface]
        else:
            names = [name for name in counters if (Path('/sys/class/net') / name / 'device').exists()]
            if not names:
                names = [name for name in counters if name != 'lo' and not name.startswith(('veth', 'docker', 'br-', 'virbr'))]
        return {'cpu_total': sum(cpu), 'cpu_idle': cpu[3] + cpu[4], 'memory': (1 - memory['MemAvailable'] / memory['MemTotal']) * 100, 'rx_bytes': sum(counters[name][0] for name in names), 'tx_bytes': sum(counters[name][1] for name in names), 'uptime': float(Path('/proc/uptime').read_text().split()[0]), 'interface': ', '.join(names)}

    def dispatch(self, operation, data):
        if operation == 'inventory':
            return self.inventory()
        if operation == 'read':
            return self.read(data['id'])
        if operation == 'logs':
            return self.logs(data['paths'], data['lines'])
        if operation == 'traffic':
            return self.traffic_top()
        if operation == 'delete':
            with self.lock():
                path = self.path(data['id'])
                content = path.read_bytes()
                if hashlib.sha256(content).hexdigest() != data.get('revision'):
                    raise OperationError('Configuration changed; reload it before deleting')
                return self.delete(data['id'], path, content)
        if operation == 'status':
            return self.status()
        if operation == 'metrics':
            return self.raw_metrics(data.get('interface', ''))
        if operation not in {'save', 'create', 'toggle', 'test', 'reload', 'restart'}:
            raise OperationError('Unknown operation')
        with self.lock():
            if operation in {'save', 'create', 'toggle'}:
                return self.edit(operation, data)
            result = self.validate()
            if operation == 'reload':
                self.reload()
            elif operation == 'restart':
                self.command(['/usr/bin/systemctl', 'restart', 'nginx'])
            return result


if __name__ == '__main__':
    try:
        payload = json.loads(sys.stdin.read(600000))
        worker = RemoteWorker(payload['root'], payload['log_root'], log_roots=payload.get('log_roots'))
        result = worker.dispatch(payload['operation'], payload.get('data', {}))
        print(json.dumps({'ok': True, 'result': result}, ensure_ascii=True))
    except Exception as error:
        print(json.dumps({'ok': False, 'error': str(error)[:3000]}, ensure_ascii=True))