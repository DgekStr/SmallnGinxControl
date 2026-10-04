import hashlib
import ipaddress
import math
import os
import re
import shutil
import ssl
import subprocess
import shlex
import tempfile
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path


class OperationError(Exception):
    pass


MAINTENANCE_MARKER = '# smallnginxcontrol-maintenance'
MAINTENANCE_URI = '/__smallnginxcontrol_maintenance.html'
ACCESS_LOG_BYTES_PATTERN = re.compile(rb'"\s+\d{3}\s+(\d+|-)(?:\s|$)')
ACCESS_LOG_TRAFFIC_PATTERN = re.compile(rb'"\s+\d{3}\s+(\d+|-)(?:[ \t]+(\d+|-))?(?=[ \t"]|$)')
TRAFFIC_LOG_FORMAT_NAME = 'smallnginxcontrol_traffic'
TRAFFIC_LOG_FORMAT_DIRECTIVE = (
    '    log_format smallnginxcontrol_traffic \'$remote_addr - $remote_user [$time_local] '
    '"$request" $status $bytes_sent $request_length "$http_referer" "$http_user_agent"\';'
)
DNS_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
EMAIL_ADDRESS = re.compile(r'^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$')


def validate_certificate_request(domain, email):
    if not isinstance(domain, str) or len(domain) > 253 or '.' not in domain or domain != domain.lower() or domain.startswith('*.'):
        raise OperationError('Для выпуска SSL укажите точное публичное DNS-имя без wildcard.')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise OperationError('Certbot HTTP challenge требует DNS-имя, а не IP-адрес.')
    labels = domain.rstrip('.').split('.')
    if domain.endswith('.') or any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise OperationError('Некорректное DNS-имя для выпуска сертификата.')
    if not isinstance(email, str) or len(email) > 254 or not EMAIL_ADDRESS.fullmatch(email):
        raise OperationError('Для Certbot укажите корректный email владельца домена.')
    return domain, email


def issue_webroot_certificate(certbot_bin, webroot, live_root, domain, email):
    validate_certificate_request(domain, email)
    if not Path(certbot_bin).is_file():
        raise OperationError(f'Certbot не найден: {certbot_bin}')
    webroot_path = Path(webroot)
    if not webroot_path.is_absolute() or not webroot_path.is_dir():
        raise OperationError(f'ACME webroot недоступен: {webroot_path}')
    arguments = [
        str(certbot_bin), 'certonly', '--webroot', '--webroot-path', str(webroot_path),
        '--cert-name', domain, '-d', domain, '--non-interactive', '--agree-tos',
        '--email', email, '--keep-until-expiring', '--deploy-hook', 'systemctl reload nginx',
    ]
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperationError(f'Ошибка запуска Certbot: {error}') from error
    output = (result.stdout + result.stderr).strip()
    if result.returncode:
        raise OperationError('Certbot не выпустил сертификат: ' + (output[-2000:] or str(result.returncode)))
    certificate = Path(live_root) / domain / 'fullchain.pem'
    private_key = Path(live_root) / domain / 'privkey.pem'
    if not certificate.is_file() or not private_key.is_file():
        raise OperationError('Certbot завершился без ожидаемой пары fullchain.pem/privkey.pem.')
    return certificate, private_key


def atomic_write(path, content):
    path = Path(path)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o640
    descriptor, temporary = tempfile.mkstemp(prefix='.snc-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def maintenance_backup_path(state, identifier):
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return Path(state) / 'maintenance' / f'{digest}.original'


def is_allowed_log_path(candidate, roots):
    if not isinstance(candidate, str) or not candidate or '$' in candidate or any(ord(char) < 32 for char in candidate):
        return False
    path = Path(candidate)
    if not path.is_absolute():
        return False
    try:
        resolved = path.resolve()
        return any(resolved.is_relative_to(Path(root).resolve()) for root in roots)
    except (OSError, RuntimeError):
        return False


def access_log_traffic_bytes(candidate, roots, sample_size=128 * 1024):
    if not is_allowed_log_path(candidate, roots):
        return 0
    path = Path(candidate)
    try:
        if not path.is_file():
            return 0
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - sample_size))
            content = stream.read(sample_size)
    except OSError:
        return 0
    return sum(int(match.group(1)) for match in ACCESS_LOG_BYTES_PATTERN.finditer(content) if match.group(1) != b'-')


def access_log_traffic_stats(candidate, roots, sample_size=128 * 1024):
    if not is_allowed_log_path(candidate, roots):
        return {'downloaded_bytes': 0, 'uploaded_bytes': None, 'uploaded_complete': False, 'has_data': False}
    path = Path(candidate)
    try:
        if not path.is_file():
            return {'downloaded_bytes': 0, 'uploaded_bytes': None, 'uploaded_complete': False, 'has_data': False}
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - sample_size))
            content = stream.read(sample_size)
    except OSError:
        return {'downloaded_bytes': 0, 'uploaded_bytes': None, 'uploaded_complete': False, 'has_data': False}
    if not content:
        return {'downloaded_bytes': 0, 'uploaded_bytes': None, 'uploaded_complete': False, 'has_data': False}
    downloaded = uploaded = records = upload_records = 0
    upload_complete = True
    lines = [line for line in content.splitlines() if line]
    for line in lines:
        match = ACCESS_LOG_TRAFFIC_PATTERN.search(line)
        if not match:
            upload_complete = False
            continue
        records += 1
        sent = match.group(1)
        if sent != b'-':
            downloaded += int(sent)
        request_size = match.group(2)
        if request_size is None or request_size == b'-':
            upload_complete = False
        else:
            uploaded += int(request_size)
            upload_records += 1
    return {
        'downloaded_bytes': downloaded,
        'uploaded_bytes': uploaded if upload_records else None,
        'uploaded_complete': bool(records) and upload_complete and upload_records == len(lines),
        'has_data': bool(lines),
    }


def access_log_traffic_totals(candidates, roots, sample_size=128 * 1024):
    stats = [access_log_traffic_stats(path, roots, sample_size) for path in dict.fromkeys(candidates)]
    data = [item for item in stats if item['has_data']]
    upload_data = [item for item in data if item['uploaded_bytes'] is not None]
    return {
        'downloaded_bytes': sum(item['downloaded_bytes'] for item in stats),
        'uploaded_bytes': sum(item['uploaded_bytes'] for item in upload_data) if upload_data else None,
        'uploaded_complete': bool(data) and all(item['uploaded_complete'] for item in data),
    }


@lru_cache(maxsize=512)
def _certificate_expiry_timestamp(path, mtime_ns):
    openssl = shutil.which('openssl') or '/usr/bin/openssl'
    try:
        result = subprocess.run([openssl, 'x509', '-in', path, '-noout', '-enddate'], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    match = re.search(r'notAfter=(.+)', result.stdout + result.stderr)
    if not match:
        return None
    try:
        return ssl.cert_time_to_seconds(match.group(1).strip())
    except (ValueError, OverflowError):
        return None


def certificate_days_remaining(certificates, now=None):
    now_timestamp = (now or datetime.now(timezone.utc)).timestamp()
    values = []
    for candidate in dict.fromkeys(certificates):
        if not isinstance(candidate, str) or not candidate or '$' in candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute():
            continue
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        expires = _certificate_expiry_timestamp(str(resolved), metadata.st_mtime_ns)
        if expires is not None:
            values.append(math.ceil((expires - now_timestamp) / 86400))
    return min(values) if values else None


def is_maintenance_config(content):
    marker = MAINTENANCE_MARKER.encode('ascii') if isinstance(content, bytes) else MAINTENANCE_MARKER
    return marker in content


def _nginx_mask(content):
    masked = list(content)
    quote = None
    escaped = False
    comment = False
    for index, character in enumerate(content):
        if comment:
            if character == '\n':
                comment = False
            else:
                masked[index] = ' '
            continue
        if quote:
            masked[index] = ' '
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character == '#':
            masked[index] = ' '
            comment = True
        elif character in {'\'', '"'}:
            masked[index] = ' '
            quote = character
    return ''.join(masked)


def _matching_brace(masked, opening, limit):
    depth = 1
    for index in range(opening + 1, limit):
        if masked[index] == '{':
            depth += 1
        elif masked[index] == '}':
            depth -= 1
            if depth == 0:
                return index
    raise OperationError('В nginx-конфигурации не закрыт блок server.')


def ensure_traffic_log_format(content):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    masked = _nginx_mask(text)
    for match in re.finditer(r'(?<![\w-])http\s*\{', masked):
        depth = 0
        for character in masked[:match.start()]:
            if character == '{':
                depth += 1
            elif character == '}':
                depth -= 1
        if depth:
            continue
        opening = masked.find('{', match.start(), match.end())
        closing = _matching_brace(masked, opening, len(masked))
        block = masked[opening + 1:closing]
        if re.search(r'(?m)^\s*log_format\s+' + re.escape(TRAFFIC_LOG_FORMAT_NAME) + r'\s', block):
            return text.encode('utf-8'), False
        line_break = text.find('\n', opening + 1, closing)
        if line_break >= 0 and not text[opening + 1:line_break].strip():
            insertion_position = line_break + 1
            insertion = TRAFFIC_LOG_FORMAT_DIRECTIVE + '\n'
        else:
            insertion_position = opening + 1
            insertion = '\n' + TRAFFIC_LOG_FORMAT_DIRECTIVE + '\n'
        updated = text[:insertion_position] + insertion + text[insertion_position:]
        return updated.encode('utf-8'), True
    raise OperationError('В nginx.conf не найден блок http для регистрации формата traffic log.')


def _argument_span(content, start, limit):
    while start < limit and content[start].isspace():
        start += 1
    if start >= limit or content[start] == ';':
        return start, start, ''
    quote = content[start] if content[start] in {'"', "'"} else ''
    end = start + 1 if quote else start
    escaped = False
    while end < limit:
        character = content[end]
        if quote:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == quote:
                end += 1
                break
        elif character.isspace() or character == ';':
            break
        end += 1
    raw = content[start:end]
    return start, end, raw[1:-1] if quote and raw.endswith(quote) else raw


def _nginx_block_scopes(masked, opening, closing):
    stack = [opening]
    scopes = {}
    for index in range(opening + 1, closing):
        if masked[index] == '{':
            stack.append(index)
        elif masked[index] == '}':
            scopes[stack.pop()] = index
    scopes[opening] = closing
    return scopes


def configure_host_access_logs(content, fallback_name, log_root='/var/log/nginx'):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    masked = _nginx_mask(text)
    root = Path(log_root).as_posix().rstrip('/')
    replacements = []
    insertions = []
    changed_hosts = []
    block_number = 0

    for server_match in re.finditer(r'(?<![\w-])server\s*\{', masked):
        opening = masked.find('{', server_match.start(), server_match.end())
        closing = _matching_brace(masked, opening, len(masked))
        block_number += 1
        scopes = _nginx_block_scopes(masked, opening, closing)

        server_names = []
        for match in re.finditer(r'(?<![\w-])server_name\s+', masked[opening + 1:closing]):
            position = opening + 1 + match.start()
            scope = max((start for start, end in scopes.items() if start < position < end), default=opening)
            if scope != opening:
                continue
            directive_end = opening + 1 + match.end()
            semicolon = masked.find(';', directive_end, closing)
            if semicolon < 0:
                raise OperationError('Директива server_name не завершена точкой с запятой.')
            try:
                server_names.extend(shlex.split(text[directive_end:semicolon], comments=False, posix=True))
            except ValueError as error:
                raise OperationError(f'Не удалось разобрать server_name: {error}') from error

        host = next((name for name in server_names if name != '_' and not name.startswith(('~', '$')) and '$' not in name), '')
        if not host:
            host = f'{fallback_name}-{block_number}'
        elif host.startswith('*.'):
            host = 'wildcard.' + host[2:]
        safe_host = re.sub(r'[^a-zA-Z0-9_.-]+', '-', host).strip('.-_').lower() or f'host-{block_number}'
        if len(safe_host) > 200:
            safe_host = safe_host[:180].rstrip('.-_') + '-' + hashlib.sha256(host.encode('utf-8')).hexdigest()[:12]
        target = f'{root}/{safe_host}-data.log'

        log_directives = []
        for match in re.finditer(r'(?<![\w-])access_log\s+', masked[opening + 1:closing]):
            position = opening + 1 + match.start()
            directive_end = opening + 1 + match.end()
            semicolon = masked.find(';', directive_end, closing)
            if semicolon < 0:
                raise OperationError('Директива access_log не завершена точкой с запятой.')
            arg_start, arg_end, first_arg = _argument_span(text, directive_end, semicolon)
            scope = max((start for start, end in scopes.items() if start < position < end), default=opening)
            log_directives.append((scope, position, semicolon + 1, arg_start, arg_end, first_arg, semicolon))

        by_scope = {}
        for directive in log_directives:
            by_scope.setdefault(directive[0], []).append(directive)
        if opening not in by_scope:
            by_scope[opening] = []

        host_changed = False
        for scope, directives in by_scope.items():
            matching = [item for item in directives if item[5] == target]
            disabled = [item for item in directives if item[5].lower() == 'off']
            if disabled:
                if matching:
                    replacements.extend((item[1], item[2], '') for item in disabled)
                else:
                    first_off = disabled[0]
                    replacements.append((first_off[3], first_off[4], target))
                    replacements.append((first_off[4], first_off[4], ' ' + TRAFFIC_LOG_FORMAT_NAME))
                    replacements.extend((item[1], item[2], '') for item in disabled[1:])
                host_changed = True
            elif not matching:
                scope_end = scopes[scope]
                line_start = text.rfind('\n', 0, scope_end) + 1
                closing_indent = re.match(r'[ \t]*', text[line_start:scope_end]).group()
                directive_indent = closing_indent + '    '
                if text[line_start:scope_end].strip():
                    insertions.append((scope_end, f'\n{directive_indent}access_log {target} {TRAFFIC_LOG_FORMAT_NAME};\n{closing_indent}'))
                else:
                    insertions.append((line_start, f'{directive_indent}access_log {target} {TRAFFIC_LOG_FORMAT_NAME};\n'))
                host_changed = True
            for matching_log in matching:
                tail = text[matching_log[4]:matching_log[6]]
                try:
                    arguments = shlex.split(tail, comments=False, posix=True)
                except ValueError as error:
                    raise OperationError(f'Не удалось разобрать параметры access_log: {error}') from error
                if not arguments or arguments[0].startswith(('buffer=', 'flush=', 'if=')) or arguments[0] == 'gzip':
                    replacements.append((matching_log[4], matching_log[4], ' ' + TRAFFIC_LOG_FORMAT_NAME))
                    host_changed = True
                elif arguments[0] in {'combined', 'main'}:
                    format_match = re.match(r'(\s*)[^\s]+', tail)
                    start = matching_log[4] + len(format_match.group(1))
                    replacements.append((start, matching_log[4] + format_match.end(), TRAFFIC_LOG_FORMAT_NAME))
                    host_changed = True
        if host_changed:
            changed_hosts.append(host)

    edits = [(position, position, insertion) for position, insertion in insertions]
    edits.extend(replacements)
    for start, end, replacement in sorted(edits, key=lambda edit: edit[0], reverse=True):
        text = text[:start] + replacement + text[end:]
    result = text.encode('utf-8')
    return result, changed_hosts


def _proxy_server_closings(masked):
    closings = []
    for match in re.finditer(r'(?<![\w-])server\s*\{', masked):
        opening = masked.find('{', match.start(), match.end())
        depth = 1
        for index in range(opening + 1, len(masked)):
            if masked[index] == '{':
                depth += 1
            elif masked[index] == '}':
                depth -= 1
                if depth == 0:
                    body = masked[opening + 1:index]
                    if re.search(r'\bserver_name\b', body) and re.search(r'\bproxy_pass\b', body):
                        closings.append(index)
                    break
        else:
            raise OperationError('В конфигурации не закрыт блок server.')
    return closings


def has_proxy_server(content):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    return bool(_proxy_server_closings(_nginx_mask(text)))


def _maintenance_block(content, closing, root, existing_handler):
    line_start = content.rfind('\n', 0, closing) + 1
    closing_indent = re.match(r'[ \t]*', content[line_start:closing]).group()
    indent = closing_indent + '    '
    if existing_handler:
        return (
            f'\n{indent}{MAINTENANCE_MARKER}: begin\n'
            f'{indent}if ($uri != /maitenance.html) {{\n'
            f'{indent}    return 503;\n'
            f'{indent}}}\n'
            f'{indent}{MAINTENANCE_MARKER}: end\n'
        )
    return (
        f'\n{indent}{MAINTENANCE_MARKER}: begin\n'
        f'{indent}error_page 503 {MAINTENANCE_URI};\n'
        f'{indent}location = {MAINTENANCE_URI} {{\n'
        f'{indent}    internal;\n'
        f'{indent}    root {Path(root).as_posix()};\n'
        f'{indent}    try_files /maitenance.html =503;\n'
        f'{indent}}}\n'
        f'{indent}if ($uri != {MAINTENANCE_URI}) {{\n'
        f'{indent}    return 503;\n'
        f'{indent}}}\n'
        f'{indent}{MAINTENANCE_MARKER}: end\n'
    )


def render_maintenance_config(content, root='/var/www/html'):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    if is_maintenance_config(text):
        raise OperationError('Конфигурация уже находится в режиме обслуживания.')
    if MAINTENANCE_URI in text:
        raise OperationError('Конфигурация уже использует служебный URI обслуживания.')
    masked = _nginx_mask(text)
    closings = _proxy_server_closings(masked)
    if not closings:
        raise OperationError('В конфигурации не найден reverse-proxy server.')
    existing_handler = 'maintenance_all.conf' in masked
    if not existing_handler and re.search(r'\berror_page\b[^;]*\b503\b', masked):
        raise OperationError('Конфигурация уже задаёт обработчик 503. Подключите maintenance_all.conf вручную.')
    for closing in reversed(closings):
        text = text[:closing] + _maintenance_block(text, closing, root, existing_handler) + text[closing:]
    return text.encode('utf-8')


def apply_transaction(change, rollback, validate, reload_service):
    try:
        change()
        validation = validate()
    except Exception:
        rollback()
        raise
    try:
        reload_service()
    except Exception as error:
        rollback()
        try:
            validate()
            reload_service()
        except Exception as recovery:
            raise OperationError(f'Apply failed: {error}. Recovery failed: {recovery}') from error
        raise OperationError(f'Apply failed; previous configuration restored: {error}') from error
    return validation


def delete_config_transaction(path, links, validate, reload_service):
    path = Path(path)
    content = path.read_bytes()
    mode = path.stat().st_mode & 0o777
    link_targets = {}
    for link in links:
        if not link.is_symlink() or link.resolve() != path.resolve():
            raise OperationError('Ссылка sites-enabled изменилась. Обновите список и повторите.')
        link_targets[link] = os.readlink(link)

    def change():
        for link in link_targets:
            link.unlink()
        path.unlink()

    def rollback():
        if not path.exists():
            atomic_write(path, content)
            os.chmod(path, mode)
        for link, target in link_targets.items():
            if not os.path.lexists(link):
                link.symlink_to(target)

    return apply_transaction(change, rollback, validate, reload_service)