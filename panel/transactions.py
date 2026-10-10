import hashlib
import html
import ipaddress
import json
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


def validate_access_log_sample_size(sample_size):
    if type(sample_size) is not int or not 1 <= sample_size <= ACCESS_LOG_SAMPLE_MAX_BYTES:
        raise OperationError('Размер выборки access log должен быть целым числом от 1 байта до 100 МБ.')
    return sample_size


MAINTENANCE_MARKER = '# smallnginxcontrol-maintenance'
MAINTENANCE_URI = '/__smallnginxcontrol_maintenance.html'
NONPAYMENT_MARKER = '# smallnginxcontrol-nonpayment'
NONPAYMENT_URI = '/__smallnginxcontrol_nonpayment.html'
ACCESS_LOG_BYTES_PATTERN = re.compile(rb'"\s+\d{3}\s+(\d+|-)(?:\s|$)')
ACCESS_LOG_TRAFFIC_PATTERN = re.compile(rb'"\s+\d{3}\s+(\d+|-)(?:[ \t]+(\d+|-))?(?=[ \t"]|$)')
TRAFFIC_LOG_FORMAT_NAME = 'smallnginxcontrol_traffic'
ACCESS_LOG_SAMPLE_DEFAULT_BYTES = 128 * 1024
ACCESS_LOG_SAMPLE_MAX_BYTES = 100_000_000
GLOBAL_TRAFFIC_BLOCK_MARKER = '# smallnginxcontrol-global-traffic-block'
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


def nonpayment_backup_path(state, identifier):
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return Path(state) / 'nonpayment' / f'{digest}.original'


def nonpayment_page_path(root, identifier):
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return Path(root) / f'.smallnginxcontrol-nonpayment-{digest}.html'


def write_nonpayment_page(path, content):
    atomic_write(path, content)
    os.chmod(path, 0o644)


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


def access_log_traffic_bytes(candidate, roots, sample_size=ACCESS_LOG_SAMPLE_DEFAULT_BYTES):
    sample_size = validate_access_log_sample_size(sample_size)
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


def access_log_traffic_stats(candidate, roots, sample_size=ACCESS_LOG_SAMPLE_DEFAULT_BYTES):
    sample_size = validate_access_log_sample_size(sample_size)
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


def access_log_traffic_totals(candidates, roots, sample_size=ACCESS_LOG_SAMPLE_DEFAULT_BYTES):
    sample_size = validate_access_log_sample_size(sample_size)
    stats = [access_log_traffic_stats(path, roots, sample_size) for path in dict.fromkeys(candidates)]
    data = [item for item in stats if item['has_data']]
    upload_data = [item for item in data if item['uploaded_bytes'] is not None]
    return {
        'downloaded_bytes': sum(item['downloaded_bytes'] for item in stats),
        'uploaded_bytes': sum(item['uploaded_bytes'] for item in upload_data) if upload_data else None,
        'uploaded_complete': bool(data) and all(item['uploaded_complete'] for item in data),
    }


@lru_cache(maxsize=512)
def _certificate_file_details(path, mtime_ns):
    openssl = shutil.which('openssl') or '/usr/bin/openssl'
    try:
        result = subprocess.run(
            [openssl, 'x509', '-in', path, '-noout', '-subject', '-issuer', '-serial', '-startdate', '-enddate', '-nameopt', 'RFC2253'],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    fields = {'subject': None, 'issuer': None, 'serial': None, 'valid_from': None, 'valid_until': None}
    time_fields = {'notBefore': 'valid_from', 'notAfter': 'valid_until'}
    labels = {'subject': 'subject', 'issuer': 'issuer', 'serial': 'serial', **time_fields}
    for line in (result.stdout + '\n' + result.stderr).splitlines():
        match = re.match(r'^(subject|issuer|serial|notBefore|notAfter)=(.*)$', line.strip())
        if not match:
            continue
        name, value = match.groups()
        if name in time_fields:
            try:
                value = datetime.fromtimestamp(ssl.cert_time_to_seconds(value.strip()), timezone.utc).isoformat(timespec='seconds')
            except (ValueError, OverflowError):
                value = None
        fields[labels[name]] = value
    if not fields['valid_until']:
        return None
    try:
        expires = ssl.cert_time_to_seconds(re.search(r'^notAfter=(.+)$', result.stdout + '\n' + result.stderr, re.MULTILINE).group(1).strip())
    except (ValueError, OverflowError):
        return None
    fields['_expires_timestamp'] = expires
    return fields


def certificate_details(certificates, now=None):
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
        details = _certificate_file_details(str(resolved), metadata.st_mtime_ns)
        if details:
            details['file'] = str(resolved)
            values.append(details)
    if not values:
        return None
    details = min(values, key=lambda value: value['_expires_timestamp']).copy()
    expires = details.pop('_expires_timestamp')
    details['days_remaining'] = math.ceil((expires - now_timestamp) / 86400)
    return details


def certificate_days_remaining(certificates, now=None):
    details = certificate_details(certificates, now)
    return details['days_remaining'] if details else None


def is_maintenance_config(content):
    marker = MAINTENANCE_MARKER.encode('ascii') if isinstance(content, bytes) else MAINTENANCE_MARKER
    return marker in content


def is_nonpayment_config(content):
    marker = NONPAYMENT_MARKER.encode('ascii') if isinstance(content, bytes) else NONPAYMENT_MARKER
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
def validate_maintenance_page_path(candidate):
    if not isinstance(candidate, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', candidate) or '..' in Path(candidate).parts:
        raise OperationError('Укажите абсолютный путь к HTML-файлу заглушки без пробелов и специальных символов.')
    path = Path(candidate).resolve()
    if not path.is_file():
        raise OperationError(f'Файл заглушки не найден: {path}')
    return path.as_posix()


def ensure_global_maintenance_include(content, include_path):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', include_path) or '..' in Path(include_path).parts:
        raise OperationError('Недопустимый путь к nginx maintenance snippet.')
    masked = _nginx_mask(text)
    insertions = []
    for server_match in re.finditer(r'(?<![\w-])server\s*\{', masked):
        opening = masked.find('{', server_match.start(), server_match.end())
        closing = _matching_brace(masked, opening, len(masked))
        scopes = _nginx_block_scopes(masked, opening, closing)
        included = False
        for match in re.finditer(r'(?<![\w-])include\s+', masked[opening + 1:closing]):
            position = opening + 1 + match.start()
            scope = max((start for start, end in scopes.items() if start < position < end), default=opening)
            if scope != opening:
                continue
            directive_end = opening + 1 + match.end()
            semicolon = masked.find(';', directive_end, closing)
            if semicolon < 0:
                raise OperationError('Директива include не завершена точкой с запятой.')
            try:
                arguments = shlex.split(text[directive_end:semicolon], comments=False, posix=True)
            except ValueError as error:
                raise OperationError(f'Не удалось разобрать include: {error}') from error
            if arguments == [include_path]:
                included = True
                break
        if included:
            continue
        line_start = text.rfind('\n', 0, opening) + 1
        server_indent = re.match(r'[ \t]*', text[line_start:opening]).group()
        insertions.append((opening + 1, f'\n{server_indent}    include {include_path};'))
    if not insertions:
        return text.encode('utf-8'), False
    for position, insertion in sorted(insertions, reverse=True):
        text = text[:position] + insertion + text[position:]
    return text.encode('utf-8'), True


def render_global_maintenance_snippet(content, page_path, flag_path):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    page_path = validate_maintenance_page_path(page_path)
    flag_path = str(flag_path)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', flag_path) or '..' in Path(flag_path).parts:
        raise OperationError('Недопустимый marker path для блокировки трафика.')
    if GLOBAL_TRAFFIC_BLOCK_MARKER in text:
        raise OperationError('Maintenance snippet уже содержит marker блокировки.')

    masked = _nginx_mask(text)
    location = re.search(r'(?<![\w-])location\s*=\s*/maitenance\.html\s*\{', masked)
    if not location:
        raise OperationError('В maintenance snippet отсутствует location для maitenance.html.')
    opening = masked.find('{', location.start(), location.end())
    closing = _matching_brace(masked, opening, len(masked))
    scopes = _nginx_block_scopes(masked, opening, closing)
    path_span = None
    directive_span = None
    for match in re.finditer(r'(?<![\w-])(?:root|alias)\s+', masked[opening + 1:closing]):
        position = opening + 1 + match.start()
        if max((start for start, end in scopes.items() if start < position < end), default=opening) != opening:
            continue
        directive_end = opening + 1 + match.end()
        semicolon = masked.find(';', directive_end, closing)
        if semicolon < 0:
            raise OperationError('Директива root/alias заглушки не завершена точкой с запятой.')
        arg_start, arg_end, _ = _argument_span(text, directive_end, semicolon)
        path_span = (arg_start, arg_end)
        directive_start = opening + 1 + match.start()
        directive_name = match.group(0).strip().split()[0]
        directive_span = (directive_start, directive_start + len(directive_name))
        break
    if path_span is None or directive_span is None:
        raise OperationError('В maintenance location отсутствует root/alias path.')
    text = text[:path_span[0]] + page_path + text[path_span[1]:]
    text = text[:directive_span[0]] + 'alias' + text[directive_span[1]:]

    guard = (
        f'{GLOBAL_TRAFFIC_BLOCK_MARKER}: begin\n'
        'set $smallnginxcontrol_traffic_blocked 0;\n'
        f'if (-f {flag_path}) {{\n'
        '    set $smallnginxcontrol_traffic_blocked 1;\n'
        '}\n'
        'if ($uri = /maitenance.html) {\n'
        '    set $smallnginxcontrol_traffic_blocked 0;\n'
        '}\n'
        'if ($smallnginxcontrol_traffic_blocked) {\n'
        '    return 503;\n'
        '}\n'
        f'{GLOBAL_TRAFFIC_BLOCK_MARKER}: end\n'
    )
    return (guard + text).encode('utf-8')


def set_global_traffic_block(config_root, state_root, page_path, enabled, config_files, validate, reload_service):
    if type(enabled) is not bool:
        raise OperationError('Состояние блокировки должно быть true или false.')
    root = Path(config_root).resolve()
    backup_root = Path(state_root) / 'global-traffic-maintenance'
    manifest_path = backup_root / 'manifest.json'
    snippet_path = root / 'snippets' / 'maintenance_all.conf'
    flag_path = root / 'snippets' / 'smallnginxcontrol-traffic-blocked.flag'

    if enabled:
        validate_maintenance_page_path(page_path)
        if manifest_path.exists() or flag_path.exists():
            raise OperationError('Глобальная блокировка уже активна или требует ручного восстановления.')
        if not snippet_path.is_file():
            raise OperationError(f'Общий nginx maintenance snippet не найден: {snippet_path}')
        originals, updated = {}, {}
        snippet_original = snippet_path.read_bytes()
        originals[snippet_path] = snippet_original
        updated[snippet_path] = render_global_maintenance_snippet(snippet_original, page_path, flag_path.as_posix())
        for identifier, candidate in config_files:
            path = Path(candidate)
            original = path.read_bytes()
            changed, was_updated = ensure_global_maintenance_include(original, snippet_path.as_posix())
            if was_updated:
                originals[path] = original
                updated[path] = changed
        backup_root.mkdir(parents=True, mode=0o700)
        manifest = {}
        for index, (path, content) in enumerate(originals.items()):
            name = f'{index:04d}.bak'
            atomic_write(backup_root / name, content)
            manifest[str(path)] = name
        atomic_write(manifest_path, json.dumps(manifest, sort_keys=True).encode('utf-8'))

        def change():
            for path, content in updated.items():
                atomic_write(path, content)
            atomic_write(flag_path, b'blocked\n')
            os.chmod(flag_path, 0o644)

        def rollback():
            for path, content in originals.items():
                atomic_write(path, content)
            flag_path.unlink(missing_ok=True)
            shutil.rmtree(backup_root, ignore_errors=True)

        result = apply_transaction(change, rollback, validate, reload_service)
        return {'message': 'Трафик заблокирован; nginx показывает страницу-заглушку.', 'files': len(updated), 'result': result}

    if not manifest_path.is_file():
        if flag_path.exists():
            raise OperationError('Marker глобальной блокировки найден без backup manifest; требуется ручное восстановление.')
        return {'message': 'Блокировка трафика уже выключена.', 'files': 0}
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    originals = {Path(path): (backup_root / name).read_bytes() for path, name in manifest.items()}
    frozen = {path: path.read_bytes() for path in originals}

    def restore():
        for path, content in originals.items():
            atomic_write(path, content)
        flag_path.unlink(missing_ok=True)

    def reapply():
        for path, content in frozen.items():
            atomic_write(path, content)
        atomic_write(flag_path, b'blocked\n')
        os.chmod(flag_path, 0o644)

    result = apply_transaction(restore, reapply, validate, reload_service)
    shutil.rmtree(backup_root)
    return {'message': 'Доступ к хостам восстановлен.', 'files': len(originals), 'result': result}


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
    return _server_closings(masked, proxy_only=True)


def _server_closings(masked, proxy_only=False):
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
                    if re.search(r'\bserver_name\b', body) and (not proxy_only or re.search(r'\bproxy_pass\b', body)):
                        closings.append(index)
                    break
        else:
            raise OperationError('В конфигурации не закрыт блок server.')
    return closings


def render_nonpayment_config(content, contact_text, page_path):
    text = content.decode('utf-8') if isinstance(content, bytes) else content
    if is_nonpayment_config(text):
        raise OperationError('Конфигурация уже отключена из-за неоплаты.')
    if is_maintenance_config(text):
        raise OperationError('Сначала восстановите обычный режим обслуживания.')
    if not isinstance(contact_text, str) or not contact_text.strip() or len(contact_text) > 500:
        raise OperationError('Текст для связи должен содержать от 1 до 500 символов.')
    page_path = Path(page_path)
    page_path_text = page_path.as_posix()
    if not page_path.is_absolute() or not re.fullmatch(r'(?:[A-Za-z]:)?/[A-Za-z0-9_./-]+', page_path_text) or '..' in page_path.parts:
        raise OperationError('Недопустимый путь к странице отключения.')
    masked = _nginx_mask(text)
    closings = _server_closings(masked)
    if not closings:
        raise OperationError('В конфигурации не найден server-блок виртуального хоста.')
    page = (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="theme-color" content="#050816"><meta name="robots" content="noindex, nofollow">'
        '<title>Доступ ограничен | FOCUSLENS.DEV</title><style>'
        ':root{color-scheme:dark;--bg:#050816;--surface:#0b1226;--surface-raised:#111b34;'
        '--text:#f5f7ff;--muted:#a4b0c7;--quiet:#74839e;--cyan:#22d3ee;--violet:#8b5cf6;'
        '--line:rgba(179,202,236,.16);--mono:"Cascadia Code","SFMono-Regular",Consolas,monospace}'
        '*{box-sizing:border-box}html{min-width:320px;min-height:100%;background:var(--bg)}'
        'body{min-height:100vh;min-height:100svh;margin:0;overflow-x:hidden;color:var(--text);'
        'background:radial-gradient(ellipse at 74% 41%,rgba(34,211,238,.08),transparent 33rem),'
        'radial-gradient(ellipse at 12% 6%,rgba(124,58,237,.12),transparent 25rem),'
        'repeating-linear-gradient(0deg,transparent 0 47px,rgba(171,195,226,.025) 48px),'
        'repeating-linear-gradient(90deg,transparent 0 47px,rgba(171,195,226,.025) 48px),var(--bg);'
        'font-family:Inter,"Segoe UI",sans-serif;line-height:1.6}'
        '.page-shell{display:flex;flex-direction:column;width:min(1320px,calc(100% - 64px));'
        'min-height:100vh;min-height:100svh;margin:0 auto}.site-header{display:flex;align-items:center;'
        'justify-content:space-between;min-height:92px;border-bottom:1px solid var(--line);'
        'animation:reveal 500ms ease-out both}.brand{color:var(--text);font-size:17px;'
        'font-weight:750;letter-spacing:.04em;text-decoration:none}.brand small{display:block;'
        'margin-top:5px;color:var(--quiet);font:500 10px var(--mono);letter-spacing:.08em}'
        '.header-label{color:var(--quiet);font:11px var(--mono);letter-spacing:.08em;text-transform:uppercase}'
        'main{display:grid;flex:1;grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);'
        'align-items:center;gap:56px;padding:58px 0 54px}.copy{max-width:650px;animation:reveal 650ms 80ms ease-out both}'
        '.eyebrow{display:flex;align-items:center;gap:11px;margin:0 0 26px;color:#a5eaf4;'
        'font:600 12px var(--mono);letter-spacing:.1em;text-transform:uppercase}.eyebrow:before{'
        'width:22px;height:1px;background:var(--cyan);content:""}h1{max-width:620px;margin:0;'
        'font-size:58px;font-weight:650;line-height:1.08;letter-spacing:0}.lead{max-width:540px;'
        'margin:23px 0 0;color:var(--muted);font-size:17px;line-height:1.75}.actions{margin-top:30px;'
        'color:var(--quiet);font-size:13px}.status-panel{position:relative;min-height:365px;overflow:hidden;'
        'padding:28px;border:1px solid var(--line);background:linear-gradient(145deg,rgba(17,27,52,.92),'
        'rgba(8,14,30,.86)),var(--surface);box-shadow:0 28px 85px rgba(0,0,0,.25);'
        'animation:reveal 700ms 160ms ease-out both}.panel-top,.panel-bottom{display:flex;'
        'justify-content:space-between;gap:16px}.panel-top{align-items:center;padding-bottom:19px;'
        'border-bottom:1px solid var(--line);color:var(--quiet);font:10px var(--mono);'
        'letter-spacing:.1em;text-transform:uppercase}.status-light{display:inline-flex;align-items:center;'
        'gap:9px;color:#c1ccd9}.status-light:before{width:7px;height:7px;border-radius:50%;'
        'background:#8aa5b8;box-shadow:0 0 0 4px rgba(138,165,184,.1);content:""}'
        '.status-display{position:relative;display:grid;min-height:248px;place-content:center;text-align:center}'
        '.status-display:before,.status-display:after{position:absolute;width:26px;height:26px;'
        'border-color:rgba(34,211,238,.55);border-style:solid;content:""}.status-display:before{'
        'top:24px;left:3px;border-width:1px 0 0 1px}.status-display:after{right:3px;bottom:22px;border-width:0 1px 1px 0}'
        '.status-code{margin:0;color:transparent;background:linear-gradient(130deg,#f5f7ff 10%,#8ea0be 83%);'
        'background-clip:text;font:600 43px/1.2 var(--mono);letter-spacing:0}.status-description{'
        'margin-top:12px;color:var(--quiet);font:10px var(--mono);letter-spacing:.13em;text-transform:uppercase}'
        '.panel-bottom{align-items:center;padding-top:19px;border-top:1px solid var(--line);'
        'color:var(--muted);font:10px var(--mono)}.panel-bottom strong{color:#a5eaf4;font-weight:600}'
        '.quote-row{display:grid;grid-template-columns:210px minmax(0,1fr);align-items:center;gap:26px;'
        'min-height:112px;padding:20px 0;border-top:1px solid var(--line);animation:reveal 700ms 240ms ease-out both}'
        '.quote-label{margin:0;color:var(--quiet);font:10px var(--mono);letter-spacing:.1em;text-transform:uppercase}'
        '.contact{min-width:0;color:#dce4f2;font-size:15px;line-height:1.65;white-space:pre-line;overflow-wrap:anywhere}'
        'footer{display:flex;min-height:66px;align-items:center;justify-content:space-between;gap:20px;'
        'border-top:1px solid var(--line);color:var(--quiet);font:10px var(--mono);letter-spacing:.04em;'
        'animation:reveal 700ms 300ms ease-out both}footer span:last-child{color:#8292ac}'
        '@keyframes reveal{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}'
        '@media(max-width:900px){.page-shell{width:min(100% - 48px,720px)}main{grid-template-columns:1fr;gap:38px;padding:48px 0 38px}'
        'h1{max-width:700px;font-size:48px}.status-panel{min-height:325px}.status-display{min-height:210px}}'
        '@media(max-width:560px){.page-shell{width:calc(100% - 36px)}.site-header{min-height:76px}'
        '.brand{font-size:14px}.brand small{font-size:9px}.header-label{max-width:114px;font-size:9px;text-align:right}'
        'main{gap:30px;padding:42px 0 32px}.eyebrow{margin-bottom:20px;font-size:10px}h1{font-size:39px}'
        '.lead{margin-top:17px;font-size:15px;line-height:1.7}.actions{margin-top:25px}'
        '.status-panel{min-height:285px;padding:20px}.panel-top,.panel-bottom{font-size:9px}'
        '.status-display{min-height:190px}.status-code{font-size:30px}.status-description{font-size:9px}'
        '.quote-row{grid-template-columns:1fr;gap:10px;padding:18px 0}.contact{font-size:13px}'
        'footer{min-height:62px;align-items:flex-start;flex-direction:column;justify-content:center;gap:2px;font-size:9px}}'
        '@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}'
        '</style></head><body><div class="page-shell"><header class="site-header">'
        '<div class="brand">FOCUSLENS<small>ENGINEERING / ACCESS</small></div>'
        '<span class="header-label">Инженерия с человеческим контролем</span></header><main>'
        '<section class="copy"><p class="eyebrow">Ограничение доступа</p>'
        '<h1>Доступ к сайту приостановлен</h1>'
        '<p class="lead">Домен или сайт отключён по причине неоплаты. После урегулирования оплаты доступ будет восстановлен.</p>'
        '<p class="actions">Сайт временно не обслуживается.</p></section>'
        '<aside class="status-panel"><div class="panel-top"><span>Account monitor / 01</span>'
        '<span class="status-light">Доступ ограничен</span></div><div class="status-display">'
        '<p class="status-code">ОТКЛЮЧЁН</p><span class="status-description">Блокировка по неоплате</span>'
        '</div><div class="panel-bottom"><span>Статус сайта</span><strong>НЕОПЛАТА</strong></div></aside></main>'
        '<section class="quote-row"><p class="quote-label">Связь с администратором</p>'
        '<div class="contact">' + html.escape(contact_text.strip()).replace('$', '&#36;').replace('\n', '&#10;') + '</div>'
        '</section><footer><span>FOCUSLENS.DEV · © 2026</span><span>Время — наша валюта. Прозрачность — гарантия.</span></footer>'
        '</div></body></html>'
    ).encode('utf-8')
    block = (
        f'\n        {NONPAYMENT_MARKER}: begin\n'
        f'        error_page 503 {NONPAYMENT_URI};\n'
        f'        location = {NONPAYMENT_URI} {{\n'
        f'            internal;\n'
        f'            default_type text/html;\n'
        f'            alias {page_path_text};\n'
        f'        }}\n'
        f'        if ($uri != {NONPAYMENT_URI}) {{ return 503; }}\n'
        f'        {NONPAYMENT_MARKER}: end\n'
    )
    for closing in reversed(closings):
        text = text[:closing] + block + text[closing:]
    return text.encode('utf-8'), page


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
