import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings

from .nginx import NginxManager
from .transactions import OperationError, apply_transaction, atomic_write


PANEL_TLS_PORT = 7444
MAX_PEM_BYTES = 200_000
PANEL_TLS_MARKER = '# smallnginxcontrol-panel-tls'


def _paths():
    directory = Path(settings.STATE_DIR) / 'panel-tls'
    return directory, directory / 'panel.crt', directory / 'panel.key', Path(settings.NGINX_ROOT) / 'conf.d' / 'smallnginxcontrol-panel.conf'


def _panel_host():
    host = settings.SNC_SERVER
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
        raise OperationError('Адрес панели должен быть IP-адресом или DNS-именем без схемы и порта.')
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        host = host.rstrip('.').lower()
        if not host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise OperationError('Некорректное DNS-имя панели для сертификата.')
        return host


def _public_key_bytes(key):
    public_key = key.public_key() if hasattr(key, 'public_key') else key
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def generate_local_certificate(host=None):
    host = _panel_host() if host is None else host
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(host))])
    now = datetime.now(timezone.utc)
    san = x509.IPAddress(host) if isinstance(host, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else x509.DNSName(host)
    subject_alt_names = [san]
    if str(host) != 'localhost':
        subject_alt_names.append(x509.DNSName('localhost'))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def validate_certificate_pair(certificate_pem, private_key_pem):
    if not isinstance(certificate_pem, (str, bytes)) or not isinstance(private_key_pem, (str, bytes)):
        raise OperationError('Загрузите PEM-сертификат и соответствующий приватный ключ.')
    if len(certificate_pem.encode('utf-8') if isinstance(certificate_pem, str) else certificate_pem) > MAX_PEM_BYTES:
        raise OperationError('Файл сертификата превышает 200 КБ.')
    if len(private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem) > MAX_PEM_BYTES:
        raise OperationError('Файл приватного ключа превышает 200 КБ.')
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8') if isinstance(certificate_pem, str) else certificate_pem)
        private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise OperationError('Не удалось прочитать PEM-сертификат или незашифрованный PEM-приватный ключ.') from error
    if _public_key_bytes(certificate.public_key()) != _public_key_bytes(private_key):
        raise OperationError('Приватный ключ не соответствует сертификату.')

    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise OperationError('Сертификат ещё не действует или уже истёк.')
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as error:
        raise OperationError('В сертификате отсутствует SAN с адресом панели.') from error
    host = _panel_host()
    if isinstance(host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        matches = host in names.get_values_for_type(x509.IPAddress)
    else:
        dns_names = [name.lower().rstrip('.') for name in names.get_values_for_type(x509.DNSName)]
        matches = host in dns_names or any(name.startswith('*.') and host.endswith(name[1:]) and host.count('.') == name.count('.') for name in dns_names)
    if not matches:
        raise OperationError('SAN сертификата не соответствует адресу панели.')
    return certificate, private_key


def _nginx_config():
    _, certificate_path, key_path, _ = _paths()
    host = _panel_host()
    return f'''{PANEL_TLS_MARKER}
server {{
    listen 0.0.0.0:{PANEL_TLS_PORT} ssl default_server;
    server_name {host};

    ssl_certificate {certificate_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:smallnginxcontrol_tls:10m;
    ssl_session_timeout 1d;

    location / {{
        proxy_pass http://127.0.0.1:{settings.SNC_PORT};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
'''.encode('utf-8')


def _restore(path, original):
    if original is None:
        Path(path).unlink(missing_ok=True)
        return
    content, mode = original
    atomic_write(path, content)
    os.chmod(path, mode)


def _apply(certificate_pem, private_key_pem, include_config=False):
    directory, certificate_path, key_path, config_path = _paths()
    if any(path.is_symlink() for path in (certificate_path, key_path, config_path)):
        raise OperationError('TLS-файлы панели не должны быть символическими ссылками.')
    include_config = include_config or not config_path.exists()
    if config_path.exists() and PANEL_TLS_MARKER.encode('ascii') not in config_path.read_bytes():
        raise OperationError('Файл конфигурации панели уже занят другой конфигурацией nginx.')
    config = _nginx_config() if include_config or not config_path.exists() else config_path.read_bytes()

    paths = [certificate_path, key_path, config_path]
    originals = {
        path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.is_file() else None
        for path in paths
    }
    manager = NginxManager()

    def change():
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        atomic_write(certificate_path, certificate_pem)
        os.chmod(certificate_path, 0o644)
        atomic_write(key_path, private_key_pem)
        os.chmod(key_path, 0o600)
        if include_config:
            atomic_write(config_path, config)
            os.chmod(config_path, 0o644)

    def rollback():
        for path, original in originals.items():
            _restore(path, original)

    with manager.lock():
        apply_transaction(change, rollback, manager.validate, manager.reload)
    return panel_tls_status()


def install_panel_tls():
    if settings.SNC_MODE == 'demo':
        raise OperationError('TLS-вход панели доступен только в production.')
    directory, certificate_path, key_path, config_path = _paths()
    if config_path.exists() and PANEL_TLS_MARKER.encode('ascii') not in config_path.read_bytes():
        raise OperationError('Файл конфигурации панели уже занят другой конфигурацией nginx.')
    if certificate_path.exists() != key_path.exists():
        raise OperationError('Найдена неполная пара TLS-файлов. Восстановите сертификат и ключ вручную.')
    if certificate_path.exists():
        certificate_pem, private_key_pem = certificate_path.read_bytes(), key_path.read_bytes()
        validate_certificate_pair(certificate_pem, private_key_pem)
    else:
        certificate_pem, private_key_pem = generate_local_certificate()
    return _apply(certificate_pem, private_key_pem, include_config=True)


def renew_panel_certificate():
    if settings.SNC_MODE == 'demo':
        raise OperationError('TLS-сертификат нельзя менять в деморежиме.')
    certificate_pem, private_key_pem = generate_local_certificate()
    _, _, _, config_path = _paths()
    return _apply(certificate_pem, private_key_pem, include_config=not config_path.exists())


def replace_panel_certificate(certificate_pem, private_key_pem):
    if settings.SNC_MODE == 'demo':
        raise OperationError('TLS-сертификат нельзя менять в деморежиме.')
    validate_certificate_pair(certificate_pem, private_key_pem)
    certificate_bytes = certificate_pem.encode('utf-8') if isinstance(certificate_pem, str) else certificate_pem
    key_bytes = private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem
    _, _, _, config_path = _paths()
    return _apply(certificate_bytes, key_bytes, include_config=not config_path.exists())


def panel_tls_status():
    if settings.SNC_MODE == 'demo':
        return {'available': False, 'installed': False}
    _, certificate_path, key_path, config_path = _paths()
    if not certificate_path.is_file() or not key_path.is_file():
        return {'available': True, 'installed': False, 'certificate_pem': ''}
    try:
        certificate, _ = validate_certificate_pair(certificate_path.read_bytes(), key_path.read_bytes())
    except OperationError as error:
        return {'available': True, 'installed': False, 'error': str(error)}
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    san = [str(address) for address in names.get_values_for_type(x509.IPAddress)]
    san.extend(names.get_values_for_type(x509.DNSName))
    return {
        'available': True,
        'installed': config_path.is_file(),
        'self_signed': certificate.issuer == certificate.subject,
        'subject': certificate.subject.rfc4514_string(),
        'sans': san,
        'not_after': certificate.not_valid_after_utc.isoformat(),
        'fingerprint': certificate.fingerprint(hashes.SHA256()).hex(':').upper(),
    }


def panel_certificate_path():
    _, certificate_path, _, _ = _paths()
    if settings.SNC_MODE == 'demo' or not certificate_path.is_file():
        raise OperationError('Сертификат панели не найден.')
    return certificate_path