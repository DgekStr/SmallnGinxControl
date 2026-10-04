import math
import os
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smallnginx.settings')

import django
django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management import call_command
from django.utils import timezone

from panel.models import AuditEvent, MetricSample
from panel.nginx import NginxManager
from panel.transactions import atomic_write


def initialize():
    call_command('migrate', interactive=False)
    users = get_user_model()
    if not users.objects.filter(username='admin').exists():
        password = '12345' if settings.SNC_MODE == 'demo' else os.environ.get('SNC_INITIAL_PASSWORD', '')
        if settings.SNC_MODE != 'demo':
            if not password:
                raise RuntimeError('Set SNC_INITIAL_PASSWORD before production bootstrap.')
            validate_password(password)
        users.objects.create_user('admin', password=password, is_staff=True, is_superuser=True)
        print('Administrator created. Password is not printed.')
    if settings.SNC_MODE != 'demo':
        return
    manager = NginxManager()
    for folder in ['conf.d', 'sites-available', 'sites-enabled']:
        (manager.root / folder).mkdir(parents=True, exist_ok=True)
    manager.logs_root.mkdir(parents=True, exist_ok=True)
    manager.maintenance_root.mkdir(parents=True, exist_ok=True)
    maintenance_page = manager.maintenance_page
    if not maintenance_page.exists():
        atomic_write(maintenance_page, '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Техническое обслуживание</title><h1>Сайт временно на обслуживании</h1></html>\n'.encode('utf-8'))
    if (manager.root / 'nginx.conf').exists():
        return
    atomic_write(manager.root / 'nginx.conf', b'worker_processes auto;\nworker_rlimit_nofile 65535;\n\nevents {\n    worker_connections 4096;\n    multi_accept on;\n}\n\nhttp {\n    include mime.types;\n    default_type application/octet-stream;\n    sendfile on;\n    tcp_nopush on;\n    keepalive_timeout 65;\n    server_tokens off;\n    gzip on;\n    gzip_types text/plain text/css application/json application/javascript;\n    include conf.d/*.conf;\n    include sites-enabled/*;\n}\n')
    sites = [
        ('focuslens.dev', 'host', '/var/www/focuslens', True, True),
        ('crm.focuslens.dev', 'proxy', 'http://192.168.0.21:3000', True, True),
        ('api.focuslens.dev', 'proxy', 'http://192.168.0.22:8000', True, True),
        ('docs.focuslens.dev', 'host', '/var/www/docs', True, True),
        ('grafana.internal', 'proxy', 'http://192.168.0.30:3000', True, False),
        ('storage.internal', 'proxy', 'http://192.168.0.31:9001', True, False),
        ('staging.focuslens.dev', 'proxy', 'http://192.168.0.24:8080', False, False),
        ('status.focuslens.dev', 'host', '/var/www/status', True, True),
    ]
    for name, kind, target, enabled, tls in sites:
        manager.create({'name': name, 'kind': kind, 'target': target, 'port': 80})
        path = manager.root / 'conf.d' / (name + '.conf')
        if tls:
            content = path.read_text().replace('listen 80;', f'listen 443 ssl;\n    ssl_certificate /etc/letsencrypt/live/{name}/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/{name}/privkey.pem;')
            atomic_write(path, content.encode())
        if not enabled:
            path.rename(path.with_name(path.name + '.disabled'))
        access = '\n'.join(f'192.168.0.{40 + number % 12} - - [04/Oct/2026:12:{number:02d}:18 +0300] "GET {"/api/health" if kind == "proxy" else "/"} HTTP/2.0" {"404" if number % 13 == 0 else "200"} {1024 + number * 41} "-" "Mozilla/5.0"' for number in range(30)) + '\n'
        atomic_write(manager.logs_root / (name + '.conf.access.log'), access.encode())
        atomic_write(manager.logs_root / (name + '.conf.error.log'), b'')
    atomic_write(manager.logs_root / 'access.log', access.encode())
    atomic_write(manager.logs_root / 'error.log', b'2026/10/04 12:00:00 [notice] 1234#1234: signal process started\n')
    now = timezone.now()
    for number in range(181):
        phase = number / 9
        sample = MetricSample.objects.create(server_id='local', cpu=18 + math.sin(phase) * 7 + math.sin(phase * 3) * 3, memory=34.6, rx_rate=3.2 + math.sin(phase * .7) * 1.6, tx_rate=1.4 + math.cos(phase) * .7, rx_mb=28416, tx_mb=12780, uptime=18 * 86400 + 7 * 3600)
        MetricSample.objects.filter(pk=sample.pk).update(created_at=now - timedelta(seconds=(180 - number) * 10))
    AuditEvent.objects.create(actor='system', action='demo_initialized', target=settings.SNC_SERVER, detail='Синтетические конфигурации и метрики. Сервер не подключён.')
    print('Local demo initialized. No remote connections made.')


if __name__ == '__main__':
    initialize()