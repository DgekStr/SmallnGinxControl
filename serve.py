import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smallnginx.settings')

from smallnginx.wsgi import application
from django.conf import settings
from panel.metrics import start_collector
from waitress import serve


if __name__ == '__main__':
    host = os.environ.get('SNC_BIND', '127.0.0.1')
    port = int(os.environ.get('SNC_PORT', '7444'))
    if settings.SNC_MODE == 'demo' and host not in {'127.0.0.1', '::1', 'localhost'}:
        raise RuntimeError('Demo with a temporary password must bind to loopback only.')
    stop, lock = start_collector()
    print(f'SmallnGinxControl [{settings.SNC_MODE}] http://{host}:{port}', flush=True)
    try:
        serve(application, host=host, port=port, threads=6, channel_timeout=30, max_request_body_size=512 * 1024, clear_untrusted_proxy_headers=True)
    finally:
        stop.set()
        lock.release()