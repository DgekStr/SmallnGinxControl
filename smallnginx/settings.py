import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = Path(os.environ.get('SNC_STATE_DIR', BASE_DIR / 'var'))
STATE_DIR.mkdir(parents=True, exist_ok=True)
SNC_MODE = os.environ.get('SNC_MODE', 'demo')
if SNC_MODE not in {'demo', 'local'}:
    raise RuntimeError('SNC_MODE must be demo or local')
DEBUG = False
secret_file = STATE_DIR / '.secret'
if not secret_file.exists():
    try:
        descriptor = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(secrets.token_urlsafe(64))
    except FileExistsError:
        pass
SECRET_KEY = os.environ.get('SNC_SECRET_KEY') or secret_file.read_text().strip()
ALLOWED_HOSTS = os.environ.get('SNC_ALLOWED_HOSTS', '127.0.0.1,localhost,[::1]').split(',')
CSRF_TRUSTED_ORIGINS = list(filter(None, os.environ.get('SNC_CSRF_ORIGINS', '').split(',')))
if os.environ.get('SNC_TRUST_PROXY', '0') == '1':
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.staticfiles', 'panel']
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
ROOT_URLCONF = 'smallnginx.urls'
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth']},
}]
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': STATE_DIR / 'db.sqlite3', 'OPTIONS': {'timeout': 20}}}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LANGUAGE_CODE = 'ru-ru'
TIME_ZONE = 'Europe/Moscow'
USE_TZ = True
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
WHITENOISE_USE_FINDERS = SNC_MODE == 'demo'
LOGIN_URL = '/login/'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600 * 8
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = os.environ.get('SNC_SECURE_COOKIES', '0') == '1'
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 512 * 1024
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 10}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
]
NGINX_ROOT = Path(os.environ.get('SNC_NGINX_ROOT', STATE_DIR / 'nginx' if SNC_MODE == 'demo' else '/etc/nginx'))
NGINX_LOG_ROOT = Path(os.environ.get('SNC_LOG_ROOT', STATE_DIR / 'logs' if SNC_MODE == 'demo' else '/var/log/nginx'))
SNC_LOG_EXTRA_ROOTS = tuple(Path(value.strip()).resolve() for value in os.environ.get('SNC_LOG_EXTRA_ROOTS', '/var/http').split(',') if value.strip())
SNC_MAINTENANCE_ROOT = Path(os.environ.get('SNC_MAINTENANCE_ROOT', STATE_DIR / 'maintenance' if SNC_MODE == 'demo' else '/var/www/html'))
SNC_ACME_WEBROOT = Path(os.environ.get('SNC_ACME_WEBROOT', '/var/www/html'))
SNC_CERTBOT_BIN = os.environ.get('SNC_CERTBOT_BIN', '/usr/bin/certbot')
SNC_CERTBOT_LIVE_ROOT = Path(os.environ.get('SNC_CERTBOT_LIVE_ROOT', '/etc/letsencrypt/live'))
NGINX_BIN = os.environ.get('SNC_NGINX_BIN', '/usr/sbin/nginx')
SNC_SERVER = os.environ.get('SNC_SERVER', '192.0.2.15')
SNC_PORT = int(os.environ.get('SNC_PORT', '7444'))
SNC_INTERFACE = os.environ.get('SNC_INTERFACE', '')