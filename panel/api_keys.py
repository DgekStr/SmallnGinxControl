import hashlib
import re
import secrets
from functools import wraps

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from .models import ApiKey


API_KEY_RESOURCES = frozenset({'servers', 'overview', 'traffic', 'hosts', 'config', 'logs', 'audit', 'traffic-maintenance', 'service'})


def key_status(user):
    credential = ApiKey.objects.filter(user=user).first()
    return {
        'enabled': credential is not None,
        'prefix': credential.prefix if credential else '',
        'read_only': credential.read_only if credential else True,
        'created_at': credential.created_at if credential else None,
        'last_used_at': credential.last_used_at if credential else None,
    }


@transaction.atomic
def generate_key(user, read_only):
    key = 'snc_' + secrets.token_urlsafe(32)
    values = {
        'key_hash': hashlib.sha256(key.encode()).hexdigest(),
        'prefix': key[:12],
        'read_only': read_only,
        'created_at': timezone.now(),
        'last_used_at': None,
    }
    if not ApiKey.objects.filter(user=user).update(**values):
        ApiKey.objects.create(user=user, **values)
    return key


def api_key_access(view_func):
    session_view = csrf_protect(view_func)

    @wraps(view_func)
    def wrapped(request, resource, *args, **kwargs):
        authorization = request.headers.get('Authorization', '')
        if not authorization:
            return session_view(request, resource, *args, **kwargs)
        parts = authorization.split() if len(authorization) <= 128 else []
        credential = None
        if len(parts) == 2 and parts[0].lower() == 'bearer' and re.fullmatch(r'snc_[A-Za-z0-9_-]{43}', parts[1]):
            key_hash = hashlib.sha256(parts[1].encode()).hexdigest()
            credential = ApiKey.objects.select_related('user').filter(key_hash=key_hash).first()
        if credential is None or not credential.user.is_active or not credential.user.is_staff:
            response = JsonResponse({'error': 'API-ключ недействителен или отозван.'}, status=401)
            response['WWW-Authenticate'] = 'Bearer'
            return response
        if resource not in API_KEY_RESOURCES:
            return JsonResponse({'error': 'Этот ресурс доступен только через сессию администратора.'}, status=403)
        if credential.read_only and request.method != 'GET':
            return JsonResponse({'error': 'API-ключ разрешает только чтение.'}, status=403)
        request.user = credential.user
        request.api_key = credential
        ApiKey.objects.filter(pk=credential.pk).update(last_used_at=timezone.now())
        return view_func(request, resource, *args, **kwargs)

    return csrf_exempt(wrapped)