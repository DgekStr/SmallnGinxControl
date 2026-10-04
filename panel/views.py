import hashlib
import json
import logging
from datetime import timedelta

import portalocker
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods, require_POST

from .metrics import snapshot
from .models import AuditEvent, LoginAttempt, MetricSample, Server, ServiceSetting
from .servers import AddressForm, ServerForm, initialize_demo, manager_for, public_server, selected_server
from .transactions import OperationError


def record(request, action, target='', success=True, detail='', server=None):
    AuditEvent.objects.create(server=server, actor=request.user.get_username() or 'anonymous', action=action, target=str(target)[:255], success=success, detail=str(detail)[:3000])


def manage_servers(request, data):
    action = data.get('action')
    if action == 'probe':
        form = AddressForm(data)
        if not form.is_valid():
            raise OperationError('Укажите корректный адрес и SSH-порт.')
        from .ssh import probe_fingerprint
        return probe_fingerprint(**form.cleaned_data)
    if action == 'test':
        server = selected_server(data.get('id', ''))
        try:
            status = manager_for(server).status()
        except OperationError as error:
            Server.objects.filter(pk=server.pk).update(last_error=str(error)[:500])
            record(request, 'server_test', server.host, False, str(error), server)
            raise
        Server.objects.filter(pk=server.pk).update(last_seen=timezone.now(), last_error='')
        record(request, 'server_test', server.host, server=server)
        return {'ok': True, 'message': 'Соединение установлено.', 'nginx': status}
    with transaction.atomic():
        if action in {'update', 'delete'}:
            server = selected_server(data.get('id', ''))
            if data.get('revision') != server.updated_at.isoformat():
                raise OperationError('Профиль сервера изменился. Обновите список.')
        elif action == 'create':
            server = Server()
        else:
            raise OperationError('Неизвестное действие с сервером.')
        if action == 'delete':
            if server.is_default:
                raise OperationError('Основной сервер нельзя удалить.')
            record(request, 'server_delete', server.name + ' / ' + server.host)
            server.delete()
            return {'ok': True, 'message': 'Подключение удалено. Удалённый nginx не изменён.'}
        defaults = {'port': 22, 'username': 'root', 'auth_method': 'key', 'nginx_root': '/etc/nginx', 'log_root': '/var/log/nginx'}
        identity_fields = ['mode', 'host', 'port', 'username', 'nginx_root', 'interface']
        old_identity = [getattr(server, field) for field in identity_fields]
        form = ServerForm({**defaults, **data}, instance=server)
        if not form.is_valid():
            raise OperationError(' '.join(str(error) for errors in form.errors.values() for error in errors))
        server = form.save()
        if action == 'update' and old_identity != [getattr(server, field) for field in identity_fields]:
            MetricSample.objects.filter(server=server).delete()
            Server.objects.filter(pk=server.pk).update(last_seen=None, last_error='')
            server.refresh_from_db()
        initialize_demo(server)
        record(request, 'server_' + action, server.name + ' / ' + server.host, server=server)
        return {'ok': True, 'server': public_server(server)}


@never_cache
@require_http_methods(['GET', 'POST'])
def sign_in(request):
    if request.user.is_authenticated:
        return redirect('/')
    error = ''
    status = 200
    if request.method == 'POST':
        username = request.POST.get('username', '')[:150]
        address = request.META.get('REMOTE_ADDR', '')
        keys = [hashlib.sha256(value.encode()).hexdigest() for value in ['ip:' + address, 'user:' + username.lower()]]
        now = timezone.now()
        with transaction.atomic():
            attempts = [LoginAttempt.objects.get_or_create(key=key, defaults={'window': now})[0] for key in keys]
            for attempt in attempts:
                if now - attempt.window > timedelta(minutes=15):
                    attempt.failures, attempt.window = 0, now
            blocked = any(attempt.failures >= 5 for attempt in attempts)
            if not blocked:
                for attempt in attempts:
                    attempt.failures += 1
                    attempt.save()
        if blocked:
            error, status = 'Слишком много попыток. Повторите через 15 минут.', 429
        else:
            user = authenticate(request, username=username, password=request.POST.get('password', ''))
            if user is not None and user.is_staff:
                LoginAttempt.objects.filter(key__in=keys).delete()
                login(request, user)
                record(request, 'login')
                return redirect('/')
            error, status = 'Неверный логин или пароль.', 401
        LoginAttempt.objects.filter(window__lt=now - timedelta(days=1)).delete()
    return render(request, 'login.html', {'error': error, 'demo': settings.SNC_MODE == 'demo', 'server': settings.SNC_SERVER}, status=status)


@require_POST
def sign_out(request):
    if request.user.is_authenticated:
        record(request, 'logout')
    logout(request)
    return redirect('/login/')


@never_cache
@login_required
@ensure_csrf_cookie
def index(request):
    if not request.user.is_staff:
        return JsonResponse({'error': 'Нет доступа.'}, status=403)
    return render(request, 'index.html', {'demo': settings.SNC_MODE == 'demo', 'server': settings.SNC_SERVER})


@never_cache
@require_http_methods(['GET', 'POST'])
def api(request, resource):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Требуется вход.'}, status=401)
    if not request.user.is_staff:
        return JsonResponse({'error': 'Нет доступа.'}, status=403)
    action, target, server = resource, '', None
    try:
        if resource == 'servers' and request.method == 'GET':
            return JsonResponse({'servers': [public_server(item) for item in Server.objects.all()]})
        if resource not in {'servers', 'password', 'settings'}:
            server = selected_server(request.GET.get('server'))
            expected_profile = request.GET.get('server_revision')
            if (expected_profile is not None or request.method == 'POST') and expected_profile != server.updated_at.isoformat():
                raise OperationError('Профиль сервера изменён или не подтверждён. Обновите страницу перед операцией.')
            manager = manager_for(server)
        if request.method == 'GET':
            if resource == 'settings':
                service_settings = ServiceSetting.get_solo()
                return JsonResponse({'log_retention_days': service_settings.log_retention_days})
            if resource == 'overview':
                return JsonResponse({'server': server.host, 'server_id': server.pk, 'server_name': server.name, 'mode': server.mode, 'nginx': manager.status(), 'metrics': snapshot(server)})
            if resource == 'traffic':
                return JsonResponse(manager.traffic_top())
            if resource == 'hosts':
                return JsonResponse(manager.inventory())
            if resource == 'config':
                return JsonResponse(manager.read(request.GET.get('id', 'nginx.conf')))
            if resource == 'logs':
                return JsonResponse(manager.logs(request.GET.get('id', ''), request.GET.get('kind', 'access'), max(1, min(500, int(request.GET.get('lines', 150))))))
            if resource == 'audit':
                return JsonResponse({'events': list(AuditEvent.objects.filter(Q(server=server) | Q(server__isnull=True))[:100].values('created_at', 'actor', 'action', 'target', 'success', 'detail', 'server_id'))})
            return JsonResponse({'error': 'Неизвестный ресурс.'}, status=404)
        if request.content_type != 'application/json':
            return JsonResponse({'error': 'Ожидается JSON.'}, status=415)
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise OperationError('Ожидается JSON-объект.')
        if resource == 'servers':
            return JsonResponse(manage_servers(request, data))
        target = data.get('id', '')
        if resource == 'hosts':
            action = data.get('action', '')
            if action == 'create':
                result = manager.create(data)
                target = data.get('name', '')
            elif action == 'toggle':
                if type(data.get('enabled')) is not bool:
                    raise OperationError('Состояние должно быть true или false.')
                result = manager.toggle(target, data['enabled'], data.get('revision'))
            elif action == 'delete':
                result = manager.delete(target, data.get('revision'))
            elif action == 'reload':
                manager.read(target)
                result = manager.service('reload')
            else:
                raise OperationError('Неизвестное действие.')
        elif resource == 'config':
            action = 'save_config'
            result = manager.save(target, data.get('content'), data.get('revision'))
        elif resource == 'service':
            action = data.get('action', '')
            if action == 'restart' and data.get('confirmation') != 'restart nginx':
                raise OperationError('Подтвердите перезапуск nginx.')
            result = manager.service(action)
        elif resource == 'password':
            action = 'password_change'
            form = PasswordChangeForm(request.user, data)
            if not form.is_valid():
                return JsonResponse({'error': ' '.join(str(message) for messages in form.errors.values() for message in messages)}, status=400)
            user = form.save()
            update_session_auth_hash(request, user)
            result = 'Пароль изменён.'
        elif resource == 'settings':
            action = 'settings_update'
            retention_days = data.get('log_retention_days')
            if type(retention_days) is not int or not 1 <= retention_days <= 3650:
                raise OperationError('Срок хранения должен быть целым числом от 1 до 3650 дней.')
            service_settings = ServiceSetting.get_solo()
            service_settings.log_retention_days = retention_days
            service_settings.save(update_fields=['log_retention_days', 'updated_at'])
            target = 'log_retention_days'
            result = 'Срок хранения журналов сохранён.'
        else:
            return JsonResponse({'error': 'Неизвестный ресурс.'}, status=404)
        record(request, action, target, server=server)
        return JsonResponse({'ok': True, 'message': result})
    except (OperationError, ValueError, TypeError, AttributeError, OSError, portalocker.exceptions.LockException) as error:
        if request.method == 'POST':
            record(request, str(action), target, False, str(error), server)
        return JsonResponse({'error': str(error)}, status=400)
    except Exception:
        logging.getLogger(__name__).exception('Panel request failed')
        return JsonResponse({'error': 'Внутренняя ошибка. Проверьте журнал SmallnGinxControl.'}, status=500)