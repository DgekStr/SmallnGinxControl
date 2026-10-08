import hashlib
import json
import logging
from datetime import timedelta

import portalocker
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.db import transaction
from django.db.models import Q
from django.http import FileResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods, require_POST

from .metrics import snapshot
from .models import AuditEvent, LoginAttempt, MetricSample, Server, ServiceSetting, TwoFactorCredential
from .panel_tls import MAX_PEM_BYTES, panel_certificate_path, panel_tls_status, renew_panel_certificate, replace_panel_certificate
from .servers import AddressForm, ServerForm, initialize_demo, manager_for, public_server, selected_server
from .transactions import ACCESS_LOG_SAMPLE_MAX_BYTES, OperationError
from .two_factor import generate_totp_secret, provisioning_uri, qr_data_uri, verify_totp


def record(request, action, target='', success=True, detail='', server=None):
    AuditEvent.objects.create(server=server, actor=request.user.get_username() or 'anonymous', action=action, target=str(target)[:255], success=success, detail=str(detail)[:3000])


def login_with_configured_timeout(request, user):
    login(request, user)
    timeout_hours = ServiceSetting.get_solo().session_timeout_hours
    request.session.set_expiry(timeout_hours * 3600)


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
    if request.method == 'GET' and request.GET.get('cancel-2fa') == '1':
        request.session.pop('two_factor_pending_user_id', None)
        request.session.pop('two_factor_pending_username', None)
        return redirect('/login/')
    error = ''
    status = 200
    pending_user_id = request.session.get('two_factor_pending_user_id')
    if request.method == 'POST':
        username = str(request.session.get('two_factor_pending_username', '') if pending_user_id else request.POST.get('username', ''))[:150]
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
        elif pending_user_id:
            user = get_user_model().objects.filter(pk=pending_user_id, is_staff=True).first()
            credential = TwoFactorCredential.objects.filter(user=user, enabled=True).first() if user else None
            secret = credential.get_secret() if credential else ''
            if user and secret and verify_totp(secret, request.POST.get('code', '')):
                request.session.pop('two_factor_pending_user_id', None)
                request.session.pop('two_factor_pending_username', None)
                LoginAttempt.objects.filter(key__in=keys).delete()
                login_with_configured_timeout(request, user)
                record(request, 'login')
                return redirect('/')
            error, status = 'Неверный одноразовый код.', 401
        else:
            user = authenticate(request, username=username, password=request.POST.get('password', ''))
            if user is not None and user.is_staff:
                credential = TwoFactorCredential.objects.filter(user=user, enabled=True).first()
                if credential:
                    request.session['two_factor_pending_user_id'] = user.pk
                    request.session['two_factor_pending_username'] = user.get_username()
                    request.session.set_expiry(300)
                    return render(request, 'login.html', {
                        'two_factor_pending': True,
                        'two_factor_username': user.get_username(),
                        'demo': settings.SNC_MODE == 'demo',
                        'server': settings.SNC_SERVER,
                    })
                LoginAttempt.objects.filter(key__in=keys).delete()
                login_with_configured_timeout(request, user)
                record(request, 'login')
                return redirect('/')
            error, status = 'Неверный логин или пароль.', 401
        LoginAttempt.objects.filter(window__lt=now - timedelta(days=1)).delete()
    return render(request, 'login.html', {
        'error': error,
        'two_factor_pending': bool(request.session.get('two_factor_pending_user_id')),
        'two_factor_username': request.session.get('two_factor_pending_username', ''),
        'demo': settings.SNC_MODE == 'demo',
        'server': settings.SNC_SERVER,
    }, status=status)


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
        if resource not in {'servers', 'password', 'settings', 'two-factor', 'panel-tls', 'panel-tls-download'}:
            server = selected_server(request.GET.get('server'))
            expected_profile = request.GET.get('server_revision')
            if (expected_profile is not None or request.method == 'POST') and expected_profile != server.updated_at.isoformat():
                raise OperationError('Профиль сервера изменён или не подтверждён. Обновите страницу перед операцией.')
            manager = manager_for(server)
        if request.method == 'GET':
            if resource == 'traffic-maintenance':
                return JsonResponse({'enabled': server.traffic_blocked, 'page_path': server.maintenance_page_path})
            if resource == 'two-factor':
                credential = TwoFactorCredential.objects.filter(user=request.user).first()
                return JsonResponse({'enabled': bool(credential and credential.enabled)})
            if resource == 'settings':
                service_settings = ServiceSetting.get_solo()
                return JsonResponse({'log_retention_days': service_settings.log_retention_days, 'session_timeout_hours': service_settings.session_timeout_hours, 'access_log_sample_bytes': service_settings.access_log_sample_bytes})
            if resource == 'panel-tls':
                return JsonResponse(panel_tls_status())
            if resource == 'panel-tls-download':
                return FileResponse(panel_certificate_path().open('rb'), as_attachment=True, filename='smallnginxcontrol-certificate.pem', content_type='application/x-pem-file')
            if resource == 'overview':
                return JsonResponse({'server': server.host, 'server_id': server.pk, 'server_name': server.name, 'mode': server.mode, 'nginx': manager.status(), 'metrics': snapshot(server)})
            if resource == 'traffic':
                sample_size = ServiceSetting.get_solo().access_log_sample_bytes
                return JsonResponse(manager.traffic_top(sample_size=sample_size))
            if resource == 'hosts':
                return JsonResponse(manager.inventory())
            if resource == 'config':
                return JsonResponse(manager.read(request.GET.get('id', 'nginx.conf')))
            if resource == 'logs':
                return JsonResponse(manager.logs(request.GET.get('id', ''), request.GET.get('kind', 'access'), max(1, min(500, int(request.GET.get('lines', 150))))))
            if resource == 'audit':
                return JsonResponse({'events': list(AuditEvent.objects.filter(Q(server=server) | Q(server__isnull=True))[:100].values('created_at', 'actor', 'action', 'target', 'success', 'detail', 'server_id'))})
            return JsonResponse({'error': 'Неизвестный ресурс.'}, status=404)
        if resource == 'panel-tls':
            action = 'panel_tls_' + ('replace' if request.content_type == 'multipart/form-data' else 'renew')
            target = settings.SNC_SERVER
            if request.content_type == 'multipart/form-data':
                certificate = request.FILES.get('certificate')
                private_key = request.FILES.get('private_key')
                if certificate is None or private_key is None:
                    raise OperationError('Загрузите сертификат и приватный ключ в PEM.')
                if certificate.size > MAX_PEM_BYTES or private_key.size > MAX_PEM_BYTES:
                    raise OperationError('Каждый PEM-файл должен быть не больше 200 КБ.')
                result = replace_panel_certificate(certificate.read(), private_key.read())
                message = 'Сертификат панели заменён.'
            elif request.content_type == 'application/json':
                data = json.loads(request.body)
                if not isinstance(data, dict) or data.get('action') != 'renew':
                    raise OperationError('Неизвестное действие сертификата.')
                result = renew_panel_certificate()
                message = 'Self-signed сертификат панели перевыпущен.'
            else:
                return JsonResponse({'error': 'Ожидается JSON или PEM upload.'}, status=415)
            record(request, action, target)
            return JsonResponse({'ok': True, 'message': message, 'certificate': result})
        if request.content_type != 'application/json':
            return JsonResponse({'error': 'Ожидается JSON.'}, status=415)
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise OperationError('Ожидается JSON-объект.')
        if resource == 'servers':
            return JsonResponse(manage_servers(request, data))
        target = data.get('id', '')
        if resource == 'traffic-maintenance':
            action = data.get('action', '')
            target = server.host
            if action == 'set_page':
                if server.traffic_blocked:
                    raise OperationError('Сначала разблокируйте трафик, затем меняйте путь заглушки.')
                page_path = manager.validate_traffic_maintenance_page(data.get('page_path', ''))
                Server.objects.filter(pk=server.pk).update(maintenance_page_path=page_path)
                server.maintenance_page_path = page_path
                result = 'Путь к странице-заглушке сохранён.'
            elif action == 'toggle':
                enabled = data.get('enabled')
                if type(enabled) is not bool:
                    raise OperationError('Состояние блокировки должно быть true или false.')
                result = manager.set_traffic_maintenance(enabled, server.maintenance_page_path)
                Server.objects.filter(pk=server.pk).update(traffic_blocked=enabled)
                server.traffic_blocked = enabled
                action = 'traffic_block' if enabled else 'traffic_unblock'
            else:
                raise OperationError('Неизвестная операция блокировки трафика.')
        elif resource == 'two-factor':
            action = data.get('action', '')
            target = request.user.get_username()
            credential, _ = TwoFactorCredential.objects.get_or_create(user=request.user)
            if action == 'begin':
                if credential.enabled:
                    raise OperationError('Сначала отключите существующую двухфакторную защиту.')
                secret = generate_totp_secret()
                credential.set_secret(secret, pending=True)
                credential.save(update_fields=['encrypted_pending_secret', 'updated_at'])
                uri = provisioning_uri(secret, request.user.get_username())
                result = {'ok': True, 'secret': secret, 'qr_data_uri': qr_data_uri(uri)}
            elif action == 'enable':
                secret = credential.get_secret(pending=True)
                if not secret or not verify_totp(secret, data.get('code', '')):
                    raise OperationError('Код не совпал. Проверьте время на устройстве и попробуйте снова.')
                credential.set_secret(secret)
                credential.set_secret('', pending=True)
                credential.enabled = True
                credential.save(update_fields=['encrypted_secret', 'encrypted_pending_secret', 'enabled', 'updated_at'])
                result = 'Двухфакторная защита включена.'
            elif action == 'disable':
                secret = credential.get_secret()
                if not credential.enabled or not secret:
                    raise OperationError('Двухфакторная защита не подключена.')
                if not verify_totp(secret, data.get('code', '')):
                    raise OperationError('Неверный одноразовый код.')
                credential.enabled = False
                credential.set_secret('')
                credential.set_secret('', pending=True)
                credential.save(update_fields=['encrypted_secret', 'encrypted_pending_secret', 'enabled', 'updated_at'])
                result = 'Двухфакторная защита отключена.'
            elif action == 'cancel':
                credential.set_secret('', pending=True)
                credential.save(update_fields=['encrypted_pending_secret', 'updated_at'])
                result = 'Настройка двухфакторной защиты отменена.'
            else:
                raise OperationError('Неизвестное действие 2FA.')
        elif resource == 'hosts':
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
            service_settings = ServiceSetting.get_solo()
            updated_fields = []
            if 'log_retention_days' in data:
                retention_days = data['log_retention_days']
                if type(retention_days) is not int or not 1 <= retention_days <= 3650:
                    raise OperationError('Срок хранения должен быть целым числом от 1 до 3650 дней.')
                service_settings.log_retention_days = retention_days
                updated_fields.append('log_retention_days')
            if 'session_timeout_hours' in data:
                timeout_hours = data['session_timeout_hours']
                if type(timeout_hours) is not int or not 1 <= timeout_hours <= 720:
                    raise OperationError('Срок admin-сессии должен быть целым числом от 1 до 720 часов.')
                service_settings.session_timeout_hours = timeout_hours
                updated_fields.append('session_timeout_hours')
            if 'access_log_sample_bytes' in data:
                sample_size = data['access_log_sample_bytes']
                if type(sample_size) is not int or not 1 <= sample_size <= ACCESS_LOG_SAMPLE_MAX_BYTES:
                    raise OperationError('Размер выборки access log должен быть целым числом от 1 байта до 100 МБ.')
                service_settings.access_log_sample_bytes = sample_size
                updated_fields.append('access_log_sample_bytes')
            if not updated_fields:
                raise OperationError('Укажите настройку для сохранения.')
            service_settings.save(update_fields=[*updated_fields, 'updated_at'])
            if 'session_timeout_hours' in updated_fields:
                request.session.set_expiry(service_settings.session_timeout_hours * 3600)
            target = ','.join(updated_fields)
            result = 'Срок admin-сессии сохранён.' if updated_fields == ['session_timeout_hours'] else 'Срок хранения журналов сохранён.' if updated_fields == ['log_retention_days'] else 'Настройки сохранены.'
        else:
            return JsonResponse({'error': 'Неизвестный ресурс.'}, status=404)
        record(request, 'two_factor_' + action if resource == 'two-factor' else action, target, server=server)
        return JsonResponse(result if isinstance(result, dict) else {'ok': True, 'message': result})
    except (OperationError, ValueError, TypeError, AttributeError, OSError, UnicodeError, portalocker.exceptions.LockException) as error:
        if request.method == 'POST':
            record(request, str(action), target, False, str(error), server)
        return JsonResponse({'error': str(error)}, status=400)
    except Exception:
        logging.getLogger(__name__).exception('Panel request failed')
        return JsonResponse({'error': 'Внутренняя ошибка. Проверьте журнал SmallnGinxControl.'}, status=500)