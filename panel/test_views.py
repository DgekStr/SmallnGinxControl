from urllib.parse import urlencode
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

import pyotp

from .models import ApiKey, AuditEvent, Server, ServiceSetting, TwoFactorCredential
from .two_factor import generate_totp_secret, provisioning_uri


class AuthenticationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('admin', password='12345', is_staff=True)

    def test_authentication_required(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.client.get('/api/hosts/').status_code, 401)
        self.assertEqual(self.client.get('/api/panel-tls/').status_code, 401)

    def test_login_password_change_logout(self):
        response = self.client.post('/login/', {'username': 'admin', 'password': '12345'})
        self.assertEqual(response.status_code, 302)
        self.assertLessEqual(self.client.session.get_expiry_age(), 24 * 60 * 60)
        response = self.client.post('/api/password/', {'old_password': '12345', 'new_password1': 'Different-secure-pass!42', 'new_password2': 'Different-secure-pass!42'}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AuditEvent.objects.filter(action='password_change').exists())
        self.assertEqual(self.client.post('/logout/').status_code, 302)
        self.assertFalse(self.client.login(username='admin', password='12345'))
        self.assertTrue(self.client.login(username='admin', password='Different-secure-pass!42'))

    def test_totp_challenge_blocks_login_until_valid_code(self):
        secret = generate_totp_secret()
        credential = TwoFactorCredential.objects.create(user=self.user)
        credential.set_secret(secret)
        credential.enabled = True
        credential.save()

        response = self.client.post('/login/', {'username': 'admin', 'password': '12345'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['two_factor_pending'])
        self.assertNotIn('_auth_user_id', self.client.session)

        valid_code = pyotp.TOTP(secret).now()
        invalid_code = '000000' if valid_code != '000000' else '000001'
        response = self.client.post('/login/', {'code': invalid_code})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('_auth_user_id', self.client.session)

        response = self.client.post('/login/', {'code': pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.user.pk)
        self.assertGreater(self.client.session.get_expiry_age(), 300)
        self.assertLessEqual(self.client.session.get_expiry_age(), 24 * 60 * 60)

    def test_two_factor_enrollment_encrypts_secret_and_requires_code(self):
        self.client.force_login(self.user)
        response = self.client.get('/api/two-factor/')
        self.assertEqual(response.json(), {'enabled': False})

        response = self.client.post('/api/two-factor/', {'action': 'begin'}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        secret = response.json()['secret']
        self.assertTrue(response.json()['qr_data_uri'].startswith('data:image/svg+xml;base64,'))
        self.assertTrue(provisioning_uri(secret, self.user.get_username()).startswith('otpauth://totp/'))
        credential = TwoFactorCredential.objects.get(user=self.user)
        self.assertNotIn(secret, credential.encrypted_pending_secret)
        self.assertEqual(credential.get_secret(pending=True), secret)

        valid_code = pyotp.TOTP(secret).now()
        invalid_code = '000000' if valid_code != '000000' else '000001'
        response = self.client.post('/api/two-factor/', {'action': 'enable', 'code': invalid_code}, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        credential.refresh_from_db()
        self.assertFalse(credential.enabled)

        response = self.client.post('/api/two-factor/', {'action': 'enable', 'code': pyotp.TOTP(secret).now()}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        credential.refresh_from_db()
        self.assertTrue(credential.enabled)
        self.assertNotIn(secret, credential.encrypted_secret)

        response = self.client.get('/api/two-factor/')
        self.assertEqual(response.json(), {'enabled': True})
        response = self.client.post('/api/two-factor/', {'action': 'disable', 'code': pyotp.TOTP(secret).now()}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        credential.refresh_from_db()
        self.assertFalse(credential.enabled)
        self.assertEqual(credential.encrypted_secret, '')

    def test_weak_password_rejected(self):
        self.client.force_login(self.user)
        response = self.client.post('/api/password/', {'old_password': '12345', 'new_password1': '12345', 'new_password2': '12345'}, content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_csrf_is_enforced(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post('/api/service/', {'action': 'restart'}, content_type='application/json').status_code, 403)
        self.assertEqual(client.post('/api/panel-tls/', {'action': 'renew'}, content_type='application/json').status_code, 403)

    def test_non_staff_is_rejected(self):
        user = get_user_model().objects.create_user('viewer', password='test')
        self.client.force_login(user)
        self.assertEqual(self.client.get('/api/hosts/').status_code, 403)

    def test_traffic_top_endpoint_is_authenticated_and_returns_ranked_items(self):
        self.client.force_login(self.user)
        ranked = {'items': [{'name': 'busy.test', 'kind': 'proxy', 'bytes': 4096}], 'sample_bytes_per_log': 128 * 1024}
        with patch('panel.views.manager_for') as manager_for:
            manager_for.return_value.traffic_top.return_value = ranked
            response = self.client.get('/api/traffic/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ranked)
        manager_for.return_value.traffic_top.assert_called_once_with(sample_size=128 * 1024)

    def test_log_retention_setting_is_persisted_and_validated(self):
        self.client.force_login(self.user)
        response = self.client.get('/api/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['log_retention_days'], 30)
        self.assertEqual(response.json()['session_timeout_hours'], 24)
        self.assertEqual(response.json()['access_log_sample_bytes'], 128 * 1024)
        self.assertEqual(response.json()['nonpayment_contact_text'], 'Свяжитесь с администратором хостинга')
        response = self.client.post('/api/settings/', {'log_retention_days': 45}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/api/settings/').json()['log_retention_days'], 45)
        response = self.client.post('/api/settings/', {'log_retention_days': 0}, content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_nonpayment_contact_text_is_persisted_and_applied_to_host_managers(self):
        self.client.force_login(self.user)
        with patch('panel.views.manager_for') as manager_for:
            response = self.client.post('/api/settings/', {'nonpayment_contact_text': 'Напишите администратору'}, content_type='application/json')

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.client.get('/api/settings/').json()['nonpayment_contact_text'], 'Напишите администратору')
        manager_for.return_value.update_nonpayment_contact.assert_called_once_with('Напишите администратору')

        for invalid in ['', ' ' * 3, 'x' * 501, 'контакт\x00']:
            with self.subTest(invalid=invalid):
                response = self.client.post('/api/settings/', {'nonpayment_contact_text': invalid}, content_type='application/json')
                self.assertEqual(response.status_code, 400)

    def test_access_log_sample_size_is_persisted_and_cannot_exceed_100_mb(self):
        self.client.force_login(self.user)
        maximum = 100_000_000
        response = self.client.post('/api/settings/', {'access_log_sample_bytes': maximum}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.client.get('/api/settings/').json()['access_log_sample_bytes'], maximum)
        self.assertEqual(ServiceSetting.get_solo().access_log_sample_bytes, maximum)
        for invalid in (0, maximum + 1, True, 1.5):
            with self.subTest(invalid=invalid):
                response = self.client.post('/api/settings/', {'access_log_sample_bytes': invalid}, content_type='application/json')
                self.assertEqual(response.status_code, 400)

    def test_mattermost_webhook_is_encrypted_and_never_returned_by_settings_api(self):
        self.client.force_login(self.user)
        webhook_url = 'https://mattermost.example/hooks/private-token'

        response = self.client.post('/api/settings/', {'mattermost_webhook_url': webhook_url}, content_type='application/json')

        self.assertEqual(response.status_code, 200, response.content)
        service_settings = ServiceSetting.get_solo()
        self.assertNotEqual(service_settings.encrypted_mattermost_webhook_url, webhook_url)
        self.assertEqual(service_settings.get_mattermost_webhook_url(), webhook_url)
        settings_response = self.client.get('/api/settings/')
        self.assertTrue(settings_response.json()['mattermost_webhook_configured'])
        self.assertNotIn('mattermost_webhook_url', settings_response.json())
        self.assertNotIn(webhook_url, settings_response.content.decode())

    @patch('panel.views.send_webhook_message')
    def test_mattermost_test_action_sends_without_saving_unsaved_url(self, send):
        self.client.force_login(self.user)
        webhook_url = 'https://mattermost.example/hooks/test-token'

        response = self.client.post('/api/settings/', {'action': 'test_mattermost_webhook', 'mattermost_webhook_url': webhook_url}, content_type='application/json')

        self.assertEqual(response.status_code, 200, response.content)
        send.assert_called_once_with(webhook_url, 'Проверочное сообщение от SmallnGinxControl.')
        self.assertFalse(ServiceSetting.get_solo().encrypted_mattermost_webhook_url)

    @override_settings(SNC_MODE='local')
    def test_domain_expiry_scheduler_requires_webhook_and_validates_schedule(self):
        self.client.force_login(self.user)
        response = self.client.post('/api/settings/', {'domain_expiry_scheduler_enabled': True}, content_type='application/json')
        self.assertEqual(response.status_code, 400)

        response = self.client.post('/api/settings/', {
            'mattermost_webhook_url': 'https://mattermost.example/hooks/token',
            'domain_expiry_scheduler_enabled': True,
            'domain_expiry_interval_days': 7,
            'domain_expiry_send_time': '08:30',
        }, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        service_settings = ServiceSetting.get_solo()
        self.assertTrue(service_settings.domain_expiry_scheduler_enabled)
        self.assertEqual(service_settings.domain_expiry_interval_days, 7)
        self.assertEqual(service_settings.domain_expiry_send_time.strftime('%H:%M'), '08:30')

        response = self.client.post('/api/settings/', {'domain_expiry_interval_days': 366}, content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_traffic_maintenance_path_and_state_are_server_scoped(self):
        self.client.force_login(self.user)
        server = Server.objects.get(pk='local')
        manager = __import__('unittest').mock.Mock()
        manager.validate_traffic_maintenance_page.return_value = '/var/www/custom.html'
        manager.set_traffic_maintenance.return_value = {'message': 'Блокировка включена.', 'files': 3, 'excluded_management_hosts': ['panel.test']}
        with patch('panel.views.manager_for', return_value=manager):
            response = self.client.get('/api/traffic-maintenance/', {'server': 'local'})
            self.assertEqual(response.json(), {'enabled': False, 'page_path': '/var/www/html/maitenance.html'})
            url = '/api/traffic-maintenance/?' + urlencode({'server': 'local', 'server_revision': server.updated_at.isoformat()})
            response = self.client.post(url, {'action': 'set_page', 'page_path': '/var/www/custom.html'}, content_type='application/json')
            self.assertEqual(response.status_code, 200, response.content)
            server.refresh_from_db()
            self.assertEqual(server.maintenance_page_path, '/var/www/custom.html')
            original_revision = server.updated_at.isoformat()
            url = '/api/traffic-maintenance/?' + urlencode({'server': 'local', 'server_revision': server.updated_at.isoformat()})
            response = self.client.post(url, {'action': 'toggle', 'enabled': True}, content_type='application/json')
            self.assertEqual(response.status_code, 200, response.content)
            server.refresh_from_db()
            self.assertTrue(server.traffic_blocked)
            self.assertEqual(server.updated_at.isoformat(), original_revision)
            response = self.client.post(url, {'action': 'toggle', 'enabled': False}, content_type='application/json')
            self.assertEqual(response.status_code, 200, response.content)
            server.refresh_from_db()
            self.assertFalse(server.traffic_blocked)

    def test_session_timeout_hours_are_validated_and_apply_to_current_session(self):
        self.client.force_login(self.user)
        response = self.client.post('/api/settings/', {'session_timeout_hours': 36}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/api/settings/').json()['session_timeout_hours'], 36)
        self.assertLessEqual(self.client.session.get_expiry_age(), 36 * 60 * 60)
        for invalid in [0, 721, True, 1.5]:
            with self.subTest(invalid=invalid):
                response = self.client.post('/api/settings/', {'session_timeout_hours': invalid}, content_type='application/json')
                self.assertEqual(response.status_code, 400)

    def test_service_requires_post_and_explicit_confirmation(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get('/api/service/').status_code, 404)
        response = self.client.post('/api/service/', {'action': 'restart'}, content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_login_rate_limit(self):
        for attempt in range(5):
            self.client.post('/login/', {'username': 'admin', 'password': 'wrong'})
        response = self.client.post('/login/', {'username': 'admin', 'password': '12345'})
        self.assertEqual(response.status_code, 429)


class ApiKeyTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('integration-admin', password='test-password', is_staff=True)
        self.client.force_login(self.user)

    def generate(self, read_only=True):
        response = self.client.post('/api/api-key/', {'action': 'generate', 'read_only': read_only}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['key']

    def bearer_client(self, key):
        return Client(enforce_csrf_checks=True, HTTP_AUTHORIZATION='Bearer ' + key)

    def test_generation_hashes_secret_and_never_returns_it_in_status_or_audit(self):
        key = self.generate()
        credential = ApiKey.objects.get(user=self.user)
        self.assertTrue(credential.read_only)
        self.assertEqual(len(credential.key_hash), 64)
        self.assertNotIn(key, credential.key_hash)
        self.assertEqual(credential.prefix, key[:12])
        response = self.client.get('/api/api-key/')
        self.assertTrue(response.json()['enabled'])
        self.assertNotIn('key', response.json())
        self.assertNotIn(key, response.content.decode())
        self.assertNotIn(key, repr(list(AuditEvent.objects.values())))
        self.assertIn('no-store', response['Cache-Control'])

    def test_bearer_authenticates_without_session_and_tracks_usage(self):
        client = self.bearer_client(self.generate())
        response = client.get('/api/servers/')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', client.session)
        self.assertIsNotNone(ApiKey.objects.get(user=self.user).last_used_at)

    def test_read_only_key_cannot_write(self):
        client = self.bearer_client(self.generate())
        with patch('panel.views.manager_for') as manager_for:
            response = client.post('/api/service/', {'action': 'reload'}, content_type='application/json')
        self.assertEqual(response.status_code, 403)
        manager_for.assert_not_called()

    def test_write_key_supports_nonpayment_and_keeps_actor_and_revision_checks(self):
        client = self.bearer_client(self.generate(read_only=False))
        server = Server.objects.create(name='Integration demo', host='127.0.0.1', mode='demo', is_default=True)
        parameters = urlencode({'server': server.pk, 'server_revision': server.updated_at.isoformat()})
        with patch('panel.views.manager_for') as manager_for:
            manager_for.return_value.toggle_nonpayment.return_value = 'Disabled'
            response = client.post('/api/hosts/?' + parameters, {'action': 'nonpayment', 'id': 'billing.conf', 'enabled': True, 'revision': 'revision-1'}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        manager_for.return_value.toggle_nonpayment.assert_called_once_with('billing.conf', True, 'revision-1', ServiceSetting.get_solo().nonpayment_contact_text)
        self.assertEqual(AuditEvent.objects.get(action='nonpayment_block').actor, self.user.get_username())
        with patch('panel.views.manager_for') as manager_for:
            response = client.post('/api/hosts/?server=' + server.pk, {'action': 'nonpayment'}, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        manager_for.assert_not_called()

    def test_rotation_and_revocation_invalidate_old_keys(self):
        old_key = self.generate()
        new_key = self.generate()
        self.assertNotEqual(old_key, new_key)
        self.assertEqual(self.bearer_client(old_key).get('/api/servers/').status_code, 401)
        self.assertEqual(self.bearer_client(new_key).get('/api/servers/').status_code, 200)
        response = self.client.post('/api/api-key/', {'action': 'revoke'}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['enabled'])
        self.assertEqual(self.bearer_client(new_key).get('/api/servers/').status_code, 401)

    def test_rotation_acquires_write_lock_before_reading_existing_key(self):
        self.generate()
        with CaptureQueriesContext(connection) as queries:
            self.generate(read_only=False)
        key_queries = [query['sql'] for query in queries if 'panel_apikey' in query['sql'].lower()]
        self.assertTrue(key_queries)
        self.assertTrue(key_queries[0].startswith('UPDATE'), key_queries[0])
        self.assertFalse(ApiKey.objects.get(user=self.user).read_only)

    def test_sensitive_resources_are_session_only_even_for_write_keys(self):
        client = self.bearer_client(self.generate(read_only=False))
        for resource in ['api-key', 'password', 'two-factor', 'settings', 'panel-tls', 'panel-tls-download']:
            with self.subTest(resource=resource):
                self.assertEqual(client.get('/api/' + resource + '/').status_code, 403)
                self.assertEqual(client.post('/api/' + resource + '/', {'action': 'generate'}, content_type='application/json').status_code, 403)

    def test_invalid_header_never_falls_back_to_admin_session(self):
        self.generate()
        for authorization in ['Bearer wrong', 'Basic credentials', 'Bearer ' + 'a' * 1000]:
            with self.subTest(authorization=authorization):
                response = self.client.get('/api/servers/', HTTP_AUTHORIZATION=authorization)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response['WWW-Authenticate'], 'Bearer')

    def test_key_in_url_is_not_accepted(self):
        key = self.generate()
        response = Client().get('/api/servers/?api_key=' + key)
        self.assertEqual(response.status_code, 401)

    def test_disabled_or_demoted_owner_invalidates_key(self):
        client = self.bearer_client(self.generate())
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        self.assertEqual(client.get('/api/servers/').status_code, 401)
        self.user.is_active = True
        self.user.is_staff = False
        self.user.save(update_fields=['is_active', 'is_staff'])
        self.assertEqual(client.get('/api/servers/').status_code, 401)

    def test_key_management_preserves_session_csrf_protection(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post('/api/api-key/', {'action': 'generate'}, content_type='application/json').status_code, 403)
        client.get('/')
        response = client.post('/api/api-key/', {'action': 'generate'}, content_type='application/json', HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.post('/api/api-key/', {'action': 'revoke'}, content_type='application/json').status_code, 403)
        self.assertEqual(client.post('/api/settings/', {'log_retention_days': 12}, content_type='application/json').status_code, 403)

    def test_key_management_is_per_admin_and_validates_mode(self):
        key = self.generate()
        other_user = get_user_model().objects.create_user('other-admin', password='test-password', is_staff=True)
        self.client.force_login(other_user)
        self.assertFalse(self.client.get('/api/api-key/').json()['enabled'])
        self.assertEqual(self.client.post('/api/api-key/', {'action': 'revoke'}, content_type='application/json').status_code, 200)
        self.assertEqual(self.bearer_client(key).get('/api/servers/').status_code, 200)
        response = self.client.post('/api/api-key/', {'action': 'generate', 'read_only': 'false'}, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ApiKey.objects.filter(user=other_user).exists())


class PanelTlsApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('admin', password='12345', is_staff=True)
        self.client.force_login(self.user)

    def test_panel_tls_status_is_available_without_private_key(self):
        status = {'available': True, 'installed': True, 'self_signed': True, 'fingerprint': 'AA:BB'}
        with patch('panel.views.panel_tls_status', return_value=status):
            response = self.client.get('/api/panel-tls/')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), status)
        self.assertNotIn('private_key', response.json())

    def test_panel_tls_renewal_is_audited(self):
        status = {'available': True, 'installed': True, 'self_signed': True}
        with patch('panel.views.renew_panel_certificate', return_value=status) as renew:
            response = self.client.post('/api/panel-tls/', {'action': 'renew'}, content_type='application/json')

        self.assertEqual(response.status_code, 200, response.content)
        renew.assert_called_once_with()
        self.assertTrue(AuditEvent.objects.filter(action='panel_tls_renew', target='192.0.2.15', success=True).exists())

    def test_panel_certificate_pair_can_be_uploaded_as_multipart(self):
        certificate = b'-----BEGIN CERTIFICATE-----\ncertificate\n'
        private_key = b'-----BEGIN PRIVATE KEY-----\nprivate-key\n'
        with patch('panel.views.replace_panel_certificate', return_value={'installed': True}) as replace:
            response = self.client.post('/api/panel-tls/', {
                'certificate': SimpleUploadedFile('certificate.pem', certificate),
                'private_key': SimpleUploadedFile('private-key.pem', private_key),
            })

        self.assertEqual(response.status_code, 200, response.content)
        replace.assert_called_once_with(certificate, private_key)
        self.assertTrue(AuditEvent.objects.filter(action='panel_tls_replace', success=True).exists())

    def test_panel_certificate_upload_size_is_limited(self):
        oversized = b'x' * 200_001
        with patch('panel.views.replace_panel_certificate') as replace:
            response = self.client.post('/api/panel-tls/', {
                'certificate': SimpleUploadedFile('certificate.pem', oversized),
                'private_key': SimpleUploadedFile('private-key.pem', b'key'),
            })

        self.assertEqual(response.status_code, 400)
        replace.assert_not_called()


class DomainExpiryApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('admin', password='12345', is_staff=True)
        self.client.force_login(self.user)

    def test_hosts_api_adds_cached_expiry_without_blocking_on_whois(self):
        server = Server.objects.get(pk='local')
        Server.objects.filter(pk=server.pk).update(mode='local')
        item = {'id': 'conf.d/shop.conf', 'name': '*.www.dgek.ru', 'domains': ['*.www.dgek.ru'], 'kind': 'host'}
        original_items = [item]
        inventory = {'items': original_items, 'warnings': []}
        enriched = {**item, 'domain_expiry': [{'domain': 'dgek.ru', 'status': 'ready', 'expires_on': '2026-10-17', 'days': 9}]}

        with override_settings(SNC_MODE='local'), patch('panel.views.manager_for') as manager_for, patch('panel.views.enrich_inventory_domains', return_value=[enriched]) as enrich:
            manager_for.return_value.inventory.return_value = inventory
            response = self.client.get('/api/hosts/?server=local')

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['items'][0]['domain_expiry'][0]['domain'], 'dgek.ru')
        enrich.assert_called_once_with(original_items, check=True, force=False)

    def test_demo_inventory_skips_whois_lookups(self):
        server = Mock(mode='demo')
        with override_settings(SNC_MODE='local'), patch('panel.views.selected_server', return_value=server), patch('panel.views.manager_for') as manager_for, patch('panel.views.enrich_inventory_domains', return_value=[]) as enrich:
            manager_for.return_value.inventory.return_value = {'items': [], 'warnings': []}
            response = self.client.get('/api/hosts/?server=demo')

        self.assertEqual(response.status_code, 200)
        enrich.assert_called_once_with([], check=False, force=False)

    def test_ssh_inventory_can_force_domain_expiry_refresh_on_connection(self):
        server = Mock(mode='ssh')
        with override_settings(SNC_MODE='local'), patch('panel.views.selected_server', return_value=server), patch('panel.views.manager_for') as manager_for, patch('panel.views.enrich_inventory_domains', return_value=[]) as enrich:
            manager_for.return_value.inventory.return_value = {'items': [], 'warnings': []}
            response = self.client.get('/api/hosts/?server=remote&refresh_domains=1')

        self.assertEqual(response.status_code, 200)
        enrich.assert_called_once_with([], check=True, force=True)