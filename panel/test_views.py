from urllib.parse import urlencode
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

import pyotp

from .models import AuditEvent, Server, TwoFactorCredential
from .two_factor import generate_totp_secret, provisioning_uri


class AuthenticationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('admin', password='12345', is_staff=True)

    def test_authentication_required(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.client.get('/api/hosts/').status_code, 401)

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

    def test_log_retention_setting_is_persisted_and_validated(self):
        self.client.force_login(self.user)
        response = self.client.get('/api/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['log_retention_days'], 30)
        self.assertEqual(response.json()['session_timeout_hours'], 24)
        response = self.client.post('/api/settings/', {'log_retention_days': 45}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/api/settings/').json()['log_retention_days'], 45)
        response = self.client.post('/api/settings/', {'log_retention_days': 0}, content_type='application/json')
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