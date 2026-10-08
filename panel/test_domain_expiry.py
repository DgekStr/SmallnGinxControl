from datetime import date, datetime, timedelta, timezone
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.db import OperationalError

from .domain_expiry import CHECK_INTERVAL, STALE_CHECKING_AFTER, enrich_inventory_domains, parse_expiration, registrable_domain, schedule_due_checks
from .models import DomainExpiry


class RegistrableDomainTests(SimpleTestCase):
    def test_wildcards_and_multilevel_suffixes_resolve_to_registration_root(self):
        self.assertEqual(registrable_domain('*.dgek.ru'), 'dgek.ru')
        self.assertEqual(registrable_domain('api.www.dgek.ru'), 'dgek.ru')
        self.assertEqual(registrable_domain('shop.example.co.uk'), 'example.co.uk')

    def test_ip_local_and_invalid_server_names_are_ignored(self):
        for value in ('192.0.2.1', '2001:db8::1', '[::1]', 'localhost', 'api.local', 'service.internal', 'demo.test', 'wiki.onion', 'tenant.github.io', '_', '~^.+$', '$host', 'singlelabel'):
            with self.subTest(value=value):
                self.assertIsNone(registrable_domain(value))

    def test_expiration_parser_handles_whois_datetime_lists_and_missing_data(self):
        aware = datetime(2027, 1, 27, 21, tzinfo=timezone.utc)
        self.assertEqual(parse_expiration([aware, datetime(2027, 2, 1)]), date(2027, 1, 27))
        self.assertIsNone(parse_expiration(None))


class DomainExpiryCacheTests(TestCase):
    def tearDown(self):
        from .domain_expiry import _in_flight, _in_flight_lock
        with _in_flight_lock:
            _in_flight.clear()

    @override_settings(SNC_MODE='local')
    @patch('panel.domain_expiry.schedule_due_checks', return_value=[])
    def test_inventory_attaches_cached_root_expiries_to_host(self, schedule):
        DomainExpiry.objects.create(domain='dgek.ru', expires_on=date(2026, 10, 17), checked_at=datetime.now(timezone.utc), status='ready')
        DomainExpiry.objects.create(domain='example.com', expires_on=date(2026, 11, 2), checked_at=datetime.now(timezone.utc), status='ready')
        items = [{'name': '*.www.dgek.ru', 'domains': ['*.www.dgek.ru', 'www.example.com']}]

        enriched = enrich_inventory_domains(items)

        expiries = {expiry['domain']: expiry for expiry in enriched[0]['domain_expiry']}
        self.assertEqual(set(expiries), {'dgek.ru', 'example.com'})
        self.assertEqual(expiries['dgek.ru']['days'], (date(2026, 10, 17) - datetime.now(timezone.utc).date()).days)
        schedule.assert_called_once()
        self.assertEqual(set(schedule.call_args.args[0]), {'dgek.ru', 'example.com'})

    def test_due_domain_is_queued_once_until_daily_interval(self):
        future = Mock()
        with patch('panel.domain_expiry._executor.submit', return_value=future) as submit:
            self.assertEqual(len(schedule_due_checks(['dgek.ru'])), 1)
            self.assertEqual(schedule_due_checks(['dgek.ru']), [])

        self.assertEqual(submit.call_count, 1)
        self.assertEqual(DomainExpiry.objects.get(pk='dgek.ru').status, 'checking')

    def test_ready_domain_is_rechecked_after_one_day(self):
        DomainExpiry.objects.create(domain='dgek.ru', expires_on=date(2027, 1, 27), checked_at=datetime.now(timezone.utc) - timedelta(hours=23), status='ready')
        with patch('panel.domain_expiry._executor.submit') as submit:
            self.assertEqual(schedule_due_checks(['dgek.ru']), [])
            submit.assert_not_called()

            DomainExpiry.objects.filter(pk='dgek.ru').update(checked_at=datetime.now(timezone.utc) - timedelta(days=1, seconds=1))
            schedule_due_checks(['dgek.ru'])

        submit.assert_called_once()

    def test_force_refresh_rechecks_cached_domain_but_not_active_lookup(self):
        DomainExpiry.objects.create(domain='dgek.ru', expires_on=date(2027, 1, 27), checked_at=datetime.now(timezone.utc), status='ready')
        future = Mock()
        with patch('panel.domain_expiry._executor.submit', return_value=future) as submit:
            self.assertEqual(len(schedule_due_checks(['dgek.ru'], force=True)), 1)
            self.assertEqual(schedule_due_checks(['dgek.ru'], force=True), [])

        submit.assert_called_once()

    def test_stale_checking_domain_is_retried_after_fifteen_minutes(self):
        DomainExpiry.objects.create(domain='dgek.ru', checked_at=datetime.now(timezone.utc) - timedelta(minutes=16), status='checking')
        with patch('panel.domain_expiry._executor.submit') as submit:
            self.assertEqual(len(schedule_due_checks(['dgek.ru'])), 1)

        submit.assert_called_once()

    def test_completed_lookup_is_cached_for_one_day(self):
        record = DomainExpiry.objects.create(domain='dgek.ru', expires_on=date(2027, 1, 27), checked_at=datetime.now(timezone.utc), status='ready')
        self.assertEqual(CHECK_INTERVAL, timedelta(days=1))
        self.assertEqual(STALE_CHECKING_AFTER, timedelta(minutes=15))
        with patch('panel.domain_expiry._executor.submit') as submit:
            self.assertEqual(schedule_due_checks(['dgek.ru']), [])
        submit.assert_not_called()

    def test_database_lock_does_not_hide_nginx_inventory(self):
        items = [{'name': 'shop.example.com', 'domains': ['shop.example.com']}]
        with patch('panel.domain_expiry.schedule_due_checks', side_effect=OperationalError('database is locked')):
            enriched = enrich_inventory_domains(items)

        self.assertEqual(enriched[0]['name'], 'shop.example.com')
        self.assertEqual(enriched[0]['domain_expiry'], [])