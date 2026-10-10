import ipaddress
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone as datetime_timezone

import tldextract
import whois
from django.db import DatabaseError, close_old_connections
from django.db.models import Q
from django.utils import timezone


logger = logging.getLogger(__name__)
CHECK_INTERVAL = timedelta(days=1)
STALE_CHECKING_AFTER = timedelta(minutes=15)
WHOIS_TIMEOUT_SECONDS = 8
LOCAL_SUFFIXES = {'arpa', 'example', 'internal', 'invalid', 'lan', 'local', 'localhost', 'onion', 'test'}
DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
PUBLIC_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='domain-expiry')
_in_flight = set()
_in_flight_futures = {}
_in_flight_lock = threading.RLock()


def registrable_domain(value):
    if not isinstance(value, str):
        return None
    candidate = value.strip().rstrip('.').lower()
    if candidate.startswith('*.'):
        candidate = candidate[2:]
    candidate = candidate.strip('[]')
    if not candidate or any(character.isspace() for character in candidate) or candidate.startswith(('~', '$')):
        return None
    try:
        candidate = candidate.encode('idna').decode('ascii')
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    if len(candidate) > 253 or any(not DOMAIN_LABEL.fullmatch(label) for label in candidate.split('.')):
        return None
    if candidate.split('.')[-1] in LOCAL_SUFFIXES:
        return None
    extracted = PUBLIC_SUFFIXES(candidate)
    domain = extracted.top_domain_under_public_suffix
    return domain.lower() if domain and extracted.suffix and not extracted.is_private else None


def parse_expiration(value):
    values = value if isinstance(value, (list, tuple, set)) else [value]
    dates = []
    for item in values:
        if isinstance(item, datetime):
            dates.append(item.date() if item.tzinfo is None else item.astimezone(datetime_timezone.utc).date())
        elif isinstance(item, date):
            dates.append(item)
    return min(dates) if dates else None


def lookup_expiration(domain):
    record = whois.whois(domain, timeout=WHOIS_TIMEOUT_SECONDS, quiet=True)
    return parse_expiration(record.get('expiration_date'))


def _complete_check(domain):
    close_old_connections()
    try:
        expires_on = lookup_expiration(domain)
        status = 'ready' if expires_on else 'unavailable'
    except Exception as error:
        logger.info('WHOIS expiry lookup failed for %s: %s', domain, error)
        expires_on, status = None, 'unavailable'
    try:
        from .models import DomainExpiry
        DomainExpiry.objects.filter(pk=domain).update(
            expires_on=expires_on,
            checked_at=timezone.now(),
            status=status,
        )
    finally:
        close_old_connections()


def _finish_check(future, domain):
    with _in_flight_lock:
        _in_flight.discard(domain)
        _in_flight_futures.pop(domain, None)


def schedule_due_checks(domains, *, force=False):
    from .models import DomainExpiry, ServiceSetting

    now = timezone.now()
    check_interval = CHECK_INTERVAL
    if not force:
        service_settings = ServiceSetting.objects.filter(pk=1).values('domain_expiry_scheduler_enabled', 'domain_expiry_interval_days').first()
        if service_settings and service_settings['domain_expiry_scheduler_enabled']:
            check_interval = timedelta(days=service_settings['domain_expiry_interval_days'])
    futures = []
    for domain in sorted(set(domains)):
        if not domain:
            continue
        with _in_flight_lock:
            if domain in _in_flight:
                continue
            DomainExpiry.objects.get_or_create(domain=domain)
            due = (
                Q(checked_at__isnull=True)
                | (Q(status='checking') & Q(checked_at__lte=now - STALE_CHECKING_AFTER))
                | (~Q(status='checking') & (Q() if force else Q(checked_at__lte=now - check_interval)))
            )
            if not DomainExpiry.objects.filter(pk=domain).filter(due).update(checked_at=now, status='checking'):
                continue
            _in_flight.add(domain)
            try:
                future = _executor.submit(_complete_check, domain)
            except Exception:
                _in_flight.discard(domain)
                DomainExpiry.objects.filter(pk=domain).update(checked_at=now, status='unavailable')
                logger.exception('Unable to queue WHOIS expiry lookup for %s', domain)
                continue
            _in_flight_futures[domain] = future
            future.add_done_callback(lambda completed, checked_domain=domain: _finish_check(completed, checked_domain))
            futures.append(future)
    return futures


def wait_for_domain_checks(domains):
    with _in_flight_lock:
        futures = [_in_flight_futures[domain] for domain in set(domains) if domain in _in_flight_futures]
    for future in futures:
        future.result()


def enrich_inventory_domains(items, *, check=True, force=False):
    from .models import DomainExpiry

    if not check:
        for item in items:
            item['domain_expiry'] = []
        return items
    roots_by_item = {}
    for index, item in enumerate(items):
        candidates = [*(item.get('domains') or []), item.get('name')]
        roots = sorted({root for candidate in candidates if (root := registrable_domain(candidate))})
        if roots:
            roots_by_item[index] = roots
    roots = {root for item_roots in roots_by_item.values() for root in item_roots}
    try:
        schedule_due_checks(roots, force=force)
        records = {record.domain: record for record in DomainExpiry.objects.filter(domain__in=roots)}
    except DatabaseError:
        logger.warning('Domain expiry cache unavailable; returning nginx inventory without registration dates', exc_info=True)
        records = {}
    today = timezone.localdate()
    for index, item in enumerate(items):
        item['domain_expiry'] = [
            {
                'domain': record.domain,
                'status': record.status,
                'expires_on': record.expires_on.isoformat() if record.expires_on else None,
                'days': (record.expires_on - today).days if record.expires_on else None,
            }
            for root in roots_by_item.get(index, [])
            if (record := records.get(root))
        ]
    return items


def refresh_due_expiries():
    from .models import DomainExpiry

    futures = schedule_due_checks(DomainExpiry.objects.values_list('domain', flat=True))
    for future in futures:
        future.result()
    return len(futures)


def collect_configured_domains():
    from .models import Server
    from .servers import manager_for

    domains = set()
    complete = True
    for server in Server.objects.exclude(mode='demo'):
        try:
            inventory = manager_for(server).inventory()
            for item in inventory.get('items', []):
                candidates = [*(item.get('domains') or []), item.get('name')]
                domains.update(root for candidate in candidates if (root := registrable_domain(candidate)))
        except Exception:
            complete = False
            logger.warning('Unable to read domains from server profile %s', server.pk, exc_info=True)
    return domains, complete


def run_expiry_scheduler():
    from .mattermost import send_webhook_message
    from .models import DomainExpiry, ServiceSetting

    service_settings = ServiceSetting.get_solo()
    if not service_settings.domain_expiry_scheduler_enabled:
        return {'checked': 0, 'notified': 0}

    now = timezone.now()
    check_due = (
        service_settings.domain_expiry_last_check_at is None
        or now - service_settings.domain_expiry_last_check_at >= timedelta(days=service_settings.domain_expiry_interval_days)
    )
    checked = 0
    monitored_domains = set(service_settings.domain_expiry_monitored_domains)
    if check_due:
        discovered_domains, complete = collect_configured_domains()
        if not complete:
            discovered_domains.update(monitored_domains)
        monitored_domains = discovered_domains
        schedule_due_checks(monitored_domains, force=True)
        wait_for_domain_checks(monitored_domains)
        service_settings.domain_expiry_monitored_domains = sorted(monitored_domains)
        service_settings.domain_expiry_last_check_at = timezone.now()
        service_settings.save(update_fields=['domain_expiry_monitored_domains', 'domain_expiry_last_check_at', 'updated_at'])
        checked = len(monitored_domains)

    if not monitored_domains:
        return {'checked': checked, 'notified': 0}
    local_now = timezone.localtime()
    if local_now.time().replace(second=0, microsecond=0) < service_settings.domain_expiry_send_time:
        return {'checked': checked, 'notified': 0}
    webhook_url = service_settings.get_mattermost_webhook_url()
    if not webhook_url:
        logger.error('Domain expiry scheduler is enabled without a Mattermost webhook.')
        return {'checked': checked, 'notified': 0}

    today = local_now.date()
    notification_cutoff = now - timedelta(days=1)
    expiring = list(
        DomainExpiry.objects.filter(
            domain__in=monitored_domains,
            status='ready',
            expires_on__lte=today + timedelta(days=9),
        )
        .filter(Q(last_notified_at__isnull=True) | Q(last_notified_at__lt=notification_cutoff))
        .order_by('expires_on', 'domain')
    )
    if not expiring:
        return {'checked': checked, 'notified': 0}

    lines = ['**Срок регистрации доменов менее 10 дней**']
    for record in expiring:
        days = (record.expires_on - today).days
        status = f'истёк {abs(days)} дн. назад' if days < 0 else f'осталось {days} дн.'
        lines.append(f'- `{record.domain}`: {record.expires_on:%Y-%m-%d}, {status}')
    send_webhook_message(webhook_url, '\n'.join(lines))
    DomainExpiry.objects.filter(pk__in=[record.pk for record in expiring]).update(last_notified_at=now)
    return {'checked': checked, 'notified': len(expiring)}