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


def schedule_due_checks(domains, *, force=False):
    from .models import DomainExpiry

    now = timezone.now()
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
                | (~Q(status='checking') & (Q() if force else Q(checked_at__lte=now - CHECK_INTERVAL)))
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
            future.add_done_callback(lambda completed, checked_domain=domain: _finish_check(completed, checked_domain))
            futures.append(future)
    return futures


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