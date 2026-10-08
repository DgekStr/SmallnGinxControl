import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import portalocker
import psutil
from django.conf import settings
from django.db import close_old_connections, connection
from django.db.models import Max
from django.utils import timezone

from .models import MetricSample, Server


def enable_sqlite_wal(db_connection=None):
    db_connection = connection if db_connection is None else db_connection
    if getattr(db_connection, 'vendor', 'sqlite') != 'sqlite':
        return False
    database_name = str(getattr(db_connection, 'settings_dict', {}).get('NAME', ''))
    if database_name == ':memory:' or 'mode=memory' in database_name:
        return False
    cursor = db_connection.cursor()
    try:
        cursor.execute('PRAGMA journal_mode=WAL')
        mode = cursor.fetchone()[0].lower()
    finally:
        cursor.close()
    return mode == 'wal'


def collect_completed(pending, previous, due, now):
    import logging

    logger = logging.getLogger(__name__)
    for identifier, future in list(pending.items()):
        if not future.done():
            continue
        try:
            previous[identifier], healthy = future.result()
        except Exception:
            logger.exception('Server metric collection failed for %s', identifier)
            previous.pop(identifier, None)
            due[identifier] = now + 30
        else:
            due[identifier] = now + (0 if healthy else 30)
        finally:
            pending.pop(identifier, None)


def sample_from_raw(raw, previous, now):
    cpu = rx_rate = tx_rate = 0
    if previous and raw['uptime'] >= previous[0]['uptime']:
        before, timestamp = previous
        elapsed = max(now - timestamp, .01)
        total = raw['cpu_total'] - before['cpu_total']
        idle = raw['cpu_idle'] - before['cpu_idle']
        cpu = max(0, min(100, (1 - idle / total) * 100)) if total > 0 else 0
        rx_rate = max(0, raw['rx_bytes'] - before['rx_bytes']) / elapsed / 1_000_000
        tx_rate = max(0, raw['tx_bytes'] - before['tx_bytes']) / elapsed / 1_000_000
    return dict(cpu=cpu, memory=raw['memory'], disk_used_bytes=raw.get('disk_used_bytes', 0), disk_total_bytes=raw.get('disk_total_bytes', 0), rx_rate=rx_rate, tx_rate=tx_rate, rx_mb=raw['rx_bytes'] / 1_000_000, tx_mb=raw['tx_bytes'] / 1_000_000, uptime=raw['uptime'])


def local_uptime():
    try:
        return float(Path('/proc/uptime').read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return time.time() - psutil.boot_time()


def local_raw(interface):
    counters = psutil.net_io_counters(pernic=True)
    if interface:
        counters = {interface: counters[interface]}
    else:
        counters = {name: value for name, value in counters.items() if name != 'lo' and not name.startswith(('veth', 'docker', 'br-', 'virbr'))}
    cpu = psutil.cpu_times()
    disk = psutil.disk_usage(Path(settings.BASE_DIR).anchor or '/')
    return dict(cpu_total=sum(cpu) - getattr(cpu, 'guest', 0) - getattr(cpu, 'guest_nice', 0), cpu_idle=cpu.idle + getattr(cpu, 'iowait', 0), memory=psutil.virtual_memory().percent, disk_used_bytes=disk.used, disk_total_bytes=disk.total, rx_bytes=sum(value.bytes_recv for value in counters.values()), tx_bytes=sum(value.bytes_sent for value in counters.values()), uptime=local_uptime())


def collect_server(server, previous):
    close_old_connections()
    try:
        now = time.monotonic()
        if server.mode == 'demo':
            offset = sum(server.pk.encode()) % 11
            phase = time.time() / 25 + offset
            sample = dict(cpu=18 + offset + math.sin(phase) * 7 + math.sin(phase * 3) * 3, memory=34.6 + offset, disk_used_bytes=320_000_000_000 + offset * 1_000_000_000, disk_total_bytes=512_000_000_000, rx_rate=3.2 + math.sin(phase * .7) * 1.6, tx_rate=1.4 + math.cos(phase) * .7, rx_mb=28416 + offset * 500 + phase % 400, tx_mb=12780 + phase % 200, uptime=(18 + offset) * 86400 + 7 * 3600 + now % 3600)
        else:
            if server.mode == 'ssh':
                from .servers import manager_for
                raw = manager_for(server).raw_metrics()
            else:
                raw = local_raw(server.interface)
            now = time.monotonic()
            sample = sample_from_raw(raw, previous, now)
            previous = (raw, now)
        if not Server.objects.filter(pk=server.pk, updated_at=server.updated_at).exists():
            return None, False
        MetricSample.objects.create(server=server, **sample)
        MetricSample.objects.filter(server=server, created_at__lt=timezone.now() - timedelta(hours=24)).delete()
        Server.objects.filter(pk=server.pk, updated_at=server.updated_at).update(last_seen=timezone.now(), last_error='')
        return previous, True
    except Exception as error:
        Server.objects.filter(pk=server.pk, updated_at=server.updated_at).update(last_error=str(error)[:500])
        return previous, False
    finally:
        close_old_connections()


def collect(stop):
    pending, previous, due, revisions = {}, {}, {}, {}
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='server-metrics') as pool:
        while not stop.is_set():
            close_old_connections()
            try:
                collect_completed(pending, previous, due, time.monotonic())
                servers = list(Server.objects.all())
                active = {server.pk for server in servers}
                for mapping in [previous, due, revisions]:
                    for identifier in set(mapping) - active:
                        mapping.pop(identifier, None)
                for server in servers:
                    if server.pk in pending or due.get(server.pk, 0) > time.monotonic():
                        continue
                    if revisions.get(server.pk) != server.updated_at:
                        previous.pop(server.pk, None)
                        revisions[server.pk] = server.updated_at
                    pending[server.pk] = pool.submit(collect_server, server, previous.get(server.pk))
            except Exception:
                import logging
                logging.getLogger(__name__).exception('Server metric scheduling failed')
            finally:
                close_old_connections()
            stop.wait(5)


def start_collector():
    lock = portalocker.Lock(str(settings.STATE_DIR / 'metrics.lock'), timeout=0)
    lock.acquire()
    try:
        enable_sqlite_wal()
    except Exception:
        lock.release()
        raise
    stop = threading.Event()
    thread = threading.Thread(target=collect, args=(stop,), name='metrics', daemon=True)
    thread.start()
    return stop, lock


def snapshot(server):
    cutoff = timezone.now() - timedelta(hours=24)
    samples = MetricSample.objects.filter(server=server, created_at__gte=cutoff)
    latest = samples.first()
    if latest is None:
        return {'current': None, 'history': [], 'peaks': {}, 'stale': True}
    peaks = samples.aggregate(cpu=Max('cpu'), rx=Max('rx_rate'), tx=Max('tx_rate'))
    history = list(samples.filter(created_at__gte=timezone.now() - timedelta(minutes=30)).order_by('id').values('created_at', 'cpu', 'rx_rate', 'tx_rate'))
    earliest = samples.order_by('id').first()
    return {
        'current': {field: getattr(latest, field) for field in ['cpu', 'memory', 'disk_used_bytes', 'disk_total_bytes', 'rx_rate', 'tx_rate', 'rx_mb', 'tx_mb', 'uptime', 'created_at']},
        'history': history, 'peaks': peaks, 'since': earliest.created_at,
        'stale': (timezone.now() - latest.created_at).total_seconds() > 20,
        'interface': server.interface or 'Физические интерфейсы',
    }