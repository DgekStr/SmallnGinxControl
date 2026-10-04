import os
import re
import stat
import subprocess
from datetime import date, datetime, timedelta
from pathlib import Path

from .transactions import OperationError


ROTATED_LOG_PATTERN = re.compile(r'^.+-data\.log\.(\d{8})(?:-\d{6}(?:-\d+)?)?$')


def rotate_and_prune_host_logs(log_root, retention_days, *, today=None, reopen=None):
    if type(retention_days) is not int or not 1 <= retention_days <= 3650:
        raise OperationError('Срок хранения должен быть целым числом от 1 до 3650 дней.')
    root = Path(log_root).resolve()
    if not root.is_dir():
        return {'rotated': 0, 'deleted': 0}

    current_date = today or date.today()
    now = datetime.now()
    rotated = []
    active_logs = [path for path in root.glob('*-data.log') if path.is_file() and not path.is_symlink()]
    for path in active_logs:
        info = path.stat()
        if info.st_size <= 0:
            continue
        stem = f'{path.name}.{now:%Y%m%d-%H%M%S}'
        archive = path.with_name(stem)
        suffix = 1
        while archive.exists():
            archive = path.with_name(f'{stem}-{suffix}')
            suffix += 1
        os.replace(path, archive)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(info.st_mode))
            try:
                if hasattr(os, 'fchown'):
                    os.fchown(descriptor, info.st_uid, info.st_gid)
                os.fchmod(descriptor, stat.S_IMODE(info.st_mode))
            finally:
                os.close(descriptor)
        except Exception:
            path.unlink(missing_ok=True)
            os.replace(archive, path)
            raise
        rotated.append(archive)

    if rotated and reopen is not None:
        reopen()

    cutoff = current_date - timedelta(days=retention_days)
    deleted = 0
    for archive in root.glob('*-data.log.*'):
        if archive.is_symlink() or not archive.is_file():
            continue
        match = ROTATED_LOG_PATTERN.fullmatch(archive.name)
        if not match:
            continue
        archived_date = datetime.strptime(match.group(1), '%Y%m%d').date()
        if archived_date <= cutoff:
            archive.unlink()
            deleted += 1
    return {'rotated': len(rotated), 'deleted': deleted}


def reopen_nginx(nginx_bin='/usr/sbin/nginx'):
    try:
        result = subprocess.run([nginx_bin, '-s', 'reopen'], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperationError(f'Не удалось переоткрыть nginx logs: {error}') from error
    if result.returncode:
        message = (result.stdout + result.stderr).strip()
        raise OperationError('Не удалось переоткрыть nginx logs: ' + (message[:1500] or str(result.returncode)))