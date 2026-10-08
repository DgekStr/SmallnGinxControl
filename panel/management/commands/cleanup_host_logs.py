from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from panel.domain_expiry import refresh_due_expiries
from panel.log_retention import reopen_nginx, rotate_and_prune_host_logs
from panel.models import ServiceSetting
from panel.transactions import OperationError


class Command(BaseCommand):
    help = 'Rotate per-host nginx data logs and remove expired archives.'

    def handle(self, *args, **options):
        retention_days = ServiceSetting.get_solo().log_retention_days
        try:
            result = rotate_and_prune_host_logs(
                settings.NGINX_LOG_ROOT,
                retention_days,
                reopen=lambda: reopen_nginx(settings.NGINX_BIN),
            )
        except (OSError, OperationError) as error:
            raise CommandError(str(error)) from error
        try:
            domain_checks = refresh_due_expiries()
        except Exception as error:
            domain_checks = 0
            self.stderr.write(self.style.WARNING(f'Domain expiry checks failed: {error}'))
        self.stdout.write(
            f'Host logs: rotated={result["rotated"]}, deleted={result["deleted"]}, retention_days={retention_days}'
        )
        if domain_checks:
            self.stdout.write(f'Domain expiry checks completed: {domain_checks}')