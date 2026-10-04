from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

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
        self.stdout.write(
            f'Host logs: rotated={result["rotated"]}, deleted={result["deleted"]}, retention_days={retention_days}'
        )