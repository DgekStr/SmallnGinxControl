from django.core.management.base import BaseCommand

from panel.domain_expiry import run_expiry_scheduler


class Command(BaseCommand):
    help = 'Refresh configured domain expiries and send scheduled Mattermost alerts.'

    def handle(self, *args, **options):
        result = run_expiry_scheduler()
        self.stdout.write(f"Domain expiry scheduler: checked={result['checked']}, notified={result['notified']}")