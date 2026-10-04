from django.core.management.base import BaseCommand

from panel.nginx import NginxManager


class Command(BaseCommand):
    help = 'Plan or enable per-host nginx access logs in <host>-data.log files.'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Write configs and reload nginx. Default is dry-run.')

    def handle(self, *args, **options):
        manager = NginxManager()
        result = manager.enable_host_logging(dry_run=not options['apply'])
        action = 'APPLIED' if options['apply'] else 'DRY RUN'
        self.stdout.write(f'{action}: {result["files"]} config files, {result["hosts"]} server blocks')
        for host in result['host_names']:
            self.stdout.write(f'  {host}')
        if not options['apply']:
            self.stdout.write('No files changed. Run with --apply to commit the plan.')