import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('panel', '0004_metricsample_disk_usage'),
    ]

    operations = [
        migrations.CreateModel(
            name='TwoFactorCredential',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('encrypted_secret', models.TextField(blank=True, default='')),
                ('encrypted_pending_secret', models.TextField(blank=True, default='')),
                ('enabled', models.BooleanField(default=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='two_factor_credential', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]