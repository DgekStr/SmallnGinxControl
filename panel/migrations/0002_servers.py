from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.core.validators
import panel.models


def attach_existing_data(apps, schema_editor):
    server = apps.get_model('panel', 'Server').objects.create(
        id='local', name='Основной nginx', host=settings.SNC_SERVER,
        mode=settings.SNC_MODE, is_default=True, interface=settings.SNC_INTERFACE,
    )
    apps.get_model('panel', 'MetricSample').objects.update(server=server)
    apps.get_model('panel', 'AuditEvent').objects.exclude(action__in=['login', 'logout', 'password_change']).update(server=server)


class Migration(migrations.Migration):
    dependencies = [('panel', '0001_initial')]
    operations = [
        migrations.CreateModel(
            name='Server',
            fields=[
                ('id', models.CharField(default=panel.models.server_id, editable=False, max_length=32, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=80)),
                ('host', models.CharField(max_length=253)),
                ('mode', models.CharField(choices=[('demo', 'Demo'), ('local', 'Local'), ('ssh', 'SSH')], max_length=8)),
                ('is_default', models.BooleanField(default=False)),
                ('port', models.PositiveIntegerField(default=22, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(65535)])),
                ('username', models.CharField(default='root', max_length=64)),
                ('auth_method', models.CharField(choices=[('key', 'SSH key'), ('password', 'Password'), ('agent', 'SSH agent')], default='key', max_length=8)),
                ('key_path', models.CharField(blank=True, max_length=500)),
                ('fingerprint', models.CharField(blank=True, max_length=100)),
                ('encrypted_secret', models.TextField(blank=True)),
                ('nginx_root', models.CharField(default='/etc/nginx', max_length=500)),
                ('log_root', models.CharField(default='/var/log/nginx', max_length=500)),
                ('interface', models.CharField(blank=True, max_length=64)),
                ('last_seen', models.DateTimeField(blank=True, null=True)),
                ('last_error', models.CharField(blank=True, max_length=500)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'ordering': ['-is_default', 'name', 'id']},
        ),
        migrations.AddField(model_name='auditevent', name='server', field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='panel.server')),
        migrations.AddField(model_name='metricsample', name='server', field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='panel.server')),
        migrations.RunPython(attach_existing_data, migrations.RunPython.noop),
    ]