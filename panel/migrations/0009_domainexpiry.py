from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0008_servicesetting_access_log_sample_bytes')]

    operations = [
        migrations.CreateModel(
            name='DomainExpiry',
            fields=[
                ('domain', models.CharField(max_length=253, primary_key=True, serialize=False)),
                ('expires_on', models.DateField(blank=True, null=True)),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('checking', 'Checking'), ('ready', 'Ready'), ('unavailable', 'Unavailable')], default='pending', max_length=16)),
            ],
            options={'ordering': ['domain']},
        ),
    ]