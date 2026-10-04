from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0003_service_settings')]

    operations = [
        migrations.AddField(
            model_name='metricsample',
            name='disk_used_bytes',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='metricsample',
            name='disk_total_bytes',
            field=models.PositiveBigIntegerField(default=0),
        ),
    ]