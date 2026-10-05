import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0007_server_traffic_maintenance')]

    operations = [
        migrations.AddField(
            model_name='servicesetting',
            name='access_log_sample_bytes',
            field=models.PositiveIntegerField(default=131072, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(100000000)]),
        ),
    ]