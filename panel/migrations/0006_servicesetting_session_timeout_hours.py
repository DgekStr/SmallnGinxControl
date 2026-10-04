import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0005_twofactorcredential')]

    operations = [
        migrations.AddField(
            model_name='servicesetting',
            name='session_timeout_hours',
            field=models.PositiveSmallIntegerField(default=24, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(720)]),
        ),
    ]