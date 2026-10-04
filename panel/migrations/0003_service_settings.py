from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):
    dependencies = [('panel', '0002_servers')]

    operations = [
        migrations.CreateModel(
            name='ServiceSetting',
            fields=[
                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ('log_retention_days', models.PositiveSmallIntegerField(default=30, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(3650)])),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]