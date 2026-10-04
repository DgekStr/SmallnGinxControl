from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0006_servicesetting_session_timeout_hours')]

    operations = [
        migrations.AddField(
            model_name='server',
            name='traffic_blocked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='server',
            name='maintenance_page_path',
            field=models.CharField(default='/var/www/html/maitenance.html', max_length=1000),
        ),
    ]