from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('panel', '0011_servicesetting_domain_expiry_monitored_domains')]

    operations = [
        migrations.AddField(
            model_name='servicesetting',
            name='nonpayment_contact_text',
            field=models.CharField(default='Свяжитесь с администратором хостинга', max_length=500),
        ),
    ]