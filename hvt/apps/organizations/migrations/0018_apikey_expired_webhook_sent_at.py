from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0017_organizationinvitation_app_roles_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="apikey",
            name="expired_webhook_sent_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

