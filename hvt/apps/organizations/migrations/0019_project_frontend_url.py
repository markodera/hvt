from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0018_apikey_expired_webhook_sent_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="frontend_url",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "Optional frontend base URL for this runtime app. "
                    "Used for project-scoped verification and password reset links."
                ),
                max_length=500,
            ),
        ),
    ]
