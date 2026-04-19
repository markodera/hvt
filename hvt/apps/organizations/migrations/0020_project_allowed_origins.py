from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0019_project_frontend_url"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="allowed_origins",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Additional browser origins allowed to call runtime auth endpoints for this project. "
                    "Use full origins like https://app.example.com or http://localhost:3000."
                ),
            ),
        ),
    ]
