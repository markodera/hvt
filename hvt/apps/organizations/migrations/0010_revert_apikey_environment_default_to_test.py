from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("organizations", "0009_change_apikey_environment_default"),
    ]

    operations = [
        migrations.AlterField(
            model_name="apikey",
            name="environment",
            field=models.CharField(
                choices=[("test", "Test"), ("live", "Live")],
                default="test",
                help_text="Test keys only access test data, live keys access production data",
                max_length=4,
            ),
        ),
    ]
