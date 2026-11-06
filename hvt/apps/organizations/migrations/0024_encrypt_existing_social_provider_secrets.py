# SPDX-License-Identifier: Apache-2.0
from django.db import migrations
from hvt.crypto import ENCRYPTION_VERSION_PREFIX, encrypt_value


def encrypt_existing_secrets(apps, schema_editor):
    SocialProviderConfig = apps.get_model("organizations", "SocialProviderConfig")
    for config in SocialProviderConfig.objects.all():
        raw_secret = config.client_secret
        if raw_secret and not raw_secret.startswith(ENCRYPTION_VERSION_PREFIX):
            config.client_secret = encrypt_value(raw_secret)
            config.save(update_fields=["client_secret"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0023_projectpermission_managed_by_projectrole_managed_by_and_more"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_secrets, noop_reverse),
    ]
