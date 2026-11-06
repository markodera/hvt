# SPDX-License-Identifier: Apache-2.0
from django.db import migrations
from hvt.crypto import ENCRYPTION_VERSION_PREFIX, encrypt_value


def encrypt_existing_totp_secrets(apps, schema_editor):
    TOTPDevice = apps.get_model("authentication", "TOTPDevice")
    for device in TOTPDevice.objects.all():
        raw_secret = device.secret
        if raw_secret and not raw_secret.startswith(ENCRYPTION_VERSION_PREFIX):
            device.secret = encrypt_value(raw_secret)
            device.save(update_fields=["secret"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0013_alter_totpdevice_secret"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_totp_secrets, noop_reverse),
    ]
