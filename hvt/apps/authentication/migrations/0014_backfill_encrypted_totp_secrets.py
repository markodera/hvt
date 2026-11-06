# SPDX-License-Identifier: Apache-2.0
from django.db import migrations, connection as default_connection
from hvt.crypto import ENCRYPTION_VERSION_PREFIX, encrypt_value


def encrypt_existing_totp_secrets(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else default_connection
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, secret FROM auth_totp_devices")
        rows = cursor.fetchall()
        for device_id, raw_secret in rows:
            if raw_secret and not raw_secret.startswith(ENCRYPTION_VERSION_PREFIX):
                encrypted = encrypt_value(raw_secret)
                cursor.execute(
                    "UPDATE auth_totp_devices SET secret = %s WHERE id = %s",
                    [encrypted, device_id],
                )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0013_totpdevice_encrypted_secret_and_backup_codes"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_totp_secrets, noop_reverse),
    ]
