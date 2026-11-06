# SPDX-License-Identifier: Apache-2.0
from django.db import connection as default_connection, migrations
from hvt.crypto import ENCRYPTION_VERSION_PREFIX, decrypt_value, encrypt_value


def encrypt_existing_totp_secrets(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else default_connection
    TOTPDevice = apps.get_model("authentication", "TOTPDevice")
    table = TOTPDevice._meta.db_table
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT id, secret FROM {table}")
        rows = cursor.fetchall()
        for device_id, secret in rows:
            if secret and not secret.startswith(ENCRYPTION_VERSION_PREFIX):
                enc = encrypt_value(secret)
                cursor.execute(f"UPDATE {table} SET secret = %s WHERE id = %s", [enc, device_id])


def decrypt_existing_totp_secrets(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else default_connection
    TOTPDevice = apps.get_model("authentication", "TOTPDevice")
    table = TOTPDevice._meta.db_table
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT id, secret FROM {table}")
        rows = cursor.fetchall()
        for device_id, secret in rows:
            if secret and secret.startswith(ENCRYPTION_VERSION_PREFIX):
                dec = decrypt_value(secret)
                cursor.execute(f"UPDATE {table} SET secret = %s WHERE id = %s", [dec, device_id])


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0013_alter_totpdevice_secret"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_totp_secrets, decrypt_existing_totp_secrets),
    ]
