# SPDX-License-Identifier: Apache-2.0
from django.db import connection as default_connection, migrations
from hvt.crypto import ENCRYPTION_VERSION_PREFIX, decrypt_value, encrypt_value


def encrypt_existing_secrets(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else default_connection
    SocialProviderConfig = apps.get_model("organizations", "SocialProviderConfig")
    table = SocialProviderConfig._meta.db_table
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT id, client_secret FROM {table}")
        rows = cursor.fetchall()
        for config_id, secret in rows:
            if secret and not secret.startswith(ENCRYPTION_VERSION_PREFIX):
                enc = encrypt_value(secret)
                cursor.execute(f"UPDATE {table} SET client_secret = %s WHERE id = %s", [enc, config_id])


def decrypt_existing_secrets(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else default_connection
    SocialProviderConfig = apps.get_model("organizations", "SocialProviderConfig")
    table = SocialProviderConfig._meta.db_table
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT id, client_secret FROM {table}")
        rows = cursor.fetchall()
        for config_id, secret in rows:
            if secret and secret.startswith(ENCRYPTION_VERSION_PREFIX):
                dec = decrypt_value(secret)
                cursor.execute(f"UPDATE {table} SET client_secret = %s WHERE id = %s", [dec, config_id])


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0023_projectpermission_managed_by_projectrole_managed_by_and_more"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_secrets, decrypt_existing_secrets),
    ]
