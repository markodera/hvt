# SPDX-License-Identifier: Apache-2.0
import hashlib
from django.db import migrations


def hash_existing_invitation_tokens(apps, schema_editor):
    conn = schema_editor.connection if schema_editor else migrations.connection
    with conn.cursor() as cursor:
        # Migrate pending organization invitations
        cursor.execute(
            "SELECT id, token FROM organization_invitations WHERE accepted_at IS NULL AND revoked_at IS NULL"
        )
        rows = cursor.fetchall()
        for inv_id, raw_token in rows:
            if raw_token:
                hashed = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                cursor.execute(
                    "UPDATE organization_invitations SET token = %s WHERE id = %s",
                    [hashed, inv_id],
                )

        # Migrate pending runtime invitations
        cursor.execute(
            "SELECT id, token FROM runtime_invitations WHERE status = 'pending'"
        )
        rows_rt = cursor.fetchall()
        for inv_id, raw_token in rows_rt:
            if raw_token:
                hashed = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                cursor.execute(
                    "UPDATE runtime_invitations SET token = %s WHERE id = %s",
                    [hashed, inv_id],
                )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0025_apikey_key_type"),
    ]

    operations = [
        migrations.RunPython(hash_existing_invitation_tokens, noop_reverse),
    ]
