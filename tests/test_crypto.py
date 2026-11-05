# SPDX-License-Identifier: Apache-2.0
from django.test import TestCase, override_settings
from django.db import models
from cryptography.fernet import Fernet
from hvt.crypto import (
    ENCRYPTION_VERSION_PREFIX,
    encrypt_value,
    decrypt_value,
    check_encryption_keys,
    EncryptedTextField,
)
from hvt.apps.organizations.models import (
    Organization,
    Project,
    ProjectRole,
    ProjectPermission,
    SocialProviderConfig,
    UserProjectRole,
    ManagedBy,
)
from hvt.apps.users.models import User


class CryptoAndEncryptionFieldTests(TestCase):
    def setUp(self):
        self.key1 = Fernet.generate_key().decode()
        self.key2 = Fernet.generate_key().decode()

    def test_encrypt_and_decrypt_with_version_prefix(self):
        with override_settings(HVT_ENCRYPTION_KEYS=[self.key1]):
            plaintext = "super-secret-oauth-token-12345"
            encrypted = encrypt_value(plaintext)
            self.assertTrue(encrypted.startswith(ENCRYPTION_VERSION_PREFIX))
            self.assertNotEqual(encrypted, plaintext)

            decrypted = decrypt_value(encrypted)
            self.assertEqual(decrypted, plaintext)

    def test_legacy_plaintext_fallback(self):
        with override_settings(HVT_ENCRYPTION_KEYS=[self.key1]):
            legacy = "plain-unencrypted-secret"
            # Does not start with v1: -> returns as is
            decrypted = decrypt_value(legacy)
            self.assertEqual(decrypted, legacy)

    def test_multifernet_key_rotation(self):
        # Encrypt with key1 as primary
        with override_settings(HVT_ENCRYPTION_KEYS=[self.key1]):
            token = encrypt_value("rotate-me")

        # Now rotate keys: key2 is primary (first), key1 is retained for decryption
        with override_settings(HVT_ENCRYPTION_KEYS=[self.key2, self.key1]):
            decrypted = decrypt_value(token)
            self.assertEqual(decrypted, "rotate-me")

            # New encryption uses key2
            new_token = encrypt_value("new-data")
            self.assertEqual(decrypt_value(new_token), "new-data")

    def test_system_check_in_production(self):
        with override_settings(DEBUG=False, HVT_ENCRYPTION_KEYS=[]):
            errors = check_encryption_keys(None)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].id, "hvt.E001")

        with override_settings(DEBUG=False, HVT_ENCRYPTION_KEYS=[self.key1]):
            errors = check_encryption_keys(None)
            self.assertEqual(len(errors), 0)


class ManagedByAndProtectedRoleTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme Corp", slug="acme")
        self.project = Project.objects.create(organization=self.org, name="App", slug="app")
        self.user = User.objects.create_user(
            email="member@example.com",
            password="SecurePassword123!",
            organization=self.org,
        )

    def test_managed_by_default(self):
        perm = ProjectPermission.objects.create(project=self.project, slug="docs.read", name="Read Docs")
        role = ProjectRole.objects.create(project=self.project, slug="viewer", name="Viewer")
        social = SocialProviderConfig.objects.create(
            project=self.project,
            provider=SocialProviderConfig.Provider.GOOGLE,
            client_id="client-id-123",
            client_secret="my-client-secret",
        )
        self.assertEqual(perm.managed_by, ManagedBy.DASHBOARD)
        self.assertEqual(role.managed_by, ManagedBy.DASHBOARD)
        self.assertEqual(social.managed_by, ManagedBy.DASHBOARD)

        # In DB, social.client_secret is encrypted
        social.refresh_from_db()
        self.assertEqual(social.client_secret, "my-client-secret")

    def test_user_project_role_protect_on_delete(self):
        role = ProjectRole.objects.create(project=self.project, slug="admin-role", name="Admin")
        UserProjectRole.objects.create(user=self.user, role=role)

        # Attempting to delete the role while user is assigned must raise ProtectedError
        with self.assertRaises(models.ProtectedError):
            role.delete()

    def test_migration_0024_encrypt_existing_plaintext_secrets(self):
        import importlib
        from django.db import connection
        from django.apps import apps
        mig = importlib.import_module("hvt.apps.organizations.migrations.0024_encrypt_existing_social_provider_secrets")
        encrypt_existing_secrets = mig.encrypt_existing_secrets

        social = SocialProviderConfig.objects.create(
            project=self.project,
            provider=SocialProviderConfig.Provider.GITHUB,
            client_id="github-app-id",
            client_secret="initial-secret",
        )
        table = SocialProviderConfig._meta.db_table
        pk_val = social.id.hex if hasattr(social.id, "hex") else str(social.id)
        # Directly insert plaintext in the DB column simulating pre-0024 release state
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {table} SET client_secret = %s WHERE id = %s",
                ["unencrypted-pre-release-plaintext-secret", pk_val],
            )
        # Verify it is raw plaintext in the DB
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT client_secret FROM {table} WHERE id = %s", [pk_val])
            raw_val = cursor.fetchone()[0]
        self.assertEqual(raw_val, "unencrypted-pre-release-plaintext-secret")
        self.assertFalse(raw_val.startswith(ENCRYPTION_VERSION_PREFIX))

        # Run migration 0024
        encrypt_existing_secrets(apps, None)

        # DB column must now be encrypted with v1:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT client_secret FROM {table} WHERE id = %s", [pk_val])
            enc_val = cursor.fetchone()[0]
        self.assertTrue(enc_val.startswith(ENCRYPTION_VERSION_PREFIX))

        # Model field must transparently decrypt back to original plaintext
        social.refresh_from_db()
        self.assertEqual(social.client_secret, "unencrypted-pre-release-plaintext-secret")

