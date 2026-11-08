from django.core.cache import cache
# SPDX-License-Identifier: Apache-2.0
"""
Tests for TOTP hardening:
1. EncryptedTextField secret at rest with v1: prefix and idempotent data backfill.
2. 10 single-use hashed backup codes generated on enable and shown once.
3. Backup codes accepted during TOTP login step (single-use).
4. Backup code regeneration endpoint requiring password re-authentication.
5. Audit-log events for backup code usage and regeneration.
"""

from unittest.mock import patch
import pyotp
from django.db import connection
from django.test import TestCase, override_settings
from rest_framework import status as http_status
from rest_framework.test import APITestCase, APIClient
from cryptography.fernet import Fernet

from hvt.crypto import ENCRYPTION_VERSION_PREFIX
from hvt.apps.authentication.models import AuditLog, TOTPDevice, TOTPBackupCode
from hvt.apps.authentication.totp_views import hash_backup_code
import importlib
migration_module = importlib.import_module("hvt.apps.authentication.migrations.0014_backfill_encrypted_totp_secrets")
encrypt_existing_totp_secrets = migration_module.encrypt_existing_totp_secrets
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.apps import apps

User = get_user_model()


class TOTPEncryptionAndBackfillTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email="totp_user@example.com", password="Password123!")

    def test_totp_secret_encrypted_at_rest_in_db(self):
        secret = "JBSWY3DPEHPK3PXP"
        device = TOTPDevice.objects.create(
            user=self.user,
            secret=secret,
            is_confirmed=True,
        )

        # Python object decrypts transparently
        self.assertEqual(device.secret, secret)

        # Raw DB value is encrypted with v1: prefix
        pk_val = device.id.hex if hasattr(device.id, "hex") else str(device.id)
        with connection.cursor() as cursor:
            cursor.execute("SELECT secret FROM auth_totp_devices WHERE id = %s", [pk_val])
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            raw_db_val = row[0]

        self.assertTrue(raw_db_val.startswith(ENCRYPTION_VERSION_PREFIX))
        self.assertNotEqual(raw_db_val, secret)

    def test_idempotent_data_backfill(self):
        raw_secret = "UNENCRYPTED_LEGACY_SECRET_12345"
        # Insert raw unencrypted secret directly
        device = TOTPDevice.objects.create(
            user=self.user,
            is_confirmed=True,
        )
        pk_val = device.id.hex if hasattr(device.id, "hex") else str(device.id)
        with connection.cursor() as cursor:
            cursor.execute("UPDATE auth_totp_devices SET secret = %s WHERE id = %s", [raw_secret, pk_val])

        # Verify raw DB value is currently unencrypted
        with connection.cursor() as cursor:
            cursor.execute("SELECT secret FROM auth_totp_devices WHERE id = %s", [pk_val])
            self.assertEqual(cursor.fetchone()[0], raw_secret)

        # Run migration backfill
        encrypt_existing_totp_secrets(apps, None)

        with connection.cursor() as cursor:
            cursor.execute("SELECT secret FROM auth_totp_devices WHERE id = %s", [pk_val])
            encrypted_val = cursor.fetchone()[0]

        self.assertTrue(encrypted_val.startswith(ENCRYPTION_VERSION_PREFIX))

        # Re-running backfill is idempotent (does not double-encrypt)
        encrypt_existing_totp_secrets(apps, None)
        with connection.cursor() as cursor:
            cursor.execute("SELECT secret FROM auth_totp_devices WHERE id = %s", [pk_val])
            self.assertEqual(cursor.fetchone()[0], encrypted_val)


class TOTPBackupCodesTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.password = "StrongPassword123!"
        self.user = User.objects.create_user(email="backup_user@example.com", password=self.password)
        EmailAddress.objects.create(user=self.user, email=self.user.email, verified=True, primary=True)
        self.client = APIClient()

    def _enable_totp(self):
        self.client.force_authenticate(user=self.user)
        # 1. Setup
        resp = self.client.post("/api/v1/auth/mfa/totp/setup/")
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        secret = resp.data["secret"]

        # 2. Verify and enable
        code = pyotp.TOTP(secret).now()
        resp = self.client.post("/api/v1/auth/mfa/totp/verify/", {"code": code})
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertTrue(resp.data["is_mfa_enabled"])
        self.assertIn("backup_codes", resp.data)
        self.assertEqual(len(resp.data["backup_codes"]), 10)
        self.client.force_authenticate(user=None)
        return resp.data["backup_codes"]

    def test_totp_enable_generates_ten_backup_codes_and_stores_only_hashes(self):
        raw_codes = self._enable_totp()
        device = TOTPDevice.objects.get(user=self.user)

        # Check database stores exactly 10 hashed codes
        codes_in_db = TOTPBackupCode.objects.filter(device=device)
        self.assertEqual(codes_in_db.count(), 10)

        # Verify only SHA-256 hashes are stored, not raw codes
        for code in codes_in_db:
            self.assertEqual(len(code.hashed_code), 64)
            self.assertNotIn(code.hashed_code, raw_codes)
            self.assertIsNone(code.used_at)

        # Verify each raw code matches its hash
        for raw in raw_codes:
            self.assertTrue(codes_in_db.filter(hashed_code=hash_backup_code(raw)).exists())

    def test_login_with_single_use_backup_code(self):
        raw_codes = self._enable_totp()
        backup_code = raw_codes[0]

        # Step 1: Login with password triggers MFA required
        resp = self.client.post("/api/v1/auth/login/", {"email": self.user.email, "password": self.password})
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertTrue(resp.data.get("mfa_required"))
        mfa_token = resp.data.get("mfa_token")

        # Step 2: Use backup code at TOTP login step
        resp = self.client.post("/api/v1/auth/mfa/totp/login/", {"mfa_token": mfa_token, "code": backup_code})
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)

        # Verify audit log
        self.assertTrue(
            AuditLog.objects.filter(
                actor_user=self.user,
                event_type=AuditLog.EventType.TOTP_BACKUP_CODE_USED
            ).exists()
        )

        # Verify backup code is marked as used
        device = TOTPDevice.objects.get(user=self.user)
        used_code_obj = device.backup_codes.get(hashed_code=hash_backup_code(backup_code))
        self.assertIsNotNone(used_code_obj.used_at)

        # Step 3: Reusing the same backup code must FAIL (single-use)
        resp2 = self.client.post("/api/v1/auth/login/", {"email": self.user.email, "password": self.password})
        mfa_token2 = resp2.data.get("mfa_token")
        fail_resp = self.client.post("/api/v1/auth/mfa/totp/login/", {"mfa_token": mfa_token2, "code": backup_code})
        self.assertEqual(fail_resp.status_code, http_status.HTTP_400_BAD_REQUEST)

    def test_direct_login_with_backup_code_in_login_endpoint(self):
        raw_codes = self._enable_totp()
        backup_code = raw_codes[1]

        # Login directly providing code = backup_code
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password, "code": backup_code}
        )
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertIn("access", resp.data)
        self.assertTrue(
            AuditLog.objects.filter(
                actor_user=self.user,
                event_type=AuditLog.EventType.TOTP_BACKUP_CODE_USED
            ).exists()
        )

    def test_regenerate_backup_codes_requires_fresh_reauth(self):
        old_raw_codes = self._enable_totp()
        self.client.force_authenticate(user=self.user)

        # Attempt regenerate with missing password -> 400
        resp = self.client.post("/api/v1/auth/mfa/totp/backup-codes/regenerate/", {})
        self.assertEqual(resp.status_code, http_status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data.get("code"), "invalid_password")

        # Attempt regenerate with wrong password -> 400
        resp = self.client.post("/api/v1/auth/mfa/totp/backup-codes/regenerate/", {"password": "WrongPassword"})
        self.assertEqual(resp.status_code, http_status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data.get("code"), "invalid_password")

        # Regenerate with correct password -> 200
        resp = self.client.post("/api/v1/auth/mfa/totp/backup-codes/regenerate/", {"password": self.password})
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        new_raw_codes = resp.data["backup_codes"]
        self.assertEqual(len(new_raw_codes), 10)
        self.assertNotEqual(old_raw_codes, new_raw_codes)

        # Verify audit log
        self.assertTrue(
            AuditLog.objects.filter(
                actor_user=self.user,
                event_type=AuditLog.EventType.TOTP_BACKUP_CODES_REGENERATED
            ).exists()
        )

        # Old codes should no longer exist or work
        self.client.force_authenticate(user=None)
        cache.clear()
        resp_login = self.client.post("/api/v1/auth/login/", {"email": self.user.email, "password": self.password})
        mfa_token = resp_login.data.get("mfa_token")

        fail_resp = self.client.post("/api/v1/auth/mfa/totp/login/", {"mfa_token": mfa_token, "code": old_raw_codes[0]})
        self.assertEqual(fail_resp.status_code, http_status.HTTP_400_BAD_REQUEST)

        # New code works
        success_resp = self.client.post("/api/v1/auth/mfa/totp/login/", {"mfa_token": mfa_token, "code": new_raw_codes[0]})
        self.assertEqual(success_resp.status_code, http_status.HTTP_200_OK)
