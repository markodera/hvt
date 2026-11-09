# SPDX-License-Identifier: Apache-2.0
"""
Tests for Item 6: Anti-user enumeration across registration, login, and password reset.
Verifies identical status codes and messages regardless of account existence or verification status.
"""

from unittest.mock import patch
from django.core.cache import cache
from rest_framework import status as http_status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress

from hvt.apps.organizations.models import Organization, Project, APIKey

User = get_user_model()


class AntiUserEnumerationTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Acme Corp", slug="acme")
        self.project = Project.objects.create(organization=self.org, name="Acme App", slug="acme-app")
        rt_prefix, self.rt_raw, rt_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.RUNTIME
        )
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=rt_prefix,
            hashed_key=rt_hash,
            scopes=["auth:runtime"],
        )
        self.api_key_str = self.rt_raw

    # -------------------------------------------------------------------------
    # 1. Control Plane Tests
    # -------------------------------------------------------------------------

    def test_control_plane_registration_anti_enumeration(self):
        existing_email = "cp_existing@example.com"
        password = "SecurePassword123!"
        user = User.objects.create_user(email=existing_email, password=password)
        EmailAddress.objects.create(user=user, email=existing_email, verified=True, primary=True)

        new_email = "cp_new@example.com"
        reg_payload_new = {"email": new_email, "password1": password, "password2": password}
        reg_payload_existing = {"email": existing_email, "password1": password, "password2": password}

        # 1. Register new email
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m1"}) as mock_send:
            resp_new = self.client.post("/api/v1/auth/register/", reg_payload_new)
            self.assertEqual(resp_new.status_code, http_status.HTTP_201_CREATED)
            self.assertEqual(resp_new.data, {"detail": "Verification e-mail sent."})

        # 2. Register existing email
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m2"}) as mock_send_exist:
            resp_exist = self.client.post("/api/v1/auth/register/", reg_payload_existing)
            # Response must be completely identical
            self.assertEqual(resp_exist.status_code, resp_new.status_code)
            self.assertEqual(resp_exist.data, resp_new.data)
            # "Account already exists" email sent instead of error
            mock_send_exist.assert_called_once()
            call_kwargs = mock_send_exist.call_args.kwargs
            self.assertEqual(call_kwargs.get("to"), existing_email)
            self.assertIn("Account Already Exists", call_kwargs.get("subject", ""))

    def test_control_plane_login_anti_enumeration(self):
        verified_email = "cp_verified@example.com"
        unverified_email = "cp_unverified@example.com"
        nonexistent_email = "cp_nonexistent@example.com"
        password = "CorrectPassword123!"

        # Verified user
        user_v = User.objects.create_user(email=verified_email, password=password)
        EmailAddress.objects.create(user=user_v, email=verified_email, verified=True, primary=True)

        # Unverified user
        user_u = User.objects.create_user(email=unverified_email, password=password)
        EmailAddress.objects.create(user=user_u, email=unverified_email, verified=False, primary=True)

        # 1. Nonexistent email login
        cache.clear()
        resp_nonexistent = self.client.post("/api/v1/auth/login/", {"email": nonexistent_email, "password": password})
        self.assertEqual(resp_nonexistent.status_code, http_status.HTTP_400_BAD_REQUEST)

        # 2. Existing user, wrong password
        cache.clear()
        resp_wrong_pw = self.client.post("/api/v1/auth/login/", {"email": verified_email, "password": "WrongPassword!"})
        self.assertEqual(resp_wrong_pw.status_code, resp_nonexistent.status_code)
        self.assertEqual(resp_wrong_pw.data, resp_nonexistent.data)

        # 3. Existing user, correct password, but UNVERIFIED
        cache.clear()
        resp_unverified = self.client.post("/api/v1/auth/login/", {"email": unverified_email, "password": password})
        self.assertEqual(resp_unverified.status_code, resp_nonexistent.status_code)
        self.assertEqual(resp_unverified.data, resp_nonexistent.data)

    def test_control_plane_password_reset_anti_enumeration(self):
        user_email = "cp_reset_user@example.com"
        user = User.objects.create_user(email=user_email, password="Password123!")
        EmailAddress.objects.create(user=user, email=user_email, verified=True, primary=True)

        nonexistent_email = "cp_reset_nonexistent@example.com"

        # 1. Existing user
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m3"}):
            resp_exist = self.client.post("/api/v1/auth/password/reset/", {"email": user_email})
            self.assertEqual(resp_exist.status_code, http_status.HTTP_200_OK)

        # 2. Nonexistent user
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m4"}):
            resp_nonexist = self.client.post("/api/v1/auth/password/reset/", {"email": nonexistent_email})
            self.assertEqual(resp_nonexist.status_code, resp_exist.status_code)
            self.assertEqual(resp_nonexist.data, resp_exist.data)

    # -------------------------------------------------------------------------
    # 2. Runtime Plane Tests
    # -------------------------------------------------------------------------

    def test_runtime_registration_anti_enumeration(self):
        existing_email = "rt_existing@example.com"
        password = "SecurePassword123!"
        user = User.objects.create_user(
            email=existing_email, password=password, organization=self.org, project=self.project
        )
        EmailAddress.objects.create(user=user, email=existing_email, verified=True, primary=True)

        new_email = "rt_new@example.com"
        reg_payload_new = {"email": new_email, "password1": password, "password2": password}
        reg_payload_existing = {"email": existing_email, "password1": password, "password2": password}

        # 1. Register new email
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m5"}):
            resp_new = self.client.post(
                "/api/v1/auth/runtime/register/",
                reg_payload_new,
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp_new.status_code, http_status.HTTP_201_CREATED)
            self.assertEqual(resp_new.data, {"detail": "Verification e-mail sent."})

        # 2. Register existing email
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m6"}) as mock_send_exist:
            resp_exist = self.client.post(
                "/api/v1/auth/runtime/register/",
                reg_payload_existing,
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp_exist.status_code, resp_new.status_code)
            self.assertEqual(resp_exist.data, resp_new.data)
            mock_send_exist.assert_called_once()
            call_kwargs = mock_send_exist.call_args.kwargs
            self.assertEqual(call_kwargs.get("to"), existing_email)
            self.assertIn("Account Already Exists", call_kwargs.get("subject", ""))

    def test_runtime_login_anti_enumeration(self):
        verified_email = "rt_verified@example.com"
        unverified_email = "rt_unverified@example.com"
        foreign_email = "rt_foreign@example.com"
        nonexistent_email = "rt_nonexistent@example.com"
        password = "CorrectPassword123!"

        # Project user (verified)
        user_v = User.objects.create_user(
            email=verified_email, password=password, organization=self.org, project=self.project
        )
        EmailAddress.objects.create(user=user_v, email=verified_email, verified=True, primary=True)

        # Project user (unverified)
        user_u = User.objects.create_user(
            email=unverified_email, password=password, organization=self.org, project=self.project
        )
        EmailAddress.objects.create(user=user_u, email=unverified_email, verified=False, primary=True)

        # Foreign org user
        other_org = Organization.objects.create(name="Other Corp", slug="other-corp")
        user_f = User.objects.create_user(
            email=foreign_email, password=password, organization=other_org
        )
        EmailAddress.objects.create(user=user_f, email=foreign_email, verified=True, primary=True)

        # 1. Nonexistent email login
        cache.clear()
        resp_nonexist = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": nonexistent_email, "password": password},
            HTTP_X_API_KEY=self.api_key_str,
        )
        self.assertEqual(resp_nonexist.status_code, http_status.HTTP_400_BAD_REQUEST)

        # 2. Existing user, wrong password
        cache.clear()
        resp_wrong_pw = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": verified_email, "password": "WrongPassword!"},
            HTTP_X_API_KEY=self.api_key_str,
        )
        self.assertEqual(resp_wrong_pw.status_code, resp_nonexist.status_code)
        self.assertEqual(resp_wrong_pw.data, resp_nonexist.data)

        # 3. Existing user, correct password, but UNVERIFIED
        cache.clear()
        resp_unverified = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": unverified_email, "password": password},
            HTTP_X_API_KEY=self.api_key_str,
        )
        self.assertEqual(resp_unverified.status_code, resp_nonexist.status_code)
        self.assertEqual(resp_unverified.data, resp_nonexist.data)

        # 4. Foreign organization user
        cache.clear()
        resp_foreign = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": foreign_email, "password": password},
            HTTP_X_API_KEY=self.api_key_str,
        )
        self.assertEqual(resp_foreign.status_code, resp_nonexist.status_code)
        self.assertEqual(resp_foreign.data, resp_nonexist.data)

    def test_runtime_password_reset_anti_enumeration(self):
        user_email = "rt_reset_user@example.com"
        user = User.objects.create_user(
            email=user_email, password="Password123!", organization=self.org, project=self.project
        )
        EmailAddress.objects.create(user=user, email=user_email, verified=True, primary=True)

        nonexistent_email = "rt_reset_nonexistent@example.com"

        # 1. Existing user
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m7"}):
            resp_exist = self.client.post(
                "/api/v1/auth/runtime/password/reset/",
                {"email": user_email},
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp_exist.status_code, http_status.HTTP_200_OK)

        # 2. Nonexistent user
        cache.clear()
        with patch("hvt.apps.authentication.email_providers.ConsoleEmailProvider.send", return_value={"id": "m8"}):
            resp_nonexist = self.client.post(
                "/api/v1/auth/runtime/password/reset/",
                {"email": nonexistent_email},
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp_nonexist.status_code, resp_exist.status_code)
            self.assertEqual(resp_nonexist.data, resp_exist.data)
