# SPDX-License-Identifier: Apache-2.0
"""
Tests for Item 5: Signup limbo prevention.
A failed verification email must not leave an unusable account.
Verifies atomic rollback on email delivery failure across control-plane and runtime registration,
allowing subsequent registration attempts with the same email to succeed.
"""

from unittest.mock import patch
from django.core.cache import cache
from rest_framework import status as http_status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress

from hvt.apps.organizations.models import Organization, Project, APIKey, WebhookDelivery

User = get_user_model()


class SignupLimboPreventionTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Test Corp", slug="test-corp")
        self.project = Project.objects.create(organization=self.org, name="Test App", slug="test-app")
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

    def test_control_plane_registration_rolls_back_on_email_failure(self):
        email = "limbo_control@example.com"
        payload = {
            "email": email,
            "password1": "SecurePass123!@",
            "password2": "SecurePass123!@",
        }

        # 1. Registration attempt while email sending fails
        with patch("hvt.apps.authentication.email.ResendEmailService.send", side_effect=RuntimeError("SMTP / Resend down")):
            resp = self.client.post("/api/v1/auth/register/", payload)
            self.assertEqual(resp.status_code, http_status.HTTP_400_BAD_REQUEST)
            self.assertIn("Verification email could not be sent", str(resp.data))

        # 2. Verify DB state: user was NOT left in limbo
        self.assertFalse(User.objects.filter(email=email).exists())
        self.assertFalse(EmailAddress.objects.filter(email=email).exists())

        # 3. Same email can register again immediately once email service recovers
        cache.clear()
        with patch("hvt.apps.authentication.email.ResendEmailService.send", return_value={"id": "msg_123"}):
            resp2 = self.client.post("/api/v1/auth/register/", payload)
            self.assertEqual(resp2.status_code, http_status.HTTP_201_CREATED)

        # 4. Verify user exists and is waiting for verification
        user = User.objects.get(email=email)
        self.assertTrue(EmailAddress.objects.filter(user=user, verified=False).exists())

    def test_runtime_registration_rolls_back_on_email_failure_and_prevents_spurious_webhooks(self):
        email = "limbo_runtime@example.com"
        payload = {
            "email": email,
            "password1": "SecurePass123!@",
            "password2": "SecurePass123!@",
        }

        # 1. Runtime registration attempt while email sending fails
        with patch("hvt.apps.authentication.email.ResendEmailService.send", side_effect=RuntimeError("Resend API down")):
            resp = self.client.post(
                "/api/v1/auth/runtime/register/",
                payload,
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp.status_code, http_status.HTTP_400_BAD_REQUEST)
            self.assertIn("Verification email could not be sent", str(resp.data))

        # 2. Verify DB state: no user created, no webhook triggered
        self.assertFalse(User.objects.filter(email=email).exists())
        self.assertEqual(WebhookDelivery.objects.count(), 0)

        # 3. Same email can register again successfully
        cache.clear()
        with patch("hvt.apps.authentication.email.ResendEmailService.send", return_value={"id": "msg_456"}):
            resp2 = self.client.post(
                "/api/v1/auth/runtime/register/",
                payload,
                HTTP_X_API_KEY=self.api_key_str,
            )
            self.assertEqual(resp2.status_code, http_status.HTTP_201_CREATED)

        # 4. Verify runtime user was cleanly registered
        user = User.objects.get(email=email)
        self.assertEqual(user.organization, self.org)
        self.assertEqual(user.project, self.project)
