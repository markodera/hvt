# SPDX-License-Identifier: Apache-2.0
"""
Tests for social account linking email verification requirements across all 6 providers:
Google, GitHub, Discord, Apple, Microsoft, GitLab.
"""

from unittest.mock import Mock
from django.test import TestCase
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model

from hvt.apps.authentication.adapters import CustomSocialAccountAdapter
from hvt.apps.organizations.models import Organization, APIKey

User = get_user_model()


class SocialLoginVerificationTests(TestCase):
    def setUp(self):
        self.adapter = CustomSocialAccountAdapter()
        self.user = User.objects.create_user(
            email="existing_user@example.com",
            password="StrongPassword123!",
        )

    def _make_sociallogin(self, provider, email="existing_user@example.com", verified=False, extra_data=None):
        sociallogin = Mock()
        sociallogin.is_existing = False
        sociallogin.provider = provider
        sociallogin.user = Mock(email=email)
        
        email_addr = Mock(email=email, verified=verified)
        sociallogin.email_addresses = [email_addr]
        
        account = Mock()
        account.provider = provider
        account.extra_data = extra_data or {}
        account.user = None
        sociallogin.account = account
        return sociallogin

    def _make_request(self, api_key=None):
        request = Mock()
        request.auth = api_key
        return request

    # -------------------------------------------------------------------------
    # 1. Google
    # -------------------------------------------------------------------------
    def test_google_verified_email_links_successfully(self):
        req = self._make_request()
        # Case A: verified in email_addresses
        sociallogin = self._make_sociallogin("google", verified=True)
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

        # Case B: verified in extra_data
        sociallogin2 = self._make_sociallogin("google", verified=False, extra_data={"email_verified": True})
        self.adapter.pre_social_login(req, sociallogin2)
        self.assertEqual(sociallogin2.user, self.user)

    def test_google_unverified_email_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("google", verified=False, extra_data={"email_verified": False})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 2. GitHub
    # -------------------------------------------------------------------------
    def test_github_verified_email_links_successfully(self):
        req = self._make_request()
        # Case A: verified in email_addresses
        sociallogin = self._make_sociallogin("github", verified=True)
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

        # Case B: verified in extra_data emails list
        extra = {"emails": [{"email": "existing_user@example.com", "verified": True}]}
        sociallogin2 = self._make_sociallogin("github", verified=False, extra_data=extra)
        self.adapter.pre_social_login(req, sociallogin2)
        self.assertEqual(sociallogin2.user, self.user)

    def test_github_unverified_email_refuses_linking(self):
        req = self._make_request()
        extra = {"emails": [{"email": "existing_user@example.com", "verified": False}]}
        sociallogin = self._make_sociallogin("github", verified=False, extra_data=extra)
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 3. Discord
    # -------------------------------------------------------------------------
    def test_discord_verified_email_links_successfully(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("discord", verified=False, extra_data={"verified": True})
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

    def test_discord_unverified_email_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("discord", verified=False, extra_data={"verified": False})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 4. Apple
    # -------------------------------------------------------------------------
    def test_apple_verified_email_links_successfully(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("apple", verified=False, extra_data={"email_verified": "true"})
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

    def test_apple_unverified_email_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("apple", verified=False, extra_data={"email_verified": "false"})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Microsoft
    # -------------------------------------------------------------------------
    def test_microsoft_verified_email_links_successfully(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("microsoft", verified=True)
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

    def test_microsoft_unverified_email_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("microsoft", verified=False, extra_data={})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 6. GitLab
    # -------------------------------------------------------------------------
    def test_gitlab_verified_email_links_successfully(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin(
            "gitlab",
            verified=False,
            extra_data={"confirmed_at": "2026-11-06T12:00:00.000Z"}
        )
        self.adapter.pre_social_login(req, sociallogin)
        self.assertEqual(sociallogin.user, self.user)

    def test_gitlab_unverified_email_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("gitlab", verified=False, extra_data={"confirmed_at": None})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Unstated / Missing verification
    # -------------------------------------------------------------------------
    def test_provider_does_not_say_refuses_linking(self):
        req = self._make_request()
        sociallogin = self._make_sociallogin("unknown_provider", verified=False, extra_data={})
        with self.assertRaises(ValidationError) as ctx:
            self.adapter.pre_social_login(req, sociallogin)
        self.assertIn("email is not verified by provider", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Runtime Plane Verification
    # -------------------------------------------------------------------------
    def test_runtime_plane_enforces_verification_on_linking(self):
        org = Organization.objects.create(name="Runtime Org", slug="runtime-org", owner=self.user)
        project = org.ensure_default_project()
        api_key = APIKey.objects.create(
            name="Runtime Key",
            organization=org,
            project=project,
            key_type=APIKey.KeyType.RUNTIME,
        )

        runtime_user = User.objects.create_user(
            email="runtime_target@example.com",
            password="StrongPassword123!",
            organization=org,
            project=project,
            role=User.Role.MEMBER,
        )

        req = self._make_request(api_key=api_key)

        # Unverified runtime social login fails
        sociallogin_unverified = self._make_sociallogin(
            "google",
            email="runtime_target@example.com",
            verified=False,
            extra_data={"email_verified": False},
        )
        with self.assertRaises(ValidationError):
            self.adapter.pre_social_login(req, sociallogin_unverified)

        # Verified runtime social login succeeds
        sociallogin_verified = self._make_sociallogin(
            "google",
            email="runtime_target@example.com",
            verified=True,
            extra_data={"email_verified": True},
        )
        self.adapter.pre_social_login(req, sociallogin_verified)
        self.assertEqual(sociallogin_verified.user, runtime_user)
