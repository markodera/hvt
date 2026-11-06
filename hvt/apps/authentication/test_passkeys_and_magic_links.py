import hashlib
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from hvt.apps.authentication.models import (
    AuditLog,
    MagicLinkToken,
    UserPasskeyCredential,
)
from hvt.apps.organizations.models import APIKey, Organization, Project, ProjectRole, UserProjectRole
from hvt.apps.users.models import User


class PasskeysAndMagicLinksTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.org = Organization.objects.create(name="Acme Corp", slug="acme")
        self.project = Project.objects.create(
            organization=self.org,
            name="Store App",
            slug="store",
            allow_signup=True,
            frontend_url="https://store.example.com",
        )
        prefix, full_key, hashed_key = APIKey.generate_key("test")
        self.raw_api_key = full_key
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Test Key",
            prefix=prefix,
            hashed_key=hashed_key,
            environment=APIKey.Environment.TEST,
            scopes=["auth:runtime"],
        )

        self.user = User.objects.create_user(
            email="owner@acme.com",
            password="SecurePassword123!",
            organization=self.org,
            role=User.Role.OWNER,
        )
        self.runtime_user = User.objects.create_user(
            email="shopper@customer.com",
            password="SecurePassword123!",
            organization=self.org,
            project=self.project,
            role=User.Role.MEMBER,
        )

    # -------------------------------------------------------------
    # Passwordless Magic Link Tests
    # -------------------------------------------------------------

    def test_control_plane_magic_link_request_and_verify(self):
        """Test control plane magic link request and single-use verification."""
        with patch("hvt.apps.authentication.magic_link_views.send_email_async") as mock_send:
            res = self.client.post("/api/v1/auth/magic-link/request/", {"email": "owner@acme.com"})
            self.assertEqual(res.status_code, status.HTTP_200_OK)
            self.assertTrue(mock_send.called)

        # Retrieve generated token from DB
        token_record = MagicLinkToken.objects.filter(user=self.user, project__isnull=True).first()
        self.assertIsNotNone(token_record)
        self.assertFalse(token_record.is_used)

        # Extract raw token from mock call
        call_args = mock_send.call_args
        html_content = call_args.kwargs.get("html_content") or call_args[1].get("html_content")
        import re
        match = re.search(r"token=([A-Za-z0-9_-]+)", html_content)
        self.assertIsNotNone(match)
        raw_token = match.group(1)

        # Verify token
        verify_res = self.client.post("/api/v1/auth/magic-link/verify/", {"token": raw_token})
        self.assertEqual(verify_res.status_code, status.HTTP_200_OK)
        self.assertIn("access", verify_res.data)
        self.assertIn("refresh", verify_res.data)

        # Confirm token is consumed and cannot be reused
        token_record.refresh_from_db()
        self.assertTrue(token_record.is_used)

        reuse_res = self.client.post("/api/v1/auth/magic-link/verify/", {"token": raw_token})
        self.assertEqual(reuse_res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_runtime_magic_link_request_and_verify(self):
        """Test API-key-scoped runtime magic link creation and verification."""
        with patch("hvt.apps.authentication.magic_link_views.send_email_async") as mock_send:
            res = self.client.post(
                "/api/v1/auth/runtime/magic-link/request/",
                {"email": "shopper@customer.com"},
                HTTP_X_API_KEY=self.raw_api_key,
            )
            self.assertEqual(res.status_code, status.HTTP_200_OK)
            self.assertTrue(mock_send.called)

        token_record = MagicLinkToken.objects.filter(user=self.runtime_user, project=self.project).first()
        self.assertIsNotNone(token_record)

        call_args = mock_send.call_args
        html_content = call_args.kwargs.get("html_content") or call_args[1].get("html_content")
        import re
        match = re.search(r"token=([A-Za-z0-9_-]+)", html_content)
        raw_token = match.group(1)

        verify_res = self.client.post(
            "/api/v1/auth/runtime/magic-link/verify/",
            {"token": raw_token},
            HTTP_X_API_KEY=self.raw_api_key,
        )
        self.assertEqual(verify_res.status_code, status.HTTP_200_OK)
        self.assertIn("access", verify_res.data)

    def test_expired_magic_link_rejected(self):
        """Test that tokens older than 15 minutes are rejected."""
        raw_token = "some_sample_token_value_here_12345"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        MagicLinkToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() - timedelta(minutes=1),
            is_used=False,
        )

        res = self.client.post("/api/v1/auth/magic-link/verify/", {"token": raw_token})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    # -------------------------------------------------------------
    # Passkeys / WebAuthn Tests
    # -------------------------------------------------------------

    def test_passkey_register_options_control_plane(self):
        """Test generating WebAuthn registration options for authenticated user."""
        self.client.force_authenticate(user=self.user)
        res = self.client.post("/api/v1/auth/passkey/register/options/")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("challenge", res.data)
        self.assertIn("rp", res.data)
        self.assertIn("user", res.data)

    def test_passkey_auth_options_control_plane(self):
        """Test generating WebAuthn authentication options for login."""
        res = self.client.post("/api/v1/auth/passkey/authenticate/options/", {"email": "owner@acme.com"})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("challenge", res.data)
        self.assertIn("challenge_key", res.data)

    def test_passkey_credential_management(self):
        """Test listing and deleting user passkeys."""
        cred = UserPasskeyCredential.objects.create(
            user=self.user,
            name="MacBook Pro Touch ID",
            credential_id="test_cred_id_12345",
            public_key="test_public_key_b64",
            sign_count=0,
        )
        self.client.force_authenticate(user=self.user)

        # List passkeys
        list_res = self.client.get("/api/v1/auth/passkey/credentials/")
        self.assertEqual(list_res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_res.data["passkeys"]), 1)
        self.assertEqual(list_res.data["passkeys"][0]["name"], "MacBook Pro Touch ID")

        # Delete passkey
        del_res = self.client.delete(f"/api/v1/auth/passkey/credentials/{cred.id}/")
        self.assertEqual(del_res.status_code, status.HTTP_200_OK)
        self.assertFalse(UserPasskeyCredential.objects.filter(id=cred.id).exists())

    def test_runtime_passkey_options(self):
        """Test runtime API-key-scoped passkey challenge generation."""
        res = self.client.post(
            "/api/v1/auth/runtime/passkey/authenticate/options/",
            {"email": "shopper@customer.com"},
            HTTP_X_API_KEY=self.raw_api_key,
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("challenge", res.data)
        self.assertIn("challenge_key", res.data)

    def test_runtime_magic_link_verify_requires_auth_runtime_scope(self):
        """Verify runtime magic link endpoints reject API keys lacking auth:runtime."""
        scoped_prefix, scoped_raw, scoped_hash = APIKey.generate_key("test")
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Restricted Scope Key",
            prefix=scoped_prefix,
            hashed_key=scoped_hash,
            environment=APIKey.Environment.TEST,
            scopes=["users:read"],
        )

        res = self.client.post(
            "/api/v1/auth/runtime/magic-link/verify/",
            {"token": "dummy_token"},
            HTTP_X_API_KEY=scoped_raw,
        )
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("auth:runtime", str(res.data))

    def test_runtime_magic_link_assigns_default_signup_role(self):
        """New users signing up via runtime magic link receive the project's default signup role."""
        member_role = ProjectRole.objects.create(
            project=self.project,
            slug="shopper",
            name="Shopper",
            is_default_signup=True,
        )
        new_email = "newuser@shopper.com"

        with patch("hvt.apps.authentication.magic_link_views.send_email_async") as mock_send:
            res = self.client.post(
                "/api/v1/auth/runtime/magic-link/request/",
                {"email": new_email},
                HTTP_X_API_KEY=self.raw_api_key,
            )
            self.assertEqual(res.status_code, status.HTTP_200_OK)

        new_user = User.objects.filter(email=new_email, project=self.project).first()
        self.assertIsNotNone(new_user)
        self.assertTrue(
            UserProjectRole.objects.filter(user=new_user, role=member_role).exists(),
            "Default signup role must be assigned to new magic link user",
        )

    def test_passkey_and_magic_link_routes_in_public_cors_allowlist(self):
        """Passkey and magic link paths must be recognized as runtime public endpoints for browser CORS preflights."""
        from django.test import RequestFactory
        from hvt.apps.organizations.runtime_origins import request_targets_runtime_public_endpoint

        rf = RequestFactory()
        passkey_req = rf.options("/api/v1/auth/runtime/passkey/authenticate/options/")
        self.assertTrue(request_targets_runtime_public_endpoint(passkey_req))

        magic_req = rf.options("/api/v1/auth/runtime/magic-link/request/")
        self.assertTrue(request_targets_runtime_public_endpoint(magic_req))
