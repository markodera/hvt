# SPDX-License-Identifier: Apache-2.0
import json
import uuid
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory

from hvt.apps.authentication.models import UserPasskeyCredential
from hvt.apps.authentication.passkey_views import (
    _resolve_rp_id,
    _resolve_expected_origin,
    _b64url_encode,
)
from hvt.apps.organizations.models import Organization, Project, APIKey

User = get_user_model()


class PasskeyOriginResolutionUnitTests(TestCase):
    """Unit tests for _resolve_rp_id and _resolve_expected_origin."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="WebAuthn Org", slug="webauthn-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Customer App",
            slug="customer-app",
            frontend_url="https://app.customer.com",
            allowed_origins=["https://preview.customer.com", "https://staging.customer.com"],
        )

    def test_rp_id_uses_explicit_project_passkey_rp_id(self):
        self.project.passkey_rp_id = "customer.com"
        self.project.save()

        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_ORIGIN="https://preview.customer.com",
        )
        rp_id = _resolve_rp_id(request, self.project)
        self.assertEqual(rp_id, "customer.com")

    def test_project_serializer_passkey_rp_id(self):
        from hvt.api.v1.serializers.organizations import ProjectSerializer
        serializer = ProjectSerializer(
            instance=self.project,
            data={"passkey_rp_id": "https://auth.custom-domain.com/"},
            partial=True,
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        updated = serializer.save()
        self.assertEqual(updated.passkey_rp_id, "auth.custom-domain.com")

    def test_rp_id_resolves_from_frontend_url(self):
        request = self.factory.post("/api/v1/auth/runtime/passkey/register/options/")
        rp_id = _resolve_rp_id(request, self.project)
        self.assertEqual(rp_id, "app.customer.com")

    def test_rp_id_resolves_from_matching_allowed_origin(self):
        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_ORIGIN="https://preview.customer.com",
        )
        rp_id = _resolve_rp_id(request, self.project)
        self.assertEqual(rp_id, "preview.customer.com")

    def test_rp_id_resolves_localhost_for_local_allowed_origin(self):
        self.project.allowed_origins.append("http://localhost:3000")
        self.project.save()

        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_ORIGIN="http://localhost:3000",
        )
        rp_id = _resolve_rp_id(request, self.project)
        self.assertEqual(rp_id, "localhost")

    def test_rp_id_ignores_unallowed_origin_and_falls_back(self):
        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_ORIGIN="https://malicious-attacker.com",
        )
        rp_id = _resolve_rp_id(request, self.project)
        # Should not resolve to malicious domain; falls back to project frontend_url
        self.assertEqual(rp_id, "app.customer.com")

    def test_expected_origin_includes_project_and_allowed_origins(self):
        request = self.factory.post("/api/v1/auth/runtime/passkey/register/verify/")
        origins = _resolve_expected_origin(request, self.project)

        # When no specific origin header, returns allowed origins list
        self.assertIsInstance(origins, list)
        self.assertIn("https://app.customer.com", origins)
        self.assertIn("https://preview.customer.com", origins)
        self.assertIn("https://staging.customer.com", origins)

    def test_expected_origin_matches_request_origin_when_valid(self):
        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/verify/",
            HTTP_ORIGIN="https://staging.customer.com",
        )
        origin = _resolve_expected_origin(request, self.project)
        self.assertEqual(origin, "https://staging.customer.com")

    def test_expected_origin_rejects_unallowed_origin(self):
        request = self.factory.post(
            "/api/v1/auth/runtime/passkey/register/verify/",
            HTTP_ORIGIN="https://evil.com",
        )
        origin = _resolve_expected_origin(request, self.project)
        # Must NOT return https://evil.com
        self.assertNotEqual(origin, "https://evil.com")


class RuntimePasskeyEndpointsOriginTests(TestCase):
    """Integration tests for runtime passkey endpoints with project custom origins."""

    def setUp(self):
        self.client = APIClient()
        self.org = Organization.objects.create(name="Passkey Tenant", slug="passkey-tenant")
        self.project = Project.objects.create(
            organization=self.org,
            name="SaaS Project",
            slug="saas-proj",
            frontend_url="https://saas.example.com",
            allowed_origins=["https://app.saas.example.com", "https://beta.saas.example.com"],
        )
        self.user = User.objects.create_user(
            email="member@saas.example.com",
            password="TestPassword123!",
            organization=self.org,
            project=self.project,
        )

        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            key_type=APIKey.KeyType.RUNTIME,
            environment=APIKey.Environment.TEST,
            prefix="testpass",
            hashed_key=APIKey.hash_key("hvt_test_testpass_secret123"),
            scopes=["auth:runtime"],
        )

    def test_register_options_uses_explicit_project_passkey_rp_id(self):
        self.project.passkey_rp_id = "example.com"
        self.project.save()
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_X_API_KEY="hvt_test_testpass_secret123",
            HTTP_ORIGIN="https://beta.saas.example.com",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["rp"]["id"], "example.com")

    def test_register_options_uses_project_frontend_url_as_rp_id(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_X_API_KEY="hvt_test_testpass_secret123",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["rp"]["id"], "saas.example.com")
        self.assertEqual(data["rp"]["name"], "SaaS Project")

    def test_register_options_uses_matching_allowed_origin_rp_id(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/v1/auth/runtime/passkey/register/options/",
            HTTP_X_API_KEY="hvt_test_testpass_secret123",
            HTTP_ORIGIN="https://beta.saas.example.com",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["rp"]["id"], "beta.saas.example.com")

    def test_auth_options_returns_project_rp_id(self):
        response = self.client.post(
            "/api/v1/auth/runtime/passkey/authenticate/options/",
            {"email": "member@saas.example.com"},
            HTTP_X_API_KEY="hvt_test_testpass_secret123",
            HTTP_ORIGIN="https://app.saas.example.com",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["rpId"], "app.saas.example.com")
        self.assertIn("challenge_key", data)

    def test_cors_preflight_on_passkey_routes_allows_project_origins(self):
        response = self.client.options(
            "/api/v1/auth/runtime/passkey/authenticate/options/",
            HTTP_ORIGIN="https://app.saas.example.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS="x-api-key,content-type",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.headers.get("Access-Control-Allow-Origin"),
            "https://app.saas.example.com",
        )

    @override_settings(CORS_ALLOW_ALL_ORIGINS=False)
    def test_cors_preflight_rejects_unallowed_origin(self):
        response = self.client.options(
            "/api/v1/auth/runtime/passkey/authenticate/options/",
            HTTP_ORIGIN="https://evil-untrusted-domain.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS="x-api-key,content-type",
        )
        self.assertNotEqual(
            response.headers.get("Access-Control-Allow-Origin"),
            "https://evil-untrusted-domain.com",
        )

    @patch("webauthn.verify_authentication_response")
    def test_auth_verify_with_project_origin_succeeds(self, mock_verify):
        mock_verification = MagicMock()
        mock_verification.new_sign_count = 1
        mock_verify.return_value = mock_verification

        # Create credential for user
        cred = UserPasskeyCredential.objects.create(
            user=self.user,
            name="MacBook TouchID",
            credential_id=_b64url_encode(b"dummy_cred_id_123"),
            public_key=_b64url_encode(b"dummy_public_key_bytes"),
            sign_count=0,
        )

        from django.core.cache import cache
        challenge_key = str(uuid.uuid4())
        cache.set(f"runtime_passkey_auth_{challenge_key}", _b64url_encode(b"dummy_challenge"), timeout=300)

        payload = {
            "challenge_key": challenge_key,
            "credential": {
                "id": _b64url_encode(b"dummy_cred_id_123"),
                "rawId": _b64url_encode(b"dummy_cred_id_123"),
                "response": {
                    "clientDataJSON": _b64url_encode(b"{}"),
                    "authenticatorData": _b64url_encode(b"{}"),
                    "signature": _b64url_encode(b"sig"),
                },
                "type": "public-key",
            },
        }

        response = self.client.post(
            "/api/v1/auth/runtime/passkey/authenticate/verify/",
            payload,
            format="json",
            HTTP_X_API_KEY="hvt_test_testpass_secret123",
            HTTP_ORIGIN="https://app.saas.example.com",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertEqual(data["user"]["email"], self.user.email)

        # Verify webauthn was called with the project's expected origin and rp_id
        mock_verify.assert_called_once()
        _, kwargs = mock_verify.call_args
        self.assertEqual(kwargs["expected_rp_id"], "app.saas.example.com")
        self.assertEqual(kwargs["expected_origin"], "https://app.saas.example.com")
