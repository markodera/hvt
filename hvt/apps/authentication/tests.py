import json
from datetime import timedelta
from unittest.mock import patch
from django.conf import settings as django_settings
from django.test import TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from allauth.socialaccount.models import SocialApp

from hvt.apps.organizations.models import (
    Organization,
    Project,
    APIKey,
    SocialProviderConfig,
)
from hvt.apps.authentication.backends import APIKeyAuthentication
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.permissions import IsAuthenticatedOrAPIKey, IsAdminOrAPIKey
from django.contrib.sites.models import Site

User = get_user_model()


class APIKeyModelTest(TestCase):
    """Test APIKey model functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

    def test_generate_key(self):
        """Test API key generation"""
        prefix, full_key, hashed_key = APIKey.generate_key()

        # Check prefix format (8 hex chars)
        self.assertEqual(len(prefix), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in prefix))

        # Check full key format
        self.assertTrue(full_key.startswith("hvt_test_"))
        self.assertEqual(len(full_key), 73)  # hvt_test_ (9) + 64 hex chars

        # Check hashed key
        self.assertIsNotNone(hashed_key)
        self.assertNotEqual(hashed_key, full_key)

    def test_create_api_key(self):
        """Test creating an API key"""
        api_key = APIKey.objects.create(
            organization=self.org, name="Test Key", scopes=["read", "write"]
        )

        self.assertEqual(api_key.organization, self.org)
        self.assertEqual(api_key.name, "Test Key")
        self.assertEqual(api_key.scopes, ["read", "write"])
        self.assertIsNotNone(api_key.prefix)
        self.assertIsNotNone(api_key.hashed_key)

    def test_verify_key(self):
        """Test key verification"""
        prefix, full_key, hashed_key = APIKey.generate_key()

        api_key = APIKey.objects.create(
            organization=self.org, name="Test Key", prefix=prefix, hashed_key=hashed_key
        )

        # Valid key should verify
        self.assertTrue(api_key.verify_key(full_key))

        # Invalid key should not verify
        self.assertFalse(api_key.verify_key("hvt_live_invalid"))

    def test_is_valid_property(self):
        """Test is_valid property"""
        api_key = APIKey.objects.create(
            organization=self.org, name="Test Key", is_active=True
        )

        # Active key without expiry should be valid
        self.assertTrue(api_key.is_valid)

        # Inactive key should be invalid
        api_key.is_active = False
        api_key.save()
        self.assertFalse(api_key.is_valid)

        # Expired key should be invalid
        api_key.is_active = True
        api_key.expires_at = timezone.now() - timedelta(days=1)
        api_key.save()
        self.assertFalse(api_key.is_valid)

    def test_update_last_used(self):
        """Test updating last_used_at timestamp"""
        api_key = APIKey.objects.create(organization=self.org, name="Test Key")

        old_last_used = api_key.last_used_at
        api_key.update_last_used()
        api_key.refresh_from_db()

        self.assertIsNotNone(api_key.last_used_at)
        if old_last_used:
            self.assertGreater(api_key.last_used_at, old_last_used)


class APIKeyAuthenticationTest(TestCase):
    """Test APIKeyAuthentication backend"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

        # Create a valid API key (environment must match key format)
        prefix, self.full_key, hashed_key = APIKey.generate_key(environment="live")
        self.api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            prefix=prefix,
            hashed_key=hashed_key,
            environment="live",
            is_active=True,
        )

        self.auth_backend = APIKeyAuthentication()

    def test_authenticate_no_key(self):
        """Test authentication without API key"""
        request = self.factory.get("/api/test/")
        result = self.auth_backend.authenticate(request)

        self.assertIsNone(result)

    def test_authenticate_valid_key(self):
        """Test authentication with valid API key"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.full_key)

        result = self.auth_backend.authenticate(request)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

        user, auth = result
        self.assertIsNone(user)
        self.assertIsInstance(auth, APIKey)
        self.assertEqual(auth.id, self.api_key.id)

    def test_authenticate_invalid_format(self):
        """Test authentication with invalid key format"""
        from rest_framework.exceptions import AuthenticationFailed

        request = self.factory.get("/api/test/", HTTP_X_API_KEY="invalid_key")

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_authenticate_invalid_prefix(self):
        """Test authentication with non-existent prefix"""
        from rest_framework.exceptions import AuthenticationFailed

        request = self.factory.get(
            "/api/test/", HTTP_X_API_KEY="hvt_live_deadbeef" + "0" * 56
        )

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_authenticate_invalid_hash(self):
        """Test authentication with invalid hash"""
        from rest_framework.exceptions import AuthenticationFailed

        # Create key with same prefix but different hash
        wrong_key = f"hvt_live_{self.api_key.prefix}" + "0" * 56

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=wrong_key)

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_authenticate_inactive_key(self):
        """Test authentication with inactive key"""
        from rest_framework.exceptions import AuthenticationFailed

        self.api_key.is_active = False
        self.api_key.save()

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.full_key)

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_authenticate_expired_key(self):
        """Test authentication with expired key"""
        from rest_framework.exceptions import AuthenticationFailed

        self.api_key.expires_at = timezone.now() - timedelta(days=1)
        self.api_key.save()

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.full_key)

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_authenticate_updates_last_used(self):
        """Test that authentication updates last_used_at"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.full_key)

        old_last_used = self.api_key.last_used_at
        self.auth_backend.authenticate(request)

        self.api_key.refresh_from_db()
        self.assertIsNotNone(self.api_key.last_used_at)
        if old_last_used:
            self.assertGreater(self.api_key.last_used_at, old_last_used)


class APIKeyPermissionTest(TestCase):
    """Test API key permission classes"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123"
        )
        self.admin_user = User.objects.create_user(
            email="admin@example.com", password="adminpass123", is_staff=True
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

        # Create API key
        prefix, self.full_key, hashed_key = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["read"],
        )

    def test_is_authenticated_or_api_key_with_user(self):
        """Test IsAuthenticatedOrAPIKey with authenticated user"""
        permission = IsAuthenticatedOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = self.user
        request.auth = None

        self.assertTrue(permission.has_permission(request, None))

    def test_is_authenticated_or_api_key_with_api_key(self):
        """Test IsAuthenticatedOrAPIKey with API key"""
        permission = IsAuthenticatedOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = None
        request.auth = self.api_key

        self.assertTrue(permission.has_permission(request, None))

    def test_is_authenticated_or_api_key_without_auth(self):
        """Test IsAuthenticatedOrAPIKey without authentication"""
        from django.contrib.auth.models import AnonymousUser

        permission = IsAuthenticatedOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = AnonymousUser()
        request.auth = None

        self.assertFalse(permission.has_permission(request, None))

    def test_is_admin_or_api_key_with_admin(self):
        """Test IsAdminOrAPIKey with admin user"""
        permission = IsAdminOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = self.admin_user
        request.auth = None

        self.assertTrue(permission.has_permission(request, None))

    def test_is_admin_or_api_key_with_regular_user(self):
        """Test IsAdminOrAPIKey with regular user"""
        permission = IsAdminOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = self.user
        request.auth = None

        self.assertFalse(permission.has_permission(request, None))

    def test_is_admin_or_api_key_with_api_key(self):
        """Test IsAdminOrAPIKey with API key"""
        permission = IsAdminOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = None
        request.auth = self.api_key

        self.assertTrue(permission.has_permission(request, None))

    def test_is_admin_or_api_key_without_auth(self):
        """Test IsAdminOrAPIKey without authentication"""
        from django.contrib.auth.models import AnonymousUser

        permission = IsAdminOrAPIKey()
        request = self.factory.get("/api/test/")
        request.user = AnonymousUser()
        request.auth = None

        self.assertFalse(permission.has_permission(request, None))


class APIKeyEndToEndTest(APITestCase):
    """End-to-end tests for API key functionality"""

    def setUp(self):
        from allauth.account.models import EmailAddress
        
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123"
        )
        # Mark email as verified (required for login with ACCOUNT_EMAIL_VERIFICATION = "mandatory")
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            verified=True,
            primary=True
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)
        # Link user to organization
        self.user.organization = self.org
        self.user.role = User.Role.OWNER
        self.user.save()

    def test_create_api_key_and_use_it(self):
        """Test creating an API key and using it for authentication"""
        # Login to get JWT token
        login_response = self.client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "testpass123"},
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        access_token = login_response.data["access"]

        # Create API key
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        create_response = self.client.post(
            "/api/v1/organizations/current/keys/",
            {"name": "Test Key", "scopes": ["read", "write"]},
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)

        api_key = create_response.data["key"]
        self.assertTrue(api_key.startswith("hvt_test_"))

        # Use API key to access protected endpoint
        self.client.credentials()  # Clear JWT
        self.client.credentials(HTTP_X_API_KEY=api_key)

        users_response = self.client.get("/api/v1/users/")

        # This should work if API key auth is properly configured
        self.assertIn(
            users_response.status_code, [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]
        )

        # If forbidden, it's a permission issue, not auth issue
        if users_response.status_code == status.HTTP_403_FORBIDDEN:
            print("API key authenticated but permission denied")
            print(f"Response: {users_response.data}")

    def test_invalid_api_key_rejected(self):
        """Test that invalid API keys are rejected"""
        self.client.credentials(HTTP_X_API_KEY="hvt_live_invalid")

        response = self.client.get("/api/v1/users/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_api_key_rejected(self):
        """Test that requests without auth are rejected"""
        response = self.client.get("/api/v1/users/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class JWTCookieAuthFlowTest(APITestCase):
    """Regression tests for browser-style JWT cookie authentication."""

    def setUp(self):
        from allauth.account.models import EmailAddress

        self.user = User.objects.create_user(
            email="cookie-user@example.com",
            password="testpass123",
            first_name="Cookie",
            last_name="User",
        )
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            verified=True,
            primary=True,
        )
        self.org = Organization.objects.create(name="Cookie Org", owner=self.user)
        self.user.organization = self.org
        self.user.role = User.Role.OWNER
        self.user.save()

    def _login(self):
        response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "testpass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response

    def test_login_sets_jwt_cookies(self):
        response = self._login()

        self.assertIn("auth-token", response.cookies)
        self.assertIn("refresh-token", response.cookies)
        self.assertIn("auth-token", self.client.cookies)
        self.assertIn("refresh-token", self.client.cookies)
        self.assertEqual(
            response.cookies["auth-token"]["samesite"],
            django_settings.REST_AUTH["JWT_AUTH_SAMESITE"],
        )
        self.assertTrue(bool(response.cookies["auth-token"]["httponly"]))
        self.assertEqual(
            bool(response.cookies["auth-token"]["secure"]),
            django_settings.REST_AUTH["JWT_AUTH_SECURE"],
        )

    def test_me_endpoint_accepts_cookie_auth(self):
        self._login()

        response = self.client.get("/api/v1/auth/me/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.user.email)

    def test_refresh_endpoint_accepts_refresh_cookie(self):
        self._login()
        del self.client.cookies["auth-token"]

        response = self.client.post("/api/v1/auth/token/refresh/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("auth-token", response.cookies)
        self.assertIn("refresh-token", response.cookies)


class JWTOrgClaimHardeningTest(APITestCase):
    """Regression tests for org-aware JWT claim handling."""

    def setUp(self):
        from allauth.account.models import EmailAddress

        self.user = User.objects.create_user(
            email="claims-user@example.com",
            password="testpass123",
            first_name="Claims",
            last_name="User",
        )
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            verified=True,
            primary=True,
        )
        self.org = Organization.objects.create(name="Claims Org", owner=self.user)
        self.other_org = Organization.objects.create(
            name="Other Claims Org",
            slug="other-claims-org",
        )
        self.user.organization = self.org
        self.user.role = User.Role.MEMBER
        self.user.save(update_fields=["organization", "role"])

    def _login(self):
        response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "testpass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response

    def test_login_access_token_includes_org_and_role_claims(self):
        response = self._login()

        access_token = AccessToken(response.cookies["auth-token"].value)
        refresh_token = RefreshToken(response.cookies["refresh-token"].value)

        self.assertEqual(access_token["org_id"], str(self.org.id))
        self.assertEqual(access_token["role"], self.user.role)
        self.assertEqual(access_token["email"], self.user.email)
        self.assertEqual(refresh_token["org_id"], str(self.org.id))
        self.assertEqual(refresh_token["role"], self.user.role)

    def test_refresh_revalidates_current_role(self):
        self._login()
        self.user.role = User.Role.ADMIN
        self.user.save(update_fields=["role"])
        del self.client.cookies["auth-token"]

        response = self.client.post("/api/v1/auth/token/refresh/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = AccessToken(response.data["access"])
        self.assertEqual(access_token["org_id"], str(self.org.id))
        self.assertEqual(access_token["role"], User.Role.ADMIN)

    def test_refresh_rejects_when_org_changes(self):
        self._login()
        self.user.organization = self.other_org
        self.user.save(update_fields=["organization"])
        del self.client.cookies["auth-token"]

        response = self.client.post("/api/v1/auth/token/refresh/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_auth_rejects_stale_org_token(self):
        self._login()
        self.user.organization = self.other_org
        self.user.save(update_fields=["organization"])

        response = self.client.get("/api/v1/auth/me/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_bearer_auth_rejects_stale_org_token(self):
        response = self._login()
        access_token = response.data["access"]
        self.user.organization = self.other_org
        self.user.save(update_fields=["organization"])
        self.client.cookies.clear()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        response = self.client.get("/api/v1/auth/me/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_ignores_stale_auth_cookie(self):
        self._login()
        self.user.organization = self.other_org
        self.user.save(update_fields=["organization"])

        response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "testpass123"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = AccessToken(response.data["access"])
        self.assertEqual(access_token["org_id"], str(self.other_org.id))

    def test_user_without_org_can_authenticate_with_null_org_claim(self):
        self.user.organization = None
        self.user.save(update_fields=["organization"])

        response = self._login()
        access_token = AccessToken(response.data["access"])
        refresh_token = RefreshToken(response.cookies["refresh-token"].value)

        self.assertIsNone(access_token.get("org_id"))
        self.assertIsNone(refresh_token.get("org_id"))

        me_response = self.client.get("/api/v1/auth/me/")
        self.assertEqual(me_response.status_code, status.HTTP_200_OK)

        del self.client.cookies["auth-token"]
        refresh_response = self.client.post("/api/v1/auth/token/refresh/", {}, format="json")
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class ControlPlaneRegistrationFlowTest(APITestCase):
    """Control-plane signup stays on /auth/register/ without API-key tenant context."""

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_register_without_api_key_creates_user_without_org(self, mock_send_mail):
        response = self.client.post(
            "/api/v1/auth/register/",
            {
                "email": "control-plane@example.com",
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
                "first_name": "Control",
                "last_name": "Plane",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        created_user = User.objects.get(email="control-plane@example.com")
        self.assertIsNone(created_user.organization_id)
        self.assertIsNone(created_user.project_id)
        self.assertTrue(
            AuditLog.objects.filter(
                event_type=AuditLog.EventType.USER_REGISTER,
                actor_user=created_user,
                organization__isnull=True,
            ).exists()
        )
        mock_send_mail.assert_called()


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class APIKeyRegistrationFlowTest(APITestCase):
    """Runtime registration flow using an API key as tenant context."""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner-runtime@example.com",
            password="testpass123",
            role=User.Role.OWNER,
        )
        self.org = Organization.objects.create(
            name="Runtime Org",
            slug="runtime-org",
            owner=self.owner,
            allow_signup=True,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()

        prefix, self.full_key, hashed_key = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Runtime Signup Key",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
        )

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_register_with_api_key_creates_member_in_key_org(self, mock_send_mail):
        response = self.client.post(
            "/api/v1/auth/runtime/register/",
            {
                "email": "shopper@example.com",
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
                "first_name": "Store",
                "last_name": "Shopper",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["detail"], "Verification e-mail sent.")

        created_user = User.objects.get(email="shopper@example.com")
        self.assertEqual(created_user.organization_id, self.org.id)
        self.assertEqual(created_user.project_id, self.default_project.id)
        self.assertEqual(created_user.role, User.Role.MEMBER)
        self.assertTrue(
            AuditLog.objects.filter(
                event_type=AuditLog.EventType.USER_REGISTER,
                actor_user=created_user,
                organization=self.org,
                project=self.default_project,
            ).exists()
        )
        mock_send_mail.assert_called()

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_register_with_api_key_respects_allow_signup(self, mock_send_mail):
        self.default_project.allow_signup = False
        self.default_project.save(update_fields=["allow_signup"])

        response = self.client.post(
            "/api/v1/auth/runtime/register/",
            {
                "email": "blocked-shopper@example.com",
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(email="blocked-shopper@example.com").exists())
        self.assertEqual(
            str(response.data["detail"]),
            "Self-service signup is disabled for this organization.",
        )
        mock_send_mail.assert_not_called()

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_control_plane_register_rejects_api_key_signup(self, mock_send_mail):
        response = self.client.post(
            "/api/v1/auth/register/",
            {
                "email": "wrong-route@example.com",
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]),
            "Use /api/v1/auth/runtime/register/ with X-API-Key for runtime registration.",
        )
        self.assertFalse(User.objects.filter(email="wrong-route@example.com").exists())
        mock_send_mail.assert_not_called()


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class RuntimeLoginFlowTest(APITestCase):
    """Runtime login flow scoped by API key organization."""

    def setUp(self):
        from allauth.account.models import EmailAddress

        self.owner = User.objects.create_user(
            email="runtime-login-owner@example.com",
            password="testpass123",
            role=User.Role.OWNER,
        )
        self.org = Organization.objects.create(
            name="Runtime Login Org",
            slug="runtime-login-org",
            owner=self.owner,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()

        self.runtime_user = User.objects.create_user(
            email="buyer@example.com",
            password="Strongpass123!",
            organization=self.org,
            role=User.Role.MEMBER,
        )
        EmailAddress.objects.create(
            user=self.runtime_user,
            email=self.runtime_user.email,
            verified=True,
            primary=True,
        )

        self.unverified_user = User.objects.create_user(
            email="unverified-buyer@example.com",
            password="Strongpass123!",
            organization=self.org,
            role=User.Role.MEMBER,
        )

        self.other_org = Organization.objects.create(
            name="Wrong Runtime Org",
            slug="wrong-runtime-org",
        )
        self.other_user = User.objects.create_user(
            email="other-buyer@example.com",
            password="Strongpass123!",
            organization=self.other_org,
            role=User.Role.MEMBER,
        )
        EmailAddress.objects.create(
            user=self.other_user,
            email=self.other_user.email,
            verified=True,
            primary=True,
        )

        prefix, self.full_key, hashed_key = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Runtime Login Key",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
        )

    def test_runtime_login_succeeds_for_verified_same_org_user(self):
        response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.runtime_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = AccessToken(response.cookies["auth-token"].value)
        self.assertEqual(access_token["org_id"], str(self.org.id))
        self.assertEqual(access_token["project_id"], str(self.default_project.id))
        self.assertEqual(access_token["project_slug"], self.default_project.slug)
        self.assertEqual(access_token["role"], User.Role.MEMBER)
        self.runtime_user.refresh_from_db()
        self.assertEqual(self.runtime_user.project_id, self.default_project.id)

    def test_runtime_refresh_preserves_project_claims(self):
        login_response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.runtime_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        del self.client.cookies["auth-token"]

        response = self.client.post("/api/v1/auth/token/refresh/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = AccessToken(response.data["access"])
        self.assertEqual(access_token["project_id"], str(self.default_project.id))
        self.assertEqual(access_token["project_slug"], self.default_project.slug)

    def test_runtime_login_rejects_wrong_org_user(self):
        response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.other_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["non_field_errors"][0]),
            "These credentials do not belong to the API key organization.",
        )

    def test_runtime_login_rejects_wrong_project_user(self):
        other_project = Project.objects.create(
            organization=self.org,
            name="Storefront Staging",
            slug="storefront-staging",
            allow_signup=True,
        )
        self.runtime_user.project = other_project
        self.runtime_user.save(update_fields=["project"])

        response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.runtime_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["non_field_errors"][0]),
            "These credentials do not belong to the API key project.",
        )

    def test_runtime_login_requires_verified_email(self):
        response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.unverified_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["non_field_errors"][0]),
            "E-mail is not verified.",
        )

    def test_runtime_login_requires_auth_runtime_scope(self):
        self.api_key.scopes = ["read"]
        self.api_key.save(update_fields=["scopes"])

        response = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.runtime_user.email, "password": "Strongpass123!"},
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["non_field_errors"][0]),
            "This API key does not have the required auth:runtime scope.",
        )


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class SocialLoginErrorHandlingTest(APITestCase):
    """Regression tests for social login error handling."""

    def setUp(self):
        Site.objects.update_or_create(
            id=1,
            defaults={"domain": "testserver", "name": "testserver"},
        )

    def test_google_social_login_returns_400_on_failure(self):
        response = self.client.post(
            "/api/v1/auth/social/google/",
            {"code": "dummy-code"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "validation_error")
        self.assertEqual(
            response.data["detail"]["non_field_errors"][0],
            "Social login failed. Please try again.",
        )

    def test_github_social_login_returns_400_on_failure(self):
        response = self.client.post(
            "/api/v1/auth/social/github/",
            {"code": "dummy-code"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "validation_error")
        self.assertEqual(
            response.data["detail"]["non_field_errors"][0],
            "Social login failed. Please try again.",
        )

    def test_control_plane_social_provider_list_uses_frontend_callback_urls(self):
        with override_settings(
            SOCIALACCOUNT_PROVIDERS={
                "google": {"APP": {"client_id": "google-client", "secret": "google-secret"}},
                "github": {"APP": {"client_id": "github-client", "secret": "github-secret"}},
            },
            FRONTEND_URL="http://localhost:5173",
        ):
            response = self.client.get("/api/v1/auth/social/providers/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        providers = {item["provider"]: item for item in response.data["providers"]}
        self.assertEqual(
            providers["google"]["callback_url"],
            "http://localhost:5173/auth/google/callback",
        )
        self.assertEqual(
            providers["github"]["callback_url"],
            "http://localhost:5173/auth/github/callback",
        )

    def test_control_plane_social_provider_list_falls_back_to_socialapp_records(self):
        site = Site.objects.get(id=1)
        app = SocialApp.objects.create(
            provider="google",
            name="Google Dashboard Login",
            client_id="google-db-client",
            secret="google-db-secret",
        )
        app.sites.add(site)

        with override_settings(SOCIALACCOUNT_PROVIDERS={}):
            response = self.client.get("/api/v1/auth/social/providers/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        providers = {item["provider"]: item for item in response.data["providers"]}
        self.assertEqual(providers["google"]["client_id"], "google-db-client")


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class PasswordResetFlowTest(APITestCase):
    """Regression tests for frontend password-reset email flow."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="reset-target@example.com",
            password="testpass123",
        )

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_password_reset_request_returns_success(self, mock_send_mail):
        response = self.client.post(
            "/api/v1/auth/password/reset/",
            {"email": self.user.email},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["detail"],
            "Password reset e-mail has been sent.",
        )
        mock_send_mail.assert_called_once()
        _, args, _ = mock_send_mail.mock_calls[0]
        self.assertEqual(args[0], "account/email/password_reset_key")
        self.assertEqual(args[1], self.user.email)
        self.assertIn("/auth/password-reset/", args[2]["password_reset_url"])

    def test_frontend_account_adapter_builds_frontend_reset_url(self):
        from hvt.apps.authentication.adapters import FrontendAccountAdapter
        from allauth.account.forms import default_token_generator
        from allauth.account.utils import user_pk_to_url_str

        adapter = FrontendAccountAdapter()
        with override_settings(FRONTEND_URL="http://localhost:5173"):
            reset_url = adapter.get_reset_password_from_key_url("uid123-reset-token-value")

        self.assertEqual(
            reset_url,
            "http://localhost:5173/auth/password-reset/uid123/reset-token-value",
        )

        uid = user_pk_to_url_str(self.user)
        token = default_token_generator.make_token(self.user)
        response = self.client.post(
            f"/api/v1/auth/password/reset/confirm/{uid}/{token}/",
            {
                "new_password1": "Updatedpass123!",
                "new_password2": "Updatedpass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Updatedpass123!"))


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class RuntimeSocialAuthFlowTest(APITestCase):
    """Runtime social auth should stay isolated to the API key project."""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="runtime-social-owner@example.com",
            password="Strongpass123!",
            role=User.Role.OWNER,
        )
        self.org = Organization.objects.create(
            name="Runtime Social Org",
            slug="runtime-social-org",
            owner=self.owner,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()
        self.other_project = Project.objects.create(
            organization=self.org,
            name="Other Runtime Project",
            slug="other-runtime-project",
            allow_signup=True,
        )

        prefix, self.full_key, hashed_key = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Runtime Social Key",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
        )

    def test_runtime_social_provider_list_is_scoped_to_api_key_project(self):
        SocialProviderConfig.objects.create(
            project=self.default_project,
            provider=SocialProviderConfig.Provider.GOOGLE,
            client_id="google-default",
            client_secret="secret-default",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )
        SocialProviderConfig.objects.create(
            project=self.other_project,
            provider=SocialProviderConfig.Provider.GITHUB,
            client_id="github-other",
            client_secret="secret-other",
            redirect_uris=["http://localhost:3000/auth/github/callback"],
            is_active=True,
        )

        response = self.client.get(
            "/api/v1/auth/runtime/social/providers/",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["project_id"], str(self.default_project.id))
        self.assertEqual(len(response.data["providers"]), 1)
        self.assertEqual(response.data["providers"][0]["provider"], "google")
        self.assertEqual(response.data["providers"][0]["client_id"], "google-default")

    def test_runtime_social_provider_list_requires_auth_runtime_scope(self):
        self.api_key.scopes = ["read"]
        self.api_key.save(update_fields=["scopes"])

        response = self.client.get(
            "/api/v1/auth/runtime/social/providers/",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["detail"],
            "This API key does not have the required auth:runtime scope.",
        )

    def test_runtime_social_login_rejects_callback_url_outside_project_allowlist(self):
        SocialProviderConfig.objects.create(
            project=self.default_project,
            provider=SocialProviderConfig.Provider.GOOGLE,
            client_id="google-default",
            client_secret="secret-default",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )

        response = self.client.post(
            "/api/v1/auth/runtime/social/google/",
            {
                "code": "dummy-code",
                "callback_url": "http://malicious.example.com/callback",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["detail"]["non_field_errors"][0],
            "This callback URL is not allowed for the configured provider.",
        )

    def test_runtime_social_login_rejects_provider_config_from_other_project(self):
        SocialProviderConfig.objects.create(
            project=self.other_project,
            provider=SocialProviderConfig.Provider.GOOGLE,
            client_id="google-other",
            client_secret="secret-other",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )

        response = self.client.post(
            "/api/v1/auth/runtime/social/google/",
            {
                "code": "dummy-code",
                "callback_url": "http://localhost:3000/auth/google/callback",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["detail"]["non_field_errors"][0],
            "Social login provider 'google' is not configured.",
        )

    @patch("hvt.api.v1.serializers.users.CustomSocialLoginSerializer.validate")
    def test_runtime_social_login_issues_project_scoped_tokens(self, mock_validate):
        runtime_user = User.objects.create_user(
            email="runtime-social-user@example.com",
            password="Strongpass123!",
            organization=self.org,
            project=self.default_project,
            role=User.Role.MEMBER,
        )
        mock_validate.return_value = {"user": runtime_user}
        SocialProviderConfig.objects.create(
            project=self.default_project,
            provider=SocialProviderConfig.Provider.GOOGLE,
            client_id="google-default",
            client_secret="secret-default",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )

        response = self.client.post(
            "/api/v1/auth/runtime/social/google/",
            {
                "code": "dummy-code",
                "callback_url": "http://localhost:3000/auth/google/callback",
            },
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = AccessToken(response.cookies["auth-token"].value)
        self.assertEqual(access_token["org_id"], str(self.org.id))
        self.assertEqual(access_token["project_id"], str(self.default_project.id))
        self.assertEqual(access_token["project_slug"], self.default_project.slug)
