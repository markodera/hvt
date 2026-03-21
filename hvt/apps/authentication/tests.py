import json
from datetime import timedelta
from django.conf import settings as django_settings
from django.test import TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from hvt.apps.organizations.models import Organization, APIKey
from hvt.apps.authentication.backends import APIKeyAuthentication
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


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class SocialLoginErrorHandlingTest(APITestCase):
    """Regression tests for social login error handling."""

    def setUp(self):
        Site.objects.update_or_create(
            id=1,
            defaults={"domain": "testserver", "name": "testserver"},
        )

    def test_google_social_login_returns_400_when_provider_not_configured(self):
        response = self.client.post(
            "/api/v1/auth/social/google/",
            {"code": "dummy-code"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "validation_error")

    def test_github_social_login_returns_400_when_provider_not_configured(self):
        response = self.client.post(
            "/api/v1/auth/social/github/",
            {"code": "dummy-code"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "validation_error")
