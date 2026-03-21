"""
Comprehensive test cases for Test/Live API Key environment isolation.
Tests that test and live environments are completely isolated.
"""
from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status

from hvt.apps.organizations.models import Organization, APIKey
from hvt.apps.authentication.backends import APIKeyAuthentication
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class TestLiveKeyGenerationTest(TestCase):
    """Test API key generation for test and live environments"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="owner@example.com", password="password123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

    def test_generate_test_key_format(self):
        """Test key should have hvt_test_ prefix"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")

        self.assertTrue(full_key.startswith("hvt_test_"))
        self.assertEqual(len(prefix), 8)
        self.assertEqual(len(full_key), 73)  # hvt_test_ (9) + 64 hex chars
        self.assertNotEqual(full_key, hashed_key)

    def test_generate_live_key_format(self):
        """Live key should have hvt_live_ prefix"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="live")

        self.assertTrue(full_key.startswith("hvt_live_"))
        self.assertEqual(len(prefix), 8)
        self.assertEqual(len(full_key), 73)  # hvt_live_ (9) + 64 hex chars
        self.assertNotEqual(full_key, hashed_key)

    def test_test_and_live_keys_are_different(self):
        """Test and live keys should be completely different"""
        test_prefix, test_key, test_hash = APIKey.generate_key(environment="test")
        live_prefix, live_key, live_hash = APIKey.generate_key(environment="live")

        self.assertNotEqual(test_key, live_key)
        self.assertNotEqual(test_hash, live_hash)

    def test_create_test_api_key(self):
        """Should create test API key with correct environment"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")

        api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
        )

        self.assertEqual(api_key.environment, "test")
        self.assertTrue(api_key.is_test)
        self.assertFalse(api_key.is_live)

    def test_create_live_api_key(self):
        """Should create live API key with correct environment"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="live")

        api_key = APIKey.objects.create(
            organization=self.org,
            name="Live Key",
            environment="live",
            prefix=prefix,
            hashed_key=hashed_key,
        )

        self.assertEqual(api_key.environment, "live")
        self.assertTrue(api_key.is_live)
        self.assertFalse(api_key.is_test)


class APIKeyAuthenticationTestLiveTest(TestCase):
    """Test authentication backend with test/live keys"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="test@example.com", password="password123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

        # Create test key
        test_prefix, self.test_full_key, test_hashed_key = APIKey.generate_key(
            environment="test"
        )
        self.test_api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            environment="test",
            prefix=test_prefix,
            hashed_key=test_hashed_key,
            is_active=True,
        )

        # Create live key
        live_prefix, self.live_full_key, live_hashed_key = APIKey.generate_key(
            environment="live"
        )
        self.live_api_key = APIKey.objects.create(
            organization=self.org,
            name="Live Key",
            environment="live",
            prefix=live_prefix,
            hashed_key=live_hashed_key,
            is_active=True,
        )

        self.auth_backend = APIKeyAuthentication()

    def test_authenticate_with_test_key(self):
        """Should authenticate successfully with test key"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.test_full_key)

        result = self.auth_backend.authenticate(request)

        self.assertIsNotNone(result)
        user, auth = result
        self.assertIsNone(user)
        self.assertIsInstance(auth, APIKey)
        self.assertEqual(auth.id, self.test_api_key.id)
        self.assertTrue(auth.is_test)

    def test_authenticate_with_live_key(self):
        """Should authenticate successfully with live key"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.live_full_key)

        result = self.auth_backend.authenticate(request)

        self.assertIsNotNone(result)
        user, auth = result
        self.assertIsNone(user)
        self.assertIsInstance(auth, APIKey)
        self.assertEqual(auth.id, self.live_api_key.id)
        self.assertTrue(auth.is_live)

    def test_reject_wrong_environment_prefix(self):
        """Should reject test key with live prefix"""
        fake_key = self.test_full_key.replace("hvt_test_", "hvt_live_")

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=fake_key)

        with self.assertRaises(AuthenticationFailed):
            self.auth_backend.authenticate(request)

    def test_reject_invalid_prefix_format(self):
        """Should reject keys without hvt_test_ or hvt_live_ prefix"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY="hvt_invalid_abc123")

        with self.assertRaises(AuthenticationFailed) as context:
            self.auth_backend.authenticate(request)

        self.assertIn("hvt_test_", str(context.exception))

    def test_inactive_test_key_rejected(self):
        """Inactive test key should be rejected"""
        self.test_api_key.is_active = False
        self.test_api_key.save()

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.test_full_key)

        with self.assertRaises(AuthenticationFailed) as context:
            self.auth_backend.authenticate(request)

        self.assertIn("inactive", str(context.exception).lower())

    def test_expired_live_key_rejected(self):
        """Expired live key should be rejected"""
        self.live_api_key.expires_at = timezone.now() - timedelta(days=1)
        self.live_api_key.save()

        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.live_full_key)

        with self.assertRaises(AuthenticationFailed) as context:
            self.auth_backend.authenticate(request)

        self.assertIn("expired", str(context.exception).lower())


class TestLiveDataIsolationTest(TestCase):
    """Test that test and live data are completely isolated"""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com", password="password123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.owner)

        # Create test users
        self.test_user1 = User.objects.create_user(
            email="test1@example.com",
            password="password123",
            organization=self.org,
            is_test=True,
        )
        self.test_user2 = User.objects.create_user(
            email="test2@example.com",
            password="password123",
            organization=self.org,
            is_test=True,
        )

        # Create live users
        self.live_user1 = User.objects.create_user(
            email="live1@example.com",
            password="password123",
            organization=self.org,
            is_test=False,
        )
        self.live_user2 = User.objects.create_user(
            email="live2@example.com",
            password="password123",
            organization=self.org,
            is_test=False,
        )

    def test_filter_test_users_only(self):
        """Should be able to filter only test users"""
        test_users = User.objects.filter(organization=self.org, is_test=True)

        self.assertEqual(test_users.count(), 2)
        self.assertIn(self.test_user1, test_users)
        self.assertIn(self.test_user2, test_users)
        self.assertNotIn(self.live_user1, test_users)
        self.assertNotIn(self.live_user2, test_users)

    def test_filter_live_users_only(self):
        """Should be able to filter only live users"""
        live_users = User.objects.filter(organization=self.org, is_test=False)

        self.assertEqual(live_users.count(), 2)
        self.assertIn(self.live_user1, live_users)
        self.assertIn(self.live_user2, live_users)
        self.assertNotIn(self.test_user1, live_users)
        self.assertNotIn(self.test_user2, live_users)

    def test_count_test_vs_live_users(self):
        """Should correctly count test vs live users"""
        total_users = User.objects.filter(organization=self.org).count()
        test_users = User.objects.filter(organization=self.org, is_test=True).count()
        live_users = User.objects.filter(organization=self.org, is_test=False).count()

        self.assertEqual(total_users, 4)
        self.assertEqual(test_users, 2)
        self.assertEqual(live_users, 2)


class APIKeySecurityTest(TestCase):
    """Security-focused tests for API keys"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", password="password123"
        )
        self.org = Organization.objects.create(name="Test Org", owner=self.user)

    def test_api_key_hash_is_not_reversible(self):
        """Hashed key should not reveal original key"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")

        # Hash should be different from key
        self.assertNotEqual(full_key, hashed_key)

        # Hash should not contain the original key
        self.assertNotIn(full_key, hashed_key)
        self.assertNotIn(prefix, hashed_key)

    def test_same_key_produces_same_hash(self):
        """Verifying the same key twice should work"""
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")

        api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
        )

        # Verify multiple times
        self.assertTrue(api_key.verify_key(full_key))
        self.assertTrue(api_key.verify_key(full_key))
        self.assertTrue(api_key.verify_key(full_key))
