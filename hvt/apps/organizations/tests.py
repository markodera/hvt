"""
Comprehensive test cases for Test/Live API Key environment isolation.
Tests that test and live environments are completely isolated.
"""
from datetime import timedelta
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient, APIRequestFactory
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken
from unittest.mock import patch

from hvt.apps.organizations.models import (
    Organization,
    Project,
    APIKey,
    ProjectPermission,
    ProjectRole,
    SocialProviderConfig,
    UserProjectRole,
    Webhook,
)
from hvt.apps.authentication.models import AuditLog
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
        self.assertIsInstance(user, AnonymousUser)
        self.assertIsInstance(auth, APIKey)
        self.assertEqual(auth.id, self.test_api_key.id)
        self.assertTrue(auth.is_test)

    def test_authenticate_with_live_key(self):
        """Should authenticate successfully with live key"""
        request = self.factory.get("/api/test/", HTTP_X_API_KEY=self.live_full_key)

        result = self.auth_backend.authenticate(request)

        self.assertIsNotNone(result)
        user, auth = result
        self.assertIsInstance(user, AnonymousUser)
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


class OrganizationOnboardingFlowTest(APITestCase):
    """Tests for organization onboarding and ownership behavior."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="founder@example.com",
            password="password123",
        )

    def test_first_organization_creation_assigns_owner_membership(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.post(
            reverse("organization_list"),
            {
                "name": "Founder Org",
                "slug": "founder-org",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.user.refresh_from_db()
        created_org = Organization.objects.get(slug="founder-org")
        self.assertEqual(created_org.owner, self.user)
        self.assertEqual(self.user.organization, created_org)
        self.assertEqual(self.user.role, User.Role.OWNER)

    def test_user_cannot_create_second_org_during_single_org_launch(self):
        existing_org = Organization.objects.create(
            name="Existing Org",
            slug="existing-org",
            owner=self.user,
        )
        self.user.organization = existing_org
        self.user.role = User.Role.OWNER
        self.user.save(update_fields=["organization", "role"])

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            reverse("organization_list"),
            {
                "name": "Second Org",
                "slug": "second-org",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertFalse(Organization.objects.filter(slug="second-org").exists())
        self.assertEqual(Organization.objects.filter(owner=self.user).count(), 1)
        self.assertEqual(self.user.organization, existing_org)
        self.assertEqual(self.user.role, User.Role.OWNER)
        self.assertIn("single-organization launch", str(response.data).lower())

    def test_user_cannot_create_org_when_already_member(self):
        existing_org = Organization.objects.create(
            name="Member Org",
            slug="member-org",
            owner=self.user,
        )
        self.user.organization = existing_org
        self.user.role = User.Role.MEMBER
        self.user.save(update_fields=["organization", "role"])

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            reverse("organization_list"),
            {
                "name": "Another Org",
                "slug": "another-org",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Organization.objects.filter(slug="another-org").exists())
        self.assertIn("single-organization launch", str(response.data).lower())


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class OrganizationTokenBootstrapFlowTest(APITestCase):
    """First-org creation should rotate tokens so the new owner can continue immediately."""

    def setUp(self):
        from allauth.account.models import EmailAddress

        self.user = User.objects.create_user(
            email="bootstrap-owner@example.com",
            password="password123",
        )
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            verified=True,
            primary=True,
        )

    def test_first_org_creation_rotates_tokens_for_immediate_current_org_updates(self):
        login_response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "password123"},
            format="json",
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        create_response = self.client.post(
            reverse("organization_list"),
            {
                "name": "Bootstrap Org",
                "slug": "bootstrap-org",
            },
            format="json",
        )

        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertIn("auth-token", create_response.cookies)
        self.assertIn("refresh-token", create_response.cookies)

        access_token = AccessToken(create_response.cookies["auth-token"].value)
        created_org = Organization.objects.get(slug="bootstrap-org")
        self.assertEqual(access_token["org_id"], str(created_org.id))

        patch_response = self.client.patch(
            reverse("current_organization"),
            {"name": "Bootstrap Org Updated"},
            format="json",
        )

        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)
        self.assertEqual(patch_response.data["name"], "Bootstrap Org Updated")


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class OrganizationDetailOwnerUpdateCompatibilityTest(APITestCase):
    """Owner updates by org id should work for frontend compatibility."""

    def setUp(self):
        from allauth.account.models import EmailAddress

        self.owner = User.objects.create_user(
            email="detail-owner@example.com",
            password="password123",
            role=User.Role.OWNER,
        )
        EmailAddress.objects.create(
            user=self.owner,
            email=self.owner.email,
            verified=True,
            primary=True,
        )
        self.org = Organization.objects.create(
            name="Detail Org",
            slug="detail-org",
            owner=self.owner,
            allow_signup=False,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])

        self.other_user = User.objects.create_user(
            email="detail-other@example.com",
            password="password123",
            role=User.Role.ADMIN,
        )
        EmailAddress.objects.create(
            user=self.other_user,
            email=self.other_user.email,
            verified=True,
            primary=True,
        )
        self.other_org = Organization.objects.create(
            name="Other Detail Org",
            slug="other-detail-org",
            owner=self.other_user,
        )
        self.other_user.organization = self.other_org
        self.other_user.save(update_fields=["organization"])

    def test_owner_can_patch_own_organization_by_id(self):
        login_response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.owner.email, "password": "password123"},
            format="json",
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        response = self.client.patch(
            reverse("organization_detail", kwargs={"pk": self.org.id}),
            {"allow_signup": True},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.org.refresh_from_db()
        self.assertTrue(self.org.allow_signup)

    def test_non_owner_cannot_patch_other_organization_by_id(self):
        self.client.force_authenticate(user=self.other_user)

        response = self.client.patch(
            reverse("organization_detail", kwargs={"pk": self.org.id}),
            {"allow_signup": True},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class ProjectAndAPIKeyScopingTest(APITestCase):
    """Project bootstrapping and project-aware API key behavior."""

    def setUp(self):
        cache.clear()
        from allauth.account.models import EmailAddress

        self.owner = User.objects.create_user(
            email="project-owner@example.com",
            password="password123",
            role=User.Role.OWNER,
        )
        EmailAddress.objects.create(
            user=self.owner,
            email=self.owner.email,
            verified=True,
            primary=True,
        )
        self.org = Organization.objects.create(
            name="Project Org",
            slug="project-org",
            owner=self.owner,
            allow_signup=False,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()
        self.client.post(
            "/api/v1/auth/login/",
            {"email": self.owner.email, "password": "password123"},
            format="json",
        )

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def test_org_creation_bootstraps_default_project(self):
        founder = User.objects.create_user(
            email="fresh-founder@example.com",
            password="password123",
        )
        from allauth.account.models import EmailAddress

        EmailAddress.objects.create(
            user=founder,
            email=founder.email,
            verified=True,
            primary=True,
        )
        self.client.post(
            "/api/v1/auth/login/",
            {"email": founder.email, "password": "password123"},
            format="json",
        )

        response = self.client.post(
            reverse("organization_list"),
            {"name": "Fresh Org", "slug": "fresh-org"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        created_org = Organization.objects.get(slug="fresh-org")
        project = created_org.projects.get(is_default=True)
        self.assertEqual(project.slug, "default")
        self.assertEqual(project.allow_signup, created_org.allow_signup)

    def test_owner_can_create_project(self):
        response = self.client.post(
            reverse("project_list_create"),
            {"name": "Storefront Prod", "slug": "storefront-prod", "allow_signup": True},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["slug"], "storefront-prod")
        self.assertFalse(response.data["is_default"])
        self.assertTrue(
            Project.objects.filter(
                organization=self.org,
                slug="storefront-prod",
            ).exists()
        )
        audit_log = AuditLog.objects.filter(
            event_type=AuditLog.EventType.PROJECT_CREATED,
            organization=self.org,
            project__slug="storefront-prod",
        ).latest("created_at")
        self.assertEqual(audit_log.event_data["slug"], "storefront-prod")

    def test_owner_can_create_project_with_frontend_url(self):
        response = self.client.post(
            reverse("project_list_create"),
            {
                "name": "Storefront Runtime",
                "slug": "storefront-runtime",
                "allow_signup": True,
                "frontend_url": "https://storefront.example.com/",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        project = Project.objects.get(
            organization=self.org,
            slug="storefront-runtime",
        )
        self.assertEqual(project.frontend_url, "https://storefront.example.com")
        self.assertEqual(
            response.data["frontend_url"],
            "https://storefront.example.com",
        )

    def test_owner_can_create_project_with_allowed_origins(self):
        response = self.client.post(
            reverse("project_list_create"),
            {
                "name": "Storefront Preview",
                "slug": "storefront-preview",
                "allow_signup": True,
                "frontend_url": "https://storefront.example.com/app",
                "allowed_origins": [
                    "https://preview.example.com:3000/path",
                    "http://localhost:3000",
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        project = Project.objects.get(
            organization=self.org,
            slug="storefront-preview",
        )
        self.assertEqual(
            project.allowed_origins,
            ["https://preview.example.com:3000", "http://localhost:3000"],
        )
        self.assertEqual(
            response.data["allowed_origins"],
            ["https://preview.example.com:3000", "http://localhost:3000"],
        )

    def test_api_key_creation_defaults_to_default_project(self):
        response = self.client.post(
            reverse("apikey_list_create"),
            {"name": "Default Project Key", "scopes": ["read:org"]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        api_key = APIKey.objects.get(id=response.data["id"])
        self.assertEqual(api_key.project_id, self.default_project.id)
        self.assertEqual(str(response.data["project"]), str(self.default_project.id))
        self.assertEqual(response.data["project_slug"], self.default_project.slug)

    def test_api_key_creation_accepts_explicit_project(self):
        project = Project.objects.create(
            organization=self.org,
            name="Storefront Prod",
            slug="storefront-prod",
            allow_signup=True,
        )

        response = self.client.post(
            reverse("apikey_list_create"),
            {
                "name": "Storefront Key",
                "scopes": ["read:org"],
                "project_id": str(project.id),
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        api_key = APIKey.objects.get(id=response.data["id"])
        self.assertEqual(api_key.project_id, project.id)
        self.assertEqual(response.data["project_slug"], "storefront-prod")

    def test_api_key_creation_rejects_unknown_scope(self):
        response = self.client.post(
            reverse("apikey_list_create"),
            {"name": "Bad Scope Key", "scopes": ["totally:unknown"]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("unsupported api key scopes", str(response.data).lower())

    def test_api_key_creation_rejects_past_expiry(self):
        response = self.client.post(
            reverse("apikey_list_create"),
            {
                "name": "Expired On Arrival",
                "scopes": ["api_keys:read"],
                "expires_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expires_at", response.data["detail"])

    @override_settings(API_KEY_MAX_PER_PROJECT=1)
    def test_api_key_creation_enforces_project_cap(self):
        first_response = self.client.post(
            reverse("apikey_list_create"),
            {"name": "First Key", "scopes": ["api_keys:read"]},
            format="json",
        )
        self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)

        second_response = self.client.post(
            reverse("apikey_list_create"),
            {"name": "Second Key", "scopes": ["api_keys:read"]},
            format="json",
        )

        self.assertEqual(second_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("api key limit", str(second_response.data).lower())
        self.assertEqual(
            APIKey.objects.filter(project=self.default_project).count(),
            1,
        )

    def test_api_key_list_marks_expired_key_as_expired(self):
        prefix, _, hashed_key = APIKey.generate_key(environment="test")
        expired_key = APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Expired Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["api_keys:read"],
            expires_at=timezone.now() - timedelta(minutes=5),
        )

        response = self.client.get(reverse("apikey_list_create"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        listed_key = next(item for item in response.data["results"] if item["id"] == str(expired_key.id))
        self.assertEqual(listed_key["status"], "expired")
        self.assertTrue(listed_key["is_expired"])
        self.assertFalse(listed_key["is_valid"])

    def test_api_key_scope_is_enforced_for_users_read(self):
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")
        APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Org Read Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["organization:read"],
        )

        api_client = APIClient()
        response = api_client.get(
            reverse("user_list"),
            HTTP_X_API_KEY=full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_project_scoped_api_key_only_sees_project_webhooks_and_audit_logs(self):
        other_project = Project.objects.create(
            organization=self.org,
            name="Storefront Staging",
            slug="storefront-staging",
            allow_signup=True,
        )
        default_webhook = Webhook.objects.create(
            organization=self.org,
            project=self.default_project,
            url="https://default.example.com/hook",
            events=["user.created"],
            secret=Webhook.generate_secret(),
            is_active=True,
            created_by=self.owner,
        )
        Webhook.objects.create(
            organization=self.org,
            project=other_project,
            url="https://staging.example.com/hook",
            events=["user.created"],
            secret=Webhook.generate_secret(),
            is_active=True,
            created_by=self.owner,
        )
        visible_audit = AuditLog.objects.create(
            event_type=AuditLog.EventType.USER_UPDATED,
            actor_user=self.owner,
            organization=self.org,
            project=self.default_project,
            success=True,
        )
        AuditLog.objects.create(
            event_type=AuditLog.EventType.USER_UPDATED,
            actor_user=self.owner,
            organization=self.org,
            project=other_project,
            success=True,
        )
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")
        APIKey.objects.create(
            organization=self.org,
            project=self.default_project,
            name="Scoped Read Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["webhooks:read", "audit_logs:read"],
        )

        api_client = APIClient()
        webhook_response = api_client.get(
            reverse("webhook_list_create"),
            HTTP_X_API_KEY=full_key,
        )
        audit_response = api_client.get(
            reverse("audit_log_list"),
            HTTP_X_API_KEY=full_key,
        )

        self.assertEqual(webhook_response.status_code, status.HTTP_200_OK)
        self.assertEqual(audit_response.status_code, status.HTTP_200_OK)
        self.assertEqual(webhook_response.data["results"][0]["id"], str(default_webhook.id))
        self.assertEqual(len(webhook_response.data["results"]), 1)
        self.assertEqual(audit_response.data["results"][0]["id"], str(visible_audit.id))
        self.assertEqual(len(audit_response.data["results"]), 1)

    def test_org_signup_toggle_syncs_default_project(self):
        response = self.client.patch(
            reverse("current_organization"),
            {"allow_signup": True},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.default_project.refresh_from_db()
        self.assertTrue(self.default_project.allow_signup)

    def test_project_update_uses_project_updated_audit_event(self):
        response = self.client.patch(
            reverse("project_detail", kwargs={"pk": self.default_project.id}),
            {"name": "Default App"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        audit_log = AuditLog.objects.filter(
            event_type=AuditLog.EventType.PROJECT_UPDATED,
            organization=self.org,
            project=self.default_project,
        ).latest("created_at")
        self.assertIn("name", audit_log.event_data["changes"])

    @patch("hvt.apps.organizations.views.trigger_webhook_event")
    def test_project_lifecycle_triggers_webhooks(self, mock_trigger):
        create_response = self.client.post(
            reverse("project_list_create"),
            {"name": "Storefront Prod", "slug": "storefront-prod", "allow_signup": True},
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        project_id = create_response.data["id"]

        update_response = self.client.patch(
            reverse("project_detail", kwargs={"pk": project_id}),
            {"name": "Storefront Production"},
            format="json",
        )
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)

        delete_response = self.client.delete(
            reverse("project_detail", kwargs={"pk": project_id}),
        )
        self.assertEqual(delete_response.status_code, status.HTTP_204_NO_CONTENT)

        called_events = [call.kwargs["event_type"] for call in mock_trigger.call_args_list]
        self.assertIn("project.created", called_events)
        self.assertIn("project.updated", called_events)
        self.assertIn("project.deleted", called_events)


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class ProjectAccessManagementTest(APITestCase):
    """Project-scoped roles, permissions, and assignment management."""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="access-owner@example.com",
            password="password123",
            role=User.Role.OWNER,
        )
        self.admin = User.objects.create_user(
            email="access-admin@example.com",
            password="password123",
            role=User.Role.ADMIN,
        )
        self.member = User.objects.create_user(
            email="access-member@example.com",
            password="password123",
            role=User.Role.MEMBER,
        )
        self.runtime_user = User.objects.create_user(
            email="runtime-buyer@example.com",
            password="password123",
            role=User.Role.MEMBER,
        )
        self.org = Organization.objects.create(
            name="Access Org",
            slug="access-org",
            owner=self.owner,
            allow_signup=True,
        )
        for user in (self.owner, self.admin, self.member, self.runtime_user):
            user.organization = self.org
            user.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()

    def test_admin_can_create_project_permission(self):
        self.client.force_authenticate(user=self.admin)

        response = self.client.post(
            reverse(
                "project_permission_list_create",
                kwargs={"project_pk": self.default_project.id},
            ),
            {
                "slug": "orders.read.own",
                "name": "Read Own Orders",
                "description": "Allow a buyer to read only their own orders.",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            ProjectPermission.objects.filter(
                project=self.default_project,
                slug="orders.read.own",
            ).exists()
        )

    def test_admin_can_create_role_with_permissions(self):
        permission = ProjectPermission.objects.create(
            project=self.default_project,
            slug="orders.read.own",
            name="Read Own Orders",
        )
        self.client.force_authenticate(user=self.admin)

        response = self.client.post(
            reverse(
                "project_role_list_create",
                kwargs={"project_pk": self.default_project.id},
            ),
            {
                "slug": "buyer",
                "name": "Buyer",
                "is_default_signup": True,
                "is_self_assignable": True,
                "permission_ids": [str(permission.id)],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role = ProjectRole.objects.get(project=self.default_project, slug="buyer")
        self.assertEqual(list(role.permissions.values_list("slug", flat=True)), ["orders.read.own"])
        self.assertTrue(role.is_self_assignable)
        self.assertTrue(response.data["is_self_assignable"])

    def test_member_cannot_manage_project_roles(self):
        self.client.force_authenticate(user=self.member)

        response = self.client.post(
            reverse(
                "project_role_list_create",
                kwargs={"project_pk": self.default_project.id},
            ),
            {
                "slug": "buyer",
                "name": "Buyer",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_owner_can_replace_user_project_roles(self):
        buyer_permission = ProjectPermission.objects.create(
            project=self.default_project,
            slug="orders.read.own",
            name="Read Own Orders",
        )
        seller_permission = ProjectPermission.objects.create(
            project=self.default_project,
            slug="orders.write.own",
            name="Write Own Orders",
        )
        buyer_role = ProjectRole.objects.create(
            project=self.default_project,
            slug="buyer",
            name="Buyer",
        )
        seller_role = ProjectRole.objects.create(
            project=self.default_project,
            slug="verified_seller",
            name="Verified Seller",
        )
        buyer_role.permissions.add(buyer_permission)
        seller_role.permissions.add(seller_permission)
        self.client.force_authenticate(user=self.owner)

        response = self.client.put(
            reverse(
                "project_user_role_assignment",
                kwargs={
                    "project_pk": self.default_project.id,
                    "user_pk": self.runtime_user.id,
                },
            ),
            {"role_slugs": ["buyer", "verified_seller"]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(response.data["permissions"]),
            {"orders.read.own", "orders.write.own"},
        )
        self.assertEqual(
            {item["slug"] for item in response.data["roles"]},
            {"buyer", "verified_seller"},
        )
        self.assertTrue(
            UserProjectRole.objects.filter(user=self.runtime_user, role=buyer_role).exists()
        )
        self.assertTrue(
            UserProjectRole.objects.filter(user=self.runtime_user, role=seller_role).exists()
        )

    def test_owner_replace_user_project_roles_rejects_unknown_slug(self):
        self.client.force_authenticate(user=self.owner)

        response = self.client.put(
            reverse(
                "project_user_role_assignment",
                kwargs={
                    "project_pk": self.default_project.id,
                    "user_pk": self.runtime_user.id,
                },
            ),
            {"role_slugs": ["missing-role"]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["role_slugs"][0]),
            "These roles do not exist in this project: missing-role",
        )

    def test_current_project_access_returns_effective_permissions(self):
        permission = ProjectPermission.objects.create(
            project=self.default_project,
            slug="orders.read.own",
            name="Read Own Orders",
        )
        role = ProjectRole.objects.create(
            project=self.default_project,
            slug="buyer",
            name="Buyer",
        )
        role.permissions.add(permission)
        UserProjectRole.objects.create(user=self.member, role=role, assigned_by=self.owner)
        self.client.force_authenticate(user=self.member)

        response = self.client.get(
            reverse(
                "current_project_access",
                kwargs={"project_pk": self.default_project.id},
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["permissions"], ["orders.read.own"])
        self.assertEqual(response.data["roles"][0]["slug"], "buyer")

    def test_current_project_access_allows_cross_project_role_assignment(self):
        secondary_project = Project.objects.create(
            organization=self.org,
            name="Secondary Store",
            slug="secondary-store",
            allow_signup=True,
        )
        permission = ProjectPermission.objects.create(
            project=secondary_project,
            slug="orders.read.secondary",
            name="Read Secondary Orders",
        )
        role = ProjectRole.objects.create(
            project=secondary_project,
            slug="secondary-buyer",
            name="Secondary Buyer",
        )
        role.permissions.add(permission)
        self.member.project = self.default_project
        self.member.save(update_fields=["project"])
        UserProjectRole.objects.create(
            user=self.member,
            role=role,
            assigned_by=self.owner,
        )
        self.client.force_authenticate(user=self.member)

        response = self.client.get(
            reverse(
                "current_project_access",
                kwargs={"project_pk": secondary_project.id},
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["permissions"], ["orders.read.secondary"])
        self.assertEqual(response.data["roles"][0]["slug"], "secondary-buyer")

    def test_role_delete_is_blocked_when_assigned(self):
        role = ProjectRole.objects.create(
            project=self.default_project,
            slug="buyer",
            name="Buyer",
        )
        UserProjectRole.objects.create(user=self.runtime_user, role=role, assigned_by=self.owner)
        self.client.force_authenticate(user=self.owner)

        response = self.client.delete(
            reverse(
                "project_role_detail",
                kwargs={"project_pk": self.default_project.id, "pk": role.id},
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(ProjectRole.objects.filter(id=role.id).exists())

    def test_permission_delete_is_blocked_when_linked_to_role(self):
        permission = ProjectPermission.objects.create(
            project=self.default_project,
            slug="orders.read.own",
            name="Read Own Orders",
        )
        role = ProjectRole.objects.create(
            project=self.default_project,
            slug="buyer",
            name="Buyer",
        )
        role.permissions.add(permission)
        self.client.force_authenticate(user=self.owner)

        response = self.client.delete(
            reverse(
                "project_permission_detail",
                kwargs={"project_pk": self.default_project.id, "pk": permission.id},
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(ProjectPermission.objects.filter(id=permission.id).exists())


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class ProjectSocialProviderConfigTest(APITestCase):
    """Project social provider config CRUD and deletion safety."""

    def setUp(self):
        cache.clear()
        from allauth.account.models import EmailAddress

        self.owner = User.objects.create_user(
            email="provider-owner@example.com",
            password="password123",
            role=User.Role.OWNER,
        )
        EmailAddress.objects.create(
            user=self.owner,
            email=self.owner.email,
            verified=True,
            primary=True,
        )
        self.org = Organization.objects.create(
            name="Provider Org",
            slug="provider-org",
            owner=self.owner,
            allow_signup=True,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.default_project = self.org.ensure_default_project()
        self.client.post(
            "/api/v1/auth/login/",
            {"email": self.owner.email, "password": "password123"},
            format="json",
        )

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def test_owner_can_create_project_social_provider_config(self):
        response = self.client.post(
            reverse(
                "social_provider_config_list_create",
                kwargs={"project_pk": self.default_project.id},
            ),
            {
                "provider": "google",
                "client_id": "google-client-id",
                "client_secret": "google-secret-value",
                "redirect_uris": ["http://localhost:3000/auth/google/callback"],
                "is_active": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["has_client_secret"])
        self.assertEqual(response.data["client_secret_last4"], "alue")
        config = SocialProviderConfig.objects.get(project=self.default_project, provider="google")
        self.assertEqual(config.client_id, "google-client-id")
        self.assertEqual(
            config.redirect_uris,
            ["http://localhost:3000/auth/google/callback"],
        )
        audit_log = AuditLog.objects.filter(
            event_type=AuditLog.EventType.PROJECT_SOCIAL_PROVIDER_CREATED,
            organization=self.org,
            project=self.default_project,
        ).latest("created_at")
        self.assertEqual(audit_log.event_data["provider"], "google")

    def test_project_delete_is_blocked_when_social_provider_config_exists(self):
        project = Project.objects.create(
            organization=self.org,
            name="Storefront Prod",
            slug="storefront-prod",
            allow_signup=True,
        )
        SocialProviderConfig.objects.create(
            project=project,
            provider="google",
            client_id="google-client-id",
            client_secret="google-secret-value",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )

        response = self.client.delete(
            reverse("project_detail", kwargs={"pk": project.id}),
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("social provider configs", str(response.data))

    def test_social_provider_update_uses_project_social_provider_updated_event(self):
        config = SocialProviderConfig.objects.create(
            project=self.default_project,
            provider="google",
            client_id="google-client-id",
            client_secret="google-secret-value",
            redirect_uris=["http://localhost:3000/auth/google/callback"],
            is_active=True,
        )

        response = self.client.patch(
            reverse(
                "social_provider_config_detail",
                kwargs={"project_pk": self.default_project.id, "pk": config.id},
            ),
            {"client_id": "updated-client-id"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        audit_log = AuditLog.objects.filter(
            event_type=AuditLog.EventType.PROJECT_SOCIAL_PROVIDER_UPDATED,
            organization=self.org,
            project=self.default_project,
        ).latest("created_at")
        self.assertEqual(audit_log.event_data["provider"], "google")
        self.assertIn("client_id", audit_log.event_data["changes"])

    @patch("hvt.apps.organizations.views.trigger_webhook_event")
    def test_social_provider_lifecycle_triggers_webhooks(self, mock_trigger):
        create_response = self.client.post(
            reverse(
                "social_provider_config_list_create",
                kwargs={"project_pk": self.default_project.id},
            ),
            {
                "provider": "google",
                "client_id": "google-client-id",
                "client_secret": "google-secret-value",
                "redirect_uris": ["http://localhost:3000/auth/google/callback"],
                "is_active": True,
            },
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        config_id = create_response.data["id"]

        update_response = self.client.patch(
            reverse(
                "social_provider_config_detail",
                kwargs={"project_pk": self.default_project.id, "pk": config_id},
            ),
            {"client_id": "updated-client-id"},
            format="json",
        )
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)

        delete_response = self.client.delete(
            reverse(
                "social_provider_config_detail",
                kwargs={"project_pk": self.default_project.id, "pk": config_id},
            )
        )
        self.assertEqual(delete_response.status_code, status.HTTP_204_NO_CONTENT)

        called_events = [call.kwargs["event_type"] for call in mock_trigger.call_args_list]
        self.assertIn("project.social_provider.created", called_events)
        self.assertIn("project.social_provider.updated", called_events)
        self.assertIn("project.social_provider.deleted", called_events)
