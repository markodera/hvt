"""
Comprehensive test cases for Role-Based Permission System.
Tests owner/admin/member roles and their permissions.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status

from hvt.apps.organizations.models import Organization, APIKey
from hvt.apps.authentication.permissions import (
    IsOrgAdminOrAPIKey,
    IsOrgOwnerOrAPIKey,
    IsOrgMemberOrAPIKey,
    IsSelfOrOrgAdmin,
    CanChangeRole,
)

User = get_user_model()


class UserRoleModelTest(TestCase):
    """Test User model role-related methods"""

    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )
        self.org.owner = self.owner
        self.org.save()

    def test_is_org_owner(self):
        """Test is_org_owner() method"""
        self.assertTrue(self.owner.is_org_owner())
        self.assertFalse(self.admin.is_org_owner())
        self.assertFalse(self.member.is_org_owner())

    def test_is_org_admin(self):
        """Test is_org_admin() method (includes owner)"""
        self.assertTrue(self.owner.is_org_admin())
        self.assertTrue(self.admin.is_org_admin())
        self.assertFalse(self.member.is_org_admin())

    def test_can_manage_users(self):
        """Test can_manage_users() method"""
        self.assertTrue(self.owner.can_manage_users())
        self.assertTrue(self.admin.can_manage_users())
        self.assertFalse(self.member.can_manage_users())

    def test_can_manage_api_keys(self):
        """Test can_manage_api_keys() method (owner only)"""
        self.assertTrue(self.owner.can_manage_api_keys())
        self.assertFalse(self.admin.can_manage_api_keys())
        self.assertFalse(self.member.can_manage_api_keys())

    def test_can_manage_organization(self):
        """Test can_manage_organization() method (owner only)"""
        self.assertTrue(self.owner.can_manage_organization())
        self.assertFalse(self.admin.can_manage_organization())
        self.assertFalse(self.member.can_manage_organization())

    def test_role_choices(self):
        """Test role choices are valid"""
        self.assertEqual(User.Role.OWNER, "owner")
        self.assertEqual(User.Role.ADMIN, "admin")
        self.assertEqual(User.Role.MEMBER, "member")


class IsOrgMemberOrAPIKeyPermissionTest(TestCase):
    """Test IsOrgMemberOrAPIKey permission class"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )
        self.user_no_org = User.objects.create_user(
            email="noorg@example.com", password="password123"
        )

        # Create API key
        prefix, self.api_key_full, hashed = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            prefix=prefix,
            hashed_key=hashed,
            scopes=["read"],
        )

        self.permission = IsOrgMemberOrAPIKey()

    def test_org_member_allowed(self):
        """Org member should have access"""
        request = self.factory.get("/test/")
        request.user = self.member
        request.auth = None

        self.assertTrue(self.permission.has_permission(request, None))

    def test_user_without_org_denied(self):
        """User without organization should be denied"""
        request = self.factory.get("/test/")
        request.user = self.user_no_org
        request.auth = None

        self.assertFalse(self.permission.has_permission(request, None))

    def test_api_key_allowed(self):
        """API key should grant access"""
        request = self.factory.get("/test/")
        request.user = None
        request.auth = self.api_key

        self.assertTrue(self.permission.has_permission(request, None))


class IsOrgAdminOrAPIKeyPermissionTest(TestCase):
    """Test IsOrgAdminOrAPIKey permission class"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )

        prefix, _, hashed = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            prefix=prefix,
            hashed_key=hashed,
            scopes=["read"],
        )

        self.permission = IsOrgAdminOrAPIKey()

    def test_owner_allowed(self):
        """Owner should have access"""
        request = self.factory.get("/test/")
        request.user = self.owner
        request.auth = None

        self.assertTrue(self.permission.has_permission(request, None))

    def test_admin_allowed(self):
        """Admin should have access"""
        request = self.factory.get("/test/")
        request.user = self.admin
        request.auth = None

        self.assertTrue(self.permission.has_permission(request, None))

    def test_member_denied(self):
        """Member should be denied"""
        request = self.factory.get("/test/")
        request.user = self.member
        request.auth = None

        self.assertFalse(self.permission.has_permission(request, None))

    def test_api_key_allowed(self):
        """API key should grant access"""
        request = self.factory.get("/test/")
        request.user = None
        request.auth = self.api_key

        self.assertTrue(self.permission.has_permission(request, None))


class IsOrgOwnerOrAPIKeyPermissionTest(TestCase):
    """Test IsOrgOwnerOrAPIKey permission class"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )

        prefix, _, hashed = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            name="Test Key",
            prefix=prefix,
            hashed_key=hashed,
            scopes=["read"],
        )

        self.permission = IsOrgOwnerOrAPIKey()

    def test_owner_allowed(self):
        """Owner should have access"""
        request = self.factory.get("/test/")
        request.user = self.owner
        request.auth = None

        self.assertTrue(self.permission.has_permission(request, None))

    def test_admin_denied(self):
        """Admin should be denied"""
        request = self.factory.get("/test/")
        request.user = self.admin
        request.auth = None

        self.assertFalse(self.permission.has_permission(request, None))

    def test_member_denied(self):
        """Member should be denied"""
        request = self.factory.get("/test/")
        request.user = self.member
        request.auth = None

        self.assertFalse(self.permission.has_permission(request, None))

    def test_api_key_allowed(self):
        """API key should grant access"""
        request = self.factory.get("/test/")
        request.user = None
        request.auth = self.api_key

        self.assertTrue(self.permission.has_permission(request, None))


class IsSelfOrOrgAdminPermissionTest(TestCase):
    """Test IsSelfOrOrgAdmin permission class"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member1 = User.objects.create_user(
            email="member1@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )
        self.member2 = User.objects.create_user(
            email="member2@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )

        self.permission = IsSelfOrOrgAdmin()

    def test_user_can_edit_self(self):
        """User should be able to edit their own profile"""
        request = self.factory.patch("/test/")
        request.user = self.member1
        request.auth = None

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.member1)
        )

    def test_member_cannot_edit_other_member(self):
        """Member should not be able to edit another member"""
        request = self.factory.patch("/test/")
        request.user = self.member1
        request.auth = None

        self.assertFalse(
            self.permission.has_object_permission(request, None, self.member2)
        )

    def test_admin_can_edit_member(self):
        """Admin should be able to edit member"""
        request = self.factory.patch("/test/")
        request.user = self.admin
        request.auth = None

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.member1)
        )

    def test_owner_can_edit_anyone(self):
        """Owner should be able to edit anyone"""
        request = self.factory.patch("/test/")
        request.user = self.owner
        request.auth = None

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.member1)
        )
        self.assertTrue(
            self.permission.has_object_permission(request, None, self.admin)
        )


class CanChangeRolePermissionTest(TestCase):
    """Test CanChangeRole permission class"""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )

        self.permission = CanChangeRole()

    def test_owner_can_promote_member_to_admin(self):
        """Owner should be able to promote member to admin"""
        request = self.factory.patch("/test/", data={"role": "admin"})
        request.user = self.owner
        request.auth = None
        request.data = {"role": "admin"}

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.member)
        )

    def test_owner_can_promote_to_owner(self):
        """Owner should be able to transfer ownership"""
        request = self.factory.patch("/test/")
        request.user = self.owner
        request.auth = None
        request.data = {"role": "owner"}

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.admin)
        )

    def test_admin_can_promote_member_to_admin(self):
        """Admin should be able to promote member to admin"""
        request = self.factory.patch("/test/")
        request.user = self.admin
        request.auth = None
        request.data = {"role": "admin"}

        self.assertTrue(
            self.permission.has_object_permission(request, None, self.member)
        )

    def test_admin_cannot_promote_to_owner(self):
        """Admin should NOT be able to promote to owner"""
        request = self.factory.patch("/test/")
        request.user = self.admin
        request.auth = None
        request.data = {"role": "owner"}

        self.assertFalse(
            self.permission.has_object_permission(request, None, self.member)
        )

    def test_member_cannot_change_roles(self):
        """Member should NOT be able to change roles"""
        request = self.factory.patch("/test/")
        request.user = self.member
        request.auth = None
        request.data = {"role": "admin"}

        self.assertFalse(
            self.permission.has_object_permission(request, None, self.member)
        )

    def test_owner_cannot_demote_self(self):
        """Owner should NOT be able to demote themselves"""
        request = self.factory.patch("/test/")
        request.user = self.owner
        request.auth = None
        request.data = {"role": "admin"}

        self.assertFalse(
            self.permission.has_object_permission(request, None, self.owner)
        )

    def test_cross_org_role_change_denied(self):
        """Cannot change roles for users in different org"""
        other_org = Organization.objects.create(name="Other Org", slug="other-org")
        other_member = User.objects.create_user(
            email="other@example.com",
            password="password123",
            organization=other_org,
            role="member",
        )

        request = self.factory.patch("/test/")
        request.user = self.owner
        request.auth = None
        request.data = {"role": "admin"}

        self.assertFalse(
            self.permission.has_object_permission(request, None, other_member)
        )


class RoleUpdateEndpointTest(APITestCase):
    """End-to-end tests for role update endpoint"""

    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            organization=self.org,
            role="owner",
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            organization=self.org,
            role="admin",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            organization=self.org,
            role="member",
        )
        prefix, self.api_key_full, hashed = APIKey.generate_key(environment="test")
        self.api_key_obj = APIKey.objects.create(
            organization=self.org,
            name="Role Update Test Key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed,
            is_active=True,
        )
        self.org.owner = self.owner
        self.org.save()

    def test_owner_can_promote_member_to_admin(self):
        """Owner should be able to promote member to admin via endpoint"""
        self.client.force_authenticate(user=self.owner)

        response = self.client.patch(
            f"/api/v1/users/{self.member.id}/role/", {"role": "admin"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.member.refresh_from_db()
        self.assertEqual(self.member.role, "admin")

    def test_admin_cannot_promote_to_owner(self):
        """Admin should NOT be able to promote member to owner via endpoint"""
        self.client.force_authenticate(user=self.admin)

        response = self.client.patch(
            f"/api/v1/users/{self.member.id}/role/", {"role": "owner"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.member.refresh_from_db()
        self.assertEqual(self.member.role, "member")

    def test_member_cannot_change_any_roles(self):
        """Member should NOT be able to change any roles"""
        self.client.force_authenticate(user=self.member)

        response = self.client.patch(
            f"/api/v1/users/{self.admin.id}/role/", {"role": "member"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_owner_demote_admin_to_member(self):
        """Owner should be able to demote admin to member"""
        self.client.force_authenticate(user=self.owner)

        response = self.client.patch(
            f"/api/v1/users/{self.admin.id}/role/", {"role": "member"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, "member")

    def test_api_key_cannot_change_roles(self):
        """API keys should not be able to change roles."""
        self.client.credentials(HTTP_X_API_KEY=self.api_key_full)

        response = self.client.patch(
            f"/api/v1/users/{self.member.id}/role/", {"role": "admin"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.member.refresh_from_db()
        self.assertEqual(self.member.role, "member")
