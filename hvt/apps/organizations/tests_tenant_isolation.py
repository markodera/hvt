from django.contrib.auth import get_user_model
from django.urls import reverse
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APITestCase

from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.tokens import HVTTokenObtainPairSerializer
from hvt.apps.organizations.models import (
    APIKey,
    Organization,
    Project,
    Webhook,
    WebhookDelivery,
)


User = get_user_model()


class TenantIsolationGateTest(APITestCase):
    """
    Cross-tenant rejection gate suite.

    These tests exercise the org-scoped API surface with both JWT and API key
    credentials and ensure tenant A cannot observe or mutate tenant B data.
    """

    def setUp(self):
        self.password = "Str0ng!Pass123"

        self.org_a = Organization.objects.create(name="Org A", slug="org-a")
        self.org_b = Organization.objects.create(name="Org B", slug="org-b")

        self.owner_a = self._create_user(
            email="owner-a@example.com", organization=self.org_a, role="owner"
        )
        self.admin_a = self._create_user(
            email="admin-a@example.com", organization=self.org_a, role="admin"
        )
        self.member_a = self._create_user(
            email="member-a@example.com", organization=self.org_a, role="member"
        )

        self.owner_b = self._create_user(
            email="owner-b@example.com", organization=self.org_b, role="owner"
        )
        self.admin_b = self._create_user(
            email="admin-b@example.com", organization=self.org_b, role="admin"
        )
        self.member_b = self._create_user(
            email="member-b@example.com", organization=self.org_b, role="member"
        )

        self.org_a.owner = self.owner_a
        self.org_a.save(update_fields=["owner"])
        self.org_b.owner = self.owner_b
        self.org_b.save(update_fields=["owner"])

        self.project_a = self.org_a.ensure_default_project()
        self.project_b = self.org_b.ensure_default_project()
        self.app_user_a = self._create_user(
            email="buyer-a@example.com",
            organization=self.org_a,
            role="member",
            project=self.project_a,
        )
        self.app_user_b = self._create_user(
            email="buyer-b@example.com",
            organization=self.org_b,
            role="member",
            project=self.project_b,
        )

        self.api_key_a = self._create_api_key(
            organization=self.org_a,
            created_by=self.owner_a,
            name="Org A API Key",
            project=self.project_a,
        )
        self.api_key_b = self._create_api_key(
            organization=self.org_b,
            created_by=self.owner_b,
            name="Org B API Key",
            project=self.project_b,
        )

        self.webhook_a = self._create_webhook(
            organization=self.org_a,
            created_by=self.owner_a,
            url="https://a.example.com/webhook",
        )
        self.webhook_b = self._create_webhook(
            organization=self.org_b,
            created_by=self.owner_b,
            url="https://b.example.com/webhook",
        )

        self.webhook_a_delivery = self._create_webhook_delivery(
            webhook=self.webhook_a,
            event_type="user.created",
            payload={"user_id": str(self.member_a.id)},
        )
        self.webhook_b_delivery = self._create_webhook_delivery(
            webhook=self.webhook_b,
            event_type="user.created",
            payload={"user_id": str(self.member_b.id)},
        )

        self.audit_a_owner = self._create_audit_log(
            actor=self.owner_a,
            organization=self.org_a,
            target=self.owner_a,
            event_type=AuditLog.EventType.USER_UPDATED,
        )
        self.audit_a_member = self._create_audit_log(
            actor=self.member_a,
            organization=self.org_a,
            target=self.member_a,
            event_type=AuditLog.EventType.USER_LOGIN,
        )
        self.audit_b_owner = self._create_audit_log(
            actor=self.owner_b,
            organization=self.org_b,
            target=self.owner_b,
            event_type=AuditLog.EventType.USER_UPDATED,
        )

    def _create_user(self, email, organization, role, project=None):
        return User.objects.create_user(
            email=email,
            password=self.password,
            organization=organization,
            project=project,
            role=role,
        )

    def _create_api_key(self, organization, created_by, name, project=None):
        prefix, full_key, hashed_key = APIKey.generate_key(environment="test")
        api_key = APIKey.objects.create(
            organization=organization,
            project=project,
            created_by=created_by,
            name=name,
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["read"],
        )
        return {"key": full_key, "obj": api_key}

    def _create_webhook(self, organization, created_by, url):
        return Webhook.objects.create(
            organization=organization,
            project=organization.ensure_default_project(),
            created_by=created_by,
            url=url,
            events=["user.created"],
            secret=Webhook.generate_secret(),
            is_active=True,
            description=f"Webhook for {organization.slug}",
        )

    def _create_webhook_delivery(self, webhook, event_type, payload):
        return WebhookDelivery.objects.create(
            webhook=webhook,
            event_type=event_type,
            payload=payload,
            status=WebhookDelivery.Status.SUCCESS,
            response_status_code=200,
            response_body="ok",
        )

    def _create_audit_log(self, actor, organization, target, event_type):
        return AuditLog.log(
            event_type=event_type,
            user=actor,
            organization=organization,
            project=getattr(actor, "project", None) or organization.ensure_default_project(),
            target=target,
            event_data={"actor_email": actor.email},
            success=True,
        )

    def _jwt_authenticate(self, user):
        token = str(HVTTokenObtainPairSerializer.get_token(user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def _api_key_authenticate(self, key):
        self.client.credentials(HTTP_X_API_KEY=key)

    def _clear_auth(self):
        self.client.credentials()

    def _result_ids(self, response):
        payload = response.data.get("results", response.data)
        return {item["id"] for item in payload}

    def test_jwt_owner_cannot_access_org_b_users(self):
        self._jwt_authenticate(self.owner_a)

        list_response = self.client.get(reverse("user_list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertIn(str(self.member_a.id), self._result_ids(list_response))
        self.assertNotIn(str(self.member_b.id), self._result_ids(list_response))

        detail_response = self.client.get(reverse("user_detail", kwargs={"pk": self.member_b.id}))
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

        update_response = self.client.patch(
            reverse("user_detail", kwargs={"pk": self.member_b.id}),
            {"first_name": "Hacked"},
            format="json",
        )
        self.assertEqual(update_response.status_code, status.HTTP_404_NOT_FOUND)

        role_response = self.client.patch(
            reverse("user_role_update", kwargs={"pk": self.member_b.id}),
            {"role": "admin"},
            format="json",
        )
        self.assertEqual(role_response.status_code, status.HTTP_404_NOT_FOUND)

        with patch("hvt.apps.users.views.trigger_webhook_event"):
            create_response = self.client.post(
                reverse("user_list"),
                {
                    "email": "new-user@example.com",
                    "password": "Newpass123!",
                    "first_name": "New",
                    "last_name": "User",
                    "organization": str(self.org_b.id),
                    "role": "member",
                },
                format="json",
            )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(str(create_response.data["organization"]), str(self.org_a.id))
        self.assertFalse(User.objects.filter(email="new-user@example.com", organization=self.org_b).exists())

    def test_api_key_cannot_access_org_b_users(self):
        self._api_key_authenticate(self.api_key_a["key"])

        list_response = self.client.get(reverse("user_list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertIn(str(self.app_user_a.id), self._result_ids(list_response))
        self.assertNotIn(str(self.member_a.id), self._result_ids(list_response))
        self.assertNotIn(str(self.member_b.id), self._result_ids(list_response))
        self.assertNotIn(str(self.app_user_b.id), self._result_ids(list_response))

        detail_response = self.client.get(reverse("user_detail", kwargs={"pk": self.app_user_b.id}))
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

        update_response = self.client.patch(
            reverse("user_detail", kwargs={"pk": self.app_user_b.id}),
            {"first_name": "Hacked"},
            format="json",
        )
        self.assertEqual(update_response.status_code, status.HTTP_403_FORBIDDEN)

        create_response = self.client.post(
            reverse("user_list"),
            {
                "email": "api-key-user@example.com",
                "password": "Newpass123!",
                "first_name": "API",
                "last_name": "Key",
                "organization": str(self.org_b.id),
                "role": "member",
            },
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_current_organization_is_scoped_to_actor_org(self):
        self._jwt_authenticate(self.owner_a)
        response = self.client.get(reverse("current_organization"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], str(self.org_a.id))
        self.assertNotEqual(response.data["id"], str(self.org_b.id))

        patch_response = self.client.patch(
            reverse("current_organization"),
            {"name": "Org A Updated"},
            format="json",
        )
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)
        self.org_a.refresh_from_db()
        self.org_b.refresh_from_db()
        self.assertEqual(self.org_a.name, "Org A Updated")
        self.assertEqual(self.org_b.name, "Org B")

    def test_current_organization_allows_api_key_read_only(self):
        self._api_key_authenticate(self.api_key_a["key"])
        response = self.client.get(reverse("current_organization"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], str(self.org_a.id))

        patch_response = self.client.patch(
            reverse("current_organization"),
            {"name": "Should Not Update"},
            format="json",
        )
        self.assertEqual(patch_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_members_and_permissions_are_scoped_to_actor_org(self):
        self._jwt_authenticate(self.owner_a)

        members_response = self.client.get(reverse("organization_members"))
        self.assertEqual(members_response.status_code, status.HTTP_200_OK)
        member_ids = {item["id"] for item in members_response.data["results"]}
        self.assertIn(str(self.member_a.id), member_ids)
        self.assertNotIn(str(self.member_b.id), member_ids)

        permissions_response = self.client.get(reverse("permissions_matrix"))
        self.assertEqual(permissions_response.status_code, status.HTTP_200_OK)
        self.assertEqual(permissions_response.data["role"], "owner")
        self.assertTrue(permissions_response.data["permissions"]["users.create"])
        self.assertTrue(permissions_response.data["permissions"]["organization.update"])

    def test_member_cannot_do_admin_actions(self):
        self._jwt_authenticate(self.member_a)

        user_create = self.client.post(
            reverse("user_list"),
            {
                "email": "blocked@example.com",
                "password": "Blockedpass123!",
                "first_name": "Blocked",
                "last_name": "User",
                "organization": str(self.org_a.id),
                "role": "member",
            },
            format="json",
        )
        self.assertEqual(user_create.status_code, status.HTTP_403_FORBIDDEN)

        role_change = self.client.patch(
            reverse("user_role_update", kwargs={"pk": self.admin_a.id}),
            {"role": "member"},
            format="json",
        )
        self.assertEqual(role_change.status_code, status.HTTP_403_FORBIDDEN)

        org_patch = self.client.patch(
            reverse("current_organization"),
            {"name": "Member Should Not Update"},
            format="json",
        )
        self.assertEqual(org_patch.status_code, status.HTTP_403_FORBIDDEN)

        key_create = self.client.post(
            reverse("apikey_list_create"),
            {"name": "Blocked Key", "scopes": ["read"], "environment": "test"},
            format="json",
        )
        self.assertEqual(key_create.status_code, status.HTTP_403_FORBIDDEN)

        webhook_create = self.client.post(
            reverse("webhook_list_create"),
            {
                "url": "https://member.example.com/webhook",
                "events": ["user.created"],
                "description": "Should fail",
            },
            format="json",
        )
        self.assertEqual(webhook_create.status_code, status.HTTP_403_FORBIDDEN)

        permissions_response = self.client.get(reverse("permissions_matrix"))
        self.assertEqual(permissions_response.status_code, status.HTTP_200_OK)
        self.assertFalse(permissions_response.data["permissions"]["users.create"])
        self.assertFalse(permissions_response.data["permissions"]["organization.update"])

    def test_api_keys_are_scoped_to_actor_org(self):
        self._jwt_authenticate(self.owner_a)

        list_response = self.client.get(reverse("apikey_list_create"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        key_ids = {item["id"] for item in list_response.data["results"]}
        self.assertIn(str(self.api_key_a["obj"].id), key_ids)
        self.assertNotIn(str(self.api_key_b["obj"].id), key_ids)

        detail_response = self.client.get(
            reverse("apikey_detail", kwargs={"pk": self.api_key_b["obj"].id})
        )
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_api_key_auth_is_read_only_for_keys(self):
        self._api_key_authenticate(self.api_key_a["key"])

        list_response = self.client.get(reverse("apikey_list_create"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        key_ids = {item["id"] for item in list_response.data["results"]}
        self.assertIn(str(self.api_key_a["obj"].id), key_ids)
        self.assertNotIn(str(self.api_key_b["obj"].id), key_ids)

        create_response = self.client.post(
            reverse("apikey_list_create"),
            {"name": "Blocked Key", "scopes": ["read"], "environment": "test"},
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_webhooks_and_deliveries_are_scoped_to_actor_org(self):
        self._jwt_authenticate(self.owner_a)

        list_response = self.client.get(reverse("webhook_list_create"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        webhook_ids = {item["id"] for item in list_response.data["results"]}
        self.assertIn(str(self.webhook_a.id), webhook_ids)
        self.assertNotIn(str(self.webhook_b.id), webhook_ids)

        detail_response = self.client.get(
            reverse("webhook_detail", kwargs={"pk": self.webhook_b.id})
        )
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

        deliveries_response = self.client.get(
            reverse("webhook_delivery_list", kwargs={"webhook_pk": self.webhook_b.id})
        )
        self.assertEqual(deliveries_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_audit_logs_are_scoped_to_actor_org(self):
        self._jwt_authenticate(self.owner_a)

        list_response = self.client.get(reverse("audit_log_list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        audit_ids = {item["id"] for item in list_response.data["results"]}
        self.assertIn(str(self.audit_a_owner.id), audit_ids)
        self.assertIn(str(self.audit_a_member.id), audit_ids)
        self.assertNotIn(str(self.audit_b_owner.id), audit_ids)

        detail_response = self.client.get(
            reverse("audit_log_detail", kwargs={"pk": self.audit_b_owner.id})
        )
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_api_key_audit_logs_are_scoped_to_actor_org(self):
        self._api_key_authenticate(self.api_key_a["key"])

        list_response = self.client.get(reverse("audit_log_list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        audit_ids = {item["id"] for item in list_response.data["results"]}
        self.assertIn(str(self.audit_a_owner.id), audit_ids)
        self.assertIn(str(self.audit_a_member.id), audit_ids)
        self.assertNotIn(str(self.audit_b_owner.id), audit_ids)

        detail_response = self.client.get(
            reverse("audit_log_detail", kwargs={"pk": self.audit_b_owner.id})
        )
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)
