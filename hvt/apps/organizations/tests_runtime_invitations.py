from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from hvt.apps.authentication.models import AuditLog
from hvt.apps.organizations.models import (
    APIKey,
    Organization,
    ProjectRole,
    RuntimeInvitation,
    UserProjectRole,
)


User = get_user_model()


class RuntimeInvitationAPITest(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
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
        self.project = self.org.ensure_default_project()
        self.project.frontend_url = "https://storefront.example.com/app"
        self.project.save(update_fields=["frontend_url", "updated_at"])

        prefix, self.full_key, hashed_key = APIKey.generate_key()
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Invite Key",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
        )

        self.create_url = reverse("runtime_invitation_list_create")
        self.accept_url = reverse("runtime_invitation_accept")

    def invite_payload(self, **overrides):
        payload = {
            "email": "teacher@example.com",
            "role_slugs": ["teacher"],
            "first_name": "Ada",
            "last_name": "Lovelace",
        }
        payload.update(overrides)
        return payload

    @patch("hvt.apps.organizations.views.ResendEmailService.send", return_value={"id": "email_123"})
    def test_create_runtime_invitation_creates_record_and_sends_email(self, mock_send):
        ProjectRole.objects.create(
            project=self.project,
            slug="teacher",
            name="Teacher",
        )

        response = self.client.post(
            self.create_url,
            self.invite_payload(),
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        invitation = RuntimeInvitation.objects.get(email="teacher@example.com")
        self.assertEqual(invitation.project, self.project)
        self.assertEqual(invitation.role_slugs, ["teacher"])
        self.assertEqual(invitation.status, RuntimeInvitation.Status.PENDING)
        self.assertNotIn("token", response.data)
        self.assertNotIn("accept_url", response.data)
        self.assertTrue(
            AuditLog.objects.filter(
                event_type=AuditLog.EventType.RUNTIME_USER_INVITED,
                actor_api_key=self.api_key,
                project=self.project,
                target_object_id=invitation.id,
            ).exists()
        )
        mock_send.assert_called_once()
        self.assertIn(
            "https://storefront.example.com/app/invite/accept?token=",
            mock_send.call_args.kwargs["text"],
        )

    def test_create_runtime_invitation_rejects_control_plane_role_slug(self):
        response = self.client.post(
            self.create_url,
            self.invite_payload(role_slugs=["owner"]),
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["role_slugs"][0]),
            "Control plane roles cannot be used in runtime invitations",
        )
        self.assertFalse(RuntimeInvitation.objects.exists())

    def test_create_runtime_invitation_rejects_invalid_role_slug(self):
        response = self.client.post(
            self.create_url,
            self.invite_payload(role_slugs=["missing-role"]),
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]["role_slugs"][0]),
            "These roles do not exist in this project: missing-role",
        )
        self.assertFalse(RuntimeInvitation.objects.exists())

    def test_create_runtime_invitation_for_platform_user_returns_201_without_record(self):
        User.objects.create_user(
            email="teacher@example.com",
            password="password123",
        )
        ProjectRole.objects.create(
            project=self.project,
            slug="teacher",
            name="Teacher",
        )

        response = self.client.post(
            self.create_url,
            self.invite_payload(),
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data, {})
        self.assertFalse(RuntimeInvitation.objects.exists())

    @patch("hvt.apps.organizations.views.ResendEmailService.send", return_value={"id": "email_123"})
    def test_create_runtime_invitation_revokes_existing_pending_invite(self, mock_send):
        ProjectRole.objects.create(
            project=self.project,
            slug="teacher",
            name="Teacher",
        )
        old_invitation = RuntimeInvitation.objects.create(
            project=self.project,
            email="teacher@example.com",
            role_slugs=["teacher"],
        )

        response = self.client.post(
            self.create_url,
            self.invite_payload(),
            format="json",
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        old_invitation.refresh_from_db()
        self.assertEqual(old_invitation.status, RuntimeInvitation.Status.REVOKED)
        invitations = RuntimeInvitation.objects.filter(email="teacher@example.com").order_by("created_at")
        self.assertEqual(invitations.count(), 2)
        self.assertEqual(invitations.last().status, RuntimeInvitation.Status.PENDING)
        self.assertNotEqual(invitations.last().id, old_invitation.id)
        mock_send.assert_called_once()

    def test_create_runtime_invitation_with_platform_jwt_is_forbidden(self):
        ProjectRole.objects.create(
            project=self.project,
            slug="teacher",
            name="Teacher",
        )
        self.client.force_authenticate(user=self.owner)

        response = self.client.post(
            self.create_url,
            self.invite_payload(),
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(RuntimeInvitation.objects.exists())

    def test_list_runtime_invitations_returns_project_scoped_results(self):
        RuntimeInvitation.objects.create(
            project=self.project,
            email="pending@example.com",
            role_slugs=["teacher"],
            status=RuntimeInvitation.Status.PENDING,
        )
        RuntimeInvitation.objects.create(
            project=self.project,
            email="accepted@example.com",
            role_slugs=["teacher"],
            status=RuntimeInvitation.Status.ACCEPTED,
            accepted_at=timezone.now(),
        )

        response = self.client.get(
            self.create_url,
            {"page_size": 50, "status": "pending"},
            HTTP_X_API_KEY=self.full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["email"], "pending@example.com")
        self.assertEqual(response.data["results"][0]["status"], RuntimeInvitation.Status.PENDING)

    def test_list_runtime_invitations_requires_runtime_scope(self):
        prefix, full_key, hashed_key = APIKey.generate_key()
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="No Runtime Scope",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["users:read"],
        )

        response = self.client.get(
            self.create_url,
            HTTP_X_API_KEY=full_key,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("required auth:runtime scope", str(response.data["detail"]))

    def test_accept_runtime_invitation_creates_user_assigns_roles_and_returns_jwt(self):
        default_role = ProjectRole.objects.create(
            project=self.project,
            slug="default-student",
            name="Default Student",
            is_default_signup=True,
        )
        invited_role = ProjectRole.objects.create(
            project=self.project,
            slug="teacher",
            name="Teacher",
        )
        invitation = RuntimeInvitation.objects.create(
            project=self.project,
            email="teacher@example.com",
            role_slugs=[invited_role.slug],
        )

        response = self.client.post(
            self.accept_url,
            {
                "token": invitation.token,
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        created_user = User.objects.get(email="teacher@example.com", project=self.project)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, RuntimeInvitation.Status.ACCEPTED)
        self.assertIsNotNone(invitation.accepted_at)
        self.assertTrue(
            UserProjectRole.objects.filter(user=created_user, role=default_role).exists()
        )
        self.assertTrue(
            UserProjectRole.objects.filter(user=created_user, role=invited_role).exists()
        )
        self.assertIn("auth-token", response.cookies)
        access_token = AccessToken(response.cookies["auth-token"].value)
        self.assertEqual(access_token["project_id"], str(self.project.id))
        self.assertEqual(
            set(access_token["app_roles"]),
            {"default-student", "teacher"},
        )
        self.assertTrue(
            AuditLog.objects.filter(
                event_type=AuditLog.EventType.RUNTIME_USER_INVITE_ACCEPTED,
                actor_user=created_user,
                project=self.project,
                target_object_id=invitation.id,
            ).exists()
        )

    def test_accept_runtime_invitation_rejects_expired_token(self):
        invitation = RuntimeInvitation.objects.create(
            project=self.project,
            email="teacher@example.com",
            role_slugs=["teacher"],
            expires_at=timezone.now() - timedelta(hours=1),
        )

        response = self.client.post(
            self.accept_url,
            {
                "token": invitation.token,
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data["detail"]), "This invitation has expired")
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, RuntimeInvitation.Status.EXPIRED)

    def test_accept_runtime_invitation_rejects_already_accepted_token(self):
        invitation = RuntimeInvitation.objects.create(
            project=self.project,
            email="teacher@example.com",
            role_slugs=["teacher"],
            status=RuntimeInvitation.Status.ACCEPTED,
            accepted_at=timezone.now(),
        )

        response = self.client.post(
            self.accept_url,
            {
                "token": invitation.token,
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["detail"]),
            "This invitation is no longer valid",
        )

    def test_accept_runtime_invitation_rejects_invalid_token(self):
        response = self.client.post(
            self.accept_url,
            {
                "token": "invalid-token",
                "password1": "Strongpass123!",
                "password2": "Strongpass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
