from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken
from unittest.mock import patch

from hvt.apps.organizations.models import Organization, OrganizationInvitation
from hvt.apps.authentication.models import AuditLog
from hvt.apps.organizations.views import _send_invitation_email


User = get_user_model()


class OrganizationInvitationAPITest(APITestCase):
    """Tests for organization invitation management and acceptance."""

    def setUp(self):
        self.invitation_expiry = timezone.now() + timedelta(days=7)
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            role="owner",
        )
        self.org = Organization.objects.create(
            name="Owner Org",
            slug="owner-org",
            owner=self.owner,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])

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

        self.other_owner = User.objects.create_user(
            email="other-owner@example.com",
            password="password123",
            role="owner",
        )
        self.other_org = Organization.objects.create(
            name="Other Org",
            slug="other-org",
            owner=self.other_owner,
        )
        self.other_owner.organization = self.other_org
        self.other_owner.save(update_fields=["organization"])

    @patch("hvt.apps.organizations.views._send_invitation_email", return_value=True)
    def test_owner_can_create_invitation(self, mock_send_invitation_email):
        self.client.force_authenticate(user=self.owner)

        response = self.client.post(
            reverse("organization_invitation_list_create"),
            {
                "email": "invitee@example.com",
                "role": "admin",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        invitation = OrganizationInvitation.objects.get(email="invitee@example.com")
        self.assertEqual(invitation.organization, self.org)
        self.assertEqual(invitation.invited_by, self.owner)
        self.assertEqual(invitation.role, OrganizationInvitation.Role.ADMIN)
        self.assertTrue(invitation.token)
        self.assertIn("/invite?token=", response.data["accept_url"])
        mock_send_invitation_email.assert_called_once()

    @patch("hvt.apps.organizations.views.ResendEmailService.send", return_value={"id": "email_123"})
    def test_invitation_email_uses_branded_templates(self, mock_send):
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.ADMIN,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        sent = _send_invitation_email(invitation)

        self.assertTrue(sent)
        mock_send.assert_called_once()
        kwargs = mock_send.call_args.kwargs
        self.assertIn(self.org.name, kwargs["subject"])
        self.assertIn("Accept invitation", kwargs["html"])
        self.assertIn("hvts.app", kwargs["html"])
        self.assertIn("/invite?token=", kwargs["text"])

    def test_admin_cannot_create_invitation(self):
        self.client.force_authenticate(user=self.admin)

        response = self.client.post(
            reverse("organization_invitation_list_create"),
            {
                "email": "invitee@example.com",
                "role": "member",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(OrganizationInvitation.objects.filter(email="invitee@example.com").exists())

    def test_owner_lists_only_current_org_invitations(self):
        own_invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )
        OrganizationInvitation.objects.create(
            organization=self.other_org,
            email="other-invitee@example.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.other_owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=self.owner)
        response = self.client.get(reverse("organization_invitation_list_create"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        invitation_ids = {item["id"] for item in response.data["results"]}
        self.assertEqual(invitation_ids, {str(own_invitation.id)})

    def test_owner_can_revoke_pending_invitation(self):
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=self.owner)
        response = self.client.delete(
            reverse("organization_invitation_revoke", kwargs={"pk": invitation.id})
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        invitation.refresh_from_db()
        self.assertIsNotNone(invitation.revoked_at)

    @patch("hvt.apps.organizations.views._send_invitation_email", return_value=True)
    def test_owner_can_resend_pending_invitation(self, mock_send_invitation_email):
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            reverse("organization_invitation_resend", kwargs={"pk": invitation.id}),
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "pending")
        mock_send_invitation_email.assert_called_once_with(invitation)
        self.assertTrue(
            AuditLog.objects.filter(
                event_type=AuditLog.EventType.ORG_INVITATION_RESENT,
                organization=self.org,
                target_object_id=invitation.id,
            ).exists()
        )

    def test_lookup_invitation_returns_public_preview(self):
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.ADMIN,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        response = self.client.get(
            reverse("organization_invitation_lookup"),
            {"token": invitation.token},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["organization_name"], self.org.name)
        self.assertEqual(response.data["organization_slug"], self.org.slug)
        self.assertEqual(response.data["role"], OrganizationInvitation.Role.ADMIN)
        self.assertEqual(response.data["status"], "pending")
        self.assertEqual(response.data["invited_by_email"], self.owner.email)

    def test_accept_invitation_assigns_user_to_org_and_role(self):
        invitee = User.objects.create_user(
            email="invitee@example.com",
            password="password123",
        )
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email=invitee.email,
            role=OrganizationInvitation.Role.ADMIN,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        invitee.refresh_from_db()
        invitation.refresh_from_db()
        self.assertEqual(invitee.organization, self.org)
        self.assertEqual(invitee.role, User.Role.ADMIN)
        self.assertEqual(invitation.accepted_by, invitee)
        self.assertIsNotNone(invitation.accepted_at)
        self.assertEqual(response.data["status"], "accepted")

    def test_accept_invitation_rotates_auth_tokens_for_immediate_access(self):
        invitee = User.objects.create_user(
            email="invitee@example.com",
            password="password123",
        )
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email=invitee.email,
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("auth-token", response.cookies)
        self.assertIn("refresh-token", response.cookies)
        access_token = AccessToken(response.cookies["auth-token"].value)
        self.assertEqual(access_token["org_id"], str(self.org.id))
        self.assertEqual(access_token["role"], User.Role.MEMBER)

        me_response = self.client.get(reverse("current_user"))
        self.assertEqual(me_response.status_code, status.HTTP_200_OK)
        self.assertEqual(me_response.data["organization"], self.org.id)

    def test_accept_invitation_requires_matching_email(self):
        invitee = User.objects.create_user(
            email="different@example.com",
            password="password123",
        )
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        invitee.refresh_from_db()
        self.assertIsNone(invitee.organization)

    def test_accept_expired_invitation_is_rejected(self):
        invitee = User.objects.create_user(
            email="invitee@example.com",
            password="password123",
        )
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email=invitee.email,
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=timezone.now() - timedelta(days=1),
        )

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data["detail"]), "This invitation has expired.")
        invitee.refresh_from_db()
        self.assertIsNone(invitee.organization)

    def test_accept_invitation_rejects_user_with_existing_organization(self):
        invitee = User.objects.create_user(
            email="invitee@example.com",
            password="password123",
        )
        existing_org = Organization.objects.create(
            name="Existing Org",
            slug="existing-org-for-invitee",
            owner=invitee,
        )
        invitee.organization = existing_org
        invitee.role = User.Role.OWNER
        invitee.save(update_fields=["organization", "role"])

        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email=invitee.email,
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        invitee.refresh_from_db()
        self.assertEqual(invitee.organization, existing_org)

    def test_revoked_invitation_cannot_be_accepted(self):
        invitee = User.objects.create_user(
            email="invitee@example.com",
            password="password123",
        )
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email=invitee.email,
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=self.invitation_expiry,
        )
        invitation.revoked_at = invitation.created_at
        invitation.save(update_fields=["revoked_at"])

        self.client.force_authenticate(user=invitee)
        response = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": invitation.token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        invitee.refresh_from_db()
        self.assertIsNone(invitee.organization)
