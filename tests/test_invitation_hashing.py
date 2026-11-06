# SPDX-License-Identifier: Apache-2.0
"""
Tests for Item 7: Invitation tokens (organization and runtime) hashed at rest.
- Tokens stored as SHA-256 hashes at rest
- Raw token shown once at creation, not in subsequent list/detail reads
- Token lookup and acceptance work by matching SHA-256 hash of incoming raw token
- Pending unhashed invitations migrated and remain accepted by their raw token
- Invitation resend rotates to new raw token and updates hash at rest
"""

import hashlib
import secrets
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.urls import reverse
from django.utils import timezone
from rest_framework import status as http_status
from rest_framework.test import APITestCase

from hvt.apps.organizations.models import (
    APIKey,
    Organization,
    OrganizationInvitation,
    Project,
    ProjectRole,
    RuntimeInvitation,
    UserProjectRole,
)
import importlib
hash_migration = importlib.import_module(
    "hvt.apps.organizations.migrations.0026_hash_existing_invitation_tokens"
)
hash_existing_invitation_tokens = hash_migration.hash_existing_invitation_tokens

User = get_user_model()


class InvitationHashingTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user(
            email="owner@invitest.com",
            password="Password123!@",
            role="owner",
        )
        self.org = Organization.objects.create(
            name="Invite Org",
            slug="invite-org",
            owner=self.owner,
            allow_signup=True,
        )
        self.owner.organization = self.org
        self.owner.save(update_fields=["organization"])
        self.project = self.org.ensure_default_project()
        self.project.frontend_url = "https://app.invitest.com"
        self.project.save(update_fields=["frontend_url", "updated_at"])

        prefix, self.full_api_key, hashed_key = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.RUNTIME
        )
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Test Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
        )

    @patch("hvt.apps.organizations.views._send_invitation_email", return_value=True)
    def test_organization_invitation_stored_as_hash_and_accepted_by_raw_token(self, mock_send_email):
        self.client.force_authenticate(user=self.owner)

        # 1. Create invitation
        response = self.client.post(
            reverse("organization_invitation_list_create"),
            {"email": "newmember@invitest.com", "role": "member"},
            format="json",
        )
        self.assertEqual(response.status_code, http_status.HTTP_201_CREATED)
        accept_url = response.data["accept_url"]
        self.assertIsNotNone(accept_url)
        parsed = urlparse(accept_url)
        raw_token = parse_qs(parsed.query)["token"][0]
        self.assertTrue(len(raw_token) > 0)

        # 2. Database stores SHA-256 hash, NOT raw token
        invitation = OrganizationInvitation.objects.get(email="newmember@invitest.com")
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertEqual(invitation.token, expected_hash)
        self.assertNotEqual(invitation.token, raw_token)

        # 3. Subsequent list does NOT expose raw token (accept_url is None)
        list_resp = self.client.get(reverse("organization_invitation_list_create"))
        self.assertEqual(list_resp.status_code, http_status.HTTP_200_OK)
        results = list_resp.data["results"]
        matching = [r for r in results if r["email"] == "newmember@invitest.com"][0]
        self.assertIsNone(matching["accept_url"])

        # 4. Lookup with raw token succeeds
        self.client.force_authenticate(user=None)
        lookup_resp = self.client.get(
            reverse("organization_invitation_lookup"),
            {"token": raw_token},
        )
        self.assertEqual(lookup_resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(lookup_resp.data["organization_slug"], self.org.slug)

        # 5. Acceptance with raw token succeeds
        invitee = User.objects.create_user(
            email="newmember@invitest.com",
            password=secrets.token_hex(16),
        )
        self.client.force_authenticate(user=invitee)
        accept_resp = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": raw_token},
            format="json",
        )
        self.assertEqual(accept_resp.status_code, http_status.HTTP_200_OK)
        invitation.refresh_from_db()
        self.assertIsNotNone(invitation.accepted_at)
        self.assertEqual(invitation.accepted_by, invitee)

    @patch("hvt.apps.organizations.views.ResendEmailService.send", return_value={"id": "em_123"})
    def test_runtime_invitation_stored_as_hash_and_accepted_by_raw_token(self, mock_email_send):
        role = ProjectRole.objects.create(
            project=self.project,
            slug="student",
            name="Student",
        )

        # 1. Create runtime invitation
        response = self.client.post(
            reverse("runtime_invitation_list_create"),
            {
                "email": "runtime_user@invitest.com",
                "role_slugs": ["student"],
                "first_name": "Alan",
                "last_name": "Turing",
            },
            format="json",
            HTTP_X_API_KEY=self.full_api_key,
        )
        self.assertEqual(response.status_code, http_status.HTTP_201_CREATED)
        raw_token = response.data.get("raw_token")
        self.assertIsNotNone(raw_token)

        # 2. Database stores SHA-256 hash
        invitation = RuntimeInvitation.objects.get(email="runtime_user@invitest.com")
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertEqual(invitation.token, expected_hash)
        self.assertNotEqual(invitation.token, raw_token)

        # 3. List does NOT expose raw_token
        list_resp = self.client.get(
            reverse("runtime_invitation_list_create"),
            HTTP_X_API_KEY=self.full_api_key,
        )
        self.assertEqual(list_resp.status_code, http_status.HTTP_200_OK)
        results = list_resp.data["results"]
        matching = [r for r in results if r["email"] == "runtime_user@invitest.com"][0]
        self.assertIsNone(matching["raw_token"])

        # 4. Accept runtime invitation using raw token
        accept_resp = self.client.post(
            reverse("runtime_invitation_accept"),
            {
                "token": raw_token,
                "password1": "SecureRuntimePass123!@",
                "password2": "SecureRuntimePass123!@",
            },
            format="json",
        )
        self.assertEqual(accept_resp.status_code, http_status.HTTP_200_OK)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, RuntimeInvitation.Status.ACCEPTED)
        self.assertTrue(
            User.objects.filter(email="runtime_user@invitest.com", project=self.project).exists()
        )

    def test_migration_hashes_existing_pending_invitations_and_preserves_acceptance(self):
        # 1. Simulate legacy unhashed organization invitation in DB
        legacy_org_raw = secrets.token_hex(32)
        inv_org = OrganizationInvitation.objects.create(
            organization=self.org,
            email="legacy_org@invitest.com",
            role=OrganizationInvitation.Role.MEMBER,
            invited_by=self.owner,
            expires_at=timezone.now() + timedelta(days=7),
        )
        # Directly update token column to unhashed raw token
        OrganizationInvitation.objects.filter(id=inv_org.id).update(token=legacy_org_raw)

        # 2. Simulate legacy unhashed runtime invitation in DB
        legacy_rt_raw = secrets.token_urlsafe(48)
        ProjectRole.objects.create(
            project=self.project,
            slug="scholar",
            name="Scholar",
        )
        inv_rt = RuntimeInvitation.objects.create(
            project=self.project,
            email="legacy_rt@invitest.com",
            role_slugs=["scholar"],
            expires_at=timezone.now() + timedelta(days=7),
        )
        RuntimeInvitation.objects.filter(id=inv_rt.id).update(token=legacy_rt_raw)

        # 3. Run migration function
        class MockSchemaEditor:
            connection = connection

        hash_existing_invitation_tokens(None, MockSchemaEditor())

        # 4. Verify tokens in DB are now SHA-256 hashes
        inv_org.refresh_from_db()
        inv_rt.refresh_from_db()
        self.assertEqual(inv_org.token, hashlib.sha256(legacy_org_raw.encode("utf-8")).hexdigest())
        self.assertEqual(inv_rt.token, hashlib.sha256(legacy_rt_raw.encode("utf-8")).hexdigest())

        # 5. Accepting with original legacy raw token still succeeds
        invitee = User.objects.create_user(
            email="legacy_org@invitest.com",
            password="LegacyPassword123!@",
        )
        self.client.force_authenticate(user=invitee)
        accept_org = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": legacy_org_raw},
            format="json",
        )
        self.assertEqual(accept_org.status_code, http_status.HTTP_200_OK)

        self.client.force_authenticate(user=None)
        accept_rt = self.client.post(
            reverse("runtime_invitation_accept"),
            {
                "token": legacy_rt_raw,
                "password1": "LegacyRtPassword123!@",
                "password2": "LegacyRtPassword123!@",
            },
            format="json",
        )
        self.assertEqual(accept_rt.status_code, http_status.HTTP_200_OK)

    @patch("hvt.apps.organizations.views._send_invitation_email", return_value=True)
    def test_resending_invitation_rotates_token_and_invalidates_previous_token(self, mock_send_email):
        self.client.force_authenticate(user=self.owner)

        # 1. Create invitation
        create_resp = self.client.post(
            reverse("organization_invitation_list_create"),
            {"email": "rotate_me@invitest.com", "role": "member"},
            format="json",
        )
        old_accept_url = create_resp.data["accept_url"]
        old_raw_token = parse_qs(urlparse(old_accept_url).query)["token"][0]
        invitation = OrganizationInvitation.objects.get(email="rotate_me@invitest.com")

        # 2. Resend invitation
        resend_resp = self.client.post(
            reverse("organization_invitation_resend", kwargs={"pk": invitation.id}),
        )
        self.assertEqual(resend_resp.status_code, http_status.HTTP_200_OK)
        new_invitation_passed_to_email = mock_send_email.call_args[0][0]
        new_raw_token = getattr(new_invitation_passed_to_email, "raw_token", None)
        self.assertIsNotNone(new_raw_token)
        self.assertNotEqual(old_raw_token, new_raw_token)

        # 3. Old raw token is rejected
        invitee = User.objects.create_user(
            email="rotate_me@invitest.com",
            password="RotatePass123!@",
        )
        self.client.force_authenticate(user=invitee)
        reject_old = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": old_raw_token},
            format="json",
        )
        self.assertEqual(reject_old.status_code, http_status.HTTP_404_NOT_FOUND)

        # 4. New raw token is accepted
        accept_new = self.client.post(
            reverse("organization_invitation_accept"),
            {"token": new_raw_token},
            format="json",
        )
        self.assertEqual(accept_new.status_code, http_status.HTTP_200_OK)
