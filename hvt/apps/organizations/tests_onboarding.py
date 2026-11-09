from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from hvt.apps.authentication.models import AuditLog
from hvt.apps.organizations.models import APIKey, Organization, Project, ProjectRole
from hvt.apps.users.models import User


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class OnboardingFlowBackendTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", return_value=None)
    def test_control_plane_signup_auto_provisions_org_and_default_test_project(self, mock_send_mail):
        """Registering a new control-plane user automatically provisions their workspace and default project."""
        signup_data = {
            "email": "fresh-dev@example.com",
            "password1": "SecurePass123!",
            "password2": "SecurePass123!",
            "first_name": "Dev",
            "last_name": "Tester",
        }
        response = self.client.post("/api/v1/auth/register/", signup_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email="fresh-dev@example.com")
        self.assertIsNotNone(user.organization)
        self.assertEqual(user.role, User.Role.OWNER)
        self.assertIn("Dev's Workspace", user.organization.name)

        # Default project exists in test mode
        default_project = user.organization.projects.filter(is_default=True).first()
        self.assertIsNotNone(default_project)
        self.assertEqual(default_project.slug, "default")
        self.assertTrue(default_project.allow_signup)

    @patch("hvt.apps.authentication.adapters.ResendAccountAdapter.send_mail", side_effect=Exception("SMTP down"))
    def test_registration_atomic_rollback_on_email_failure_leaves_no_zombies(self, mock_send_mail):
        """If email setup or dispatch crashes, transaction.atomic rolls back all User, Org, and Project records."""
        signup_data = {
            "email": "limbo-victim@example.com",
            "password1": "SecurePass123!",
            "password2": "SecurePass123!",
            "first_name": "Victim",
            "last_name": "Limbo",
        }
        response = self.client.post("/api/v1/auth/register/", signup_data)
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR])

        # Assert no zombie user was created
        self.assertFalse(User.objects.filter(email="limbo-victim@example.com").exists())
        # Assert no orphaned organization was created
        self.assertFalse(Organization.objects.filter(name__icontains="Victim's Workspace").exists())

    def test_onboarding_status_endpoint(self):
        """GET /api/v1/organizations/current/projects/<id>/onboarding/ returns 4 live checklist steps."""
        owner = User.objects.create_user(
            email="founder@example.com",
            password="StrongPass123!",
            role=User.Role.OWNER,
        )
        org = Organization.objects.create(name="Acme", slug="acme", owner=owner)
        owner.organization = org
        owner.save(update_fields=["organization"])
        project = org.ensure_default_project()

        self.client.force_authenticate(user=owner)
        url = f"/api/v1/organizations/current/projects/{project.id}/onboarding/"

        # 1. Initial status: project_created=True, others False
        res = self.client.get(url)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        data = res.data
        self.assertTrue(data["project_created"])
        self.assertFalse(data["schema_synced"])
        self.assertFalse(data["first_signup"])
        self.assertFalse(data["first_login"])
        self.assertFalse(data["all_completed"])
        self.assertTrue(data["can_use_setup_prompt"])

        # 2. Schema synced: create a project role
        ProjectRole.objects.create(
            project=project,
            name="Member",
            slug="member",
            is_default_signup=True,
        )
        res = self.client.get(url)
        self.assertTrue(res.data["schema_synced"])
        self.assertFalse(res.data["all_completed"])

        # 3. First signup: runtime user created for this project
        User.objects.create_user(
            email="enduser@customer.com",
            password="StrongPass123!",
            organization=org,
            project=project,
            role=User.Role.MEMBER,
        )
        res = self.client.get(url)
        self.assertTrue(res.data["first_signup"])
        self.assertFalse(res.data["all_completed"])

        # 4. First login: USER_LOGIN audit log recorded for this project
        AuditLog.objects.create(
            event_type=AuditLog.EventType.USER_LOGIN,
            organization=org,
            project=project,
            success=True,
            event_data={"email": "enduser@customer.com"},
        )
        res = self.client.get(url)
        self.assertTrue(res.data["first_login"])
        self.assertTrue(res.data["all_completed"])

    def test_passwordless_and_social_logins_complete_first_login_onboarding(self):
        """Verify MAGIC_LINK_VERIFIED, PASSKEY_LOGIN, SOCIAL_LOGIN, and RUNTIME_USER_INVITE_ACCEPTED mark first_login=True."""
        owner = User.objects.create_user(
            email="founder@example.com",
            password="StrongPass123!",
            role=User.Role.OWNER,
        )
        org = Organization.objects.create(name="Gamma Labs", slug="gamma-labs", owner=owner)
        owner.organization = org
        owner.save(update_fields=["organization"])
        project = org.ensure_default_project()

        ProjectRole.objects.create(
            project=project,
            name="Member",
            slug="member",
            is_default_signup=True,
        )
        runtime_user = User.objects.create_user(
            email="runtime@gamma.com",
            password="StrongPass123!",
            organization=org,
            project=project,
            role=User.Role.MEMBER,
        )

        self.client.force_authenticate(user=owner)
        url = f"/api/v1/organizations/current/projects/{project.id}/onboarding/"

        # Initially false
        res = self.client.get(url)
        self.assertFalse(res.data["first_login"])

        # Test each passwordless/runtime event type
        passwordless_events = [
            AuditLog.EventType.MAGIC_LINK_VERIFIED,
            AuditLog.EventType.PASSKEY_LOGIN,
            AuditLog.EventType.SOCIAL_LOGIN,
            AuditLog.EventType.RUNTIME_USER_INVITE_ACCEPTED,
        ]

        for evt in passwordless_events:
            log_entry = AuditLog.log(
                event_type=evt,
                user=runtime_user,
                project=project,
                event_data={"email": runtime_user.email, "project_id": str(project.id)},
                success=True,
            )
            res = self.client.get(url)
            self.assertTrue(
                res.data["first_login"],
                f"Expected first_login to be True after event {evt}"
            )
            self.assertTrue(res.data["all_completed"])
            log_entry.delete()

    def test_setup_prompt_generation_and_option_c_lock(self):
        """POST setup-prompt mints temporary 15-minute test management key and enforces Option C."""
        owner = User.objects.create_user(
            email="lead@example.com",
            password="StrongPass123!",
            role=User.Role.OWNER,
        )
        org = Organization.objects.create(name="Beta Labs", slug="beta-labs", owner=owner)
        owner.organization = org
        owner.save(update_fields=["organization"])
        project = org.ensure_default_project()

        self.client.force_authenticate(user=owner)
        url = f"/api/v1/organizations/current/projects/{project.id}/setup-prompt/"

        # 1. Generate prompt
        res = self.client.post(url)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(res.data["key"].startswith("hvt_mgmt_test_"))
        self.assertIn("••••••••••••••••", res.data["masked_key"])
        self.assertEqual(res.data["expires_in_seconds"], 900)
        self.assertIn("HVT_MANAGEMENT_KEY", res.data["prompt"])
        self.assertIn("HVT_API_URL", res.data["prompt"])
        self.assertIn("HVT_PROJECT_ID", res.data["prompt"])
        self.assertIn("--project ", res.data["prompt"])
        self.assertIn(str(project.id), res.data["prompt"])

        # Verify key exists in DB with 15-minute expiry and provisioning scopes
        key_obj = APIKey.objects.get(prefix=res.data["prefix"])
        self.assertEqual(key_obj.key_type, APIKey.KeyType.MANAGEMENT)
        self.assertEqual(key_obj.environment, APIKey.Environment.TEST)
        self.assertTrue(key_obj.has_scope("schema:sync"))
        self.assertFalse(key_obj.has_scope("auth:runtime"))

        # 2. Option C lock: Add active live key -> setup-prompt must be blocked
        prefix, full_live, hashed_live = APIKey.generate_key(
            environment=APIKey.Environment.LIVE,
            key_type=APIKey.KeyType.RUNTIME,
        )
        APIKey.objects.create(
            name="Production Runtime Key",
            prefix=prefix,
            hashed_key=hashed_live,
            environment=APIKey.Environment.LIVE,
            key_type=APIKey.KeyType.RUNTIME,
            organization=org,
            project=project,
            scopes=["auth:runtime"],
            is_active=True,
            expires_at=timezone.now() + timedelta(days=30),
        )

        res_locked = self.client.post(url)
        self.assertEqual(res_locked.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Option C plane isolation", res_locked.data["detail"])


    def test_setup_prompt_via_management_key(self):
        """Management API key with schema:sync can generate setup prompt via X-API-Key."""
        owner = User.objects.create_user(
            email="api-owner@example.com",
            password="StrongPass123!",
            role=User.Role.OWNER,
        )
        org = Organization.objects.create(name="Delta Labs", slug="delta-labs", owner=owner)
        owner.organization = org
        owner.save(update_fields=["organization"])
        project = org.ensure_default_project()

        prefix, full_mgmt, hashed_mgmt = APIKey.generate_key(
            environment=APIKey.Environment.TEST,
            key_type=APIKey.KeyType.MANAGEMENT,
        )
        APIKey.objects.create(
            name="CI Management Key",
            prefix=prefix,
            hashed_key=hashed_mgmt,
            environment=APIKey.Environment.TEST,
            key_type=APIKey.KeyType.MANAGEMENT,
            organization=org,
            project=project,
            created_by=owner,
            scopes=["schema:plan", "schema:sync"],
            is_active=True,
            expires_at=timezone.now() + timedelta(days=7),
        )

        url = f"/api/v1/organizations/current/projects/{project.id}/setup-prompt/"

        # Unauthenticated client calling with X-API-Key
        anon_client = APIClient()
        res = anon_client.post(url, HTTP_X_API_KEY=full_mgmt)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(res.data["key"].startswith("hvt_mgmt_test_"))
        self.assertIn(str(project.id), res.data["prompt"])

        # Mismatched project key should be denied
        other_project = Project.objects.create(name="Other", slug="other", organization=org)
        other_url = f"/api/v1/organizations/current/projects/{other_project.id}/setup-prompt/"
        res_mismatch = anon_client.post(other_url, HTTP_X_API_KEY=full_mgmt)
        self.assertEqual(res_mismatch.status_code, status.HTTP_403_FORBIDDEN)
