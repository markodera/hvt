# SPDX-License-Identifier: Apache-2.0
import uuid
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from allauth.socialaccount.models import SocialAccount

from hvt.apps.organizations.models import (
    APIKey,
    ManagedBy,
    Organization,
    Project,
    ProjectPermission,
    ProjectRole,
    ProjectRolePermission,
    SocialProviderConfig,
    UserProjectRole,
)
from hvt.apps.users.models import User
from hvt.apps.authentication.models import AuditLog


class SchemaSyncAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.org = Organization.objects.create(name="Acme Corp", slug="acme")
        self.project = Project.objects.create(organization=self.org, name="Platform", slug="platform")

        # Provisioning Management Key with schema:sync
        mgmt_prefix, self.mgmt_raw, mgmt_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        self.mgmt_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="CI Sync Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=mgmt_prefix,
            hashed_key=mgmt_hash,
            scopes=["schema:sync"],
        )

        # Plan-only Key with schema:plan
        plan_prefix, self.plan_raw, plan_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        self.plan_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="PR Plan Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=plan_prefix,
            hashed_key=plan_hash,
            scopes=["schema:plan"],
        )

        self.sync_url = f"/api/v1/organizations/current/projects/{self.project.id}/sync/"

    def test_first_sync_mints_runtime_client_key(self):
        manifest = {
            "schema_version": 1,
            "permissions": [{"slug": "posts.read", "name": "Read Posts"}],
            "roles": [{"slug": "reader", "name": "Reader", "permissions": ["posts.read"]}],
        }

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(self.sync_url, manifest, format="json")

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data["status"], "applied")
        self.assertIsNotNone(res.data["client_key"])
        self.assertTrue(res.data["client_key"].startswith("hvt_test_"))
        self.assertIsNotNone(res.data["client_key_prefix"])

        # Check DB
        self.assertTrue(ProjectPermission.objects.filter(project=self.project, slug="posts.read").exists())
        self.assertTrue(ProjectRole.objects.filter(project=self.project, slug="reader").exists())

    def test_repeat_sync_returns_client_key_null(self):
        manifest = {
            "schema_version": 1,
            "permissions": [{"slug": "posts.read", "name": "Read Posts"}],
        }

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        # First sync
        res1 = self.client.post(self.sync_url, manifest, format="json")
        first_key = res1.data["client_key"]
        first_prefix = res1.data["client_key_prefix"]

        # Second sync
        res2 = self.client.post(self.sync_url, manifest, format="json")
        self.assertEqual(res2.status_code, status.HTTP_200_OK)
        self.assertIsNone(res2.data["client_key"])
        self.assertEqual(res2.data["client_key_prefix"], first_prefix)

    def test_issue_client_key_param_mints_extra_key(self):
        manifest = {"schema_version": 1}

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res1 = self.client.post(self.sync_url, manifest, format="json")
        self.assertIsNotNone(res1.data["client_key"])

        # Sync with issue_client_key=true
        res2 = self.client.post(f"{self.sync_url}?issue_client_key=true", manifest, format="json")
        self.assertEqual(res2.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(res2.data["client_key"])
        self.assertNotEqual(res1.data["client_key_prefix"], res2.data["client_key_prefix"])

    def test_dry_run_persists_nothing_and_returns_null_client_key(self):
        manifest = {
            "schema_version": 1,
            "permissions": [{"slug": "ephemeral.perm", "name": "Ephemeral"}],
        }

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(f"{self.sync_url}?dry_run=true", manifest, format="json")

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data["status"], "planned")
        self.assertIsNone(res.data["client_key"])

        # Check DB was rolled back
        self.assertFalse(ProjectPermission.objects.filter(project=self.project, slug="ephemeral.perm").exists())

    def test_schema_plan_scope_allows_dry_run_rejects_apply(self):
        manifest = {"schema_version": 1}

        self.client.credentials(HTTP_X_API_KEY=self.plan_raw)
        # Apply attempt without dry_run=true
        res_apply = self.client.post(self.sync_url, manifest, format="json")
        self.assertEqual(res_apply.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("schema:plan", str(res_apply.data))

        # Dry run with schema:plan
        res_plan = self.client.post(f"{self.sync_url}?dry_run=true", manifest, format="json")
        self.assertEqual(res_plan.status_code, status.HTTP_200_OK)
        self.assertEqual(res_plan.data["status"], "planned")

    def test_adoption_of_dashboard_created_objects(self):
        # Create dashboard-owned perm and role
        perm = ProjectPermission.objects.create(
            project=self.project, slug="comments.create", name="Create Comments", managed_by=ManagedBy.DASHBOARD
        )
        role = ProjectRole.objects.create(
            project=self.project, slug="author", name="Author", managed_by=ManagedBy.DASHBOARD
        )

        manifest = {
            "schema_version": 1,
            "permissions": [{"slug": "comments.create", "name": "Create Comments (Manifest)"}],
            "roles": [{"slug": "author", "name": "Author", "permissions": ["comments.create"]}],
        }

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(self.sync_url, manifest, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)

        perm.refresh_from_db()
        role.refresh_from_db()
        self.assertEqual(perm.managed_by, ManagedBy.MANIFEST)
        self.assertEqual(perm.name, "Create Comments (Manifest)")
        self.assertEqual(role.managed_by, ManagedBy.MANIFEST)

        actions = [c["action"] for c in res.data["changes"]]
        self.assertIn("adopted", actions)

    def test_pruning_and_safety_checks(self):
        # 1. Dashboard-owned role not in manifest is NOT pruned
        dashboard_role = ProjectRole.objects.create(
            project=self.project, slug="super-mod", name="Mod", managed_by=ManagedBy.DASHBOARD
        )
        # 2. Manifest-owned role without users IS pruned
        stale_role = ProjectRole.objects.create(
            project=self.project, slug="stale-role", name="Stale", managed_by=ManagedBy.MANIFEST
        )
        # 3. Manifest-owned role WITH assigned user is BLOCKED from prune
        busy_role = ProjectRole.objects.create(
            project=self.project, slug="busy-role", name="Busy", managed_by=ManagedBy.MANIFEST
        )
        user = User.objects.create_user(
            email="busy@example.com", password="Password123!", organization=self.org, project=self.project
        )
        UserProjectRole.objects.create(user=user, role=busy_role)

        # Manifest containing neither stale_role nor busy_role
        manifest = {"schema_version": 1}

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(f"{self.sync_url}?prune=true", manifest, format="json")
        # Should be blocked because busy_role has assigned users
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Cannot prune role 'busy-role'", str(res.data))

        # Dashboard role and stale role still exist
        self.assertTrue(ProjectRole.objects.filter(id=dashboard_role.id).exists())
        self.assertTrue(ProjectRole.objects.filter(id=stale_role.id).exists())

        # Now remove user assignment and retry
        UserProjectRole.objects.filter(user=user, role=busy_role).delete()
        res_ok = self.client.post(f"{self.sync_url}?prune=true", manifest, format="json")
        self.assertEqual(res_ok.status_code, status.HTTP_200_OK)

        # Stale role and busy role are pruned; dashboard role is untouched!
        self.assertFalse(ProjectRole.objects.filter(id=stale_role.id).exists())
        self.assertFalse(ProjectRole.objects.filter(id=busy_role.id).exists())
        self.assertTrue(ProjectRole.objects.filter(id=dashboard_role.id).exists())

    def test_social_provider_secret_handling_and_redaction(self):
        # 1. New provider requires client_secret
        manifest_missing_secret = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "google",
                    "client_id": "google-client-id-123",
                    "allowed_redirect_uris": ["http://localhost:3000/callback"],
                }
            ],
        }
        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res_fail = self.client.post(self.sync_url, manifest_missing_secret, format="json")
        self.assertEqual(res_fail.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("client_secret is required", str(res_fail.data))

        # 2. Creating with client_secret
        manifest_create = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "google",
                    "client_id": "google-client-id-123",
                    "client_secret": "my-google-secret-xyz",
                    "allowed_redirect_uris": ["http://localhost:3000/callback"],
                }
            ],
        }
        res_create = self.client.post(self.sync_url, manifest_create, format="json")
        self.assertEqual(res_create.status_code, status.HTTP_200_OK)
        # Assert secret is redacted from response
        self.assertNotIn("my-google-secret-xyz", str(res_create.data))

        sp = SocialProviderConfig.objects.get(project=self.project, provider="google")
        self.assertEqual(sp.client_secret, "my-google-secret-xyz")

        # 3. Update provider without client_secret retains existing secret
        manifest_update = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "google",
                    "client_id": "google-client-id-NEW",
                    "allowed_redirect_uris": ["http://localhost:3000/callback"],
                }
            ],
        }
        res_update = self.client.post(self.sync_url, manifest_update, format="json")
        self.assertEqual(res_update.status_code, status.HTTP_200_OK)

        sp.refresh_from_db()
        self.assertEqual(sp.client_id, "google-client-id-NEW")
        self.assertEqual(sp.client_secret, "my-google-secret-xyz")  # Retained!

    def test_redirect_uri_security_validation(self):
        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)

        # Wildcard rejected
        bad_manifest_1 = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "github",
                    "client_id": "gh-1",
                    "client_secret": "sec",
                    "allowed_redirect_uris": ["https://*.example.com/callback"],
                }
            ],
        }
        res1 = self.client.post(self.sync_url, bad_manifest_1, format="json")
        self.assertEqual(res1.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("wildcards", str(res1.data))

        # Fragment rejected
        bad_manifest_2 = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "github",
                    "client_id": "gh-1",
                    "client_secret": "sec",
                    "allowed_redirect_uris": ["https://example.com/callback#token"],
                }
            ],
        }
        res2 = self.client.post(self.sync_url, bad_manifest_2, format="json")
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("fragments", str(res2.data))

        # Plain HTTP to non-localhost rejected
        bad_manifest_3 = {
            "schema_version": 1,
            "social_providers": [
                {
                    "provider": "github",
                    "client_id": "gh-1",
                    "client_secret": "sec",
                    "allowed_redirect_uris": ["http://external.example.com/callback"],
                }
            ],
        }
        res3 = self.client.post(self.sync_url, bad_manifest_3, format="json")
        self.assertEqual(res3.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("HTTPS is required", str(res3.data))

    def test_key_and_url_project_mismatch_returns_404(self):
        other_project = Project.objects.create(organization=self.org, name="Other", slug="other")
        mismatched_url = f"/api/v1/organizations/current/projects/{other_project.id}/sync/"

        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(mismatched_url, {"schema_version": 1}, format="json")
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_yaml_payload_sync(self):
        yaml_content = """
schema_version: 1
permissions:
  - slug: yaml.perm
    name: YAML Permission
roles:
  - slug: yaml.role
    name: YAML Role
    permissions:
      - yaml.perm
"""
        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(
            self.sync_url,
            data=yaml_content,
            content_type="application/x-yaml",
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(ProjectPermission.objects.filter(project=self.project, slug="yaml.perm").exists())

    def test_option_c_test_management_key_blocked_on_live_project(self):
        # Create an active live key on this project
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Live Key",
            environment="live",
            key_type=APIKey.KeyType.RUNTIME,
            prefix="livepref",
            hashed_key="hashlive",
            scopes=["auth:runtime"],
        )

        # Attempt to sync with test management key
        self.client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = self.client.post(self.sync_url, {"schema_version": 1}, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Test management keys cannot modify projects with active live keys", str(res.data))
