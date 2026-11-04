# SPDX-License-Identifier: Apache-2.0
from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError
from rest_framework import exceptions, permissions
from rest_framework.views import APIView
from rest_framework.response import Response

from hvt.apps.organizations.models import Organization, Project, APIKey
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.backends import (
    RuntimeAPIKeyAuthentication,
    ManagementAPIKeyAuthentication,
    APIKeyAuthentication,
)
from hvt.apps.authentication.permissions import _allow_api_key
from hvt.api.v1.serializers.organizations import APIKeyCreateSerializer


class DummyWriteViewWithoutScopes(APIView):
    pass


class DummyWriteViewWithScopes(APIView):
    api_key_write_scopes = ("schema:sync",)


class PlaneSeparationAndAuthTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.org = Organization.objects.create(name="Acme Corp", slug="acme")
        self.project = Project.objects.create(organization=self.org, name="App", slug="app")

        # Create runtime key
        rt_prefix, self.rt_raw, rt_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.RUNTIME
        )
        self.rt_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Client Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=rt_prefix,
            hashed_key=rt_hash,
            scopes=["auth:runtime"],
        )

        # Create management key
        mgmt_prefix, self.mgmt_raw, mgmt_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        self.mgmt_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Management Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=mgmt_prefix,
            hashed_key=mgmt_hash,
            scopes=["schema:sync"],
        )

    def test_key_generation_formats(self):
        self.assertTrue(self.rt_raw.startswith("hvt_test_"))
        self.assertTrue(self.mgmt_raw.startswith("hvt_mgmt_test_"))

        # Live formats
        _, live_rt, _ = APIKey.generate_key(environment="live", key_type=APIKey.KeyType.RUNTIME)
        _, live_mgmt, _ = APIKey.generate_key(environment="live", key_type=APIKey.KeyType.MANAGEMENT)
        self.assertTrue(live_rt.startswith("hvt_live_"))
        self.assertTrue(live_mgmt.startswith("hvt_mgmt_live_"))

    def test_scope_implications(self):
        # schema:sync implies roles:write, permissions:write, providers:write, schema:plan
        self.assertTrue(self.mgmt_key.has_scope("roles:write"))
        self.assertTrue(self.mgmt_key.has_scope("permissions:write"))
        self.assertTrue(self.mgmt_key.has_scope("providers:write"))
        self.assertTrue(self.mgmt_key.has_scope("schema:plan"))
        self.assertTrue(self.mgmt_key.has_scope("roles:read"))

        # Create key with only schema:plan
        plan_prefix, plan_raw, plan_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        plan_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Plan Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=plan_prefix,
            hashed_key=plan_hash,
            scopes=["schema:plan"],
        )
        self.assertTrue(plan_key.has_scope("schema:plan"))
        self.assertTrue(plan_key.has_scope("roles:read"))
        self.assertFalse(plan_key.has_scope("schema:sync"))
        self.assertFalse(plan_key.has_scope("roles:write"))

    def test_clean_enforces_plane_scopes(self):
        # Runtime key with provisioning scope
        invalid_rt = APIKey(
            organization=self.org,
            project=self.project,
            name="Bad RT",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            scopes=["schema:sync"],
        )
        with self.assertRaises(ValidationError):
            invalid_rt.clean()

        # Management key with runtime auth scope
        invalid_mgmt = APIKey(
            organization=self.org,
            project=self.project,
            name="Bad MGMT",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            scopes=["auth:runtime"],
        )
        with self.assertRaises(ValidationError):
            invalid_mgmt.clean()

        # Management key with api_keys:write
        invalid_mgmt_key_mgmt = APIKey(
            organization=self.org,
            project=self.project,
            name="Bad MGMT 2",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            scopes=["api_keys:write"],
        )
        with self.assertRaises(ValidationError):
            invalid_mgmt_key_mgmt.clean()

    def test_runtime_auth_rejects_management_key_with_exact_403_and_audit_log(self):
        request = self.factory.get("/api/v1/auth/runtime/me/")
        auth = RuntimeAPIKeyAuthentication()

        # Management key presented to runtime authentication class
        with self.assertRaises(exceptions.PermissionDenied) as ctx:
            auth.validate_key(self.mgmt_raw, request=request)

        self.assertEqual(
            str(ctx.exception),
            "Management keys cannot be used for runtime authentication. Use a runtime client key.",
        )

        # Check AuditLog security event
        log = AuditLog.objects.filter(
            event_type=AuditLog.EventType.SECURITY_VIOLATION
        ).latest("created_at")
        self.assertFalse(log.success)
        self.assertEqual(
            log.error_message,
            "Management keys cannot be used for runtime authentication. Use a runtime client key.",
        )
        self.assertEqual(log.actor_api_key, self.mgmt_key)

    def test_management_auth_rejects_runtime_key(self):
        request = self.factory.post("/api/v1/organizations/current/projects/sync/")
        auth = ManagementAPIKeyAuthentication()

        with self.assertRaises(exceptions.PermissionDenied) as ctx:
            auth.validate_key(self.rt_raw, request=request)

        self.assertEqual(
            str(ctx.exception),
            "Runtime client keys cannot be used for management endpoints. Use a management key.",
        )

    def test_default_deny_on_writes(self):
        request = self.factory.post("/api/v1/some/endpoint/")
        request.auth = self.mgmt_key

        # View without declared write scopes
        view_without_scopes = DummyWriteViewWithoutScopes()
        allowed = _allow_api_key(request, view_without_scopes, "TestPerm")
        self.assertFalse(allowed)

        # View with declared write scopes
        view_with_scopes = DummyWriteViewWithScopes()
        allowed_with_scopes = _allow_api_key(request, view_with_scopes, "TestPerm")
        self.assertTrue(allowed_with_scopes)

    def test_all_runtime_endpoints_reject_management_key_via_http_client(self):
        """Integration test verifying every runtime route rejects management keys with 403 and records AuditLog."""
        from rest_framework.test import APIClient
        from rest_framework import status

        client = APIClient()
        client.credentials(HTTP_X_API_KEY=self.mgmt_raw)

        runtime_routes = [
            ("/api/v1/auth/runtime/login/", "post", {"email": "test@example.com", "password": "password123"}),
            ("/api/v1/auth/runtime/register/", "post", {"email": "test@example.com", "password": "password123"}),
            ("/api/v1/auth/runtime/password/reset/", "post", {"email": "test@example.com"}),
            ("/api/v1/auth/runtime/passkey/authenticate/options/", "post", {}),
            ("/api/v1/auth/runtime/magic-link/request/", "post", {"email": "test@example.com"}),
            ("/api/v1/runtime/invitations/", "get", {}),
        ]

        for path, method, data in runtime_routes:
            initial_count = AuditLog.objects.filter(event_type=AuditLog.EventType.SECURITY_VIOLATION).count()
            if method == "post":
                response = client.post(path, data=data, format="json")
            else:
                response = client.get(path)

            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN,
                f"Route {path} did not reject management key with 403; got {response.status_code}: {response.data}"
            )
            self.assertIn(
                "Management keys cannot be used for runtime authentication. Use a runtime client key.",
                str(response.data)
            )

            # Assert AuditLog event was recorded
            new_count = AuditLog.objects.filter(event_type=AuditLog.EventType.SECURITY_VIOLATION).count()
            self.assertGreater(
                new_count,
                initial_count,
                f"Route {path} did not create a security.violation AuditLog entry"
            )

    def test_permission_matrix_for_schema_sync(self):
        """Verifies exact permission matrix: schema:plan vs schema:sync vs insufficient scopes."""
        from rest_framework.test import APIClient
        from rest_framework import status

        sync_url = f"/api/v1/organizations/current/projects/{self.project.id}/sync/"

        # 1. Key with only roles:read (insufficient for dry_run and live)
        _, read_raw, read_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        read_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Read-Only Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=read_raw[len("hvt_mgmt_test_"):len("hvt_mgmt_test_") + 8],
            hashed_key=read_hash,
            scopes=["roles:read"],
        )

        client = APIClient()
        client.credentials(HTTP_X_API_KEY=read_raw)
        res = client.post(sync_url + "?dry_run=true", {"schema_version": 1}, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("permission", str(res.data).lower())

        # 2. Key with schema:plan (allowed for dry_run=true, forbidden for dry_run=false)
        _, plan_raw, plan_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.MANAGEMENT
        )
        plan_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Plan Key",
            environment="test",
            key_type=APIKey.KeyType.MANAGEMENT,
            prefix=plan_raw[len("hvt_mgmt_test_"):len("hvt_mgmt_test_") + 8],
            hashed_key=plan_hash,
            scopes=["schema:plan"],
        )
        client.credentials(HTTP_X_API_KEY=plan_raw)
        res_plan_ok = client.post(sync_url + "?dry_run=true", {"schema_version": 1}, format="json")
        self.assertEqual(res_plan_ok.status_code, status.HTTP_200_OK)
        self.assertEqual(res_plan_ok.data["status"], "planned")

        res_plan_fail = client.post(sync_url, {"schema_version": 1}, format="json")
        self.assertEqual(res_plan_fail.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("The 'schema:plan' scope permits dry-run only", str(res_plan_fail.data))

        # 3. Key with schema:sync (allowed for both dry_run=true and dry_run=false)
        client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res_sync_dry = client.post(sync_url + "?dry_run=true", {"schema_version": 1}, format="json")
        self.assertEqual(res_sync_dry.status_code, status.HTTP_200_OK)

        res_sync_live = client.post(sync_url, {"schema_version": 1}, format="json")
        self.assertEqual(res_sync_live.status_code, status.HTTP_200_OK)
        self.assertEqual(res_sync_live.data["status"], "applied")
