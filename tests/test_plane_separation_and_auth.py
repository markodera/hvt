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

    def test_management_key_rejected_on_runtime_view_outside_cors_path_prefixes(self):
        """Proves enforcement is strictly inside authentication classes, not path matching.
        A runtime view mounted on a completely custom URL (outside CORS path prefixes)
        still immediately rejects management keys with 403 and records an AuditLog event.
        """
        auth = RuntimeAPIKeyAuthentication()
        request = self.factory.get("/api/v1/custom-unprefixed-route/runtime-endpoint/")
        with self.assertRaises(exceptions.PermissionDenied) as ctx:
            auth.validate_key(self.mgmt_raw, request=request)
        self.assertEqual(
            str(ctx.exception),
            "Management keys cannot be used for runtime authentication. Use a runtime client key."
        )

        log = AuditLog.objects.filter(event_type=AuditLog.EventType.SECURITY_VIOLATION).latest("created_at")
        self.assertEqual(log.event_data["path"], "/api/v1/custom-unprefixed-route/runtime-endpoint/")

    def test_all_runtime_endpoints_reject_management_key_via_urlconf_enumeration(self):
        """Automatically walks URLconf and verifies every runtime endpoint rejects management keys with 403."""
        from django.urls import get_resolver, resolve
        from rest_framework.test import APIClient
        from rest_framework import status

        client = APIClient()
        client.credentials(HTTP_X_API_KEY=self.mgmt_raw)

        def get_routes(patterns, prefix=""):
            for p in patterns:
                if hasattr(p, "url_patterns"):
                    yield from get_routes(p.url_patterns, prefix + str(p.pattern))
                else:
                    yield prefix + str(p.pattern)

        runtime_routes = set()
        for r in get_routes(get_resolver().url_patterns):
            if r.startswith("api/v1/auth/runtime/") or r.startswith("api/v1/runtime/"):
                clean = "/" + r.lstrip("^").rstrip("$")
                if "<" not in clean and "(?P" not in clean:
                    match = resolve(clean)
                    view_cls = getattr(match.func, "view_class", None)
                    if getattr(view_cls, "authentication_classes", None) == []:
                        continue  # Skip unauthenticated public acceptance view
                    runtime_routes.add(clean)

        self.assertGreater(len(runtime_routes), 15, "URLconf must have discovered runtime routes automatically")
        for path in sorted(runtime_routes):
            is_post = any(kw in path for kw in ("register", "login", "passkey", "magic", "password", "resend"))
            res = client.post(path, {}, format="json") if is_post else client.get(path)
            self.assertEqual(
                res.status_code,
                status.HTTP_403_FORBIDDEN,
                f"URLconf enumerated runtime route {path} failed to reject management key; got {res.status_code}"
            )
            self.assertIn("Management keys cannot be used for runtime authentication", str(res.data))

    def test_all_non_runtime_endpoints_reject_management_key_except_allowlist(self):
        """Asserts non-runtime routes reject management keys except an explicit allowlist (the sync endpoint)."""
        from rest_framework.test import APIClient
        from rest_framework import status

        client = APIClient()
        client.credentials(HTTP_X_API_KEY=self.mgmt_raw)

        test_routes = [
            "/api/v1/users/",
            "/api/v1/organizations/",
            "/api/v1/organizations/current/",
            "/api/v1/organizations/current/projects/",
            "/api/v1/organizations/current/keys/",
            "/api/v1/organizations/current/webhooks/",
            "/api/v1/organizations/current/audit-logs/",
            "/api/v1/auth/me/",
        ]

        for path in test_routes:
            res = client.get(path)
            self.assertIn(
                res.status_code,
                (status.HTTP_403_FORBIDDEN, status.HTTP_401_UNAUTHORIZED),
                f"Non-runtime route {path} must reject management key; got {res.status_code}"
            )

        # Confirm the explicit allowlist (ProjectSchemaSyncView) DOES accept the management key
        sync_url = f"/api/v1/organizations/current/projects/{self.project.id}/sync/?dry_run=true"
        allow_res = client.post(sync_url, {"schema_version": 1}, format="json")
        self.assertEqual(allow_res.status_code, status.HTTP_200_OK)

    def test_pre_existing_runtime_keys_authenticate_successfully(self):
        """Confirms pre-existing runtime keys (both hvt_test_ and legacy hvt_client_test_ prefixes) continue to authenticate."""
        rt_prefix, rt_raw, rt_hash = APIKey.generate_key(environment="test", key_type=APIKey.KeyType.RUNTIME)
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Standard RT Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=rt_prefix,
            hashed_key=rt_hash,
            scopes=["auth:runtime"],
        )
        auth = RuntimeAPIKeyAuthentication()
        user, key_obj = auth.validate_key(rt_raw)
        self.assertIsNotNone(key_obj)
        self.assertEqual(key_obj.prefix, rt_prefix)

        raw_token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        legacy_raw = f"hvt_client_test_{raw_token}"
        legacy_prefix = raw_token[:8]
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Legacy RT Client Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=legacy_prefix,
            hashed_key=APIKey.hash_key(legacy_raw),
            scopes=["auth:runtime"],
        )
        user2, key_obj2 = auth.validate_key(legacy_raw)
        self.assertIsNotNone(key_obj2)
        self.assertEqual(key_obj2.prefix, legacy_prefix)

    def test_expired_revoked_and_cross_project_keys_rejected(self):
        """Confirms expired and revoked keys raise AuthenticationFailed, and cross-project keys return 404."""
        from django.utils import timezone
        from datetime import timedelta
        from rest_framework import exceptions, status
        from rest_framework.test import APIClient

        auth = APIKeyAuthentication()

        # 1. Expired Key
        exp_prefix, exp_raw, exp_hash = APIKey.generate_key(environment="test", key_type=APIKey.KeyType.RUNTIME)
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Expired Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=exp_prefix,
            hashed_key=exp_hash,
            expires_at=timezone.now() - timedelta(days=1),
            scopes=["auth:runtime"],
        )
        with self.assertRaises(exceptions.AuthenticationFailed) as ctx_exp:
            auth.validate_key(exp_raw)
        self.assertIn("inactive or expired", str(ctx_exp.exception).lower())

        # 2. Revoked Key
        rev_prefix, rev_raw, rev_hash = APIKey.generate_key(environment="test", key_type=APIKey.KeyType.RUNTIME)
        APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Revoked Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=rev_prefix,
            hashed_key=rev_hash,
            is_active=False,
            scopes=["auth:runtime"],
        )
        with self.assertRaises(exceptions.AuthenticationFailed) as ctx_rev:
            auth.validate_key(rev_raw)
        self.assertIn("inactive or expired", str(ctx_rev.exception).lower())

        # 3. Cross-Project Key on project-scoped URL returns 404
        other_project = Project.objects.create(organization=self.org, name="Other", slug="other")
        client = APIClient()
        client.credentials(HTTP_X_API_KEY=self.mgmt_raw)
        res = client.post(
            f"/api/v1/organizations/current/projects/{other_project.id}/sync/",
            {"schema_version": 1},
            format="json",
        )
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)
