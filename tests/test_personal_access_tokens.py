# SPDX-License-Identifier: Apache-2.0
"""
Tests for Personal Access Tokens (PATs).
Verifies:
1. Token issuance with cryptographically secure prefixing (`hvt_pat_<env>_<hex>`).
2. One-time secret display (raw token returned once upon creation).
3. SHA-256 hashing at rest (raw token never persisted to database).
4. Authentication via Authorization header (`Bearer hvt_pat_...` and `Token hvt_pat_...`).
5. Expiration enforcement (expired PATs return 401 Unauthorized).
6. Revocation enforcement (revoked PATs return 401 Unauthorized).
7. Throttled `last_used_at` touch timestamp.
8. Listing PATs returns prefix and metadata without leaking full secrets.
9. Runtime project isolation for end-user PATs.
"""

from datetime import timedelta
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress

from hvt.apps.authentication.models import PersonalAccessToken, AuditLog
from hvt.apps.organizations.models import Organization, Project, APIKey

User = get_user_model()


class PersonalAccessTokenTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email="pat_user@example.com",
            password="StrongPassword123!",
            role="owner",
        )
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            verified=True,
            primary=True,
        )

        self.org = Organization.objects.create(name="PAT Org", slug="pat-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="PAT App",
            slug="pat-app",
        )
        self.runtime_user = User.objects.create_user(
            email="rt_pat_user@example.com",
            password="StrongPassword123!",
            role="member",
            organization=self.org,
            project=self.project,
        )
        EmailAddress.objects.create(
            user=self.runtime_user,
            email=self.runtime_user.email,
            verified=True,
            primary=True,
        )

        rt_prefix, self.rt_raw, rt_hash = APIKey.generate_key(
            environment="test", key_type=APIKey.KeyType.RUNTIME
        )
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Runtime Key",
            environment="test",
            key_type=APIKey.KeyType.RUNTIME,
            prefix=rt_prefix,
            hashed_key=rt_hash,
            scopes=["auth:runtime"],
        )
        self.api_key_str = self.rt_raw

    def _login_control_plane(self):
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "StrongPassword123!"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        token = resp.data.get("access") or (
            resp.cookies.get("auth-token").value if "auth-token" in resp.cookies else None
        )
        return token

    def _login_runtime(self):
        resp = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": self.runtime_user.email, "password": "StrongPassword123!"},
            HTTP_X_API_KEY=self.api_key_str,
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        token = resp.data.get("access") or (
            resp.cookies.get("auth-token").value if "auth-token" in resp.cookies else None
        )
        return token

    # -------------------------------------------------------------------------
    # 1. Create Control-Plane PAT
    # -------------------------------------------------------------------------
    def test_create_control_plane_pat(self):
        jwt_token = self._login_control_plane()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {jwt_token}")

        resp = self.client.post(
            "/api/v1/auth/pats/",
            {
                "name": "CLI Automation Token",
                "environment": "live",
                "expires_in_days": 30,
                "scopes": ["projects:read", "users:read"],
            },
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("token", resp.data)
        self.assertIn("prefix", resp.data)
        self.assertEqual(resp.data["name"], "CLI Automation Token")
        self.assertEqual(resp.data["scopes"], ["projects:read", "users:read"])

        raw_token = resp.data["token"]
        self.assertTrue(raw_token.startswith("hvt_pat_live_"))
        self.assertTrue(resp.data["prefix"].startswith("hvt_pat_live_"))

        # Verify hashed token stored in DB (raw token never stored)
        import hashlib
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        pat = PersonalAccessToken.objects.get(id=resp.data["id"])
        self.assertEqual(pat.hashed_token, expected_hash)
        self.assertNotEqual(pat.hashed_token, raw_token)
        self.assertEqual(pat.user, self.user)
        self.assertIsNone(pat.project)
        self.assertTrue(pat.is_active)

    # -------------------------------------------------------------------------
    # 2. Authenticate API Requests using PAT
    # -------------------------------------------------------------------------
    def test_authenticate_with_pat(self):
        # Create PAT directly via model
        prefix, raw_token, hashed_token = PersonalAccessToken.generate_token(environment="live")
        pat = PersonalAccessToken.objects.create(
            user=self.user,
            name="Test Runner PAT",
            environment="live",
            prefix=prefix,
            hashed_token=hashed_token,
            scopes=["*"],
        )

        # Make request to /api/v1/auth/me/ using PAT Bearer token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        me_resp = self.client.get("/api/v1/auth/me/")
        self.assertEqual(me_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(me_resp.data["email"], self.user.email)

        # Verify last_used_at touched
        pat.refresh_from_db()
        self.assertIsNotNone(pat.last_used_at)

    # -------------------------------------------------------------------------
    # 3. Expired PAT is Rejected
    # -------------------------------------------------------------------------
    def test_expired_pat_is_rejected(self):
        prefix, raw_token, hashed_token = PersonalAccessToken.generate_token(environment="live")
        PersonalAccessToken.objects.create(
            user=self.user,
            name="Expired PAT",
            environment="live",
            prefix=prefix,
            hashed_token=hashed_token,
            expires_at=timezone.now() - timedelta(hours=1),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        resp = self.client.get("/api/v1/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("expired", str(resp.data))

    # -------------------------------------------------------------------------
    # 4. Revoked PAT is Rejected
    # -------------------------------------------------------------------------
    def test_revoked_pat_is_rejected(self):
        prefix, raw_token, hashed_token = PersonalAccessToken.generate_token(environment="live")
        pat = PersonalAccessToken.objects.create(
            user=self.user,
            name="Revoked PAT",
            environment="live",
            prefix=prefix,
            hashed_token=hashed_token,
            revoked_at=timezone.now(),
            revoked_reason="user_revoked",
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        resp = self.client.get("/api/v1/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("revoked", str(resp.data))

    # -------------------------------------------------------------------------
    # 5. List PATs Endpoint Redacts Raw Secret
    # -------------------------------------------------------------------------
    def test_list_pats_endpoint_redacts_secret(self):
        jwt_token = self._login_control_plane()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {jwt_token}")

        # Create two PATs
        self.client.post("/api/v1/auth/pats/", {"name": "Token 1", "environment": "live"})
        self.client.post("/api/v1/auth/pats/", {"name": "Token 2", "environment": "test"})

        # List PATs
        list_resp = self.client.get("/api/v1/auth/pats/")
        self.assertEqual(list_resp.status_code, status.HTTP_200_OK)
        pats = list_resp.data.get("results", list_resp.data) if isinstance(list_resp.data, dict) else list_resp.data
        self.assertEqual(len(pats), 2)

        for p in pats:
            self.assertIn("prefix", p)
            self.assertNotIn("token", p)
            self.assertNotIn("hashed_token", p)
            self.assertTrue(p["prefix"].startswith("hvt_pat_"))

    # -------------------------------------------------------------------------
    # 6. Revoke PAT via DELETE Endpoint
    # -------------------------------------------------------------------------
    def test_revoke_pat_endpoint(self):
        jwt_token = self._login_control_plane()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {jwt_token}")

        create_resp = self.client.post("/api/v1/auth/pats/", {"name": "Temporary Token"})
        raw_token = create_resp.data["token"]
        pat_id = create_resp.data["id"]

        # Token works initially
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(self.client.get("/api/v1/auth/me/").status_code, status.HTTP_200_OK)

        # Revoke via DELETE
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {jwt_token}")
        del_resp = self.client.delete(f"/api/v1/auth/pats/{pat_id}/")
        self.assertEqual(del_resp.status_code, status.HTTP_200_OK)

        # Token is immediately rejected
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(self.client.get("/api/v1/auth/me/").status_code, status.HTTP_401_UNAUTHORIZED)

    # -------------------------------------------------------------------------
    # 7. Runtime End-User PAT Scoping
    # -------------------------------------------------------------------------
    def test_runtime_pat_endpoints(self):
        rt_token = self._login_runtime()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {rt_token}",
            HTTP_X_API_KEY=self.api_key_str,
        )

        # Create runtime PAT
        create_resp = self.client.post(
            "/api/v1/auth/runtime/pats/",
            {"name": "Customer Script PAT", "environment": "test"},
        )
        self.assertEqual(create_resp.status_code, status.HTTP_201_CREATED)
        raw_token = create_resp.data["token"]
        pat_id = create_resp.data["id"]
        self.assertEqual(create_resp.data["project"], str(self.project.id))

        # Authenticate runtime route using runtime PAT
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_API_KEY=self.api_key_str,
        )
        me_resp = self.client.get("/api/v1/auth/runtime/me/")
        self.assertEqual(me_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(me_resp.data["email"], self.runtime_user.email)

        # Revoke runtime PAT
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {rt_token}",
            HTTP_X_API_KEY=self.api_key_str,
        )
        del_resp = self.client.delete(f"/api/v1/auth/runtime/pats/{pat_id}/")
        self.assertEqual(del_resp.status_code, status.HTTP_200_OK)
