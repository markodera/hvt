# SPDX-License-Identifier: Apache-2.0
"""
Tests for Step 7: Session Revocation & Device Management.
Verifies:
1. Session ID (sid) stamped in access and refresh tokens.
2. UserSession model tracking IP, user-agent, and device details.
3. Real-time access token revocation via Redis / cache registry.
4. Refresh token rejection when session is revoked.
5. Listing active sessions with is_current flag.
6. Revoking specific sessions (remote device logout).
7. Revoking all other sessions (global remote logout).
8. Project-scoped runtime session isolation.
9. Cache failure / resilience fallback to database.
"""

from unittest.mock import patch
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress

from allauth.account.models import EmailAddress

from hvt.apps.authentication.models import UserSession, AuditLog
from hvt.apps.authentication.sessions import (
    create_user_session,
    is_session_active,
    revoke_session,
    revoke_all_user_sessions,
)
from hvt.apps.organizations.models import Organization, Project, APIKey

User = get_user_model()


class SessionRevocationTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email="session_user@example.com",
            password="StrongPassword123!",
            role="owner",
        )
        EmailAddress.objects.create(user=self.user, email=self.user.email, verified=True, primary=True)
        self.org = Organization.objects.create(name="Session Org", slug="session-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Session App",
            slug="session-app",
        )
        self.runtime_user = User.objects.create_user(
            email="rt_user@example.com",
            password="StrongPassword123!",
            role="member",
            organization=self.org,
            project=self.project,
        )
        EmailAddress.objects.create(user=self.runtime_user, email=self.runtime_user.email, verified=True, primary=True)
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

    def _extract_tokens(self, resp):
        access = resp.data.get("access") or (resp.cookies.get("auth-token").value if "auth-token" in resp.cookies else None)
        refresh = resp.data.get("refresh") or (resp.cookies.get("refresh-token").value if "refresh-token" in resp.cookies else None)
        return access, refresh

    # -------------------------------------------------------------------------
    # 1. Login Issues Token with `sid` and Registers Session
    # -------------------------------------------------------------------------
    def test_login_creates_session_and_stamps_sid(self):
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
            HTTP_USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0",
            REMOTE_ADDR="198.51.100.42",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        access_val, refresh_val = self._extract_tokens(resp)
        self.assertIsNotNone(access_val)
        self.assertIsNotNone(refresh_val)

        # Verify session record in DB
        session = UserSession.objects.filter(user=self.user, revoked_at__isnull=True).first()
        self.assertIsNotNone(session)
        self.assertEqual(session.ip_address, "198.51.100.42")
        self.assertIn("Chrome", session.device_name)
        self.assertEqual(session.user_agent, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0")

        # Verify sid in access and refresh token claims
        from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
        access = AccessToken(access_val)
        refresh = RefreshToken(refresh_val)
        self.assertEqual(access.get("sid"), str(session.id))
        self.assertEqual(refresh.get("sid"), str(session.id))

        # Request with access token succeeds
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
        me_resp = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_resp.status_code, status.HTTP_200_OK)

    # -------------------------------------------------------------------------
    # 2. Immediate Access Token Revocation
    # -------------------------------------------------------------------------
    def test_revoked_session_immediately_blocks_access_token(self):
        # Login to obtain token
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token, _ = self._extract_tokens(resp)
        session = UserSession.objects.filter(user=self.user).first()
        self.assertIsNotNone(session)

        # Token works initially
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        me_resp = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_resp.status_code, status.HTTP_200_OK)

        # Revoke session
        revoke_session(session.id, reason="admin_revoked")

        # Next request with same access token is rejected immediately (even though JWT unexpired)
        me_revoked = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_revoked.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("Session has been revoked", str(me_revoked.data))

    # -------------------------------------------------------------------------
    # 3. Revoked Session Blocks Token Refresh
    # -------------------------------------------------------------------------
    def test_revoked_session_blocks_token_refresh(self):
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        _, refresh_token = self._extract_tokens(resp)
        session = UserSession.objects.filter(user=self.user).first()

        # Revoke session
        revoke_session(session.id)

        # Attempt to refresh
        refresh_resp = self.client.post(
            "/api/v1/auth/token/refresh/",
            {"refresh": refresh_token},
        )
        self.assertEqual(refresh_resp.status_code, status.HTTP_401_UNAUTHORIZED)

    # -------------------------------------------------------------------------
    # 4. Token Refresh Preserves Session ID
    # -------------------------------------------------------------------------
    def test_token_refresh_preserves_session_id(self):
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        _, refresh_token = self._extract_tokens(resp)
        orig_session = UserSession.objects.filter(user=self.user).first()

        # Refresh
        refresh_resp = self.client.post(
            "/api/v1/auth/token/refresh/",
            {"refresh": refresh_token},
        )
        self.assertEqual(refresh_resp.status_code, status.HTTP_200_OK)

        from rest_framework_simplejwt.tokens import AccessToken
        new_access = AccessToken(refresh_resp.data["access"])
        self.assertEqual(new_access.get("sid"), str(orig_session.id))

    # -------------------------------------------------------------------------
    # 5. List Sessions API (`GET /api/v1/auth/sessions/`)
    # -------------------------------------------------------------------------
    def test_list_active_sessions_with_is_current(self):
        # Create Device A
        resp_a = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            REMOTE_ADDR="198.51.100.1",
        )
        token_a, _ = self._extract_tokens(resp_a)

        # Create Device B
        resp_b = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
            HTTP_USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
            REMOTE_ADDR="198.51.100.2",
        )
        token_b, _ = self._extract_tokens(resp_b)

        # Query sessions endpoint using Device A's token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")
        list_resp = self.client.get("/api/v1/auth/sessions/")
        self.assertEqual(list_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_resp.data), 2)

        # Verify is_current flags
        session_a_data = next(s for s in list_resp.data if s["ip_address"] == "198.51.100.1")
        session_b_data = next(s for s in list_resp.data if s["ip_address"] == "198.51.100.2")
        self.assertTrue(session_a_data["is_current"])
        self.assertFalse(session_b_data["is_current"])
        self.assertIn("Windows", session_a_data["device_name"])
        self.assertIn("iPhone", session_b_data["device_name"])

    # -------------------------------------------------------------------------
    # 6. Revoke Specific Session Endpoint (`DELETE /api/v1/auth/sessions/<id>/`)
    # -------------------------------------------------------------------------
    def test_revoke_specific_session_endpoint(self):
        # Login Device A and Device B
        resp_a = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token_a, _ = self._extract_tokens(resp_a)

        resp_b = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token_b = resp_b.data["access"]
        from rest_framework_simplejwt.tokens import AccessToken
        sid_b = AccessToken(token_b).get("sid")

        # From Device A, revoke Device B
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")
        del_resp = self.client.delete(f"/api/v1/auth/sessions/{sid_b}/")
        self.assertEqual(del_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(del_resp.data["detail"], "Session revoked successfully.")

        # Device B is now blocked
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_b}")
        me_b = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_b.status_code, status.HTTP_401_UNAUTHORIZED)

        # Device A remains functional
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")
        me_a = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_a.status_code, status.HTTP_200_OK)

    # -------------------------------------------------------------------------
    # 7. Revoke All Other Sessions (`POST /api/v1/auth/sessions/revoke-all/`)
    # -------------------------------------------------------------------------
    def test_revoke_all_other_sessions(self):
        resp_a = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token_a, _ = self._extract_tokens(resp_a)

        resp_b = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token_b = resp_b.data["access"]

        resp_c = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token_c = resp_c.data["access"]

        # Call revoke-all from Device A
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")
        revoke_all_resp = self.client.post("/api/v1/auth/sessions/revoke-all/")
        self.assertEqual(revoke_all_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(revoke_all_resp.data["revoked_count"], 2)

        # Devices B and C are revoked
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_b}")
        self.assertEqual(self.client.get("/api/v1/auth/user/").status_code, status.HTTP_401_UNAUTHORIZED)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_c}")
        self.assertEqual(self.client.get("/api/v1/auth/user/").status_code, status.HTTP_401_UNAUTHORIZED)

        # Device A remains active
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")
        self.assertEqual(self.client.get("/api/v1/auth/user/").status_code, status.HTTP_200_OK)

    # -------------------------------------------------------------------------
    # 8. Runtime Session Isolation
    # -------------------------------------------------------------------------
    def test_runtime_user_session_endpoints(self):
        resp_rt = self.client.post(
            "/api/v1/auth/runtime/login/",
            {"email": "rt_user@example.com", "password": "StrongPassword123!"},
            HTTP_X_API_KEY=self.api_key_str,
            HTTP_USER_AGENT="MobileApp/1.0 (Android 14)",
            REMOTE_ADDR="198.51.100.99",
        )
        self.assertEqual(resp_rt.status_code, status.HTTP_200_OK)
        token_rt, _ = self._extract_tokens(resp_rt)

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {token_rt}",
            HTTP_X_API_KEY=self.api_key_str,
        )

        # List runtime sessions
        rt_list = self.client.get("/api/v1/auth/runtime/sessions/")
        self.assertEqual(rt_list.status_code, status.HTTP_200_OK)
        self.assertEqual(len(rt_list.data), 1)
        self.assertEqual(rt_list.data[0]["project"], str(self.project.id))
        self.assertTrue(rt_list.data[0]["is_current"])

        # Revoke runtime session
        sid = rt_list.data[0]["id"]
        del_rt = self.client.delete(f"/api/v1/auth/runtime/sessions/{sid}/")
        self.assertEqual(del_rt.status_code, status.HTTP_200_OK)

        # Token is immediately rejected
        me_rt = self.client.get("/api/v1/auth/runtime/user/")
        self.assertEqual(me_rt.status_code, status.HTTP_401_UNAUTHORIZED)

    # -------------------------------------------------------------------------
    # 9. Cache Miss / Resilience Fallback to Database
    # -------------------------------------------------------------------------
    def test_cache_miss_falls_back_to_database(self):
        resp = self.client.post(
            "/api/v1/auth/login/",
            {"email": "session_user@example.com", "password": "StrongPassword123!"},
        )
        token, _ = self._extract_tokens(resp)
        from rest_framework_simplejwt.tokens import AccessToken
        sid = AccessToken(token).get("sid")

        # Clear Redis/Django cache completely
        cache.clear()

        # System should fall back to DB lookup seamlessly and keep session active
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        me_resp = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_resp.status_code, status.HTTP_200_OK)

        # Now revoke in DB and clear cache again
        UserSession.objects.filter(id=sid).update(revoked_at=timezone.now(), revoked_reason="db_revoked")
        cache.clear()

        # Request fails via DB fallback
        me_revoked = self.client.get("/api/v1/auth/user/")
        self.assertEqual(me_revoked.status_code, status.HTTP_401_UNAUTHORIZED)
