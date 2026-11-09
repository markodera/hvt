# SPDX-License-Identifier: Apache-2.0
import json
import uuid
import jwt
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework_simplejwt.exceptions import InvalidToken, TokenBackendError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from hvt.apps.authentication.jwt_keys import (
    get_jwt_private_key_pem,
    get_jwt_public_key_pem,
    get_jwt_key_id,
    get_jwt_issuer,
    get_jwks,
    _load_pem_string,
    check_jwt_signing_keys,
)
from hvt.apps.authentication.jwt_backend import HVTAsymmetricTokenBackend
from hvt.apps.authentication.tokens import (
    _stamp_org_claims,
    build_hvt_token_pair,
    HVTTokenObtainPairSerializer,
)
from hvt.apps.authentication.backends import HVTJWTAuthentication
from hvt.apps.organizations.models import Organization, Project, APIKey
from hvt.jwt_verify import verify_hvt_token, TokenVerificationError

User = get_user_model()


class AsymmetricJWTKeyTests(TestCase):
    """Test cryptographic key generation, caching, and JWKS formatting."""

    def test_key_generation_and_properties(self):
        priv_pem = get_jwt_private_key_pem()
        pub_pem = get_jwt_public_key_pem()
        kid = get_jwt_key_id()
        issuer = get_jwt_issuer()

        self.assertTrue(
            priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
            or priv_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
        )
        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(kid.startswith("hvt-"))
        self.assertTrue(len(issuer) > 0)

    def test_jwks_structure(self):
        jwks = get_jwks()
        self.assertIn("keys", jwks)
        self.assertGreaterEqual(len(jwks["keys"]), 1)

        primary_key = jwks["keys"][0]
        self.assertEqual(primary_key["kty"], "RSA")
        self.assertEqual(primary_key["use"], "sig")
        self.assertEqual(primary_key["alg"], "RS256")
        self.assertEqual(primary_key["kid"], get_jwt_key_id())
        self.assertIn("n", primary_key)
        self.assertIn("e", primary_key)

    def test_rotated_keys_in_jwks(self):
        # Generate secondary RSA key
        sec_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sec_pub_pem = sec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        with override_settings(
            HVT_JWT_ROTATION_PUBLIC_KEYS=[{"key": sec_pub_pem, "kid": "hvt-rot-test"}]
        ):
            jwks = get_jwks()
            self.assertEqual(len(jwks["keys"]), 2)
            kids = [k["kid"] for k in jwks["keys"]]
            self.assertIn("hvt-rot-test", kids)


    def test_unescape_pem_newlines(self):
        escaped_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        loaded = _load_pem_string(escaped_pem)
        self.assertNotIn("\\n", loaded)
        self.assertIn("\n", loaded)
        self.assertTrue(loaded.startswith("-----BEGIN PUBLIC KEY-----\n"))

    def test_issuer_configuration(self):
        with override_settings(HVT_JWT_ISSUER="https://custom.auth.org"):
            self.assertEqual(get_jwt_issuer(), "https://custom.auth.org")


class AsymmetricTokenBackendTests(TestCase):
    """Test token signing, header stamps, claim stamping, and algorithm validation."""

    def setUp(self):
        self.backend = HVTAsymmetricTokenBackend()

    def test_encode_stamps_rs256_and_kid(self):
        payload = {"user_id": 42, "role": "owner"}
        token = self.backend.encode(payload)
        self.assertIsInstance(token, str)

        unverified_header = jwt.get_unverified_header(token)
        self.assertEqual(unverified_header["alg"], "RS256")
        self.assertEqual(unverified_header["kid"], self.backend.key_id)
        self.assertEqual(unverified_header["typ"], "JWT")

    def test_encode_and_decode_cycle(self):
        payload = {"user_id": 99, "role": "member"}
        token = self.backend.encode(payload)
        decoded = self.backend.decode(token)

        self.assertEqual(decoded["user_id"], 99)
        self.assertEqual(decoded["sub"], "99")
        self.assertEqual(decoded["iss"], self.backend.issuer)
        self.assertIn("jti", decoded)
        self.assertIn("iat", decoded)

    def test_tampered_token_rejected(self):
        payload = {"user_id": 1}
        token = self.backend.encode(payload)
        tampered = token[:-6] + "xxxxxx"

        with self.assertRaises(TokenBackendError):
            self.backend.decode(tampered)

    def test_legacy_hs256_token_fallback_decode(self):
        legacy_payload = {"user_id": 123, "role": "admin"}
        legacy_token = jwt.encode(
            legacy_payload,
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        decoded = self.backend.decode(legacy_token)
        self.assertEqual(decoded["user_id"], 123)
        self.assertEqual(decoded["role"], "admin")


    def test_rejects_token_with_wrong_issuer(self):
        payload = {"user_id": 99, "role": "member", "iss": "https://attacker.example.com"}
        # Sign with valid key but wrong issuer
        token = jwt.encode(
            payload,
            self.backend.prepared_signing_key,
            algorithm="RS256",
            headers={"kid": self.backend.key_id, "typ": "JWT"},
        )
        with self.assertRaises(TokenBackendError):
            self.backend.decode(token)


class JWKSEndpointsTests(TestCase):
    """Test public JWKS and OIDC Discovery HTTP endpoints."""

    def setUp(self):
        self.client = APIClient()

    def test_root_jwks_endpoint(self):
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Access-Control-Allow-Origin"], "*")
        self.assertIn("max-age=3600", response["Cache-Control"])

        data = response.json()
        self.assertIn("keys", data)
        self.assertGreaterEqual(len(data["keys"]), 1)
        self.assertEqual(data["keys"][0]["alg"], "RS256")

    def test_root_openid_configuration_endpoint(self):
        response = self.client.get("/.well-known/openid-configuration")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Access-Control-Allow-Origin"], "*")

        data = response.json()
        self.assertIn("issuer", data)
        self.assertIn("jwks_uri", data)
        self.assertTrue(data["jwks_uri"].endswith("/.well-known/jwks.json"))
        self.assertIn("RS256", data["id_token_signing_alg_values_supported"])

    def test_auth_namespaced_endpoints(self):
        r1 = self.client.get("/api/v1/auth/.well-known/jwks.json")
        self.assertEqual(r1.status_code, status.HTTP_200_OK)
        r2 = self.client.get("/api/v1/auth/.well-known/openid-configuration")
        self.assertEqual(r2.status_code, status.HTTP_200_OK)


class OfflineVerificationHelperTests(TestCase):
    """Test hvt.jwt_verify.verify_hvt_token helper."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="offline-test@example.com",
            password="TestPassword123!",
        )

    def test_verify_with_local_jwks(self):
        token_pair = build_hvt_token_pair(self.user)
        access_str = str(token_pair[0])

        claims = verify_hvt_token(access_str)
        self.assertEqual(claims["sub"], str(self.user.id))
        self.assertEqual(claims["email"], self.user.email)

    def test_verify_with_direct_public_key(self):
        token_pair = build_hvt_token_pair(self.user)
        access_str = str(token_pair[0])
        pub_pem = get_jwt_public_key_pem()

        claims = verify_hvt_token(access_str, public_key_pem=pub_pem)
        self.assertEqual(claims["sub"], str(self.user.id))

    def test_verify_project_id_matching(self):
        org = Organization.objects.create(name="Helper Org", slug="helper-org")
        proj = Project.objects.create(organization=org, name="Proj 1", slug="proj-1")
        access, _ = build_hvt_token_pair(self.user, project=proj)

        # Match project
        claims = verify_hvt_token(str(access), expected_project_id=str(proj.id))
        self.assertEqual(claims["project_id"], str(proj.id))

        # Mismatch project
        other_proj_id = uuid.uuid4()
        with self.assertRaises(TokenVerificationError) as ctx:
            verify_hvt_token(str(access), expected_project_id=str(other_proj_id))
        self.assertIn("mismatch", str(ctx.exception))

    def test_verify_invalid_token(self):
        with self.assertRaises(TokenVerificationError):
            verify_hvt_token("not-a-token")


class CrossProjectTokenIsolationTests(TestCase):
    """Test rejection of tokens presented across mismatched projects."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.org = Organization.objects.create(name="Tenant Org", slug="tenant-org")
        self.proj_a = Project.objects.create(organization=self.org, name="Project A", slug="proj-a")
        self.proj_b = Project.objects.create(organization=self.org, name="Project B", slug="proj-b")

        self.user_a = User.objects.create_user(
            email="usera@example.com",
            password="TestPassword123!",
            organization=self.org,
            project=self.proj_a,
        )

        # Create API keys for proj_a and proj_b
        self.api_key_a = APIKey.objects.create(
            organization=self.org,
            project=self.proj_a,
            key_type=APIKey.KeyType.RUNTIME,
            environment=APIKey.Environment.TEST,
            prefix="testkeya",
            hashed_key=APIKey.hash_key("hvt_test_testkeya_12345678"),
        )
        self.api_key_b = APIKey.objects.create(
            organization=self.org,
            project=self.proj_b,
            key_type=APIKey.KeyType.RUNTIME,
            environment=APIKey.Environment.TEST,
            prefix="testkeyb",
            hashed_key=APIKey.hash_key("hvt_test_testkeyb_12345678"),
        )

    def test_token_for_project_a_accepted_with_project_a_key(self):
        access, _ = build_hvt_token_pair(self.user_a, project=self.proj_a)
        request = self.factory.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {access}",
            HTTP_X_API_KEY="hvt_test_testkeya_12345678",
        )
        request.auth = self.api_key_a

        auth = HVTJWTAuthentication()
        user, validated_token = auth.authenticate(request)
        self.assertEqual(user.id, self.user_a.id)
        self.assertEqual(validated_token["project_id"], str(self.proj_a.id))

    def test_token_for_project_a_rejected_with_project_b_key(self):
        access, _ = build_hvt_token_pair(self.user_a, project=self.proj_a)
        request = self.factory.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {access}",
            HTTP_X_API_KEY="hvt_test_testkeyb_12345678",
        )
        request.auth = self.api_key_b

        auth = HVTJWTAuthentication()
        with self.assertRaises(InvalidToken) as ctx:
            auth.authenticate(request)
        self.assertIn("Token was not issued for this project", str(ctx.exception))


class SystemCheckTests(TestCase):
    """Test Django system check check_jwt_signing_keys."""

    @patch("hvt.apps.authentication.jwt_keys.sys.argv", ["manage.py", "runserver"])
    @override_settings(DEBUG=False, TESTING=False, HVT_JWT_PRIVATE_KEY=None)
    def test_check_fails_in_production_without_key(self):
        with patch.dict("os.environ", {}, clear=True):
            errors = check_jwt_signing_keys(None)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].id, "hvt.E002")

    @patch("hvt.apps.authentication.jwt_keys.sys.argv", ["manage.py", "runserver"])
    @override_settings(DEBUG=False, TESTING=False)
    def test_check_passes_in_production_with_valid_key(self):
        priv_pem = get_jwt_private_key_pem()
        with override_settings(HVT_JWT_PRIVATE_KEY=priv_pem):
            errors = check_jwt_signing_keys(None)
            self.assertEqual(len(errors), 0)
