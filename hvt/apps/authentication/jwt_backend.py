# SPDX-License-Identifier: Apache-2.0
import logging
import uuid
from typing import Any, Dict, Optional

import jwt
from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import TokenBackendError

from hvt.apps.authentication.jwt_keys import (
    get_jwt_issuer,
    get_jwt_key_id,
    get_jwt_private_key_pem,
    get_jwt_public_key_pem,
    get_jwks,
)

logger = logging.getLogger(__name__)


class HVTAsymmetricTokenBackend(TokenBackend):
    """
    Production asymmetric token backend for HVT.
    Signs tokens using RS256 with key ID (kid) header and OIDC standard claims (iss, sub, aud, jti).
    Supports offline public-key verification via JWKS, with graceful fallback for legacy HS256 tokens.
    """

    def __init__(
        self,
        algorithm: str = "RS256",
        signing_key: Optional[str] = None,
        verifying_key: Optional[str] = None,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        jwk_url: Optional[str] = None,
        leeway: Any = 0,
        json_encoder: Any = None,
    ):
        signing_key = signing_key or get_jwt_private_key_pem()
        verifying_key = verifying_key or get_jwt_public_key_pem()
        issuer = issuer or get_jwt_issuer()

        super().__init__(
            algorithm=algorithm,
            signing_key=signing_key,
            verifying_key=verifying_key,
            audience=audience,
            issuer=issuer,
            jwk_url=jwk_url,
            leeway=leeway,
            json_encoder=json_encoder,
        )
        self.key_id = get_jwt_key_id()

    def encode(self, payload: Dict[str, Any]) -> str:
        """
        Encode and sign payload with RS256, embedding kid header and standard OIDC claims.
        """
        jwt_payload = payload.copy()

        # Stamp standard OIDC claims if missing
        if "iss" not in jwt_payload and self.issuer is not None:
            jwt_payload["iss"] = self.issuer
        if "jti" not in jwt_payload:
            jwt_payload["jti"] = uuid.uuid4().hex
        if "sub" not in jwt_payload and "user_id" in jwt_payload:
            jwt_payload["sub"] = str(jwt_payload["user_id"])
        if "iat" not in jwt_payload:
            jwt_payload["iat"] = int(timezone.now().timestamp())

        headers = {
            "kid": self.key_id,
            "typ": "JWT",
        }

        try:
            token = jwt.encode(
                jwt_payload,
                self.prepared_signing_key,
                algorithm=self.algorithm,
                headers=headers,
                json_encoder=self.json_encoder,
            )
            if isinstance(token, bytes):
                return token.decode("utf-8")
            return token
        except Exception as exc:
            raise TokenBackendError(f"Could not encode token: {exc}") from exc

    def decode(self, token: str, verify: bool = True) -> Dict[str, Any]:
        """
        Decode token verifying asymmetric RS256 signature against active or rotated public keys.
        Supports graceful verification of legacy HS256 tokens using SECRET_KEY.
        """
        if not verify:
            return jwt.decode(
                token,
                options={"verify_signature": False},
                leeway=self.leeway,
            )

        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise TokenBackendError(f"Invalid token header: {exc}") from exc

        token_alg = unverified_header.get("alg")

        # 1. Asymmetric RS256 (Default & Canonical)
        if token_alg == "RS256":
            token_kid = unverified_header.get("kid")
            verifying_key = self.prepared_verifying_key

            # Check if token was signed by a rotated key
            if token_kid and token_kid != self.key_id:
                jwks = get_jwks()
                for key_dict in jwks.get("keys", []):
                    if key_dict.get("kid") == token_kid:
                        from jwt.algorithms import RSAAlgorithm
                        verifying_key = RSAAlgorithm.from_jwk(key_dict)
                        break

            try:
                return jwt.decode(
                    token,
                    verifying_key,
                    algorithms=["RS256"],
                    leeway=self.leeway,
                    options={"verify_aud": False},  # Audience validated per-route
                )
            except Exception as exc:
                raise TokenBackendError(f"Token is invalid or expired: {exc}") from exc

        # 2. Legacy HS256 Fallback
        elif token_alg == "HS256":
            legacy_secret = getattr(settings, "SECRET_KEY", "")
            try:
                return jwt.decode(
                    token,
                    legacy_secret,
                    algorithms=["HS256"],
                    leeway=self.leeway,
                    options={"verify_aud": False},
                )
            except Exception as exc:
                raise TokenBackendError(f"Legacy HS256 token is invalid: {exc}") from exc

        raise TokenBackendError(f"Unsupported token algorithm: '{token_alg}'. Expected RS256.")
