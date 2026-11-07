# SPDX-License-Identifier: Apache-2.0
"""
Lightweight offline JWT verification helper for HVT.
Allows Python services (FastAPI, Flask, Celery, Django microservices) to verify HVT tokens
offline using cached JWKS without sharing backend secret keys.
"""
from typing import Any, Dict, Optional
import jwt
from jwt import PyJWKClient, PyJWKSet
from jwt.exceptions import PyJWTError


class TokenVerificationError(Exception):
    """Raised when an HVT token cannot be verified."""
    pass


def verify_hvt_token(
    token: str,
    expected_project_id: Optional[str] = None,
    jwks_url: Optional[str] = None,
    public_key_pem: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    leeway: int = 0,
) -> Dict[str, Any]:
    """
    Verifies an HVT asymmetric RS256 token against a public key or JWKS URL.
    Returns the decoded claims dictionary.
    """
    if not token or not isinstance(token, str):
        raise TokenVerificationError("Token must be a non-empty string.")

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    try:
        # If direct public key provided
        if public_key_pem:
            claims = jwt.decode(
                token,
                public_key_pem,
                algorithms=["RS256"],
                issuer=expected_issuer,
                options={"verify_aud": False},
                leeway=leeway,
            )
        elif jwks_url:
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=expected_issuer,
                options={"verify_aud": False},
                leeway=leeway,
            )
        else:
            # Fallback to local server's JWKS
            from hvt.apps.authentication.jwt_keys import get_jwks
            jwks = get_jwks()
            jwk_set = PyJWKSet.from_dict(jwks)
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            try:
                key = jwk_set[kid]
            except (KeyError, TypeError):
                raise TokenVerificationError(f"Token Key ID ('{kid}') not found in JWKS.")
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=expected_issuer,
                options={"verify_aud": False},
                leeway=leeway,
            )

        if expected_project_id:
            token_project = claims.get("project_id") or claims.get("aud")
            if str(token_project) != str(expected_project_id):
                raise TokenVerificationError(
                    f"Token project mismatch: expected '{expected_project_id}', found '{token_project}'."
                )

        return claims
    except PyJWTError as exc:
        raise TokenVerificationError(f"JWT verification failed: {exc}") from exc
