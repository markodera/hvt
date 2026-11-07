# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
import sys
import warnings
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.checks import Error, Tags, register
from django.core.exceptions import ImproperlyConfigured
from jwt.algorithms import RSAAlgorithm

_CACHED_DEV_PRIVATE_KEY_PEM: Optional[str] = None
_CACHED_DEV_PUBLIC_KEY_PEM: Optional[str] = None


def _load_pem_string(val: Optional[str]) -> Optional[str]:
    """Return raw PEM string if val is PEM content, or read from file if it is a path."""
    if not val:
        return None
    val = val.strip()
    if "\\n" in val:
        val = val.replace("\\n", "\n")
    if "-----BEGIN" in val:
        return val
    # If it is a path to an existing file
    if os.path.isfile(val):
        with open(val, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if "\\n" in content:
                content = content.replace("\\n", "\n")
            return content
    return val


def _generate_in_memory_dev_key() -> tuple[str, str]:
    """Generate a clean 2048-bit RSA key pair for development and testing."""
    global _CACHED_DEV_PRIVATE_KEY_PEM, _CACHED_DEV_PUBLIC_KEY_PEM
    if _CACHED_DEV_PRIVATE_KEY_PEM and _CACHED_DEV_PUBLIC_KEY_PEM:
        return _CACHED_DEV_PRIVATE_KEY_PEM, _CACHED_DEV_PUBLIC_KEY_PEM

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    _CACHED_DEV_PRIVATE_KEY_PEM = priv_pem
    _CACHED_DEV_PUBLIC_KEY_PEM = pub_pem
    return priv_pem, pub_pem


def get_jwt_private_key_pem() -> str:
    """
    Returns the RSA private key PEM for asymmetric token signing.
    In development (DEBUG=True) or testing, generates an in-memory RSA key if unconfigured.
    In production (DEBUG=False), raises ImproperlyConfigured if not configured.
    """
    global _CACHED_DEV_PRIVATE_KEY_PEM
    raw_key = getattr(settings, "HVT_JWT_PRIVATE_KEY", None) or os.getenv("HVT_JWT_PRIVATE_KEY")
    pem = _load_pem_string(raw_key)
    if pem:
        return pem

    if _CACHED_DEV_PRIVATE_KEY_PEM:
        return _CACHED_DEV_PRIVATE_KEY_PEM

    is_testing = getattr(settings, "TESTING", False) or "test" in sys.argv or any("test" in arg for arg in sys.argv)
    if settings.DEBUG or is_testing:
        if not is_testing:
            warnings.warn(
                "HVT_JWT_PRIVATE_KEY is not configured. Using generated in-memory RSA key because DEBUG is True. "
                "Configure HVT_JWT_PRIVATE_KEY for production deployments.",
                RuntimeWarning,
                stacklevel=2,
            )
        priv_pem, _ = _generate_in_memory_dev_key()
        return priv_pem

    raise ImproperlyConfigured(
        "HVT_JWT_PRIVATE_KEY must be set when DEBUG is False. "
        "Set an RSA private key in PEM format (or path to .pem file) in the environment."
    )


def get_jwt_public_key_pem() -> str:
    """
    Returns the RSA public key PEM corresponding to the signing key.
    Automatically derived from the private key if not explicitly set.
    """
    global _CACHED_DEV_PUBLIC_KEY_PEM
    raw_pub = getattr(settings, "HVT_JWT_PUBLIC_KEY", None) or os.getenv("HVT_JWT_PUBLIC_KEY")
    pub_pem = _load_pem_string(raw_pub)
    if pub_pem:
        return pub_pem

    if _CACHED_DEV_PUBLIC_KEY_PEM:
        return _CACHED_DEV_PUBLIC_KEY_PEM

    # Derive from private key
    priv_pem = get_jwt_private_key_pem()
    private_key = serialization.load_pem_private_key(
        priv_pem.encode("utf-8"),
        password=None,
    )
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def get_jwt_key_id() -> str:
    """Returns the Key ID (kid) stamped into token headers and the JWKS."""
    explicit_kid = getattr(settings, "HVT_JWT_KEY_ID", None) or os.getenv("HVT_JWT_KEY_ID")
    if explicit_kid:
        return str(explicit_kid).strip()

    # Deterministic fingerprint from public key
    pub_pem = get_jwt_public_key_pem()
    fp = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()[:16]
    return f"hvt-{fp}"


def get_jwt_issuer() -> str:
    """Returns the canonical token issuer (iss claim)."""
    explicit = (
        getattr(settings, "HVT_JWT_ISSUER", None)
        or os.getenv("HVT_JWT_ISSUER")
        or getattr(settings, "HVT_API_URL", None)
        or os.getenv("HVT_API_URL")
        or getattr(settings, "BACKEND_URL", None)
        or os.getenv("BACKEND_URL")
    )
    if explicit:
        return str(explicit).rstrip("/")

    # Canonical default issuer
    return "https://api.hvts.app"


def get_jwks() -> Dict[str, List[Dict[str, Any]]]:
    """
    Constructs an RFC 7517 JSON Web Key Set (JWKS) containing the active public key
    and any rotated unexpired public keys.
    """
    primary_pub_pem = get_jwt_public_key_pem()
    primary_kid = get_jwt_key_id()

    primary_key_obj = serialization.load_pem_public_key(primary_pub_pem.encode("utf-8"))
    primary_jwk_dict = RSAAlgorithm.to_jwk(primary_key_obj, as_dict=True)
    primary_jwk_dict["kid"] = primary_kid
    primary_jwk_dict["use"] = "sig"
    primary_jwk_dict["alg"] = "RS256"

    keys: List[Dict[str, Any]] = [primary_jwk_dict]

    # Optional rotated older keys
    rotation_keys = getattr(settings, "HVT_JWT_ROTATION_PUBLIC_KEYS", [])
    if isinstance(rotation_keys, (list, tuple)):
        for idx, rot_item in enumerate(rotation_keys):
            if isinstance(rot_item, dict) and "key" in rot_item:
                rot_pem = _load_pem_string(rot_item["key"])
                rot_kid = rot_item.get("kid", f"hvt-rot-{idx}")
            elif isinstance(rot_item, str):
                rot_pem = _load_pem_string(rot_item)
                rot_kid = f"hvt-rot-{idx}"
            else:
                continue

            if rot_pem:
                try:
                    rot_key_obj = serialization.load_pem_public_key(rot_pem.encode("utf-8"))
                    rot_jwk = RSAAlgorithm.to_jwk(rot_key_obj, as_dict=True)
                    rot_jwk["kid"] = rot_kid
                    rot_jwk["use"] = "sig"
                    rot_jwk["alg"] = "RS256"
                    keys.append(rot_jwk)
                except Exception:
                    pass

    return {"keys": keys}


@register(Tags.security)
def check_jwt_signing_keys(app_configs, **kwargs):
    """
    Django system check ensuring HVT_JWT_PRIVATE_KEY is configured in production.
    """
    errors = []
    is_testing = getattr(settings, "TESTING", False) or "test" in sys.argv or any("test" in arg for arg in sys.argv)
    if not settings.DEBUG and not is_testing:
        raw_key = getattr(settings, "HVT_JWT_PRIVATE_KEY", None) or os.getenv("HVT_JWT_PRIVATE_KEY")
        pem = _load_pem_string(raw_key)
        if not pem:
            errors.append(
                Error(
                    "HVT_JWT_PRIVATE_KEY must be configured in production when DEBUG is False.",
                    hint="Set HVT_JWT_PRIVATE_KEY to an RSA private key PEM (or path to a .pem file).",
                    id="hvt.E002",
                )
            )
        else:
            try:
                serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
            except Exception as exc:
                errors.append(
                    Error(
                        f"HVT_JWT_PRIVATE_KEY is not a valid RSA private key PEM: {exc}",
                        hint="Verify the PEM formatting and headers of your RSA private key.",
                        id="hvt.E002",
                    )
                )
    return errors
