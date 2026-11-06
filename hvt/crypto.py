# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import warnings
from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.core.checks import Error, Tags, register
from django.core.exceptions import ImproperlyConfigured
from django.db import models

ENCRYPTION_VERSION_PREFIX = "v1:"


def get_multi_fernet() -> MultiFernet:
    """
    Returns a MultiFernet instance initialized with HVT_ENCRYPTION_KEYS.
    The first key encrypts; all keys decrypt.
    If HVT_ENCRYPTION_KEYS is empty and DEBUG=True, derives a key from SECRET_KEY.
    If HVT_ENCRYPTION_KEYS is empty and DEBUG=False, raises ImproperlyConfigured.
    """
    raw_keys = getattr(settings, "HVT_ENCRYPTION_KEYS", [])
    if isinstance(raw_keys, str):
        keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    elif isinstance(raw_keys, (list, tuple)):
        keys = [str(k).strip() for k in raw_keys if str(k).strip()]
    else:
        keys = []

    if keys:
        fernets = []
        for k in keys:
            if isinstance(k, str):
                fernets.append(Fernet(k.encode("utf-8")))
            else:
                fernets.append(Fernet(k))
        return MultiFernet(fernets)

    if settings.DEBUG:
        warnings.warn(
            "HVT_ENCRYPTION_KEYS is not configured. Deriving fallback encryption key from SECRET_KEY because DEBUG is True. Configure HVT_ENCRYPTION_KEYS for production.",
            RuntimeWarning,
            stacklevel=2,
        )
        derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(derived)
        return MultiFernet([Fernet(key)])

    raise ImproperlyConfigured(
        "HVT_ENCRYPTION_KEYS must be set when DEBUG is False. Set comma-separated Fernet keys in environment."
    )


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string and prepend the version prefix."""
    if plaintext is None:
        return ""
    plaintext_str = str(plaintext)
    if not plaintext_str:
        return ""
    mf = get_multi_fernet()
    token = mf.encrypt(plaintext_str.encode("utf-8")).decode("utf-8")
    return f"{ENCRYPTION_VERSION_PREFIX}{token}"


def decrypt_value(ciphertext: str) -> str:
    """
    Decrypt a version-prefixed ciphertext string.
    If the string lacks the version prefix, returns it as legacy unencrypted plaintext.
    """
    if not ciphertext:
        return ""
    if not isinstance(ciphertext, str):
        ciphertext = str(ciphertext)
    if ciphertext.startswith(ENCRYPTION_VERSION_PREFIX):
        token = ciphertext[len(ENCRYPTION_VERSION_PREFIX):]
        mf = get_multi_fernet()
        return mf.decrypt(token.encode("utf-8")).decode("utf-8")
    # Legacy unencrypted fallback
    return ciphertext


class EncryptedTextField(models.TextField):
    """
    TextField that transparently encrypts values on write using MultiFernet
    and decrypts on read. Includes a version prefix (v1:) for future key/algorithm rotation.
    Unencrypted legacy values are read as-is and encrypted on save.
    """

    description = "MultiFernet-encrypted text field with version prefix"

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt_value(value)

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, str) and value.startswith(ENCRYPTION_VERSION_PREFIX):
            try:
                return decrypt_value(value)
            except Exception:
                return value
        return value

    def get_prep_value(self, value):
        if value is None:
            return value
        if not isinstance(value, str):
            value = str(value)
        if not value:
            return value
        if value.startswith(ENCRYPTION_VERSION_PREFIX):
            return value
        return encrypt_value(value)


@register(Tags.security)
def check_encryption_keys(app_configs, **kwargs):
    """System check to ensure HVT_ENCRYPTION_KEYS is configured in production."""
    errors = []
    raw_keys = getattr(settings, "HVT_ENCRYPTION_KEYS", [])
    keys = (
        [k.strip() for k in raw_keys.split(",") if k.strip()]
        if isinstance(raw_keys, str)
        else [str(k).strip() for k in raw_keys if str(k).strip()]
    )
    if not settings.DEBUG and not keys:
        errors.append(
            Error(
                "HVT_ENCRYPTION_KEYS must be set when DEBUG is False.",
                hint="Provide one or more comma-separated Fernet keys via HVT_ENCRYPTION_KEYS.",
                id="hvt.E001",
            )
        )
    return errors
