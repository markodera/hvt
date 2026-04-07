"""
Rate limting/throttling classes for HVT API.
Implements per-organization and per-API-key rate limits.
"""

import hashlib

from django.core.exceptions import ImproperlyConfigured
from rest_framework.settings import api_settings
from rest_framework.throttling import SimpleRateThrottle

from hvt.apps.organizations.models import APIKey


class DynamicRateThrottle(SimpleRateThrottle):
    """Resolve throttle rates from the current DRF settings on each instantiation."""

    def get_rate(self):
        if not getattr(self, "scope", None):
            msg = f"You must set either `.scope` or `.rate` for '{self.__class__.__name__}' throttle"
            raise ImproperlyConfigured(msg)

        try:
            return api_settings.DEFAULT_THROTTLE_RATES[self.scope]
        except KeyError as exc:
            raise ImproperlyConfigured(
                f"No default throttle rate set for '{self.scope}' scope"
            ) from exc


class OrganizationRateThrottle(DynamicRateThrottle):
    """
    Rate limit based on organiization.
    Works with both JWT(user.organization) and API Keys.

    Default: 1000 requests/hour per organization
    """

    scope = "organization"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, APIKey):
            org_id = request.auth.organization.id
        elif (
            request.user and request.user.is_authenticated and request.user.organization
        ):
            org_id = request.user.organization.id
        else:
            return self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": str(org_id)}


class APIKeyRateThrottle(DynamicRateThrottle):
    """Rate limit per API Key - 100 req/min"""

    scope = "api_key"

    def get_cache_key(self, request, view):
        if not isinstance(request.auth, APIKey):
            return None

        return self.cache_format % {"scope": self.scope, "ident": str(request.auth.id)}


class BurstRateThrottle(DynamicRateThrottle):
    """Burst protection - 20 req/sec"""

    scope = "burst"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, APIKey):
            ident = str(request.auth.organization.id)
        elif (
            request.user and request.user.is_authenticated and request.user.organization
        ):
            ident = str(request.user.organization.id)
        else:
            ident = self.get_ident(request)

        return self.cache_format % {"scope": self.scope, "ident": ident}


class AnonRateThrottle(DynamicRateThrottle):
    """Anonymous requests - 10 req/min per IP"""

    scope = "anon"

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            return None
        if isinstance(request.auth, APIKey):
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class IPAddressRateThrottle(DynamicRateThrottle):
    """Rate limit purely by client IP address."""

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class RequestFieldRateThrottle(DynamicRateThrottle):
    """Rate limit by a request field value without storing it in plaintext."""

    field_name = ""

    def get_field_value(self, request):
        try:
            value = request.data.get(self.field_name)
        except Exception:
            return ""
        return str(value or "").strip().lower()

    def get_cache_key(self, request, view):
        value = self.get_field_value(request)
        if not value:
            return None

        ident = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return self.cache_format % {"scope": self.scope, "ident": ident}


class EmailFieldRateThrottle(RequestFieldRateThrottle):
    field_name = "email"


class APIKeyScopeRateThrottle(DynamicRateThrottle):
    """Rate limit by API key when the request authenticated with one."""

    def get_cache_key(self, request, view):
        if not isinstance(request.auth, APIKey):
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": str(request.auth.id),
        }


class AuthenticatedUserRateThrottle(DynamicRateThrottle):
    """Rate limit by authenticated user, falling back to IP."""

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            ident = f"user:{request.user.pk}"
        else:
            ident = self.get_ident(request)

        return self.cache_format % {"scope": self.scope, "ident": ident}


class RefreshTokenRateThrottle(AuthenticatedUserRateThrottle):
    """Rate limit refresh attempts by authenticated user or IP address."""

    scope = "auth_token_refresh"


class LoginIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_login_ip"


class LoginEmailRateThrottle(EmailFieldRateThrottle):
    scope = "auth_login_email"


class RegisterIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_register_ip"


class RegisterEmailRateThrottle(EmailFieldRateThrottle):
    scope = "auth_register_email"


class RuntimeRegisterAPIKeyThrottle(APIKeyScopeRateThrottle):
    scope = "auth_runtime_register_api_key"


class PasswordResetIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_password_reset_ip"


class PasswordResetEmailRateThrottle(EmailFieldRateThrottle):
    scope = "auth_password_reset_email"


class PasswordResetConfirmIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_password_reset_confirm_ip"


class PasswordResetValidateIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_password_reset_validate_ip"


class PasswordChangeUserRateThrottle(AuthenticatedUserRateThrottle):
    scope = "auth_password_change_user"


class EmailVerificationIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_email_verification_ip"


class ResendVerificationIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_resend_verification_ip"


class ResendVerificationEmailRateThrottle(EmailFieldRateThrottle):
    scope = "auth_resend_verification_email"


class SocialLoginIPRateThrottle(IPAddressRateThrottle):
    scope = "auth_social_login_ip"


class RuntimeLoginAPIKeyThrottle(APIKeyScopeRateThrottle):
    scope = "auth_runtime_login_api_key"


class RuntimeSocialLoginAPIKeyThrottle(APIKeyScopeRateThrottle):
    scope = "auth_runtime_social_api_key"
