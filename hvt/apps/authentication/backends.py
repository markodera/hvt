import logging

from django.contrib.auth.models import AnonymousUser
from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from rest_framework import authentication, exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication

from hvt.apps.organizations.models import APIKey
from hvt.apps.authentication.tokens import _OrgClaimVerificationMixin

logger = logging.getLogger(__name__)


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication using X-API-Key header.

    Supports both test and live keys:
    - hvt_test_xxxxx - Test environment
    - hvt_live_xxxxx - Live environment
    """

    keyword = "X-API-Key"

    def authenticate(self, request):
        api_key = request.headers.get(self.keyword) or request.META.get(
            "HTTP_X_API_KEY"
        )

        if not api_key:
            return None

        logger.debug("[APIKeyAuthentication] API key header detected")
        return self.validate_key(api_key)

    def validate_key(self, key: str):
        """Validate the API key and return (user, auth_info)."""

        # Check key format (hvt_test_xxx or hvt_live_xxx)
        if not (key.startswith("hvt_test_") or key.startswith("hvt_live_")):
            logger.warning("[APIKeyAuthentication] Invalid key format")
            raise exceptions.AuthenticationFailed(
                "Invalid API key format. Expected hvt_test_* or hvt_live_*"
            )

        # Determine environment from key
        if key.startswith("hvt_test_"):
            environment = "test"
            raw_key = key.replace("hvt_test_", "")
        else:
            environment = "live"
            raw_key = key.replace("hvt_live_", "")

        # Extract prefix (first 8 chars of raw key)
        try:
            prefix = raw_key[:8]
        except (IndexError, ValueError):
            raise exceptions.AuthenticationFailed("Invalid API key format.")

        logger.info(
            f"[APIKeyAuthentication] Looking for prefix: {prefix}, env: {environment}"
        )

        # Find key by prefix and environment
        try:
            api_key_obj = APIKey.objects.select_related("organization", "project").get(
                prefix=prefix,
                environment=environment,
            )
        except APIKey.DoesNotExist:
            logger.warning(f"[APIKeyAuthentication] Key not found: {prefix}")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        # Verify the full key hash
        if not api_key_obj.verify_key(key):
            logger.warning(f"[APIKeyAuthentication] Hash mismatch for: {prefix}")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        # Check if key is valid (active + not expired)
        if not api_key_obj.is_valid:
            logger.warning(f"[APIKeyAuthentication] Key inactive/expired: {prefix}")
            raise exceptions.AuthenticationFailed("API key is inactive or expired.")

        if api_key_obj.organization and not api_key_obj.organization.is_active:
            raise exceptions.AuthenticationFailed("API key organization is inactive.")

        if api_key_obj.project_id is None:
            api_key_obj.project = api_key_obj.organization.ensure_default_project()
            api_key_obj.save(update_fields=["project"])
        elif api_key_obj.project.organization_id != api_key_obj.organization_id:
            raise exceptions.AuthenticationFailed(
                "API key project does not belong to the organization."
            )
        elif not api_key_obj.project.is_active:
            raise exceptions.AuthenticationFailed("API key project is inactive.")

        # Update last used timestamp
        api_key_obj.update_last_used()

        logger.info(f"[APIKeyAuthentication] Success: {prefix} ({environment})")
        return (AnonymousUser(), api_key_obj)

    def authenticate_header(self, request):
        return self.keyword


class HVTJWTAuthentication(_OrgClaimVerificationMixin, JWTAuthentication):
    """Bearer JWT auth with org claim verification."""


class HVTJWTCookieAuthentication(_OrgClaimVerificationMixin, JWTCookieAuthentication):
    """Cookie-based JWT auth with the same org claim verification."""
