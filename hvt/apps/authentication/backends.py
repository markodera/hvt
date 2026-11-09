# SPDX-License-Identifier: Apache-2.0
import logging

from django.contrib.auth.models import AnonymousUser
from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from rest_framework import authentication, exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication

from hvt.apps.organizations.models import APIKey
from hvt.apps.organizations.runtime_origins import (
    origin_is_allowed_for_api_key,
    request_targets_runtime_api_key_endpoint,
)
from hvt.apps.authentication.tokens import _OrgClaimVerificationMixin

logger = logging.getLogger(__name__)


def parse_api_key_components(key: str) -> tuple[str, str, str]:
    """
    Parses full key string and returns (key_type, environment, prefix).
    Supported key patterns:
    - hvt_mgmt_test_xxx -> ('management', 'test', prefix)
    - hvt_mgmt_live_xxx -> ('management', 'live', prefix)
    - hvt_test_xxx      -> ('runtime', 'test', prefix)
    - hvt_live_xxx      -> ('runtime', 'live', prefix)
    - hvt_client_test_x -> ('runtime', 'test', prefix)
    - hvt_client_live_x -> ('runtime', 'live', prefix)
    """
    if key.startswith("hvt_mgmt_test_"):
        raw_key = key[len("hvt_mgmt_test_"):]
        return "management", "test", raw_key[:8]
    elif key.startswith("hvt_mgmt_live_"):
        raw_key = key[len("hvt_mgmt_live_"):]
        return "management", "live", raw_key[:8]
    elif key.startswith("hvt_test_"):
        raw_key = key[len("hvt_test_"):]
        return "runtime", "test", raw_key[:8]
    elif key.startswith("hvt_live_"):
        raw_key = key[len("hvt_live_"):]
        return "runtime", "live", raw_key[:8]
    elif key.startswith("hvt_client_test_"):
        raw_key = key[len("hvt_client_test_"):]
        return "runtime", "test", raw_key[:8]
    elif key.startswith("hvt_client_live_"):
        raw_key = key[len("hvt_client_live_"):]
        return "runtime", "live", raw_key[:8]
    else:
        raise exceptions.AuthenticationFailed(
            "Invalid API key format. Expected hvt_test_*, hvt_live_*, or hvt_mgmt_*"
        )


def emit_management_key_runtime_violation_audit(request, api_key_obj: APIKey):
    """Write an append-only security AuditLog entry when a verified management key is used on runtime routes."""
    try:
        from hvt.apps.authentication.models import AuditLog

        AuditLog.objects.create(
            event_type=AuditLog.EventType.SECURITY_VIOLATION,
            actor_api_key=api_key_obj,
            organization=api_key_obj.organization,
            project=api_key_obj.project,
            ip_address=request.META.get("REMOTE_ADDR") if request else None,
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:500] if request else "",
            success=False,
            error_message="Management keys cannot be used for runtime authentication. Use a runtime client key.",
            event_data={
                "path": getattr(request, "path", ""),
                "method": getattr(request, "method", ""),
                "key_prefix": api_key_obj.prefix,
                "environment": api_key_obj.environment,
                "reason": "management_key_runtime_violation",
            },
        )
    except Exception as exc:
        logger.error(f"[SecurityAudit] Failed to record security violation audit log: {exc}")


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Base authentication using X-API-Key header.
    Validates key signature, expiration, organization and project status.
    """

    keyword = "X-API-Key"
    allow_management_keys = False

    def authenticate(self, request):
        api_key = request.headers.get(self.keyword) or request.META.get(
            "HTTP_X_API_KEY"
        )

        if not api_key:
            return None

        logger.debug("[APIKeyAuthentication] API key header detected")
        return self.validate_key(api_key, request=request)

    def validate_key(self, key: str, request=None):
        from hvt.apps.organizations.api_key_expiry import emit_api_key_expiry_webhook

        key_type, environment, prefix = parse_api_key_components(key)

        try:
            api_key_obj = APIKey.objects.select_related("organization", "project").get(
                prefix=prefix,
                environment=environment,
            )
        except APIKey.DoesNotExist:
            logger.warning(f"[APIKeyAuthentication] Key not found: {prefix}")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        if not api_key_obj.verify_key(key):
            logger.warning(f"[APIKeyAuthentication] Hash mismatch for: {prefix}")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        # Plane check: verified management keys are rejected unless authenticator explicitly allows them
        if api_key_obj.key_type == APIKey.KeyType.MANAGEMENT and not self.allow_management_keys:
            emit_management_key_runtime_violation_audit(request, api_key_obj)
            is_runtime = isinstance(self, RuntimeAPIKeyAuthentication) or (
                request is not None and request_targets_runtime_api_key_endpoint(request)
            )
            msg = (
                "Management keys cannot be used for runtime authentication. Use a runtime client key."
                if is_runtime
                else "Management keys are not permitted on this endpoint."
            )
            raise exceptions.PermissionDenied(msg)

        if api_key_obj.is_expired:
            emit_api_key_expiry_webhook(api_key_obj)
            logger.warning(f"[APIKeyAuthentication] Key inactive/expired: {prefix}")
            raise exceptions.AuthenticationFailed("API key is inactive or expired.")

        if not api_key_obj.is_valid:
            logger.warning(f"[APIKeyAuthentication] Key inactive/expired: {prefix}")
            raise exceptions.AuthenticationFailed("API key is inactive or expired.")

        if api_key_obj.organization and not api_key_obj.organization.is_active:
            raise exceptions.AuthenticationFailed("API key organization is inactive.")

        if api_key_obj.project_id is None:
            default_project = (
                api_key_obj.organization.get_default_project()
                or api_key_obj.organization.ensure_default_project()
            )
            if default_project is None:
                raise exceptions.AuthenticationFailed(
                    "API key is not attached to a project."
                )
            api_key_obj.project = default_project
            api_key_obj.save(update_fields=["project"])
        elif api_key_obj.project.organization_id != api_key_obj.organization_id:
            raise exceptions.AuthenticationFailed(
                "API key project does not belong to the organization."
            )
        elif not api_key_obj.project.is_active:
            raise exceptions.AuthenticationFailed("API key project is inactive.")

        # If targeting runtime route, enforce origin
        if request is not None and request_targets_runtime_api_key_endpoint(request):

            request_origin = (request.headers.get("origin") or "").strip()
            if request_origin:
                request_host_origin = ""
                try:
                    request_host_origin = f"{request.scheme}://{request.get_host()}"
                except Exception:
                    request_host_origin = ""

                if not origin_is_allowed_for_api_key(
                    request_origin,
                    api_key_obj,
                    request_host_origin=request_host_origin,
                ):
                    raise exceptions.PermissionDenied(
                        "This origin is not allowed for the provided API key."
                    )

        api_key_obj.update_last_used()
        logger.info(f"[APIKeyAuthentication] Success: {prefix} ({environment})")
        return (AnonymousUser(), api_key_obj)

    def authenticate_header(self, request):
        return self.keyword


class RuntimeAPIKeyAuthentication(APIKeyAuthentication):
    """
    Dedicated authentication class for runtime client routes.
    Accepts ONLY runtime keys. Rejects management keys with 403 and writes security AuditLog.
    """
    allow_management_keys = False

    def validate_key(self, key: str, request=None):
        return super().validate_key(key, request=request)


class ManagementAPIKeyAuthentication(APIKeyAuthentication):
    """
    Dedicated authentication class for management / schema provisioning routes.
    Accepts ONLY management keys. Rejects runtime client keys with 403.
    """
    allow_management_keys = True

    def validate_key(self, key: str, request=None):
        key_type, environment, prefix = parse_api_key_components(key)
        if key_type != "management":
            raise exceptions.PermissionDenied(
                "Runtime client keys cannot be used for management endpoints. Use a management key."
            )

        user, api_key_obj = super().validate_key(key, request=request)
        if api_key_obj.key_type != APIKey.KeyType.MANAGEMENT:
            raise exceptions.PermissionDenied(
                "Runtime client keys cannot be used for management endpoints. Use a management key."
            )
        return user, api_key_obj


class HVTJWTAuthentication(_OrgClaimVerificationMixin, JWTAuthentication):
    """Bearer JWT auth with org claim verification."""


class HVTJWTCookieAuthentication(_OrgClaimVerificationMixin, JWTCookieAuthentication):
    """Cookie-based JWT auth with the same org claim verification."""



class PersonalAccessTokenAuthentication(authentication.BaseAuthentication):
    """
    Personal Access Token (PAT) authentication backend.
    Accepts:
      - Authorization: Bearer hvt_pat_<env>_<hex>
      - Authorization: Token hvt_pat_<env>_<hex>
      - X-PAT: hvt_pat_<env>_<hex>

    Returns (user, pat) on success.
    Returns None if no PAT header is present (allowing fallback to JWT/APIKey).
    Raises AuthenticationFailed if a PAT is present but invalid/expired/revoked.
    """

    def authenticate_header(self, request):
        return 'Bearer realm="api"'

    def get_raw_token(self, request) -> str | None:
        auth_header = request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION")
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() in ("bearer", "token") and parts[1].startswith("hvt_pat_"):
                return parts[1].strip()

        x_pat = request.headers.get("X-PAT") or request.META.get("HTTP_X_PAT")
        if x_pat and x_pat.strip().startswith("hvt_pat_"):
            return x_pat.strip()

        return None

    def authenticate(self, request):
        raw_token = self.get_raw_token(request)
        if not raw_token:
            return None

        import hashlib
        from django.utils import timezone
        from hvt.apps.authentication.models import PersonalAccessToken

        hashed_token = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        try:
            pat = PersonalAccessToken.objects.select_related("user", "project").get(
                hashed_token=hashed_token
            )
        except PersonalAccessToken.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid personal access token.")

        if pat.revoked_at is not None:
            raise exceptions.AuthenticationFailed("Personal access token has been revoked.")

        if pat.expires_at is not None and pat.expires_at <= timezone.now():
            raise exceptions.AuthenticationFailed("Personal access token has expired.")

        if not pat.user or not pat.user.is_active:
            raise exceptions.AuthenticationFailed("User account is inactive or disabled.")

        if pat.project and not pat.project.is_active:
            raise exceptions.AuthenticationFailed("Associated project is inactive.")

        pat.update_last_used()
        return (pat.user, pat)
