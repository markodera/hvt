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


def emit_management_key_runtime_violation_audit(request, prefix: str, environment: str):
    """Write an immutable security AuditLog entry when a management key is used on runtime routes."""
    try:
        from hvt.apps.authentication.models import AuditLog

        api_key_obj = APIKey.objects.select_related("organization", "project").filter(
            prefix=prefix, environment=environment
        ).first()

        AuditLog.objects.create(
            event_type=AuditLog.EventType.SECURITY_VIOLATION,
            actor_api_key=api_key_obj,
            organization=api_key_obj.organization if api_key_obj else None,
            project=api_key_obj.project if api_key_obj else None,
            ip_address=request.META.get("REMOTE_ADDR") if request else None,
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:500] if request else "",
            success=False,
            error_message="Management keys cannot be used for runtime authentication. Use a runtime client key.",
            event_data={
                "path": getattr(request, "path", ""),
                "method": getattr(request, "method", ""),
                "key_prefix": prefix,
                "environment": environment,
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

        # Plane check: runtime routes never accept management keys
        if request is not None and request_targets_runtime_api_key_endpoint(request):
            if key_type == "management":
                emit_management_key_runtime_violation_audit(request, prefix, environment)
                raise exceptions.PermissionDenied(
                    "Management keys cannot be used for runtime authentication. Use a runtime client key."
                )

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

        # If targeting runtime route, enforce key_type and origin
        if request is not None and request_targets_runtime_api_key_endpoint(request):
            if api_key_obj.key_type == APIKey.KeyType.MANAGEMENT:
                emit_management_key_runtime_violation_audit(request, prefix, environment)
                raise exceptions.PermissionDenied(
                    "Management keys cannot be used for runtime authentication. Use a runtime client key."
                )

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

    def validate_key(self, key: str, request=None):
        key_type, environment, prefix = parse_api_key_components(key)
        if key_type == "management":
            emit_management_key_runtime_violation_audit(request, prefix, environment)
            raise exceptions.PermissionDenied(
                "Management keys cannot be used for runtime authentication. Use a runtime client key."
            )

        user, api_key_obj = super().validate_key(key, request=request)
        if api_key_obj.key_type == APIKey.KeyType.MANAGEMENT:
            emit_management_key_runtime_violation_audit(request, prefix, environment)
            raise exceptions.PermissionDenied(
                "Management keys cannot be used for runtime authentication. Use a runtime client key."
            )
        return user, api_key_obj


class ManagementAPIKeyAuthentication(APIKeyAuthentication):
    """
    Dedicated authentication class for management / schema provisioning routes.
    Accepts ONLY management keys. Rejects runtime client keys with 403.
    """

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
