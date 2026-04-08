"""Custom JWT serializers and authentication helpers for HVT."""

import logging

from rest_framework import exceptions
from rest_framework import serializers
from dj_rest_auth.app_settings import api_settings as dj_rest_auth_settings
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

logger = logging.getLogger(__name__)


def _stamp_org_claims(token, user, project=None) -> None:
    """Embed HVT-specific claims into a SimpleJWT token."""
    from hvt.apps.organizations.access import (
        get_user_project_permission_slugs,
        get_user_project_role_slugs,
    )

    org = getattr(user, "organization", None)
    token["org_id"] = str(org.id) if org else None
    token["org_slug"] = org.slug if org else ""
    token["project_id"] = str(project.id) if project else None
    token["project_slug"] = project.slug if project else ""
    token["role"] = user.role
    token["email"] = user.email
    token["app_roles"] = get_user_project_role_slugs(user, project) if project else []
    token["app_permissions"] = (
        get_user_project_permission_slugs(user, project) if project else []
    )


def _validate_refresh_context(refresh_token: RefreshToken):
    """Load and validate the current user context for a refresh token."""
    from hvt.apps.users.models import User
    from hvt.apps.organizations.models import Project
    from hvt.apps.organizations.access import user_has_project_access

    user_id = refresh_token.get("user_id")
    token_org_id = refresh_token.get("org_id")
    token_project_id = refresh_token.get("project_id")

    if not user_id:
        raise exceptions.AuthenticationFailed("Invalid token: missing user_id claim.")

    try:
        user = User.objects.select_related("organization", "project").get(id=user_id)
    except User.DoesNotExist as exc:
        raise exceptions.AuthenticationFailed("User not found.") from exc

    if not user.is_active:
        raise exceptions.AuthenticationFailed("User account is disabled.")

    user_org = getattr(user, "organization", None)
    if user_org is None and token_org_id is None:
        return user, None

    if user_org is None or token_org_id is None or str(user_org.id) != str(token_org_id):
        raise exceptions.AuthenticationFailed(
            "Token organization does not match the current user organization."
        )

    if not token_project_id:
        return user, None

    try:
        project = Project.objects.select_related("organization").get(id=token_project_id)
    except Project.DoesNotExist as exc:
        raise exceptions.AuthenticationFailed("Token project was not found.") from exc

    if not project.is_active:
        raise exceptions.AuthenticationFailed("Token project is inactive.")

    if str(project.organization_id) != str(user_org.id):
        raise exceptions.AuthenticationFailed(
            "Token project does not belong to the current user organization."
        )

    if not user_has_project_access(user, project):
        raise exceptions.AuthenticationFailed(
            "Token project does not match the current user project."
        )

    return user, project


def build_hvt_token_pair(user, project=None):
    """Issue an HVT token pair with optional project context."""
    refresh = HVTTokenObtainPairSerializer.get_token(user, project=project)
    return refresh.access_token, refresh


class HVTTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Token pair serializer that stamps org context into both tokens."""

    @classmethod
    def get_token(cls, user, project=None) -> RefreshToken:
        token = super().get_token(user)
        _stamp_org_claims(token, user, project=project)
        return token


class HVTTokenRefreshSerializer(TokenRefreshSerializer):
    """Refresh serializer that revalidates org membership and restamps claims."""

    def validate(self, attrs: dict) -> dict:
        refresh_token = RefreshToken(attrs["refresh"])
        user, project = _validate_refresh_context(refresh_token)

        data = super().validate(attrs)

        access_token = AccessToken(data["access"])
        _stamp_org_claims(access_token, user, project=project)
        data["access"] = str(access_token)

        if "refresh" in data:
            refreshed_refresh = RefreshToken(data["refresh"])
            _stamp_org_claims(refreshed_refresh, user, project=project)
            data["refresh"] = str(refreshed_refresh)

        logger.debug(
            "[HVTTokenRefreshSerializer] Refreshed claims for user=%s org=%s role=%s",
            user.id,
            access_token.get("org_id"),
            access_token.get("role"),
        )
        return data


class HVTCookieTokenRefreshSerializer(HVTTokenRefreshSerializer):
    """Cookie-aware refresh serializer that preserves HVT org claim validation."""

    refresh = serializers.CharField(required=False)

    def extract_refresh_token(self):
        request = self.context["request"]
        if request.data.get("refresh"):
            return request.data["refresh"]

        cookie_name = dj_rest_auth_settings.JWT_AUTH_REFRESH_COOKIE
        if cookie_name:
            refresh_token = request.COOKIES.get(cookie_name)
            if refresh_token:
                return refresh_token

        raise InvalidToken("No valid refresh token found.")

    def validate(self, attrs):
        attrs["refresh"] = self.extract_refresh_token()
        return super().validate(attrs)


class _OrgClaimVerificationMixin:
    """Shared org claim enforcement for JWT auth backends."""

    PUBLIC_AUTH_PATH_PREFIXES = (
        "/api/v1/auth/login",
        "/api/v1/auth/runtime/register",
        "/api/v1/auth/runtime/login",
        "/api/v1/auth/runtime/social",
        "/api/v1/auth/register",
        "/api/v1/auth/social",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/token/refresh",
    )

    def _is_public_auth_path(self, request) -> bool:
        path = (getattr(request, "path_info", "") or "").rstrip("/")
        return any(
            path == prefix or path.startswith(f"{prefix}/")
            for prefix in self.PUBLIC_AUTH_PATH_PREFIXES
        )

    def authenticate(self, request):
        if self._is_public_auth_path(request):
            return None
        return super().authenticate(request)

    def get_user(self, validated_token):
        from hvt.apps.organizations.models import Project
        from hvt.apps.organizations.access import user_has_project_access

        user = super().get_user(validated_token)
        token_org_id = validated_token.get("org_id")
        token_project_id = validated_token.get("project_id")
        user_org = getattr(user, "organization", None)

        if user_org is None and token_org_id is None:
            return user

        if user_org is None or token_org_id is None or str(user_org.id) != str(token_org_id):
            raise InvalidToken("Token organization does not match the current user.")

        if token_project_id:
            try:
                project = Project.objects.select_related("organization").get(
                    id=token_project_id
                )
            except Project.DoesNotExist as exc:
                raise InvalidToken("Token project was not found.") from exc

            if not project.is_active:
                raise InvalidToken("Token project is inactive.")

            if str(project.organization_id) != str(user_org.id):
                raise InvalidToken(
                    "Token project does not belong to the current user organization."
                )

            if not user_has_project_access(user, project):
                raise InvalidToken("Token project does not match the current user project.")

        return user
