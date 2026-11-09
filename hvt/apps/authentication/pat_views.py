# SPDX-License-Identifier: Apache-2.0
"""
Personal Access Token (PAT) views for developer automation, CLI tools, and API scripting.
Includes endpoints for:
- Control-Plane PATs (Dashboard / Operator tokens with project__isnull=True)
- Runtime PATs (End-user tokens scoped to an active Project)
"""

import logging
from datetime import timedelta
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import permissions, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import PersonalAccessToken, AuditLog
from .permissions import IsPlatformUser
from hvt.apps.organizations.models import Project

logger = logging.getLogger(__name__)


def _resolve_runtime_project(request):
    """Resolves the active Project for runtime requests."""
    auth = getattr(request, "auth", None)
    pid = None
    if hasattr(auth, "get"):
        pid = auth.get("project_id")
    if not pid and hasattr(request, "_auth") and hasattr(request._auth, "get"):
        pid = request._auth.get("project_id")
    if not pid and hasattr(auth, "project_id"):
        pid = auth.project_id
    if not pid and hasattr(request.user, "project_id"):
        pid = request.user.project_id

    if not pid:
        api_key_header = request.headers.get("X-API-Key") or request.META.get("HTTP_X_API_KEY")
        if api_key_header:
            from hvt.apps.organizations.models import APIKey
            from hvt.apps.authentication.backends import parse_api_key_components
            try:
                _, env, prefix = parse_api_key_components(api_key_header)
                ak = APIKey.objects.filter(prefix=prefix, environment=env).first()
                if ak:
                    pid = ak.project_id
            except Exception:
                pass

    if not pid:
        return None

    try:
        return Project.objects.filter(id=pid, is_active=True).first()
    except Exception:
        return None


class PersonalAccessTokenSerializer(serializers.ModelSerializer):
    """Safe, redacted serializer for listing and retrieving PATs."""
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = PersonalAccessToken
        fields = [
            "id",
            "name",
            "prefix",
            "environment",
            "scopes",
            "project",
            "created_at",
            "expires_at",
            "last_used_at",
            "revoked_at",
            "is_active",
        ]
        read_only_fields = fields


class PersonalAccessTokenCreateSerializer(serializers.Serializer):
    """Input serializer for creating a new Personal Access Token."""
    name = serializers.CharField(max_length=120, required=True)
    environment = serializers.ChoiceField(
        choices=PersonalAccessToken.Environment.choices,
        default=PersonalAccessToken.Environment.LIVE,
        required=False,
    )
    expires_in_days = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=1,
        max_value=365,
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=64),
        required=False,
        default=list,
    )


class PersonalAccessTokenCreateResponseSerializer(serializers.ModelSerializer):
    """Creation response serializer returning the plaintext token once."""
    token = serializers.CharField(read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = PersonalAccessToken
        fields = [
            "id",
            "name",
            "token",
            "prefix",
            "environment",
            "scopes",
            "project",
            "created_at",
            "expires_at",
            "last_used_at",
            "is_active",
        ]
        read_only_fields = fields


class ControlPlanePATListCreateView(APIView):
    """
    List and create Personal Access Tokens for control-plane users.
    Raw token secret is returned once upon creation and never stored.
    """
    permission_classes = [permissions.IsAuthenticated, IsPlatformUser]

    @extend_schema(
        summary="List control-plane personal access tokens",
        responses={200: PersonalAccessTokenSerializer(many=True)},
    )
    def get(self, request):
        pats = PersonalAccessToken.objects.filter(
            user=request.user,
            project__isnull=True,
        )
        serializer = PersonalAccessTokenSerializer(pats, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Create a control-plane personal access token",
        request=PersonalAccessTokenCreateSerializer,
        responses={201: PersonalAccessTokenCreateResponseSerializer},
    )
    def post(self, request):
        in_serializer = PersonalAccessTokenCreateSerializer(data=request.data)
        in_serializer.is_valid(raise_exception=True)
        data = in_serializer.validated_data

        # Enforce that a PAT cannot create child PATs with scopes exceeding itself
        if isinstance(getattr(request, "auth", None), PersonalAccessToken):
            auth_pat = request.auth
            auth_scopes = auth_pat.scopes or []
            if auth_scopes and "*" not in auth_scopes and "admin" not in auth_scopes:
                requested_scopes = set(data.get("scopes", []))
                if not requested_scopes or "*" in requested_scopes or "admin" in requested_scopes or not requested_scopes.issubset(set(auth_scopes)):
                    raise serializers.ValidationError(
                        {"scopes": "Cannot create a personal access token with scopes exceeding the authorizing token."}
                    )

        env = data.get("environment", PersonalAccessToken.Environment.LIVE)
        prefix, raw_token, hashed_token = PersonalAccessToken.generate_token(environment=env)

        expires_in_days = data.get("expires_in_days")
        if expires_in_days:
            expires_at = timezone.now() + timedelta(days=expires_in_days)
        else:
            expires_at = data.get("expires_at")

        pat = PersonalAccessToken.objects.create(
            user=request.user,
            project=None,
            name=data["name"],
            environment=env,
            prefix=prefix,
            hashed_token=hashed_token,
            scopes=data.get("scopes", []),
            expires_at=expires_at,
        )

        AuditLog.log(
            event_type=AuditLog.EventType.PAT_CREATED,
            request=request,
            user=request.user,
            project=None,
            target=pat,
            event_data={
                "pat_id": str(pat.id),
                "name": pat.name,
                "prefix": pat.prefix,
                "environment": pat.environment,
                "scopes": pat.scopes,
            },
        )

        resp_data = PersonalAccessTokenSerializer(pat).data
        resp_data["token"] = raw_token
        return Response(resp_data, status=status.HTTP_201_CREATED)


class ControlPlanePATRevokeView(APIView):
    """
    Revoke a control-plane personal access token by ID.
    """
    permission_classes = [permissions.IsAuthenticated, IsPlatformUser]

    @extend_schema(
        summary="Revoke a control-plane personal access token",
        responses={
            200: OpenApiResponse(description="Token revoked"),
            404: OpenApiResponse(description="Token not found"),
        },
    )
    def delete(self, request, pk):
        pat = PersonalAccessToken.objects.filter(
            id=pk,
            user=request.user,
            project__isnull=True,
        ).first()

        if not pat:
            return Response(
                {"error": "Personal access token not found.", "code": "pat_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        pat.revoked_at = timezone.now()
        pat.revoked_reason = "user_revoked"
        pat.save(update_fields=["revoked_at", "revoked_reason"])

        AuditLog.log(
            event_type=AuditLog.EventType.PAT_REVOKED,
            request=request,
            user=request.user,
            project=None,
            target=pat,
            event_data={"pat_id": str(pat.id), "name": pat.name, "prefix": pat.prefix},
        )

        return Response(
            {"detail": "Personal access token revoked successfully.", "ok": True},
            status=status.HTTP_200_OK,
        )


class RuntimePATListCreateView(APIView):
    """
    List and create Personal Access Tokens for runtime end-users scoped to a Project.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="List runtime personal access tokens",
        responses={200: PersonalAccessTokenSerializer(many=True)},
    )
    def get(self, request):
        project = _resolve_runtime_project(request)
        if not project:
            return Response(
                {"error": "Runtime project context is required.", "code": "project_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pats = PersonalAccessToken.objects.filter(
            user=request.user,
            project=project,
        )
        serializer = PersonalAccessTokenSerializer(pats, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Create a runtime personal access token",
        request=PersonalAccessTokenCreateSerializer,
        responses={201: PersonalAccessTokenCreateResponseSerializer},
    )
    def post(self, request):
        project = _resolve_runtime_project(request)
        if not project:
            return Response(
                {"error": "Runtime project context is required.", "code": "project_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        in_serializer = PersonalAccessTokenCreateSerializer(data=request.data)
        in_serializer.is_valid(raise_exception=True)
        data = in_serializer.validated_data

        # Enforce that a PAT cannot create child PATs with scopes exceeding itself
        if isinstance(getattr(request, "auth", None), PersonalAccessToken):
            auth_pat = request.auth
            auth_scopes = auth_pat.scopes or []
            if auth_scopes and "*" not in auth_scopes and "admin" not in auth_scopes:
                requested_scopes = set(data.get("scopes", []))
                if not requested_scopes or "*" in requested_scopes or "admin" in requested_scopes or not requested_scopes.issubset(set(auth_scopes)):
                    raise serializers.ValidationError(
                        {"scopes": "Cannot create a personal access token with scopes exceeding the authorizing token."}
                    )

        env = data.get("environment", PersonalAccessToken.Environment.LIVE)
        prefix, raw_token, hashed_token = PersonalAccessToken.generate_token(environment=env)

        expires_in_days = data.get("expires_in_days")
        if expires_in_days:
            expires_at = timezone.now() + timedelta(days=expires_in_days)
        else:
            expires_at = data.get("expires_at")

        pat = PersonalAccessToken.objects.create(
            user=request.user,
            project=project,
            name=data["name"],
            environment=env,
            prefix=prefix,
            hashed_token=hashed_token,
            scopes=data.get("scopes", []),
            expires_at=expires_at,
        )

        AuditLog.log(
            event_type=AuditLog.EventType.PAT_CREATED,
            request=request,
            user=request.user,
            project=project,
            target=pat,
            event_data={
                "pat_id": str(pat.id),
                "name": pat.name,
                "prefix": pat.prefix,
                "environment": pat.environment,
                "scopes": pat.scopes,
                "project_id": str(project.id),
            },
        )

        resp_data = PersonalAccessTokenSerializer(pat).data
        resp_data["token"] = raw_token
        return Response(resp_data, status=status.HTTP_201_CREATED)


class RuntimePATRevokeView(APIView):
    """
    Revoke a runtime personal access token by ID.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Revoke a runtime personal access token",
        responses={
            200: OpenApiResponse(description="Token revoked"),
            404: OpenApiResponse(description="Token not found"),
        },
    )
    def delete(self, request, pk):
        project = _resolve_runtime_project(request)
        if not project:
            return Response(
                {"error": "Runtime project context is required.", "code": "project_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pat = PersonalAccessToken.objects.filter(
            id=pk,
            user=request.user,
            project=project,
        ).first()

        if not pat:
            return Response(
                {"error": "Personal access token not found.", "code": "pat_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        pat.revoked_at = timezone.now()
        pat.revoked_reason = "user_revoked"
        pat.save(update_fields=["revoked_at", "revoked_reason"])

        AuditLog.log(
            event_type=AuditLog.EventType.PAT_REVOKED,
            request=request,
            user=request.user,
            project=project,
            target=pat,
            event_data={
                "pat_id": str(pat.id),
                "name": pat.name,
                "prefix": pat.prefix,
                "project_id": str(project.id),
            },
        )

        return Response(
            {"detail": "Personal access token revoked successfully.", "ok": True},
            status=status.HTTP_200_OK,
        )
