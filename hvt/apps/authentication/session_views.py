# SPDX-License-Identifier: Apache-2.0
"""
Session management views for device inspection, single session revocation,
and global remote logout across control-plane and runtime users.
"""

import logging
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import permissions, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView

from .models import UserSession, AuditLog
from .permissions import IsPlatformUser
from .sessions import revoke_session, revoke_all_user_sessions

logger = logging.getLogger(__name__)


class UserSessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)

    class Meta:
        model = UserSession
        fields = [
            "id",
            "project",
            "ip_address",
            "device_name",
            "user_agent",
            "created_at",
            "last_active_at",
            "is_current",
        ]
        read_only_fields = fields

    def get_is_current(self, obj) -> bool:
        request = self.context.get("request")
        if not request:
            return False
        auth = getattr(request, "auth", None)
        current_sid = getattr(auth, "get", lambda k: None)("sid") if auth else None
        return str(obj.id) == str(current_sid) if current_sid else False


class SessionListView(ListAPIView):
    """
    List all active sessions and connected devices for the current control-plane user.
    """
    permission_classes = [permissions.IsAuthenticated, IsPlatformUser]
    serializer_class = UserSessionSerializer
    pagination_class = None

    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user,
            project__isnull=True,
            revoked_at__isnull=True,
        ).order_by("-last_active_at")


class SessionRevokeView(APIView):
    """
    Revoke a specific session by ID, immediately terminating its access across devices.
    """
    permission_classes = [permissions.IsAuthenticated, IsPlatformUser]

    @extend_schema(
        summary="Revoke a specific session",
        responses={
            200: OpenApiResponse(description="Session revoked"),
            404: OpenApiResponse(description="Session not found"),
        },
    )
    def delete(self, request, pk):
        session = UserSession.objects.filter(
            id=pk,
            user=request.user,
            project__isnull=True,
            revoked_at__isnull=True,
        ).first()

        if not session:
            return Response(
                {"error": "Session not found or already revoked.", "code": "session_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        revoke_session(session.id, reason="user_revoked")

        AuditLog.log(
            event_type=AuditLog.EventType.SESSION_REVOKED,
            request=request,
            user=request.user,
            event_data={"session_id": str(session.id), "device": session.device_name},
        )

        return Response(
            {"detail": "Session revoked successfully."},
            status=status.HTTP_200_OK,
        )


class SessionRevokeAllView(APIView):
    """
    Remote logout: Revoke all other active sessions for the current user,
    leaving only the requesting session active.
    """
    permission_classes = [permissions.IsAuthenticated, IsPlatformUser]

    @extend_schema(
        summary="Revoke all other active sessions",
        responses={
            200: OpenApiResponse(description="Sessions revoked"),
        },
    )
    def post(self, request):
        auth = getattr(request, "auth", None)
        current_sid = getattr(auth, "get", lambda k: None)("sid") if auth else None

        revoked_count = revoke_all_user_sessions(
            user=request.user,
            project=None,
            except_session_id=current_sid,
            reason="logout_all",
        )

        AuditLog.log(
            event_type=AuditLog.EventType.SESSION_REVOKED_ALL,
            request=request,
            user=request.user,
            event_data={"revoked_count": revoked_count, "exempt_sid": str(current_sid) if current_sid else None},
        )

        return Response(
            {
                "detail": "All other sessions revoked successfully.",
                "revoked_count": revoked_count,
            },
            status=status.HTTP_200_OK,
        )


# =============================================================================
# Runtime Sessions API (API-Key + User JWT Scoped)
# =============================================================================

def _resolve_runtime_project_id(request):
    auth = getattr(request, "auth", None)
    if hasattr(auth, "get"):
        pid = auth.get("project_id")
        if pid:
            return pid
    if hasattr(request, "_auth") and hasattr(request._auth, "get"):
        pid = request._auth.get("project_id")
        if pid:
            return pid
    if hasattr(auth, "project_id"):
        return auth.project_id
    if hasattr(request.user, "project_id"):
        return request.user.project_id
    return None


class RuntimeSessionListView(ListAPIView):
    """
    List active sessions for an end-user within the current project.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSessionSerializer
    pagination_class = None

    def get_queryset(self):
        project_id = _resolve_runtime_project_id(self.request)
        return UserSession.objects.filter(
            user=self.request.user,
            project_id=project_id,
            revoked_at__isnull=True,
        ).order_by("-last_active_at")


class RuntimeSessionRevokeView(APIView):
    """
    Revoke a specific runtime user session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        project_id = _resolve_runtime_project_id(request)

        session = UserSession.objects.filter(
            id=pk,
            user=request.user,
            project_id=project_id,
            revoked_at__isnull=True,
        ).first()

        if not session:
            return Response(
                {"error": "Session not found or already revoked.", "code": "session_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        revoke_session(session.id, reason="runtime_user_revoked")

        AuditLog.log(
            event_type=AuditLog.EventType.SESSION_REVOKED,
            request=request,
            user=request.user,
            project=session.project,
            event_data={"session_id": str(session.id), "device": session.device_name},
        )

        return Response(
            {"detail": "Session revoked successfully."},
            status=status.HTTP_200_OK,
        )


class RuntimeSessionRevokeAllView(APIView):
    """
    Revoke all other runtime sessions for the current end-user in this project.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        project_id = _resolve_runtime_project_id(request)
        auth = getattr(request, "auth", None)
        current_sid = getattr(auth, "get", lambda k: None)("sid") if auth else None

        revoked_count = revoke_all_user_sessions(
            user=request.user,
            project=project_id,
            except_session_id=current_sid,
            reason="runtime_logout_all",
        )

        from hvt.apps.organizations.models import Project
        project_obj = Project.objects.filter(id=project_id).first() if project_id else None

        AuditLog.log(
            event_type=AuditLog.EventType.SESSION_REVOKED_ALL,
            request=request,
            user=request.user,
            project=project_obj,
            event_data={"revoked_count": revoked_count, "exempt_sid": str(current_sid) if current_sid else None},
        )

        return Response(
            {
                "detail": "All other sessions revoked successfully.",
                "revoked_count": revoked_count,
            },
            status=status.HTTP_200_OK,
        )
