"""
Audit log views — read-only API for querying organization audit events.

Permissions:
- Owner / Admin: see ALL events for the organization
- Member: see only their own events (actor_user = self)
- API Key: read-only, all org events
"""

import logging

from rest_framework import generics, filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.permissions import IsOrgMemberOrAPIKey
from hvt.apps.organizations.models import APIKey
from hvt.pagination import AuditLogCursorPagination
from hvt.api.v1.serializers.audit import AuditLogSerializer

logger = logging.getLogger(__name__)


def _get_org(request):
    """Extract organization from API key or authenticated user."""
    if isinstance(request.auth, APIKey):
        return request.auth.organization
    if request.user and request.user.is_authenticated:
        return request.user.organization
    return None


@extend_schema_view(
    get=extend_schema(
        tags=["Audit Logs"],
        summary="List audit log entries",
        description=(
            "Returns audit log entries for the current organization. "
            "Admins and owners see all events. Members see only their own events. "
            "Supports filtering by event_type, success, actor. "
            "Uses cursor-based pagination for efficient time-series queries."
        ),
        parameters=[
            OpenApiParameter(
                name="event_type",
                type=OpenApiTypes.STR,
                description="Filter by event type (e.g. user.login, api_key.created)",
            ),
            OpenApiParameter(
                name="success",
                type=OpenApiTypes.BOOL,
                description="Filter by success/failure status",
            ),
            OpenApiParameter(
                name="actor_user",
                type=OpenApiTypes.UUID,
                description="Filter by actor user ID (admin/owner only)",
            ),
        ],
    ),
)
class AuditLogListView(generics.ListAPIView):
    """
    GET /api/v1/organizations/current/audit-logs/

    Read-only list of audit events for the current organization.
    - Owner/Admin: all org events
    - Member: only events where they are the actor
    - API Key: all org events (read-only)
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsOrgMemberOrAPIKey]
    pagination_class = AuditLogCursorPagination
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["event_type", "success"]
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]

    def get_queryset(self):
        org = _get_org(self.request)
        if not org:
            return AuditLog.objects.none()

        qs = AuditLog.objects.filter(organization=org)

        # Members can only see their own events
        user = self.request.user
        is_api_key = isinstance(self.request.auth, APIKey)
        if not is_api_key and user.is_authenticated:
            if not user.can_manage_users():
                # Member — restrict to own events
                qs = qs.filter(actor_user=user)

        # Optional: filter by actor_user (admin/owner only)
        actor_user_id = self.request.query_params.get("actor_user")
        if actor_user_id and (is_api_key or user.can_manage_users()):
            qs = qs.filter(actor_user_id=actor_user_id)

        return qs


@extend_schema_view(
    get=extend_schema(
        tags=["Audit Logs"],
        summary="Retrieve an audit log entry",
        description="Get full details of a single audit log entry.",
    ),
)
class AuditLogDetailView(generics.RetrieveAPIView):
    """
    GET /api/v1/organizations/current/audit-logs/<id>/

    Retrieve a single audit log entry. Same role restrictions apply:
    members can only see their own events.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsOrgMemberOrAPIKey]

    def get_queryset(self):
        org = _get_org(self.request)
        if not org:
            return AuditLog.objects.none()

        qs = AuditLog.objects.filter(organization=org)

        user = self.request.user
        is_api_key = isinstance(self.request.auth, APIKey)
        if not is_api_key and user.is_authenticated:
            if not user.can_manage_users():
                qs = qs.filter(actor_user=user)

        return qs
