from rest_framework import generics, permissions, status, filters
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view

from .models import Organization, APIKey, Webhook, WebhookDelivery
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.permissions import IsOrgOwnerOrAPIKey, IsOrgAdminOrAPIKey, IsOrgMemberOrAPIKey
from hvt.apps.organizations.permissions import IsOrganizationOwner
from hvt.apps.organizations.webhooks import trigger_webhook_event
from hvt.pagination import LargeResultPagination
from hvt.api.v1.serializers.organizations import (
    OrganizationSerializer,
    APIKeyCreateSerializer,
    APIKeyListSerializer,
    WebhookSerializer,
    WebhookDeliverySerializer,
)

import logging

logger = logging.getLogger(__name__)


def _authenticated_user_or_none(request):
    user = getattr(request, "user", None)
    if user and getattr(user, "is_authenticated", False):
        return user
    return None


@extend_schema_view(
    get=extend_schema(
        tags=["Organizations"],
        summary="List all organizations",
        description="List all organizations. Superuser only.",
    ),
    post=extend_schema(
        tags=["Organizations"],
        summary="Create an organization",
        description="Create a new organization. The authenticated user becomes the owner. Max 3 per user.",
    ),
)
class OrganizationListView(generics.ListCreateAPIView):
    """
    GET /api/v1/organizations/ - List all organizations (superuser only)
    POST /api/v1/organizations/ - Create organization (authenticated)
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [permissions.IsAuthenticated()]
        return [permissions.IsAdminUser()]

    def perform_create(self, serializer):
        from rest_framework.serializers import ValidationError
        user = self.request.user

        owned_org_count = user.owned_organization.count()
        if owned_org_count >= 3:
            raise ValidationError("You can only create up to 3 organizations.")

        org = serializer.save(owner=user)

        if not user.organization:
            user.organization = org
            user.role = "owner"
            user.save(update_fields=["organization", "role"])

        # Audit log
        AuditLog.log(
            event_type=AuditLog.EventType.ORG_CREATED,
            request=self.request,
            user=user,
            organization=org,
            target=org,
            event_data={"org_name": org.name, "org_slug": org.slug},
            success=True,
        )


@extend_schema_view(
    get=extend_schema(
        tags=["Organizations"],
        summary="Retrieve an organization",
        description="Get organization details by ID. Superuser only.",
    ),
    put=extend_schema(
        tags=["Organizations"],
        summary="Update an organization (full)",
        description="Replace all editable fields. Superuser only.",
    ),
    patch=extend_schema(
        tags=["Organizations"],
        summary="Update an organization (partial)",
        description="Partially update an organization. Superuser only.",
    ),
    delete=extend_schema(
        tags=["Organizations"],
        summary="Delete an organization",
        description="Delete an organization and all related data. Superuser only.",
    ),
)
class OrganizationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET/PATCH/DELETE /api/v1/organizations/<id>/ - Superuser only
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAdminUser]


@extend_schema_view(
    get=extend_schema(
        tags=["Organizations"],
        summary="Get current organization",
        description="Returns the organization for the authenticated user or API key.",
    ),
    put=extend_schema(
        tags=["Organizations"],
        summary="Update current organization (full)",
        description="Replace all editable fields on the current organization. Owner only.",
    ),
    patch=extend_schema(
        tags=["Organizations"],
        summary="Update current organization (partial)",
        description="Partially update the current organization. Owner only.",
    ),
)
class CurrentOrganizationView(generics.RetrieveUpdateAPIView):
    """
    GET /api/v1/organizations/current/ - Get current user's organization
    PATCH /api/v1/organizations/current/ - Update current organization (owner only)
    """
    serializer_class = OrganizationSerializer

    def perform_update(self, serializer):
        org = self.get_object()
        old_data = OrganizationSerializer(org).data
        updated_org = serializer.save()
        new_data = OrganizationSerializer(updated_org).data

        changes = {
            field: {"old": old_data[field], "new": new_data[field]}
            for field in old_data
            if old_data[field] != new_data[field]
        }

        if changes:
            AuditLog.log(
                event_type=AuditLog.EventType.ORG_UPDATED,
                request=self.request,
                user=_authenticated_user_or_none(self.request),
                organization=updated_org,
                target=updated_org,
                event_data={"changes": changes},
                success=True,
            )

    def get_permissions(self):
        if self.request.method in ["PATCH", "PUT"]:
            return [permissions.IsAuthenticated(), IsOrganizationOwner()]
        return [IsOrgMemberOrAPIKey()]

    def get_object(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            raise NotFound("No organization found")

        if not org:
            raise NotFound("User is not part of any organization")

        if self.request.method in ["PATCH", "PUT"]:
            self.check_object_permissions(self.request, org)
        return org


@extend_schema_view(
    get=extend_schema(
        tags=["API Keys"],
        summary="List API keys",
        description=(
            "List all API keys for the current organization. "
            "Supports filtering by environment (test/live) and is_active. "
            "Supports search by name and prefix."
        ),
    ),
    post=extend_schema(
        tags=["API Keys"],
        summary="Create an API key",
        description=(
            "Create a new API key. The full key value is returned only once in the response. "
            "Store it securely — it cannot be retrieved again."
        ),
        request=APIKeyCreateSerializer,
        responses={201: APIKeyCreateSerializer},
    ),
)
class APIKeyListCreateView(generics.ListCreateAPIView):
    """
    GET: List all API Keys for the current organization.
    POST: Create a new API Key.
    """
    permission_classes = [IsOrgOwnerOrAPIKey]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["environment", "is_active"]
    search_fields = ["name", "prefix"]
    ordering_fields = ["name", "environment", "created_at", "last_used_at"]
    ordering = ["-created_at"]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return APIKey.objects.none()

        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return APIKeyCreateSerializer
        return APIKeyListSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if isinstance(self.request.auth, APIKey):
            context["organization"] = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            context["organization"] = self.request.user.organization
        return context

    def perform_create(self, serializer):
        actor_user = _authenticated_user_or_none(self.request)
        actor_api_key = self.request.auth if isinstance(self.request.auth, APIKey) else None
        org = (
            self.request.auth.organization
            if isinstance(self.request.auth, APIKey)
            else self.request.user.organization
        )

        api_key = serializer.save(
            organization=org,
            created_by=actor_user,
        )

        # Audit log
        AuditLog.log(
            event_type=AuditLog.EventType.API_KEY_CREATED,
            request=self.request,
            user=actor_user,
            api_key=actor_api_key,
            organization=org,
            target=api_key,
            event_data={
                "key_name": api_key.name,
                "environment": api_key.environment,
                "scopes": api_key.scopes,
            },
            success=True,
        )

        # Trigger webhook: api_key.created
        trigger_webhook_event(
            organization=org,
            event_type="api_key.created",
            payload={
                "api_key_id": str(api_key.id),
                "name": api_key.name,
                "environment": api_key.environment,
            },
        )


@extend_schema_view(
    get=extend_schema(
        tags=["API Keys"],
        summary="Retrieve an API key",
        description="Get API key details (no sensitive data).",
    ),
    delete=extend_schema(
        tags=["API Keys"],
        summary="Delete an API key",
        description="Permanently delete an API key. This action cannot be undone.",
    ),
)
class APIKeyDetailView(generics.RetrieveDestroyAPIView):
    """
    GET: Get API Key details.
    DELETE: Revoke (delete) an API key.
    """
    serializer_class = APIKeyListSerializer
    permission_classes = [IsOrgOwnerOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return APIKey.objects.none()

        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)

    def destroy(self, request, *args, **kwargs):
        api_key = self.get_object()
        response = super().destroy(request, *args, **kwargs)

        if response.status_code == status.HTTP_204_NO_CONTENT:
            AuditLog.log(
                event_type=AuditLog.EventType.API_KEY_REVOKED,
                request=request,
                user=_authenticated_user_or_none(request),
                api_key=request.auth if isinstance(request.auth, APIKey) else None,
                organization=api_key.organization,
                target=api_key,
                event_data={
                    "key_name": api_key.name,
                    "environment": api_key.environment,
                    "action": "deleted",
                },
                success=True,
            )

            # Trigger webhook: api_key.revoked
            trigger_webhook_event(
                organization=api_key.organization,
                event_type="api_key.revoked",
                payload={
                    "api_key_id": str(api_key.id),
                    "name": api_key.name,
                    "action": "deleted",
                },
            )

        return response


@extend_schema_view(
    patch=extend_schema(
        tags=["API Keys"],
        summary="Revoke an API key",
        description="Deactivate an API key without deleting it. The key can no longer be used for authentication.",
    ),
)
class APIKeyRevokeView(generics.UpdateAPIView):
    """
    PATCH: Deactivate an API key without deleting it.
    """
    serializer_class = APIKeyListSerializer
    permission_classes = [IsOrgOwnerOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return APIKey.objects.none()

        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)

    def patch(self, request, *args, **kwargs):
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save(update_fields=["is_active"])

        AuditLog.log(
            event_type=AuditLog.EventType.API_KEY_REVOKED,
            request=request,
            user=_authenticated_user_or_none(request),
            api_key=request.auth if isinstance(request.auth, APIKey) else None,
            organization=api_key.organization,
            target=api_key,
            event_data={
                "key_name": api_key.name,
                "environment": api_key.environment,
                "action": "deactivated",
            },
            success=True,
        )

        # Trigger webhook: api_key.revoked
        trigger_webhook_event(
            organization=api_key.organization,
            event_type="api_key.revoked",
            payload={
                "api_key_id": str(api_key.id),
                "name": api_key.name,
                "action": "deactivated",
            },
        )

        return Response({"detail": "API key revoked"}, status=status.HTTP_200_OK)


# --- Webhook CRUD Views ---


@extend_schema_view(
    get=extend_schema(
        tags=["Webhooks"],
        summary="List webhooks",
        description=(
            "List all webhooks for the current organization. "
            "Supports filtering by is_active. "
            "Supports search by url and description."
        ),
    ),
    post=extend_schema(
        tags=["Webhooks"],
        summary="Create a webhook",
        description=(
            "Create a new webhook endpoint. A signing secret is auto-generated and "
            "returned in the response. Store it securely — use it to verify webhook payloads."
        ),
    ),
)
class WebhookListCreateView(generics.ListCreateAPIView):
    """Manage webhooks for current organization."""
    permission_classes = [IsOrgAdminOrAPIKey]
    serializer_class = WebhookSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["is_active"]
    search_fields = ["url", "description"]
    ordering_fields = ["created_at", "last_triggered_at", "success_count", "failure_count"]
    ordering = ["-created_at"]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return Webhook.objects.none()

        return Webhook.objects.filter(organization=org)

    def perform_create(self, serializer):
        org = (
            self.request.auth.organization
            if isinstance(self.request.auth, APIKey)
            else self.request.user.organization
        )
        serializer.save(
            organization=org,
            created_by=self.request.user
            if self.request.user and self.request.user.is_authenticated
            else None,
            secret=Webhook.generate_secret(),
        )


@extend_schema_view(
    get=extend_schema(
        tags=["Webhooks"],
        summary="Retrieve a webhook",
        description="Get webhook details including configuration and delivery stats.",
    ),
    put=extend_schema(
        tags=["Webhooks"],
        summary="Update a webhook (full)",
        description="Replace all editable fields on a webhook.",
    ),
    patch=extend_schema(
        tags=["Webhooks"],
        summary="Update a webhook (partial)",
        description="Partially update a webhook (e.g. change events or disable).",
    ),
    delete=extend_schema(
        tags=["Webhooks"],
        summary="Delete a webhook",
        description="Permanently delete a webhook and all its delivery records.",
    ),
)
class WebhookDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET/PATCH/DELETE a specific webhook.
    """
    serializer_class = WebhookSerializer
    permission_classes = [IsOrgAdminOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return Webhook.objects.none()

        return Webhook.objects.filter(organization=org)


@extend_schema_view(
    get=extend_schema(
        tags=["Webhooks"],
        summary="List webhook deliveries",
        description=(
            "List delivery attempts for a specific webhook. "
            "Supports filtering by status (pending/success/failed/retrying) and event_type."
        ),
    ),
)
class WebhookDeliveryListView(generics.ListAPIView):
    """
    GET delivery attempts for a specific webhook.
    """
    serializer_class = WebhookDeliverySerializer
    permission_classes = [IsOrgAdminOrAPIKey]
    pagination_class = LargeResultPagination
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["status", "event_type"]
    ordering_fields = ["created_at", "delivered_at", "status"]
    ordering = ["-created_at"]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return WebhookDelivery.objects.none()

        webhook = get_object_or_404(
            Webhook,
            pk=self.kwargs["webhook_pk"],
            organization=org,
        )
        return WebhookDelivery.objects.filter(webhook=webhook).order_by("-created_at")


# ── Permissions Matrix ───────────────────────────────────────────────


# The definitive permission matrix for HVT.
# Each key is a resource/action, value maps role -> bool.
PERMISSION_MATRIX = {
    "users.list": {"owner": True, "admin": True, "member": True},
    "users.read": {"owner": True, "admin": True, "member": True},
    "users.create": {"owner": True, "admin": True, "member": False},
    "users.update": {"owner": True, "admin": True, "member": False},
    "users.delete": {"owner": True, "admin": True, "member": False},
    "users.change_role": {"owner": True, "admin": True, "member": False},
    "users.update_self": {"owner": True, "admin": True, "member": True},
    "organization.read": {"owner": True, "admin": True, "member": True},
    "organization.update": {"owner": True, "admin": False, "member": False},
    "organization.delete": {"owner": True, "admin": False, "member": False},
    "api_keys.list": {"owner": True, "admin": False, "member": False},
    "api_keys.create": {"owner": True, "admin": False, "member": False},
    "api_keys.revoke": {"owner": True, "admin": False, "member": False},
    "api_keys.delete": {"owner": True, "admin": False, "member": False},
    "webhooks.list": {"owner": True, "admin": True, "member": False},
    "webhooks.create": {"owner": True, "admin": True, "member": False},
    "webhooks.update": {"owner": True, "admin": True, "member": False},
    "webhooks.delete": {"owner": True, "admin": True, "member": False},
    "webhooks.deliveries": {"owner": True, "admin": True, "member": False},
    "audit_logs.list_all": {"owner": True, "admin": True, "member": False},
    "audit_logs.list_own": {"owner": True, "admin": True, "member": True},
    "audit_logs.read": {"owner": True, "admin": True, "member": True},
}


class PermissionsMatrixView(APIView):
    """
    GET /api/v1/organizations/current/permissions/

    Returns:
    - matrix: the full role -> permission mapping
    - role: the current user's role (or 'api_key')
    - permissions: what the current user/key can actually do
    """

    permission_classes = [IsOrgMemberOrAPIKey]

    @extend_schema(
        tags=["Organizations"],
        summary="Get permissions matrix",
        description=(
            "Returns the full RBAC permission matrix plus the current user's "
            "role and effective permissions. Useful for frontends to render "
            "UI based on what the current user can do."
        ),
        responses={
            200: {
                "type": "object",
                "properties": {
                    "role": {"type": "string", "example": "admin"},
                    "permissions": {
                        "type": "object",
                        "additionalProperties": {"type": "boolean"},
                    },
                    "matrix": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "owner": {"type": "boolean"},
                                "admin": {"type": "boolean"},
                                "member": {"type": "boolean"},
                            },
                        },
                    },
                },
            }
        },
    )

    def get(self, request, *args, **kwargs):
        is_api_key = isinstance(request.auth, APIKey)
        role = "api_key" if is_api_key else getattr(request.user, "role", "member")

        if is_api_key:
            # API keys get read-only on everything they can access
            effective = {
                action: (
                    "list" in action
                    or "read" in action
                    or action.endswith("list_all")
                    or action.endswith("list_own")
                )
                for action in PERMISSION_MATRIX
            }
        else:
            effective = {
                action: roles.get(role, False)
                for action, roles in PERMISSION_MATRIX.items()
            }

        return Response({
            "role": role,
            "permissions": effective,
            "matrix": PERMISSION_MATRIX,
        })