from rest_framework import generics, status, filters
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view

from hvt.apps.users.models import User
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.permissions import (
    CanChangeRole,
    IsOrgAdminOrAPIKey,
    IsOrgMemberOrAPIKey,
)
from hvt.apps.organizations.models import APIKey
from hvt.apps.organizations.webhooks import trigger_webhook_event
from hvt.api.v1.serializers.users import (
    UserSerializer,
    UserCreateSerializer,
    UserRoleUpdateSerializer,
    OrganizationMemberSerializer,
)

import logging

logger = logging.getLogger(__name__)


def _get_org(request):
    """Extract organization from either API key or authenticated user."""
    if isinstance(request.auth, APIKey):
        return request.auth.organization
    if request.user and request.user.is_authenticated:
        return request.user.organization
    return None


def _get_user_queryset(request):
    """Base user queryset scoped by org and, for API keys, by project."""
    org = _get_org(request)
    if not org:
        return User.objects.none()

    queryset = User.objects.filter(organization=org)
    if isinstance(request.auth, APIKey) and request.auth.project_id:
        queryset = queryset.filter(project=request.auth.project)
    return queryset


@extend_schema_view(
    get=extend_schema(
        tags=["Users"],
        summary="List organization users",
        description=(
            "Returns all users belonging to the authenticated user's organization. "
            "Supports filtering by role, is_active, is_test. "
            "Supports search by email, first_name, last_name. "
            "Supports ordering by email, role, created_at."
        ),
    ),
    post=extend_schema(
        tags=["Users"],
        summary="Create a user",
        description="Create a new user in the organization. Requires admin or owner role.",
        request=UserCreateSerializer,
        responses={201: UserSerializer},
    ),
)
class UserListView(generics.ListCreateAPIView):
    """
    List all users in the organization or create a new user.

    GET: Returns all users belonging to the authenticated user's organization.
    POST: Creates a new user within the organization (admin only).
    """
    permission_classes = [IsOrgMemberOrAPIKey]
    api_key_read_scopes = ("users:read",)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["role", "is_active", "is_test"]
    search_fields = ["email", "first_name", "last_name"]
    ordering_fields = ["email", "role", "created_at"]
    ordering = ["-created_at"]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return UserCreateSerializer
        return UserSerializer

    def get_queryset(self):
        return _get_user_queryset(self.request).order_by("-created_at")

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsOrgAdminOrAPIKey()]
        return [IsOrgMemberOrAPIKey()]

    def perform_create(self, serializer):
        org = _get_org(self.request)
        user = serializer.save(organization=org)

        AuditLog.log(
            event_type=AuditLog.EventType.USER_CREATED,
            request=self.request,
            user=self.request.user if self.request.user.is_authenticated else None,
            organization=org,
            project=user.project,
            target=user,
            event_data={
                'created_user_email': user.email,
            },
            success=True,
        )

        # Trigger webhook for user creation
        trigger_webhook_event(
            organization=org,
            project=user.project,
            event_type='user.created',
            payload={
                'user_id': str(user.id),
                'email': user.email,
                'role': user.role,
            },
        )


@extend_schema_view(
    get=extend_schema(
        tags=["Users"],
        summary="Retrieve a user",
        description="Get details of a specific user in the organization.",
    ),
    put=extend_schema(
        tags=["Users"],
        summary="Update a user (full)",
        description="Replace all editable fields on a user. Requires admin role.",
    ),
    patch=extend_schema(
        tags=["Users"],
        summary="Update a user (partial)",
        description="Partially update a user. Requires admin role.",
    ),
    delete=extend_schema(
        tags=["Users"],
        summary="Delete a user",
        description="Remove a user from the organization. Requires admin role. Cannot delete yourself.",
    ),
)
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a specific user.

    GET: Retrieve user details (org member).
    PUT/PATCH: Update user details (admin only).
    DELETE: Remove user from organization (admin only).
    """
    serializer_class = UserSerializer
    permission_classes = [IsOrgMemberOrAPIKey]
    api_key_read_scopes = ("users:read",)
    lookup_field = 'pk'

    def get_queryset(self):
        return _get_user_queryset(self.request)

    def get_permissions(self):
        if self.request.method in ('PUT', 'PATCH', 'DELETE'):
            return [IsOrgAdminOrAPIKey()]
        return [IsOrgMemberOrAPIKey()]

    def perform_update(self, serializer):
        user = self.get_object()
        old_data = UserSerializer(user).data
        updated_user = serializer.save()
        new_data = UserSerializer(updated_user).data

        changes = {
            field: {'old': old_data[field], 'new': new_data[field]}
            for field in old_data
            if old_data[field] != new_data[field]
        }

        org = _get_org(self.request)

        if changes:
            AuditLog.log(
                event_type=AuditLog.EventType.USER_UPDATED,
                request=self.request,
                user=self.request.user if self.request.user.is_authenticated else None,
                organization=org,
                project=updated_user.project,
                target=updated_user,
                event_data={
                    'changes': changes,
                },
                success=True,
            )

            # Trigger webhook for user update
            trigger_webhook_event(
                organization=org,
                project=updated_user.project,
                event_type='user.updated',
                payload={
                    'user_id': str(updated_user.id),
                    'email': updated_user.email,
                    'changes': changes,
                },
            )

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        user_id = str(user.id)
        user_email = user.email
        org = _get_org(request)

        # Prevent self-deletion (only for JWT-authenticated users)
        if request.user.is_authenticated and user == request.user:
            return Response(
                {'error': 'You cannot delete your own account.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        response = super().destroy(request, *args, **kwargs)

        if response.status_code == 204:
            AuditLog.log(
                event_type=AuditLog.EventType.USER_DELETED,
                request=request,
                user=request.user if request.user.is_authenticated else None,
                organization=org,
                project=user.project,
                event_data={
                    'deleted_user_id': user_id,
                    'deleted_user_email': user_email,
                },
                success=True,
            )

            # Trigger webhook for user deletion
            trigger_webhook_event(
                organization=org,
                project=user.project,
                event_type='user.deleted',
                payload={
                    'user_id': user_id,
                    'email': user_email,
                },
            )

        return response


@extend_schema_view(
    put=extend_schema(
        tags=["Users"],
        summary="Update user role (full)",
        description=(
            "Change a user's role. Requires admin role. "
            "Cannot change your own role or demote the last admin."
        ),
    ),
    patch=extend_schema(
        tags=["Users"],
        summary="Update user role (partial)",
        description=(
            "Change a user's role. Requires admin role. "
            "Cannot change your own role or demote the last admin."
        ),
    ),
)
class UserRoleUpdateView(generics.UpdateAPIView):
    """
    Update a user's role within the organization.

    PATCH/PUT: Change user role (admin only).
    Prevents changing own role or demoting the last admin.
    """
    serializer_class = UserRoleUpdateSerializer
    permission_classes = [IsOrgAdminOrAPIKey, CanChangeRole]
    lookup_field = 'pk'

    def get_queryset(self):
        return _get_user_queryset(self.request)

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        old_role = user.role
        new_role = request.data.get('role', old_role)
        org = _get_org(request)

        # Prevent changing own role (only for JWT-authenticated users)
        if request.user.is_authenticated and user == request.user:
            return Response(
                {'error': 'You cannot change your own role.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Prevent demoting the last admin (unless requester is owner)
        if old_role == 'admin' and new_role != 'admin':
            is_owner = request.user.is_authenticated and request.user.is_org_owner()
            if not is_owner:
                admin_count = User.objects.filter(
                    organization=org,
                    role='admin',
                ).count()
                if admin_count <= 1:
                    return Response(
                        {'error': 'Cannot demote the last admin.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        response = super().update(request, *args, **kwargs)

        if old_role != new_role:
            AuditLog.log(
                event_type=AuditLog.EventType.USER_ROLE_CHANGED,
                request=request,
                user=request.user if request.user.is_authenticated else None,
                organization=org,
                project=user.project,
                target=user,
                event_data={
                    'target_user_email': user.email,
                    'old_role': old_role,
                    'new_role': new_role,
                },
                success=True,
            )

            # Trigger webhook for role change
            trigger_webhook_event(
                organization=org,
                project=user.project,
                event_type='user.role.changed',
                payload={
                    'user_id': str(user.id),
                    'email': user.email,
                    'old_role': old_role,
                    'new_role': new_role,
                },
            )

        return response


@extend_schema_view(
    get=extend_schema(
        tags=["Users"],
        summary="List organization members",
        description=(
            "Returns all members with role info and promotion/demotion eligibility. "
            "Supports filtering by role, is_active. "
            "Supports search by email, first_name, last_name."
        ),
    ),
)
class OrganizationMembersView(generics.ListAPIView):
    """
    List all members of the current organization.

    GET: Returns members with role info, promotion/demotion eligibility.
    Accessible by any org member or valid API key.
    """
    serializer_class = OrganizationMemberSerializer
    permission_classes = [IsOrgMemberOrAPIKey]
    api_key_read_scopes = ("users:read",)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["role", "is_active"]
    search_fields = ["email", "first_name", "last_name"]
    ordering_fields = ["email", "role", "created_at"]
    ordering = ["-created_at"]

    def get_queryset(self):
        return _get_user_queryset(self.request).order_by("-created_at")
