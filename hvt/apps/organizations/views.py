from rest_framework import generics, permissions, status, filters, serializers
from rest_framework.response import Response
from rest_framework.exceptions import NotAuthenticated, NotFound, PermissionDenied
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view, inline_serializer
from django.conf import settings
from django.utils import timezone
from dj_rest_auth.app_settings import api_settings as dj_rest_auth_settings
from dj_rest_auth.jwt_auth import set_jwt_cookies

from .models import (
    Organization,
    Project,
    APIKey,
    ProjectPermission,
    ProjectRole,
    RuntimeInvitation,
    SocialProviderConfig,
    Webhook,
    WebhookDelivery,
    OrganizationInvitation,
)
from hvt.apps.authentication.backends import (
    APIKeyAuthentication,
    HVTJWTCookieAuthentication,
    HVTJWTAuthentication,
)
from hvt.apps.authentication.identity import (
    get_control_plane_users_by_email,
    get_runtime_project_users_by_email,
)
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.permissions import (
    IsOrgOwnerOrAPIKey,
    IsOrgAdminOrAPIKey,
    IsOrgMemberOrAPIKey,
    IsPlatformUser,
)
from hvt.apps.authentication.throttling import APIKeyRateThrottle
from hvt.apps.authentication.tokens import HVTTokenObtainPairSerializer, build_hvt_token_pair
from hvt.apps.organizations.access import (
    assign_default_signup_roles,
    get_user_project_permission_slugs,
    get_user_project_roles,
    sync_user_project_roles,
    user_has_project_access,
)
from hvt.apps.organizations.permissions import (
    IsOrganizationOwner,
    IsCurrentOrganizationAdmin,
    IsCurrentOrganizationOwner,
)
from hvt.apps.organizations.runtime_roles import resolve_project_roles_or_error
from hvt.apps.organizations.webhooks import trigger_webhook_event
from hvt.pagination import LargeResultPagination, StandardPagination
from hvt.apps.authentication.email import (
    ResendEmailService,
    build_email_context,
    build_frontend_url,
    render_email_template,
)
from hvt.apps.users.models import User
from hvt.api.v1.serializers.organizations import (
    OrganizationSerializer,
    ProjectSerializer,
    APIKeyCreateSerializer,
    APIKeyListSerializer,
    ProjectPermissionSerializer,
    ProjectRoleSerializer,
    ProjectRoleSummarySerializer,
    ProjectUserRoleAccessSerializer,
    ProjectUserRoleAssignmentUpdateSerializer,
    SocialProviderConfigSerializer,
    WebhookSerializer,
    WebhookDeliverySerializer,
    OrganizationInvitationCreateSerializer,
    OrganizationInvitationSerializer,
    OrganizationInvitationPublicSerializer,
    OrganizationInvitationAcceptSerializer,
    RuntimeInvitationAcceptSerializer,
    RuntimeInvitationCreateSerializer,
    RuntimeInvitationSerializer,
)

import logging

logger = logging.getLogger(__name__)


def _authenticated_user_or_none(request):
    user = getattr(request, "user", None)
    if user and getattr(user, "is_authenticated", False):
        return user
    return None


def _current_user_project_queryset(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated or not user.organization_id:
        return Project.objects.none()
    return Project.objects.filter(organization=user.organization)


def _get_current_project_or_404(request, project_pk):
    return get_object_or_404(_current_user_project_queryset(request), pk=project_pk)


def _serialize_user_project_access(user, project) -> dict:
    roles = list(get_user_project_roles(user, project))
    permissions = get_user_project_permission_slugs(user, project)
    return {
        "user": str(user.id),
        "project": str(project.id),
        "roles": ProjectRoleSummarySerializer(roles, many=True).data,
        "permissions": permissions,
    }


def _sync_default_project_signup(org: Organization) -> None:
    """Keep the default project's signup toggle aligned with org onboarding."""
    default_project = org.ensure_default_project()
    if default_project.allow_signup != org.allow_signup:
        default_project.allow_signup = org.allow_signup
        default_project.save(update_fields=["allow_signup", "updated_at"])


def _set_rotated_auth_tokens(response, user, project=None) -> None:
    """Rotate JWTs after an org context change so current-org requests work immediately."""
    user.refresh_from_db()
    refresh_token = HVTTokenObtainPairSerializer.get_token(
        user,
        project=project or getattr(user, "project", None),
    )
    access_token = refresh_token.access_token
    access_value = str(access_token)
    refresh_value = str(refresh_token)

    response.data["access"] = access_value
    response.data["refresh"] = "" if dj_rest_auth_settings.JWT_AUTH_HTTPONLY else refresh_value
    set_jwt_cookies(response, access_value, refresh_value)


def _set_bootstrap_auth_tokens(response, user) -> None:
    _set_rotated_auth_tokens(response, user)


def _build_invitation_accept_url(invitation: OrganizationInvitation) -> str:
    return f"{settings.FRONTEND_URL.rstrip('/')}/invite?token={invitation.token}"


def _send_invitation_email(invitation: OrganizationInvitation) -> bool:
    if not getattr(settings, "RESEND_API_KEY", ""):
        logger.warning(
            "Skipping invitation email because RESEND_API_KEY is not configured",
            extra={"invitation_id": str(invitation.id), "email": invitation.email},
        )
        return False

    accept_url = _build_invitation_accept_url(invitation)
    role_label = invitation.get_role_display()
    app_role_labels = [
        role.name or role.slug
        for role in invitation.app_roles.all().order_by("name", "slug")
    ]
    email_context = build_email_context(
        {
            "organization_name": invitation.organization.name,
            "organization_slug": invitation.organization.slug,
            "invitee_email": invitation.email,
            "invited_by_email": invitation.invited_by.email if invitation.invited_by else "",
            "invited_by_name": invitation.invited_by.full_name if invitation.invited_by and invitation.invited_by.full_name else (invitation.invited_by.email if invitation.invited_by else ""),
            "role_label": role_label,
            "project_name": invitation.project.name if invitation.project else "",
            "project_slug": invitation.project.slug if invitation.project else "",
            "app_role_labels": app_role_labels,
            "accept_url": accept_url,
            "expires_at_display": timezone.localtime(invitation.expires_at).strftime("%B %d, %Y at %H:%M %Z"),
        }
    )
    subject, text, html = render_email_template(
        "organizations/email/invitation",
        email_context,
    )

    try:
        ResendEmailService().send(
            to=invitation.email,
            subject=subject,
            html=html,
            text=text,
        )
        return True
    except Exception:
        logger.exception(
            "Failed to send organization invitation email",
            extra={"invitation_id": str(invitation.id), "email": invitation.email},
        )
        return False


def _build_runtime_invitation_accept_url(invitation: RuntimeInvitation) -> str:
    return build_frontend_url(
        "/invite/accept",
        project=invitation.project,
        query={"token": invitation.token},
    )


def _send_runtime_invitation_email(
    invitation: RuntimeInvitation,
    *,
    first_name: str = "",
    last_name: str = "",
) -> bool:
    if not getattr(settings, "RESEND_API_KEY", ""):
        logger.warning(
            "Skipping runtime invitation email because RESEND_API_KEY is not configured",
            extra={"invitation_id": str(invitation.id), "email": invitation.email},
        )
        return False

    accept_url = _build_runtime_invitation_accept_url(invitation)
    email_context = build_email_context(
        {
            "project": invitation.project,
            "project_name": invitation.project.name,
            "invitee_email": invitation.email,
            "invitee_first_name": (first_name or "").strip(),
            "invitee_last_name": (last_name or "").strip(),
            "invitee_name": " ".join(
                part
                for part in [(first_name or "").strip(), (last_name or "").strip()]
                if part
            ),
            "role_slugs": invitation.role_slugs,
            "accept_url": accept_url,
            "expires_at_display": timezone.localtime(invitation.expires_at).strftime(
                "%B %d, %Y at %H:%M %Z"
            ),
        }
    )
    subject, text, html = render_email_template(
        "organizations/email/runtime_invitation",
        email_context,
    )

    try:
        ResendEmailService().send(
            to=invitation.email,
            subject=subject,
            html=html,
            text=text,
        )
        return True
    except Exception:
        logger.exception(
            "Failed to send runtime invitation email",
            extra={"invitation_id": str(invitation.id), "email": invitation.email},
        )
        return False


@extend_schema_view(
    get=extend_schema(
        tags=["Organizations"],
        summary="List all organizations",
        description="List all organizations. Superuser only.",
    ),
    post=extend_schema(
        tags=["Organizations"],
        summary="Create an organization",
        description="Create a new organization. The authenticated user becomes the owner. Single organization per user at launch.",
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
            return [permissions.IsAuthenticated(), IsPlatformUser()]
        return [permissions.IsAdminUser()]

    def create(self, request, *args, **kwargs):
        self._bootstrap_org_tokens = False
        response = super().create(request, *args, **kwargs)
        if getattr(self, "_bootstrap_org_tokens", False):
            _set_bootstrap_auth_tokens(response, request.user)
        return response

    def perform_create(self, serializer):
        from rest_framework.serializers import ValidationError
        user = self.request.user
        had_organization = bool(user.organization_id)

        if user.organization_id or user.owned_organization.exists():
            raise ValidationError(
                "Single-organization launch: you already belong to an organization."
            )

        org = serializer.save(owner=user)
        org.ensure_default_project()

        if not had_organization:
            user.organization = org
            user.role = "owner"
            user.save(update_fields=["organization", "role"])
            self._bootstrap_org_tokens = True

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

    def get_permissions(self):
        if self.request.method in ["PATCH", "PUT"]:
            return [permissions.IsAuthenticated(), IsPlatformUser()]
        return [permissions.IsAdminUser()]

    def get_queryset(self):
        user = getattr(self.request, "user", None)
        if self.request.method in ["PATCH", "PUT"] and user and user.is_authenticated:
            if user.is_staff:
                return Organization.objects.all()
            return Organization.objects.filter(owner=user)
        return Organization.objects.all()

    def perform_update(self, serializer):
        org = self.get_object()
        old_data = OrganizationSerializer(org).data
        updated_org = serializer.save()
        if old_data.get("allow_signup") != updated_org.allow_signup:
            _sync_default_project_signup(updated_org)
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
    api_key_read_scopes = ("organization:read",)

    def perform_update(self, serializer):
        org = self.get_object()
        old_data = OrganizationSerializer(org).data
        updated_org = serializer.save()
        if old_data.get("allow_signup") != updated_org.allow_signup:
            _sync_default_project_signup(updated_org)
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
            return [permissions.IsAuthenticated(), IsPlatformUser(), IsOrganizationOwner()]
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
        tags=["Projects"],
        summary="List projects",
        description="List projects for the current organization. Owner only.",
    ),
    post=extend_schema(
        tags=["Projects"],
        summary="Create a project",
        description="Create a new project in the current organization. Owner only.",
        request=ProjectSerializer,
        responses={201: ProjectSerializer},
    ),
)
class ProjectListCreateView(generics.ListCreateAPIView):
    """List and create projects for the current organization."""

    serializer_class = ProjectSerializer
    permission_classes = [IsCurrentOrganizationOwner]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "slug"]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = ["created_at", "name"]

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsCurrentOrganizationOwner()]
        return [IsCurrentOrganizationAdmin()]

    def get_queryset(self):
        return _current_user_project_queryset(self.request)

    def perform_create(self, serializer):
        project = serializer.save(organization=self.request.user.organization)
        AuditLog.log(
            event_type=AuditLog.EventType.PROJECT_CREATED,
            request=self.request,
            user=_authenticated_user_or_none(self.request),
            organization=project.organization,
            project=project,
            target=project,
            event_data={
                "name": project.name,
                "slug": project.slug,
                "allow_signup": project.allow_signup,
                "is_default": project.is_default,
                "frontend_url": project.frontend_url,
                "allowed_origins": project.allowed_origins,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=project.organization,
            project=project,
            event_type=Webhook.EventType.PROJECT_CREATED,
            payload={
                "project_id": str(project.id),
                "name": project.name,
                "slug": project.slug,
                "allow_signup": project.allow_signup,
                "is_default": project.is_default,
                "frontend_url": project.frontend_url,
                "allowed_origins": project.allowed_origins,
            },
        )


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="Retrieve a project",
        description="Get details for a project in the current organization. Owner only.",
    ),
    patch=extend_schema(
        tags=["Projects"],
        summary="Update a project",
        description="Update a project in the current organization. Owner only.",
    ),
    delete=extend_schema(
        tags=["Projects"],
        summary="Delete a project",
        description="Delete a non-default project in the current organization. Owner only.",
    ),
)
class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a project in the current organization."""

    serializer_class = ProjectSerializer
    permission_classes = [IsCurrentOrganizationOwner]

    def get_permissions(self):
        if self.request.method == "GET":
            return [IsCurrentOrganizationAdmin()]
        return [IsCurrentOrganizationOwner()]

    def get_queryset(self):
        return _current_user_project_queryset(self.request)

    def perform_update(self, serializer):
        project = self.get_object()
        old_data = ProjectSerializer(project).data
        updated_project = serializer.save()
        new_data = ProjectSerializer(updated_project).data

        changes = {
            field: {"old": old_data[field], "new": new_data[field]}
            for field in old_data
            if old_data[field] != new_data[field]
        }

        if changes:
            AuditLog.log(
                event_type=AuditLog.EventType.PROJECT_UPDATED,
                request=self.request,
                user=_authenticated_user_or_none(self.request),
                organization=updated_project.organization,
                project=updated_project,
                target=updated_project,
                event_data={"changes": changes},
                success=True,
            )
            trigger_webhook_event(
                organization=updated_project.organization,
                project=updated_project,
                event_type=Webhook.EventType.PROJECT_UPDATED,
                payload={
                    "project_id": str(updated_project.id),
                    "name": updated_project.name,
                    "slug": updated_project.slug,
                    "changes": changes,
                },
            )

    def perform_destroy(self, instance):
        if instance.is_default:
            raise serializers.ValidationError("The default project cannot be deleted.")
        if instance.api_keys.exists():
            raise serializers.ValidationError(
                "Delete or revoke this project's API keys before deleting the project."
            )
        if instance.webhooks.exists():
            raise serializers.ValidationError(
                "Delete this project's webhooks before deleting the project."
            )
        if instance.users.exists():
            raise serializers.ValidationError(
                "Delete or move this project's users before deleting the project."
            )
        if instance.social_provider_configs.exists():
            raise serializers.ValidationError(
                "Delete this project's social provider configs before deleting the project."
            )
        if instance.organization_invitations.filter(
            accepted_at__isnull=True,
            revoked_at__isnull=True,
        ).exists():
            raise serializers.ValidationError(
                "Revoke or accept this project's pending invitations before deleting the project."
            )
        if instance.app_roles.exists():
            raise serializers.ValidationError(
                "Delete this project's app roles before deleting the project."
            )
        if instance.app_permissions.exists():
            raise serializers.ValidationError(
                "Delete this project's app permissions before deleting the project."
            )

        AuditLog.log(
            event_type=AuditLog.EventType.PROJECT_DELETED,
            request=self.request,
            user=_authenticated_user_or_none(self.request),
            organization=instance.organization,
            project=instance,
            target=instance,
            event_data={
                "name": instance.name,
                "slug": instance.slug,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=instance.organization,
            project=instance,
            event_type=Webhook.EventType.PROJECT_DELETED,
            payload={
                "project_id": str(instance.id),
                "name": instance.name,
                "slug": instance.slug,
            },
        )
        instance.delete()


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="List project app permissions",
        description="List dynamic app permissions for a project in the current organization. Owner/admin only.",
    ),
    post=extend_schema(
        tags=["Projects"],
        summary="Create project app permission",
        description="Create a dynamic app permission for a project. Owner/admin only.",
        request=ProjectPermissionSerializer,
        responses={201: ProjectPermissionSerializer},
    ),
)
class ProjectPermissionListCreateView(generics.ListCreateAPIView):
    """List and create project-scoped app permissions."""

    serializer_class = ProjectPermissionSerializer
    permission_classes = [IsCurrentOrganizationAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["slug", "name", "description"]
    ordering_fields = ["slug", "name", "created_at", "updated_at"]
    ordering = ["slug"]

    def _get_project(self):
        return _get_current_project_or_404(self.request, self.kwargs["project_pk"])

    def get_queryset(self):
        return ProjectPermission.objects.filter(project=self._get_project())

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["project"] = self._get_project()
        return context

    def perform_create(self, serializer):
        serializer.save(project=self._get_project())


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="Retrieve project app permission",
        description="Retrieve a dynamic app permission for a project. Owner/admin only.",
    ),
    patch=extend_schema(
        tags=["Projects"],
        summary="Update project app permission",
        description="Update a dynamic app permission for a project. Owner/admin only.",
    ),
    delete=extend_schema(
        tags=["Projects"],
        summary="Delete project app permission",
        description="Delete a dynamic app permission for a project after unlinking it from roles. Owner/admin only.",
    ),
)
class ProjectPermissionDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a project app permission."""

    serializer_class = ProjectPermissionSerializer
    permission_classes = [IsCurrentOrganizationAdmin]

    def _get_project(self):
        return _get_current_project_or_404(self.request, self.kwargs["project_pk"])

    def get_queryset(self):
        return ProjectPermission.objects.filter(project=self._get_project())

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["project"] = self._get_project()
        return context

    def perform_destroy(self, instance):
        if instance.role_links.exists():
            raise serializers.ValidationError(
                "Remove this permission from all project roles before deleting it."
            )
        instance.delete()


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="List project app roles",
        description="List dynamic app roles for a project in the current organization. Owner/admin only.",
    ),
    post=extend_schema(
        tags=["Projects"],
        summary="Create project app role",
        description="Create a dynamic app role and attach permissions. Owner/admin only.",
        request=ProjectRoleSerializer,
        responses={201: ProjectRoleSerializer},
    ),
)
class ProjectRoleListCreateView(generics.ListCreateAPIView):
    """List and create project-scoped app roles."""

    serializer_class = ProjectRoleSerializer
    permission_classes = [IsCurrentOrganizationAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["slug", "name", "description"]
    ordering_fields = ["name", "slug", "created_at", "updated_at"]
    ordering = ["name", "slug"]

    def _get_project(self):
        return _get_current_project_or_404(self.request, self.kwargs["project_pk"])

    def get_queryset(self):
        return ProjectRole.objects.filter(project=self._get_project()).prefetch_related(
            "permissions"
        )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["project"] = self._get_project()
        return context

    def perform_create(self, serializer):
        serializer.save()


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="Retrieve project app role",
        description="Retrieve a dynamic app role for a project. Owner/admin only.",
    ),
    patch=extend_schema(
        tags=["Projects"],
        summary="Update project app role",
        description="Update a dynamic app role and its permissions. Owner/admin only.",
    ),
    delete=extend_schema(
        tags=["Projects"],
        summary="Delete project app role",
        description="Delete a dynamic app role after removing it from users. Owner/admin only.",
    ),
)
class ProjectRoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a project app role."""

    serializer_class = ProjectRoleSerializer
    permission_classes = [IsCurrentOrganizationAdmin]

    def _get_project(self):
        return _get_current_project_or_404(self.request, self.kwargs["project_pk"])

    def get_queryset(self):
        return ProjectRole.objects.filter(project=self._get_project()).prefetch_related(
            "permissions"
        )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["project"] = self._get_project()
        return context

    def perform_destroy(self, instance):
        if instance.assignments.exists():
            raise serializers.ValidationError(
                "Remove this role from all users before deleting it."
            )
        if instance.organization_invitations.filter(
            accepted_at__isnull=True,
            revoked_at__isnull=True,
        ).exists():
            raise serializers.ValidationError(
                "Remove this role from pending invitations before deleting it."
            )
        instance.delete()


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="Get user app access for a project",
        description="Get a user's assigned app roles and effective permissions for a project. Owner/admin only.",
        responses={200: ProjectUserRoleAccessSerializer},
    ),
    put=extend_schema(
        tags=["Projects"],
        summary="Replace user app roles for a project",
        description="Replace a user's assigned app roles for a project. Owner/admin only.",
        request=ProjectUserRoleAssignmentUpdateSerializer,
        responses={200: ProjectUserRoleAccessSerializer},
    ),
    patch=extend_schema(
        tags=["Projects"],
        summary="Replace user app roles for a project",
        description="Replace a user's assigned app roles for a project. Owner/admin only.",
        request=ProjectUserRoleAssignmentUpdateSerializer,
        responses={200: ProjectUserRoleAccessSerializer},
    ),
)
class ProjectUserRoleAssignmentView(APIView):
    """Read or replace a user's assigned app roles for a project."""

    permission_classes = [IsCurrentOrganizationAdmin]

    def _get_project(self):
        return _get_current_project_or_404(self.request, self.kwargs["project_pk"])

    def _get_user(self, project):
        user = get_object_or_404(
            User.objects.filter(organization=self.request.user.organization),
            pk=self.kwargs["user_pk"],
        )
        return user

    def get(self, request, *args, **kwargs):
        project = self._get_project()
        user = self._get_user(project)
        payload = _serialize_user_project_access(user, project)
        serializer = ProjectUserRoleAccessSerializer(payload)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        return self._replace_roles(request)

    def patch(self, request, *args, **kwargs):
        return self._replace_roles(request)

    def _replace_roles(self, request):
        project = self._get_project()
        user = self._get_user(project)
        serializer = ProjectUserRoleAssignmentUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        roles, _ = resolve_project_roles_or_error(
            project,
            serializer.validated_data["role_slugs"],
            field_name="role_slugs",
            invalid_message_prefix="These roles do not exist in this project: ",
        )

        sync_user_project_roles(
            user,
            project,
            roles,
            assigned_by=request.user,
        )
        payload = _serialize_user_project_access(user, project)
        response_serializer = ProjectUserRoleAccessSerializer(payload)
        return Response(response_serializer.data, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Projects"],
    summary="Get current project access",
    description="Return the authenticated user's app roles and effective permissions for a project.",
    responses={200: ProjectUserRoleAccessSerializer},
)
class CurrentProjectAccessView(APIView):
    """Expose the current user's effective app access for a project."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        project = _get_current_project_or_404(request, kwargs["project_pk"])
        if not user_has_project_access(request.user, project):
            raise NotFound("Project not found.")

        payload = _serialize_user_project_access(request.user, project)
        serializer = ProjectUserRoleAccessSerializer(payload)
        return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="List project social providers",
        description="List social provider configs for a project in the current organization. Owner only.",
    ),
    post=extend_schema(
        tags=["Projects"],
        summary="Create a project social provider config",
        description="Create or configure a social provider for a project in the current organization. Owner only.",
        request=SocialProviderConfigSerializer,
        responses={201: SocialProviderConfigSerializer},
    ),
)
class SocialProviderConfigListCreateView(generics.ListCreateAPIView):
    """List and create per-project social provider configs."""

    serializer_class = SocialProviderConfigSerializer
    permission_classes = [IsCurrentOrganizationOwner]

    def _get_project(self):
        user = getattr(self.request, "user", None)
        if not user or not user.is_authenticated or not user.organization_id:
            raise NotFound("Project not found.")
        return get_object_or_404(
            Project,
            organization=user.organization,
            id=self.kwargs["project_pk"],
        )

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return SocialProviderConfig.objects.none()
        project = self._get_project()
        return SocialProviderConfig.objects.filter(project=project).order_by("provider")

    def perform_create(self, serializer):
        project = self._get_project()
        config = serializer.save(project=project)
        AuditLog.log(
            event_type=AuditLog.EventType.PROJECT_SOCIAL_PROVIDER_CREATED,
            request=self.request,
            user=_authenticated_user_or_none(self.request),
            organization=project.organization,
            project=project,
            target=config,
            event_data={
                "provider": config.provider,
                "is_active": config.is_active,
                "redirect_uris": config.redirect_uris,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=project.organization,
            project=project,
            event_type=Webhook.EventType.PROJECT_SOCIAL_PROVIDER_CREATED,
            payload={
                "social_provider_config_id": str(config.id),
                "provider": config.provider,
                "is_active": config.is_active,
                "redirect_uris": config.redirect_uris,
            },
        )


@extend_schema_view(
    get=extend_schema(
        tags=["Projects"],
        summary="Retrieve a project social provider config",
        description="Retrieve a social provider config for a project in the current organization. Owner only.",
    ),
    patch=extend_schema(
        tags=["Projects"],
        summary="Update a project social provider config",
        description="Update a social provider config for a project in the current organization. Owner only.",
    ),
    delete=extend_schema(
        tags=["Projects"],
        summary="Delete a project social provider config",
        description="Delete a social provider config for a project in the current organization. Owner only.",
    ),
)
class SocialProviderConfigDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a per-project social provider config."""

    serializer_class = SocialProviderConfigSerializer
    permission_classes = [IsCurrentOrganizationOwner]

    def get_queryset(self):
        user = getattr(self.request, "user", None)
        if not user or not user.is_authenticated or not user.organization_id:
            return SocialProviderConfig.objects.none()
        return SocialProviderConfig.objects.filter(project__organization=user.organization)

    def perform_update(self, serializer):
        config = self.get_object()
        old_data = SocialProviderConfigSerializer(config).data
        updated_config = serializer.save()
        new_data = SocialProviderConfigSerializer(updated_config).data
        changes = {
            field: {"old": old_data[field], "new": new_data[field]}
            for field in old_data
            if old_data[field] != new_data[field]
        }

        if changes:
            AuditLog.log(
                event_type=AuditLog.EventType.PROJECT_SOCIAL_PROVIDER_UPDATED,
                request=self.request,
                user=_authenticated_user_or_none(self.request),
                organization=updated_config.organization,
                project=updated_config.project,
                target=updated_config,
                event_data={
                    "provider": updated_config.provider,
                    "changes": changes,
                },
                success=True,
            )
            trigger_webhook_event(
                organization=updated_config.organization,
                project=updated_config.project,
                event_type=Webhook.EventType.PROJECT_SOCIAL_PROVIDER_UPDATED,
                payload={
                    "social_provider_config_id": str(updated_config.id),
                    "provider": updated_config.provider,
                    "changes": changes,
                },
            )

    def perform_destroy(self, instance):
        AuditLog.log(
            event_type=AuditLog.EventType.PROJECT_SOCIAL_PROVIDER_DELETED,
            request=self.request,
            user=_authenticated_user_or_none(self.request),
            organization=instance.organization,
            project=instance.project,
            target=instance,
            event_data={
                "provider": instance.provider,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=instance.organization,
            project=instance.project,
            event_type=Webhook.EventType.PROJECT_SOCIAL_PROVIDER_DELETED,
            payload={
                "social_provider_config_id": str(instance.id),
                "provider": instance.provider,
            },
        )
        instance.delete()


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
    api_key_read_scopes = ("api_keys:read",)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["environment", "is_active", "project"]
    search_fields = ["name", "prefix"]
    ordering_fields = ["name", "environment", "project__name", "created_at", "last_used_at"]
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
        queryset = APIKey.objects.select_related("project").filter(organization=org)
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            queryset = queryset.filter(project=self.request.auth.project)
        return queryset

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
            project=api_key.project,
            target=api_key,
            event_data={
                "key_name": api_key.name,
                "environment": api_key.environment,
                "project_id": str(api_key.project_id) if api_key.project_id else None,
                "project_slug": api_key.project.slug if api_key.project_id else "",
                "scopes": api_key.scopes,
            },
            success=True,
        )

        # Trigger webhook: api_key.created
        trigger_webhook_event(
            organization=org,
            project=api_key.project,
            event_type="api_key.created",
            payload={
                "api_key_id": str(api_key.id),
                "name": api_key.name,
                "environment": api_key.environment,
                "project_id": str(api_key.project_id) if api_key.project_id else None,
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
    api_key_read_scopes = ("api_keys:read",)

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return APIKey.objects.none()

        if not org:
            return APIKey.objects.none()
        queryset = APIKey.objects.select_related("project").filter(organization=org)
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            queryset = queryset.filter(project=self.request.auth.project)
        return queryset

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
                project=api_key.project,
                target=api_key,
                event_data={
                    "key_name": api_key.name,
                    "environment": api_key.environment,
                    "project_id": str(api_key.project_id) if api_key.project_id else None,
                    "action": "deleted",
                },
                success=True,
            )

            # Trigger webhook: api_key.revoked
            trigger_webhook_event(
                organization=api_key.organization,
                project=api_key.project,
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
    api_key_read_scopes = ("api_keys:read",)

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return APIKey.objects.none()

        if not org:
            return APIKey.objects.none()
        queryset = APIKey.objects.select_related("project").filter(organization=org)
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            queryset = queryset.filter(project=self.request.auth.project)
        return queryset

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
            project=api_key.project,
            target=api_key,
            event_data={
                "key_name": api_key.name,
                "environment": api_key.environment,
                "project_id": str(api_key.project_id) if api_key.project_id else None,
                "action": "deactivated",
            },
            success=True,
        )

        # Trigger webhook: api_key.revoked
        trigger_webhook_event(
            organization=api_key.organization,
            project=api_key.project,
            event_type="api_key.revoked",
            payload={
                "api_key_id": str(api_key.id),
                "name": api_key.name,
                "action": "deactivated",
            },
        )

        return Response({"detail": "API key revoked"}, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=["Organizations"],
        summary="List organization invitations",
        description="List invitations for the current organization. Owner only.",
    ),
    post=extend_schema(
        tags=["Organizations"],
        summary="Create organization invitation",
        description="Invite a user to the current organization as an admin or member. Owner only.",
    ),
)
class OrganizationInvitationListCreateView(generics.ListCreateAPIView):
    """Manage invitations for the current organization."""

    permission_classes = [permissions.IsAuthenticated, IsPlatformUser, IsCurrentOrganizationOwner]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False) or not self.request.user.is_authenticated:
            return OrganizationInvitation.objects.none()
        return OrganizationInvitation.objects.filter(
            organization=self.request.user.organization
        ).select_related("project", "invited_by", "accepted_by").prefetch_related("app_roles")

    def get_serializer_class(self):
        if self.request.method == "POST":
            return OrganizationInvitationCreateSerializer
        return OrganizationInvitationSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["organization"] = self.request.user.organization
        return context

    def perform_create(self, serializer):
        invitation = serializer.save(
            organization=self.request.user.organization,
            invited_by=self.request.user,
        )
        email_sent = _send_invitation_email(invitation)

        AuditLog.log(
            event_type=AuditLog.EventType.ORG_INVITATION_CREATED,
            request=self.request,
            user=self.request.user,
            organization=self.request.user.organization,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
                "email_sent": email_sent,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=self.request.user.organization,
            project=invitation.project,
            event_type=Webhook.EventType.ORG_INVITATION_CREATED,
            payload={
                "invitation_id": str(invitation.id),
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
                "expires_at": invitation.expires_at.isoformat(),
                "email_sent": email_sent,
            },
        )


@extend_schema_view(
    post=extend_schema(
        tags=["Organizations"],
        summary="Resend organization invitation",
        description="Resend a pending invitation email for the current organization. Owner only.",
    ),
)
class OrganizationInvitationResendView(generics.GenericAPIView):
    """Resend a pending invitation email."""

    permission_classes = [permissions.IsAuthenticated, IsPlatformUser, IsCurrentOrganizationOwner]
    serializer_class = OrganizationInvitationSerializer

    def get_queryset(self):
        return OrganizationInvitation.objects.filter(
            organization=self.request.user.organization
        ).select_related("project", "invited_by", "accepted_by").prefetch_related("app_roles")

    def post(self, request, *args, **kwargs):
        invitation = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])

        if invitation.accepted_at:
            raise serializers.ValidationError(
                {"detail": "Accepted invitations cannot be resent."}
            )

        if invitation.revoked_at:
            raise serializers.ValidationError(
                {"detail": "Revoked invitations cannot be resent."}
            )

        if invitation.is_expired:
            raise serializers.ValidationError(
                {"detail": "Expired invitations cannot be resent."}
            )

        email_sent = _send_invitation_email(invitation)

        AuditLog.log(
            event_type=AuditLog.EventType.ORG_INVITATION_RESENT,
            request=request,
            user=request.user,
            organization=request.user.organization,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
                "email_sent": email_sent,
            },
            success=True,
        )
        trigger_webhook_event(
            organization=request.user.organization,
            project=invitation.project,
            event_type=Webhook.EventType.ORG_INVITATION_RESENT,
            payload={
                "invitation_id": str(invitation.id),
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
                "expires_at": invitation.expires_at.isoformat(),
                "email_sent": email_sent,
            },
        )

        invitation.refresh_from_db()
        return Response(
            OrganizationInvitationSerializer(invitation).data,
            status=status.HTTP_200_OK,
        )


@extend_schema_view(
    delete=extend_schema(
        tags=["Organizations"],
        summary="Revoke organization invitation",
        description="Revoke a pending invitation for the current organization. Owner only.",
    ),
)
class OrganizationInvitationRevokeView(generics.DestroyAPIView):
    """Revoke a pending invitation without deleting the audit trail."""

    permission_classes = [permissions.IsAuthenticated, IsPlatformUser, IsCurrentOrganizationOwner]
    serializer_class = OrganizationInvitationSerializer

    def get_queryset(self):
        return OrganizationInvitation.objects.filter(
            organization=self.request.user.organization
        ).select_related("project", "invited_by", "accepted_by").prefetch_related("app_roles")

    def destroy(self, request, *args, **kwargs):
        invitation = self.get_object()

        if invitation.accepted_at:
            raise serializers.ValidationError(
                {"detail": "Accepted invitations cannot be revoked."}
            )

        if invitation.revoked_at:
            raise serializers.ValidationError(
                {"detail": "This invitation has already been revoked."}
            )

        invitation.revoked_at = timezone.now()
        invitation.save(update_fields=["revoked_at", "updated_at"])

        AuditLog.log(
            event_type=AuditLog.EventType.ORG_INVITATION_REVOKED,
            request=request,
            user=request.user,
            organization=request.user.organization,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
            },
            success=True,
        )
        trigger_webhook_event(
            organization=request.user.organization,
            project=invitation.project,
            event_type=Webhook.EventType.ORG_INVITATION_REVOKED,
            payload={
                "invitation_id": str(invitation.id),
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": list(invitation.app_roles.values_list("slug", flat=True)),
            },
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    tags=["Organizations"],
    summary="Get invitation details by token",
    description="Public invitation preview for the frontend accept page.",
    responses={200: OrganizationInvitationPublicSerializer},
)
class OrganizationInvitationLookupView(APIView):
    """Resolve an invitation token into safe preview metadata."""

    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        token = (request.query_params.get("token") or "").strip()
        if not token:
            raise serializers.ValidationError({"token": ["This field is required."]})

        invitation = get_object_or_404(
            OrganizationInvitation.objects.select_related("organization", "project").prefetch_related("app_roles"),
            token=token,
        )

        return Response(
            OrganizationInvitationPublicSerializer(invitation).data,
            status=status.HTTP_200_OK,
        )


@extend_schema(
    tags=["Organizations"],
    summary="Accept organization invitation",
    description="Accept an invitation using its token. The authenticated user's email must match the invitation email.",
    request=OrganizationInvitationAcceptSerializer,
    responses={200: OrganizationInvitationSerializer},
)
class OrganizationInvitationAcceptView(APIView):
    """Accept an invitation and join the organization."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = OrganizationInvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        invitation = get_object_or_404(
            OrganizationInvitation.objects.select_related("organization", "project", "invited_by").prefetch_related("app_roles"),
            token=serializer.validated_data["token"],
        )

        if invitation.accepted_at:
            raise serializers.ValidationError(
                {"detail": "This invitation has already been accepted."}
            )

        if invitation.revoked_at:
            raise serializers.ValidationError(
                {"detail": "This invitation has been revoked."}
            )

        if invitation.is_expired:
            raise serializers.ValidationError(
                {"detail": "This invitation has expired."}
            )

        if request.user.email.lower() != invitation.email.lower():
            raise serializers.ValidationError(
                {"detail": "This invitation is for a different email address."}
            )

        if (
            request.user.organization_id
            and request.user.organization_id != invitation.organization_id
        ):
            raise serializers.ValidationError(
                {"detail": "You already belong to a different organization."}
            )

        invited_app_roles = list(invitation.app_roles.all())
        with transaction.atomic():
            update_fields = []
            is_new_org_membership = request.user.organization_id is None
            if is_new_org_membership:
                request.user.organization = invitation.organization
                request.user.role = invitation.role
                update_fields.extend(["organization", "role"])
                if invitation.project_id and invitation.role == User.Role.MEMBER:
                    request.user.project = invitation.project
                    update_fields.append("project")
            elif (
                invitation.project_id
                and invitation.role == User.Role.MEMBER
                and request.user.project_id is None
            ):
                # Preserve existing project affinity when present, but seed legacy
                # users that never had a primary project so user.project-based access
                # does not remain empty.
                request.user.project = invitation.project
                update_fields.append("project")

            if update_fields:
                request.user.save(update_fields=update_fields)

            if invitation.project_id:
                if invited_app_roles:
                    sync_user_project_roles(
                        request.user,
                        invitation.project,
                        invited_app_roles,
                        assigned_by=invitation.invited_by,
                    )
                else:
                    assign_default_signup_roles(
                        request.user,
                        invitation.project,
                        assigned_by=invitation.invited_by,
                    )

            invitation.accepted_by = request.user
            invitation.accepted_at = timezone.now()
            invitation.save(update_fields=["accepted_by", "accepted_at", "updated_at"])

        AuditLog.log(
            event_type=AuditLog.EventType.ORG_INVITATION_ACCEPTED,
            request=request,
            user=request.user,
            organization=invitation.organization,
            project=invitation.project,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": [role.slug for role in invited_app_roles],
            },
            success=True,
        )
        trigger_webhook_event(
            organization=invitation.organization,
            project=invitation.project,
            event_type=Webhook.EventType.ORG_INVITATION_ACCEPTED,
            payload={
                "invitation_id": str(invitation.id),
                "email": invitation.email,
                "accepted_by_user_id": str(request.user.id),
                "accepted_by_email": request.user.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": [role.slug for role in invited_app_roles],
            },
        )
        AuditLog.log(
            event_type=AuditLog.EventType.ORG_MEMBER_ADDED,
            request=request,
            user=request.user,
            organization=invitation.organization,
            project=invitation.project,
            target=request.user,
            event_data={
                "email": request.user.email,
                "role": invitation.role,
                "project_id": str(invitation.project_id) if invitation.project_id else None,
                "project_slug": invitation.project.slug if invitation.project_id else "",
                "app_roles": [role.slug for role in invited_app_roles],
            },
            success=True,
        )

        invitation.refresh_from_db()
        response = Response(
            OrganizationInvitationSerializer(invitation).data,
            status=status.HTTP_200_OK,
        )
        _set_rotated_auth_tokens(response, request.user, project=invitation.project)
        return response


@extend_schema_view(
    get=extend_schema(
        tags=["Runtime Invitations"],
        summary="List runtime invitations",
        description=(
            "List runtime invitations for the project resolved from the provided API key. "
            "Supports optional filtering by status and email."
        ),
        responses={200: RuntimeInvitationSerializer(many=True)},
    ),
    post=extend_schema(
        tags=["Runtime Invitations"],
        summary="Create runtime invitation",
        description="Invite a runtime user into the project resolved from the provided API key.",
        request=RuntimeInvitationCreateSerializer,
        responses={201: RuntimeInvitationSerializer},
    ),
)
class RuntimeInvitationListCreateView(APIView):
    authentication_classes = [
        APIKeyAuthentication,
        HVTJWTCookieAuthentication,
        HVTJWTAuthentication,
    ]
    permission_classes = [permissions.AllowAny]
    throttle_classes = [APIKeyRateThrottle]

    def _get_runtime_api_key(self, request) -> APIKey:
        if request.user and request.user.is_authenticated and not isinstance(request.auth, APIKey):
            raise PermissionDenied("Platform JWT authentication is not allowed on this endpoint.")

        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise NotAuthenticated("A valid X-API-Key header is required.")
        if not api_key.has_scope("auth:runtime"):
            raise PermissionDenied("This API key does not have the required auth:runtime scope.")
        if not api_key.project_id:
            raise PermissionDenied("Runtime invitations require a project-scoped API key.")
        return api_key

    def get(self, request, *args, **kwargs):
        api_key = self._get_runtime_api_key(request)

        queryset = RuntimeInvitation.objects.filter(project=api_key.project).order_by("-created_at")

        status_filter = (request.query_params.get("status") or "").strip().lower()
        if status_filter:
            if status_filter not in RuntimeInvitation.Status.values:
                raise serializers.ValidationError(
                    {"status": ["Invalid status filter for runtime invitations."]}
                )
            queryset = queryset.filter(status=status_filter)

        email_filter = (request.query_params.get("email") or "").strip().lower()
        if email_filter:
            queryset = queryset.filter(email=email_filter)

        paginator = StandardPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        serializer = RuntimeInvitationSerializer(page if page is not None else queryset, many=True)
        if page is not None:
            return paginator.get_paginated_response(serializer.data)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        api_key = self._get_runtime_api_key(request)

        project = api_key.project
        serializer = RuntimeInvitationCreateSerializer(
            data=request.data,
            context={"project": project},
        )
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        if get_runtime_project_users_by_email(email, api_key).exists():
            raise serializers.ValidationError(
                {"email": ["A user with this email already exists in this project"]}
            )

        if get_control_plane_users_by_email(email).exists():
            return Response({}, status=status.HTTP_201_CREATED)

        with transaction.atomic():
            RuntimeInvitation.objects.filter(
                project=project,
                email=email,
                status=RuntimeInvitation.Status.PENDING,
            ).update(status=RuntimeInvitation.Status.REVOKED)
            invitation = RuntimeInvitation.objects.create(
                project=project,
                email=email,
                role_slugs=serializer.validated_data["role_slugs"],
                invited_by=_authenticated_user_or_none(request),
            )

        email_sent = _send_runtime_invitation_email(
            invitation,
            first_name=serializer.validated_data.get("first_name", ""),
            last_name=serializer.validated_data.get("last_name", ""),
        )
        AuditLog.log(
            event_type=AuditLog.EventType.RUNTIME_USER_INVITED,
            request=request,
            api_key=api_key,
            organization=project.organization,
            project=project,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role_slugs": invitation.role_slugs,
                "email_sent": email_sent,
            },
            success=True,
        )

        return Response(
            RuntimeInvitationSerializer(invitation).data,
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=["Runtime Invitations"],
    summary="Accept runtime invitation",
    description="Accept a runtime invitation token and immediately return a JWT pair.",
    request=RuntimeInvitationAcceptSerializer,
    responses={200: inline_serializer(
        name="RuntimeInvitationAcceptResponse",
        fields={
            "access": serializers.CharField(),
            "refresh": serializers.CharField(),
        },
    )},
)
class RuntimeInvitationAcceptView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RuntimeInvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        invitation = get_object_or_404(
            RuntimeInvitation.objects.select_related(
                "project",
                "project__organization",
                "invited_by",
            ),
            token=serializer.validated_data["token"],
        )

        if invitation.status != RuntimeInvitation.Status.PENDING:
            raise serializers.ValidationError(
                {"detail": "This invitation is no longer valid"}
            )

        if invitation.is_expired:
            invitation.status = RuntimeInvitation.Status.EXPIRED
            invitation.save(update_fields=["status"])
            raise serializers.ValidationError(
                {"detail": "This invitation has expired"}
            )

        invited_roles, _ = resolve_project_roles_or_error(
            invitation.project,
            invitation.role_slugs,
            field_name="role_slugs",
            invalid_message_prefix="These roles do not exist in this project: ",
        )

        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    email=invitation.email,
                    password=serializer.validated_data["password1"],
                    organization=invitation.project.organization,
                    project=invitation.project,
                    role=User.Role.MEMBER,
                )
                assign_default_signup_roles(
                    user,
                    invitation.project,
                    assigned_by=invitation.invited_by,
                )
                merged_roles = list(get_user_project_roles(user, invitation.project))
                merged_role_ids = {role.id for role in merged_roles}
                for invited_role in invited_roles:
                    if invited_role.id not in merged_role_ids:
                        merged_roles.append(invited_role)
                sync_user_project_roles(
                    user,
                    invitation.project,
                    merged_roles,
                    assigned_by=invitation.invited_by,
                )
                invitation.status = RuntimeInvitation.Status.ACCEPTED
                invitation.accepted_at = timezone.now()
                invitation.save(update_fields=["status", "accepted_at"])
        except IntegrityError as exc:
            raise serializers.ValidationError(
                {"email": ["A user with this email already exists in this project"]}
            ) from exc

        AuditLog.log(
            event_type=AuditLog.EventType.RUNTIME_USER_INVITE_ACCEPTED,
            request=request,
            user=user,
            organization=invitation.project.organization,
            project=invitation.project,
            target=invitation,
            event_data={
                "email": invitation.email,
                "role_slugs": invitation.role_slugs,
            },
            success=True,
        )

        access_token, refresh_token = build_hvt_token_pair(
            user,
            project=invitation.project,
        )
        access_value = str(access_token)
        refresh_value = str(refresh_token)
        response = Response(
            {
                "access": access_value,
                "refresh": ""
                if dj_rest_auth_settings.JWT_AUTH_HTTPONLY
                else refresh_value,
            },
            status=status.HTTP_200_OK,
        )
        set_jwt_cookies(response, access_value, refresh_value)
        return response


# --- Webhook CRUD Views ---


@extend_schema_view(
    get=extend_schema(
        tags=["Webhooks"],
        summary="Webhook delivery summary",
        description="Get an overview of webhook delivery statistics over the last 24 hours.",
        responses={
            200: inline_serializer(
                name="WebhookSummaryResponse",
                fields={
                    "total_deliveries_24h": serializers.IntegerField(),
                    "successful_24h": serializers.IntegerField(),
                    "failed_24h": serializers.IntegerField(),
                },
            )
        },
    )
)
class WebhookSummaryView(APIView):
    """
    Get summarized webhook delivery info for last 24 hours.
    """
    permission_classes = [IsOrgAdminOrAPIKey]
    api_key_read_scopes = ("webhooks:read",)

    def get(self, request, *args, **kwargs):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
            project = getattr(self.request.auth, "project", None)
        elif self.request.user and hasattr(self.request.user, "organization"):
            org = self.request.user.organization
            project = None
        else:
            return Response({"total_deliveries_24h": 0, "successful_24h": 0, "failed_24h": 0})

        if not org:
            return Response({"total_deliveries_24h": 0, "successful_24h": 0, "failed_24h": 0})

        time_threshold = timezone.now() - timedelta(hours=24)
        
        # Filter deliveries for these webhooks
        qs = WebhookDelivery.objects.filter(
            webhook__organization=org,
            created_at__gte=time_threshold
        )
        
        if project:
            qs = qs.filter(webhook__project=project)
            
        stats = qs.aggregate(
            total=Count('id'),
            success_count=Count('id', filter=Q(status='success')),
            failed_count=Count('id', filter=Q(status='failed'))
        )
        
        return Response({
            "total_deliveries_24h": stats["total"] or 0,
            "successful_24h": stats["success_count"] or 0,
            "failed_24h": stats["failed_count"] or 0,
        })


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
    api_key_read_scopes = ("webhooks:read",)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["is_active", "project"]
    search_fields = ["url", "description"]
    ordering_fields = ["created_at", "last_triggered_at", "success_count", "failure_count", "project__name"]
    ordering = ["-created_at"]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return Webhook.objects.none()

        queryset = Webhook.objects.select_related("project").filter(organization=org)
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            queryset = queryset.filter(project=self.request.auth.project)
        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if isinstance(self.request.auth, APIKey):
            context["organization"] = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            context["organization"] = self.request.user.organization
        return context

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
    api_key_read_scopes = ("webhooks:read",)

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return Webhook.objects.none()

        queryset = Webhook.objects.select_related("project").filter(organization=org)
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            queryset = queryset.filter(project=self.request.auth.project)
        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if isinstance(self.request.auth, APIKey):
            context["organization"] = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            context["organization"] = self.request.user.organization
        return context


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
    api_key_read_scopes = ("webhooks:read",)
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
        if isinstance(self.request.auth, APIKey) and self.request.auth.project_id:
            if webhook.project_id != self.request.auth.project_id:
                raise NotFound("Webhook not found.")
        return WebhookDelivery.objects.filter(webhook=webhook).order_by("-created_at")


# ── Permissions Matrix ───────────────────────────────────────────────


# The definitive permission matrix for HVT.
# Each key is a resource/action, value maps role -> bool.
PERMISSION_MATRIX = {
    "projects.list": {"owner": True, "admin": True, "member": False},
    "projects.read": {"owner": True, "admin": True, "member": False},
    "projects.create": {"owner": True, "admin": False, "member": False},
    "projects.update": {"owner": True, "admin": False, "member": False},
    "projects.delete": {"owner": True, "admin": False, "member": False},
    "project_access.read": {"owner": True, "admin": True, "member": True},
    "project_permissions.manage": {"owner": True, "admin": True, "member": False},
    "project_roles.manage": {"owner": True, "admin": True, "member": False},
    "project_role_assignments.manage": {"owner": True, "admin": True, "member": False},
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
    "organization.invites.list": {"owner": True, "admin": False, "member": False},
    "organization.invites.create": {"owner": True, "admin": False, "member": False},
    "organization.invites.revoke": {"owner": True, "admin": False, "member": False},
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
    api_key_read_scopes = ("organization:read",)

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
            scope_requirements = {
                "users.list": ("users:read",),
                "users.read": ("users:read",),
                "organization.read": ("organization:read",),
                "api_keys.list": ("api_keys:read",),
                "webhooks.list": ("webhooks:read",),
                "webhooks.deliveries": ("webhooks:read",),
                "audit_logs.list_all": ("audit_logs:read",),
                "audit_logs.list_own": ("audit_logs:read",),
                "audit_logs.read": ("audit_logs:read",),
            }
            effective = {
                action: request.auth.has_any_scope(*scope_requirements.get(action, ()))
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
