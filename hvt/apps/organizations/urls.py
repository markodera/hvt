from django.urls import path
from . import views
from hvt.apps.users.views import OrganizationMembersView
from hvt.apps.authentication.audit_views import AuditLogListView, AuditLogDetailView

urlpatterns = [
    # Organization CRUD
    path("", views.OrganizationListView.as_view(), name="organization_list"),
    path(
        "<uuid:pk>/", views.OrganizationDetailView.as_view(), name="organization_detail"
    ),
    path(
        "current/", views.CurrentOrganizationView.as_view(), name="current_organization"
    ),
    path(
        "current/projects/",
        views.ProjectListCreateView.as_view(),
        name="project_list_create",
    ),
    path(
        "current/projects/<uuid:pk>/",
        views.ProjectDetailView.as_view(),
        name="project_detail",
    ),
    path(
        "current/projects/<uuid:project_pk>/social-providers/",
        views.SocialProviderConfigListCreateView.as_view(),
        name="social_provider_config_list_create",
    ),
    path(
        "current/projects/<uuid:project_pk>/social-providers/<uuid:pk>/",
        views.SocialProviderConfigDetailView.as_view(),
        name="social_provider_config_detail",
    ),
    path(
        "current/invitations/",
        views.OrganizationInvitationListCreateView.as_view(),
        name="organization_invitation_list_create",
    ),
    path(
        "current/invitations/<uuid:pk>/",
        views.OrganizationInvitationRevokeView.as_view(),
        name="organization_invitation_revoke",
    ),
    path(
        "current/invitations/<uuid:pk>/resend/",
        views.OrganizationInvitationResendView.as_view(),
        name="organization_invitation_resend",
    ),
    path(
        "invitations/lookup/",
        views.OrganizationInvitationLookupView.as_view(),
        name="organization_invitation_lookup",
    ),
    path(
        "invitations/accept/",
        views.OrganizationInvitationAcceptView.as_view(),
        name="organization_invitation_accept",
    ),
    # Current Organization Members
    path(
        "current/members/",
        OrganizationMembersView.as_view(),
        name="organization_members",
    ),
    # API Key Management
    path(
        "current/keys/", views.APIKeyListCreateView.as_view(), name="apikey_list_create"
    ),
    path(
        "current/keys/<uuid:pk>/",
        views.APIKeyDetailView.as_view(),
        name="apikey_detail",
    ),
    path(
        "current/keys/<uuid:pk>/revoke/",
        views.APIKeyRevokeView.as_view(),
        name="apikey_revoke",
    ),
    # Webhook Management
    path(
        "current/webhooks/",
        views.WebhookListCreateView.as_view(),
        name="webhook_list_create",
    ),
    path(
        "current/webhooks/<uuid:pk>/",
        views.WebhookDetailView.as_view(),
        name="webhook_detail",
    ),
    path(
        "current/webhooks/<uuid:webhook_pk>/deliveries/",
        views.WebhookDeliveryListView.as_view(),
        name="webhook_delivery_list",
    ),
    # Audit Logs
    path(
        "current/audit-logs/",
        AuditLogListView.as_view(),
        name="audit_log_list",
    ),
    path(
        "current/audit-logs/<uuid:pk>/",
        AuditLogDetailView.as_view(),
        name="audit_log_detail",
    ),
    # Permissions Matrix
    path(
        "current/permissions/",
        views.PermissionsMatrixView.as_view(),
        name="permissions_matrix",
    ),
]
