from django.urls import path
from . import views
from hvt.apps.users.views import OrganizationMembersView

urlpatterns = [
    # Organization CRUD
    path("", views.OrganizationListView.as_view(), name="organization_list"),
    path("<uuid:pk>/", views.OrganizationDetailView.as_view(), name="organization_detail"),
    path("current/", views.CurrentOrganizationView.as_view(), name="current_organization"),

    # Current Organization Members
    path("current/members/", OrganizationMembersView.as_view(), name="organization_members"),

    # API Key Management
    path("current/keys/", views.APIKeyListCreateView.as_view(), name="apikey_list_create"),
    path("current/keys/<uuid:pk>", views.APIKeyDetailView.as_view(), name="apikey_detail"),
    path("current/keys/<uuid:pk>/revoke/", views.APIKeyRevokeView.as_view(), name="apikey_revoke",)
]