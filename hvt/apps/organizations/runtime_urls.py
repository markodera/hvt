from django.urls import path

from hvt.apps.organizations import views


urlpatterns = [
    path(
        "invitations/",
        views.RuntimeInvitationListCreateView.as_view(),
        name="runtime_invitation_list_create",
    ),
    path(
        "invitations/accept/",
        views.RuntimeInvitationAcceptView.as_view(),
        name="runtime_invitation_accept",
    ),
]
