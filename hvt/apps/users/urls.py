from django.urls import path
from . import views

urlpatterns = [
    path("", views.UserListView.as_view(), name="user_list"),
    path("<uuid:pk>/", views.UserDetailView.as_view(), name="user_detail"),
    path(
        "<uuid:pk>/role/", views.UserRoleUpdateView.as_view(), name="user_role_update"
    ),
]
