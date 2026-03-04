from django.urls import path, include

urlpatterns = [
    # Authentication endpoints (dj-rest-auth)
    path("auth/", include("hvt.apps.authentication.urls")),
    # User management
    path("users/", include("hvt.apps.users.urls")),
    # Organization management
    path("organizations/", include("hvt.apps.organizations.urls")),
]
