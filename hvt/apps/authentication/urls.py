from django.urls import path, include
from dj_rest_auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    UserDetailsView,
)
from . import views


urlpatterns = [
    # dj-rest-auth endpoints (explicit to avoid schema collisions)
    path("runtime/register/", views.HVTRuntimeRegisterView.as_view(), name="runtime_register"),
    path("runtime/login/", views.RuntimeLoginView.as_view(), name="runtime_login"),
    path(
        "runtime/social/providers/",
        views.RuntimeSocialProviderListView.as_view(),
        name="runtime_social_provider_list",
    ),
    path(
        "runtime/social/google/",
        views.RuntimeGoogleLogin.as_view(),
        name="runtime_google_login",
    ),
    path(
        "runtime/social/github/",
        views.RuntimeGithubLogin.as_view(),
        name="runtime_github_login",
    ),
    path("login/", LoginView.as_view(), name="rest_login"),
    path("logout/", LogoutView.as_view(), name="rest_logout"),
    path("user/", UserDetailsView.as_view(), name="rest_user_details"),
    path("password/reset/", PasswordResetView.as_view(), name="rest_password_reset"),
    path(
        "password/reset/validate/",
        views.PasswordResetTokenValidationView.as_view(),
        name="rest_password_reset_validate",
    ),
    path("password/change/", PasswordChangeView.as_view(), name="rest_password_change"),
    # Password reset confirm — single endpoint with tokens in URL (no duplicate)
    path(
        "password/reset/confirm/<str:uidb64>/<str:token>/",
        views.HVTPasswordResetConfirmView.as_view(),
        name="rest_password_reset_confirm",
    ),
    # Registration with email verification
    path("register/", views.HVTRegisterView.as_view(), name="rest_register"),
    path("register/", include("dj_rest_auth.registration.urls")),
    # JWT token refresh
    path("token/refresh/", views.HVTTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "social/providers/",
        views.ControlPlaneSocialProviderListView.as_view(),
        name="social_provider_list",
    ),
    # Social login endpoint
    path("social/google/", views.GoogleLogin.as_view(), name="google_login"),
    path("social/github/", views.GithubLogin.as_view(), name="github_login"),
    # Custom endpoints
    path("me/", views.CurrentUserView.as_view(), name="current_user"),
    # Webhooks
    path("webhooks/resend/", views.resend_webhook, name="resend_webhook"),
]
