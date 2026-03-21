from django.urls import path, include
from dj_rest_auth.jwt_auth import get_refresh_view
from dj_rest_auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    PasswordResetConfirmView,
    UserDetailsView,
)
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from django.conf import settings
from . import views


# Social login views
class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.FRONTEND_URL + "/auth/google/callback"
    client_class = OAuth2Client


class GithubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    callback_url = settings.FRONTEND_URL + "/auth/github/callback"


urlpatterns = [
    # dj-rest-auth endpoints (explicit to avoid schema collisions)
    path("login/", LoginView.as_view(), name="rest_login"),
    path("logout/", LogoutView.as_view(), name="rest_logout"),
    path("user/", UserDetailsView.as_view(), name="rest_user_details"),
    path("password/reset/", PasswordResetView.as_view(), name="rest_password_reset"),
    path("password/change/", PasswordChangeView.as_view(), name="rest_password_change"),
    # Password reset confirm — single endpoint with tokens in URL (no duplicate)
    path(
        "password/reset/confirm/<str:uidb64>/<str:token>/",
        PasswordResetConfirmView.as_view(),
        name="rest_password_reset_confirm",
    ),
    # Registration with email verification
    path("register/", include("dj_rest_auth.registration.urls")),
    # JWT token refresh
    path("token/refresh/", get_refresh_view().as_view(), name="token_refresh"),
    # Social login endpoint
    path("social/google/", GoogleLogin.as_view(), name="google_login"),
    path("social/github/", GithubLogin.as_view(), name="github_login"),
    # Custom endpoints
    path("me/", views.CurrentUserView.as_view(), name="current_user"),
    # Webhooks
    path("webhooks/resend/", views.resend_webhook, name="resend_webhook"),
]