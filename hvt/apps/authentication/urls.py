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
from hvt.api.v1.serializers.users import CustomSocialLoginSerializer
from . import views


# Social login views
class CompatOAuth2Client(OAuth2Client):
    """
    Backward-compatible OAuth2 client for dj-rest-auth social serializer.

    dj-rest-auth's SocialLoginSerializer passes a positional `scope` argument
    when constructing the client, while allauth's OAuth2Client constructor in
    this codebase version does not accept that positional parameter. This shim
    accepts both signatures and forwards only supported arguments.
    The dropped `scope` argument is not required by allauth's OAuth2Client in
    this version because provider scopes come from provider settings/request.
    """

    def __init__(
        self,
        request,
        consumer_key,
        consumer_secret,
        access_token_method,
        access_token_url,
        callback_url,
        scope=None,
        scope_delimiter=" ",
        headers=None,
        basic_auth=False,
    ):
        super().__init__(
            request,
            consumer_key,
            consumer_secret,
            access_token_method,
            access_token_url,
            callback_url,
            scope_delimiter=scope_delimiter,
            headers=headers,
            basic_auth=basic_auth,
        )


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.FRONTEND_URL + "/auth/google/callback"
    client_class = CompatOAuth2Client
    serializer_class = CustomSocialLoginSerializer


class GithubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    callback_url = settings.FRONTEND_URL + "/auth/github/callback"
    client_class = CompatOAuth2Client
    serializer_class = CustomSocialLoginSerializer


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
