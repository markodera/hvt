from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from dj_rest_auth.views import PasswordResetConfirmView
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from django.conf import settings
from . import views

# Social login views 
class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.FRONTEND_URL+"auth/google/callback"
    client_class = OAuth2Client

class GithubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    callback_url = settings.FRONTEND_URL+"auth/github/callback"


urlpatterns = [
    # dj-rest-auth endpoints: login, logout, password reset
    path("", include("dj_rest_auth.urls")),
    
    # Registration with email verification
    path("register/", include("dj_rest_auth.registration.urls")),
    
    # JWT token refresh
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    path("password/reset/confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    # Social login endpoint
    path("social/google/", GoogleLogin.as_view(), name="google_login"),
    path("social/github/", GithubLogin.as_view(), name="github_login"),
    # Custom endpoints
    path("me/", views.CurrentUserView.as_view(), name="current_user"),
    
    # Webhooks
    path("webhooks/resend/", views.resend_webhook, name="resend_webhook"),
]
