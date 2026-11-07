from django.urls import path, include
from dj_rest_auth.views import (
    LogoutView,
)
from . import views
from . import totp_views
from . import passkey_views
from . import magic_link_views
from . import jwks_views


urlpatterns = [
    path(".well-known/jwks.json", jwks_views.JWKSView.as_view(), name="auth_jwks"),
    path(".well-known/openid-configuration", jwks_views.OpenIDConfigurationView.as_view(), name="auth_openid_configuration"),
    # MFA / Two-Factor Authentication (TOTP)
    path("mfa/totp/status/", totp_views.TOTPStatusView.as_view(), name="totp_status"),
    path("mfa/totp/setup/", totp_views.TOTPSetupView.as_view(), name="totp_setup"),
    path("mfa/totp/verify/", totp_views.TOTPVerifyView.as_view(), name="totp_verify"),
    path("mfa/totp/disable/", totp_views.TOTPDisableView.as_view(), name="totp_disable"),
    path("mfa/totp/login/", totp_views.TOTPLoginView.as_view(), name="totp_login"),

    # Passkeys / WebAuthn (FIDO2 Biometrics) - Control Plane
    path("passkey/register/options/", passkey_views.PasskeyRegisterOptionsView.as_view(), name="passkey_register_options"),
    path("passkey/register/verify/", passkey_views.PasskeyRegisterVerifyView.as_view(), name="passkey_register_verify"),
    path("passkey/authenticate/options/", passkey_views.PasskeyAuthOptionsView.as_view(), name="passkey_auth_options"),
    path("passkey/authenticate/verify/", passkey_views.PasskeyAuthVerifyView.as_view(), name="passkey_auth_verify"),
    path("passkey/credentials/", passkey_views.PasskeyCredentialListView.as_view(), name="passkey_credentials_list"),
    path("passkey/credentials/<uuid:pk>/", passkey_views.PasskeyCredentialDeleteView.as_view(), name="passkey_credentials_delete"),

    # Passkeys / WebAuthn (FIDO2 Biometrics) - Runtime Plane
    path("runtime/passkey/register/options/", passkey_views.RuntimePasskeyRegisterOptionsView.as_view(), name="runtime_passkey_register_options"),
    path("runtime/passkey/register/verify/", passkey_views.RuntimePasskeyRegisterVerifyView.as_view(), name="runtime_passkey_register_verify"),
    path("runtime/passkey/authenticate/options/", passkey_views.RuntimePasskeyAuthOptionsView.as_view(), name="runtime_passkey_auth_options"),
    path("runtime/passkey/authenticate/verify/", passkey_views.RuntimePasskeyAuthVerifyView.as_view(), name="runtime_passkey_auth_verify"),

    # Passwordless Magic Links - Control Plane
    path("magic-link/request/", magic_link_views.MagicLinkRequestView.as_view(), name="magic_link_request"),
    path("magic-link/verify/", magic_link_views.MagicLinkVerifyView.as_view(), name="magic_link_verify"),

    # Passwordless Magic Links - Runtime Plane
    path("runtime/magic-link/request/", magic_link_views.RuntimeMagicLinkRequestView.as_view(), name="runtime_magic_link_request"),
    path("runtime/magic-link/verify/", magic_link_views.RuntimeMagicLinkVerifyView.as_view(), name="runtime_magic_link_verify"),

    # dj-rest-auth endpoints (explicit to avoid schema collisions)
    path("runtime/register/", views.HVTRuntimeRegisterView.as_view(), name="runtime_register"),
    path(
        "runtime/register/verify-email/",
        views.HVTVerifyEmailView.as_view(),
        name="runtime_verify_email",
    ),
    path(
        "runtime/register/resend-email/",
        views.HVTRuntimeResendEmailVerificationView.as_view(),
        name="runtime_resend_email",
    ),
    path("runtime/login/", views.RuntimeLoginView.as_view(), name="runtime_login"),
    path(
        "runtime/password/reset/",
        views.HVTRuntimePasswordResetView.as_view(),
        name="runtime_password_reset",
    ),
    path(
        "runtime/password/reset/validate/",
        views.PasswordResetTokenValidationView.as_view(),
        name="runtime_password_reset_validate",
    ),
    path(
        "runtime/password/reset/confirm/<str:uidb64>/<str:token>/",
        views.HVTPasswordResetConfirmView.as_view(),
        name="runtime_password_reset_confirm",
    ),
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
    path(
        "runtime/social/discord/",
        views.RuntimeDiscordLogin.as_view(),
        name="runtime_discord_login",
    ),
    path(
        "runtime/social/apple/",
        views.RuntimeAppleLogin.as_view(),
        name="runtime_apple_login",
    ),
    path(
        "runtime/social/microsoft/",
        views.RuntimeMicrosoftLogin.as_view(),
        name="runtime_microsoft_login",
    ),
    path(
        "runtime/social/gitlab/",
        views.RuntimeGitlabLogin.as_view(),
        name="runtime_gitlab_login",
    ),
    path("runtime/me/", views.RuntimeCurrentUserView.as_view(), name="runtime_current_user"),
    path("login/", views.HVTLoginView.as_view(), name="rest_login"),
    path("logout/", LogoutView.as_view(), name="rest_logout"),
    path("user/", views.HVTUserDetailsView.as_view(), name="rest_user_details"),
    path("password/reset/", views.HVTPasswordResetView.as_view(), name="rest_password_reset"),
    path(
        "password/reset/validate/",
        views.PasswordResetTokenValidationView.as_view(),
        name="rest_password_reset_validate",
    ),
    path("password/change/", views.HVTPasswordChangeView.as_view(), name="rest_password_change"),
    # Password reset confirm — single endpoint with tokens in URL (no duplicate)
    path(
        "password/reset/confirm/<str:uidb64>/<str:token>/",
        views.HVTPasswordResetConfirmView.as_view(),
        name="rest_password_reset_confirm",
    ),
    # Registration with email verification
    path("register/", views.HVTRegisterView.as_view(), name="rest_register"),
    path(
        "register/verify-email/",
        views.HVTVerifyEmailView.as_view(),
        name="rest_verify_email",
    ),
    path(
        "register/resend-email/",
        views.HVTResendEmailVerificationView.as_view(),
        name="rest_resend_email",
    ),
    path("register/", include("dj_rest_auth.registration.urls")),
    # JWT token refresh
    path("token/refresh/", views.HVTTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "social/providers/",
        views.ControlPlaneSocialProviderListView.as_view(),
        name="social_provider_list",
    ),
    # Social login endpoint - Control Plane
    path("social/google/", views.GoogleLogin.as_view(), name="google_login"),
    path("social/github/", views.GithubLogin.as_view(), name="github_login"),
    path("social/discord/", views.DiscordLogin.as_view(), name="discord_login"),
    path("social/apple/", views.AppleLogin.as_view(), name="apple_login"),
    path("social/microsoft/", views.MicrosoftLogin.as_view(), name="microsoft_login"),
    path("social/gitlab/", views.GitlabLogin.as_view(), name="gitlab_login"),
    # Custom endpoints
    path("me/", views.CurrentUserView.as_view(), name="current_user"),
    # Webhooks
    path("webhooks/resend/", views.resend_webhook, name="resend_webhook"),
]
