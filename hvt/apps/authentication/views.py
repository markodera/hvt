from urllib.parse import urljoin

from rest_framework import generics, permissions, serializers, status, views
from rest_framework.exceptions import NotAuthenticated, PermissionDenied
from rest_framework.response import Response
from django.conf import settings
from django.utils.encoding import force_str
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from drf_spectacular.utils import extend_schema, extend_schema_view, inline_serializer
from drf_spectacular.types import OpenApiTypes
from dj_rest_auth.app_settings import api_settings as dj_rest_auth_settings
from dj_rest_auth.jwt_auth import set_jwt_cookies
from dj_rest_auth.views import (
    LoginView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetView,
)
from dj_rest_auth.registration.views import (
    RegisterView,
    ResendEmailVerificationView,
    SocialLoginView,
    VerifyEmailView,
)
from allauth.account import app_settings as allauth_account_settings
from allauth.account.models import EmailAddress
from allauth.account.utils import complete_signup
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from rest_framework_simplejwt.views import TokenRefreshView
import hmac
import hashlib
import os
import json

from hvt.apps.users.models import User
from hvt.apps.organizations.models import APIKey, SocialProviderConfig
from hvt.api.v1.serializers.users import (
    UserSerializer,
    RuntimeLoginSerializer,
    CustomSocialLoginSerializer,
    RuntimeSocialLoginSerializer,
    ControlPlaneRegisterSerializer,
    RuntimeRegisterSerializer,
)
from hvt.apps.authentication.adapters import CustomSocialAccountAdapter
from hvt.apps.authentication.serializers import (
    RuntimePasswordResetSerializer,
    RuntimeResendEmailVerificationSerializer,
)
from hvt.apps.authentication.throttling import (
    BurstRateThrottle,
    EmailVerificationIPRateThrottle,
    LoginEmailRateThrottle,
    LoginIPRateThrottle,
    OrganizationRateThrottle,
    PasswordChangeUserRateThrottle,
    PasswordResetConfirmIPRateThrottle,
    PasswordResetEmailRateThrottle,
    PasswordResetIPRateThrottle,
    PasswordResetValidateIPRateThrottle,
    RefreshTokenRateThrottle,
    RegisterEmailRateThrottle,
    RegisterIPRateThrottle,
    ResendVerificationEmailRateThrottle,
    ResendVerificationIPRateThrottle,
    RuntimeLoginAPIKeyThrottle,
    RuntimePasswordResetAPIKeyThrottle,
    RuntimeRegisterAPIKeyThrottle,
    RuntimeResendVerificationAPIKeyThrottle,
    RuntimeSocialLoginAPIKeyThrottle,
    SocialLoginIPRateThrottle,
)
from hvt.apps.authentication.tokens import (
    build_hvt_token_pair,
    HVTCookieTokenRefreshSerializer,
)


class PasswordResetTokenValidationSerializer(serializers.Serializer):
    """Validate password reset uid/token pairs without consuming the token."""

    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        if "allauth" in settings.INSTALLED_APPS:
            from allauth.account.forms import default_token_generator
            from allauth.account.utils import url_str_to_user_pk as uid_decoder
        else:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.http import urlsafe_base64_decode as uid_decoder

        try:
            uid = force_str(uid_decoder(attrs["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": ["Invalid value"]})

        if not default_token_generator.check_token(user, attrs["token"]):
            raise serializers.ValidationError({"token": ["Invalid value"]})

        return attrs


class HVTCompatibilityOAuth2Client(OAuth2Client):
    """Bridge dj-rest-auth's expected OAuth2Client signature to allauth's current one."""

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
        self.scope = scope or []


def _frontend_callback_url(path: str) -> str:
    return urljoin(f"{settings.FRONTEND_URL.rstrip('/')}/", path.lstrip("/"))


def _provider_scope(provider: str):
    if provider == "google":
        return ["openid", "email", "profile"]
    if provider == "github":
        return ["user:email"]
    return []


def _provider_authorization_url(provider: str) -> str:
    if provider == "google":
        return "https://accounts.google.com/o/oauth2/v2/auth"
    if provider == "github":
        return "https://github.com/login/oauth/authorize"
    return ""


CONTROL_PLANE_LOGIN_THROTTLES = [
    BurstRateThrottle,
    LoginIPRateThrottle,
    LoginEmailRateThrottle,
]
CONTROL_PLANE_REGISTER_THROTTLES = [
    BurstRateThrottle,
    RegisterIPRateThrottle,
    RegisterEmailRateThrottle,
]
PASSWORD_RESET_REQUEST_THROTTLES = [
    BurstRateThrottle,
    PasswordResetIPRateThrottle,
    PasswordResetEmailRateThrottle,
]
PASSWORD_RESET_CONFIRM_THROTTLES = [
    BurstRateThrottle,
    PasswordResetConfirmIPRateThrottle,
]
PASSWORD_RESET_VALIDATE_THROTTLES = [
    BurstRateThrottle,
    PasswordResetValidateIPRateThrottle,
]
PASSWORD_CHANGE_THROTTLES = [
    BurstRateThrottle,
    PasswordChangeUserRateThrottle,
]
VERIFY_EMAIL_THROTTLES = [
    BurstRateThrottle,
    EmailVerificationIPRateThrottle,
]
RESEND_EMAIL_THROTTLES = [
    BurstRateThrottle,
    ResendVerificationIPRateThrottle,
    ResendVerificationEmailRateThrottle,
]
SOCIAL_LOGIN_THROTTLES = [
    BurstRateThrottle,
    SocialLoginIPRateThrottle,
]
RUNTIME_LOGIN_THROTTLES = [
    BurstRateThrottle,
    OrganizationRateThrottle,
    RuntimeLoginAPIKeyThrottle,
    LoginIPRateThrottle,
    LoginEmailRateThrottle,
]
RUNTIME_REGISTER_THROTTLES = [
    BurstRateThrottle,
    OrganizationRateThrottle,
    RuntimeRegisterAPIKeyThrottle,
    RegisterIPRateThrottle,
    RegisterEmailRateThrottle,
]
RUNTIME_PASSWORD_RESET_REQUEST_THROTTLES = [
    BurstRateThrottle,
    OrganizationRateThrottle,
    RuntimePasswordResetAPIKeyThrottle,
    PasswordResetIPRateThrottle,
    PasswordResetEmailRateThrottle,
]
RUNTIME_RESEND_EMAIL_THROTTLES = [
    BurstRateThrottle,
    OrganizationRateThrottle,
    RuntimeResendVerificationAPIKeyThrottle,
    ResendVerificationIPRateThrottle,
    ResendVerificationEmailRateThrottle,
]
RUNTIME_SOCIAL_LOGIN_THROTTLES = [
    BurstRateThrottle,
    OrganizationRateThrottle,
    RuntimeSocialLoginAPIKeyThrottle,
    SocialLoginIPRateThrottle,
]
TOKEN_REFRESH_THROTTLES = [
    BurstRateThrottle,
    RefreshTokenRateThrottle,
]


@extend_schema_view(
    get=extend_schema(
        tags=["Auth"],
        summary="Get current user profile",
        description="Returns the authenticated user's profile information.",
    ),
    put=extend_schema(
        tags=["Auth"],
        summary="Update current user profile (full)",
        description="Replace all editable fields on the current user's profile.",
    ),
    patch=extend_schema(
        tags=["Auth"],
        summary="Update current user profile (partial)",
        description="Partially update the current user's profile.",
    ),
)
class CurrentUserView(generics.RetrieveUpdateAPIView):
    """
    GET /api/v1/auth/me - Get current authenticated user
    PUT/PATCH /api/v1/auth/me - Update current user profile
    """

    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class HVTLoginView(LoginView):
    throttle_classes = CONTROL_PLANE_LOGIN_THROTTLES


@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        summary="Runtime login",
        description=(
            "Authenticate an end user within the organization identified by the "
            "provided X-API-Key."
        ),
    ),
)
class RuntimeLoginView(LoginView):
    """API-key-scoped login flow for customer-facing app users."""

    serializer_class = RuntimeLoginSerializer
    throttle_classes = RUNTIME_LOGIN_THROTTLES

    def login(self):
        self.user = self.serializer.validated_data["user"]
        project = getattr(self.request.auth, "project", None)
        self.access_token, self.refresh_token = build_hvt_token_pair(
            self.user,
            project=project,
        )
        if dj_rest_auth_settings.SESSION_LOGIN:
            self.process_login()


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = _frontend_callback_url("/auth/google/callback")
    client_class = HVTCompatibilityOAuth2Client
    serializer_class = CustomSocialLoginSerializer
    throttle_classes = SOCIAL_LOGIN_THROTTLES


class GithubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    callback_url = _frontend_callback_url("/auth/github/callback")
    client_class = HVTCompatibilityOAuth2Client
    serializer_class = CustomSocialLoginSerializer
    throttle_classes = SOCIAL_LOGIN_THROTTLES


class RuntimeSocialLoginView(SocialLoginView):
    """API-key-scoped social login flow for customer-facing app users."""

    permission_classes = [permissions.AllowAny]
    serializer_class = RuntimeSocialLoginSerializer
    client_class = HVTCompatibilityOAuth2Client
    throttle_classes = RUNTIME_SOCIAL_LOGIN_THROTTLES

    def login(self):
        self.user = self.serializer.validated_data["user"]
        project = getattr(self.request.auth, "project", None)
        self.access_token, self.refresh_token = build_hvt_token_pair(
            self.user,
            project=project,
        )
        if dj_rest_auth_settings.SESSION_LOGIN:
            self.process_login()


class RuntimeGoogleLogin(RuntimeSocialLoginView):
    adapter_class = GoogleOAuth2Adapter


class RuntimeGithubLogin(RuntimeSocialLoginView):
    adapter_class = GitHubOAuth2Adapter

class ControlPlaneSocialProviderListView(views.APIView):
    """Expose configured control-plane social providers for the HVT dashboard."""

    permission_classes = [permissions.AllowAny]
    serializer_class = None

    @extend_schema(
        tags=["Auth"],
        summary="List control-plane social providers",
        description="List active generic social auth providers configuration.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request, *args, **kwargs):
        providers = []
        adapter = CustomSocialAccountAdapter()
        for provider in ("google", "github"):
            config = settings.SOCIALACCOUNT_PROVIDERS.get(provider, {})
            app_config = config.get("APP") or {}
            client_id = app_config.get("client_id") or ""
            if not client_id:
                try:
                    app = adapter.get_app(request, provider=provider)
                except (SocialApp.DoesNotExist, SocialApp.MultipleObjectsReturned):
                    app = None
                client_id = getattr(app, "client_id", "") or ""
            if not client_id:
                continue
            providers.append(
                {
                    "provider": provider,
                    "client_id": client_id,
                    "authorization_url": _provider_authorization_url(provider),
                    "scope": _provider_scope(provider),
                    "callback_url": _frontend_callback_url(f"/auth/{provider}/callback"),
                }
            )
        return Response({"providers": providers}, status=status.HTTP_200_OK)


class RuntimeSocialProviderListView(views.APIView):
    """Expose active project-scoped runtime social providers for an API key."""

    permission_classes = [permissions.AllowAny]
    serializer_class = None

    @extend_schema(
        tags=["Auth"],
        summary="List runtime social providers",
        description="List active project-scoped runtime social providers configuration that match the API Key.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request, *args, **kwargs):
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            return Response(
                {"detail": "A valid X-API-Key header is required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not api_key.has_scope("auth:runtime"):
            return Response(
                {"detail": "This API key does not have the required auth:runtime scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = SocialProviderConfig.objects.filter(
            project=api_key.project,
            is_active=True,
        ).order_by("provider")
        providers = [
            {
                "provider": config.provider,
                "client_id": config.client_id,
                "authorization_url": _provider_authorization_url(config.provider),
                "scope": _provider_scope(config.provider),
                "redirect_uris": config.redirect_uris,
                "project_id": str(config.project_id),
                "project_slug": config.project.slug,
            }
            for config in queryset
        ]
        return Response(
            {
                "project_id": str(api_key.project_id) if api_key.project_id else None,
                "project_slug": api_key.project.slug if api_key.project_id else "",
                "providers": providers,
            },
            status=status.HTTP_200_OK,
        )


class HVTTokenRefreshView(TokenRefreshView):
    """JWT refresh view that preserves HVT org/project claim validation."""

    serializer_class = HVTCookieTokenRefreshSerializer
    throttle_classes = TOKEN_REFRESH_THROTTLES

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK and response.data.get("access"):
            set_jwt_cookies(
                response,
                response.data["access"],
                response.data.get("refresh"),
            )
        return response


class RuntimeAPIKeyScopedRequestMixin:
    """Shared API-key validation for runtime public endpoints."""

    def require_runtime_api_key(self, request) -> APIKey:
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise NotAuthenticated("A valid X-API-Key header is required.")
        if not api_key.has_scope("auth:runtime"):
            raise PermissionDenied(
                "This API key does not have the required auth:runtime scope."
            )
        return api_key


class HVTPasswordResetView(PasswordResetView):
    throttle_classes = PASSWORD_RESET_REQUEST_THROTTLES


@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        summary="Runtime password reset request",
        description=(
            "Request a password reset email for an end user within the organization "
            "and project resolved from the provided X-API-Key."
        ),
    ),
)
class HVTRuntimePasswordResetView(RuntimeAPIKeyScopedRequestMixin, PasswordResetView):
    serializer_class = RuntimePasswordResetSerializer
    throttle_classes = RUNTIME_PASSWORD_RESET_REQUEST_THROTTLES

    def post(self, request, *args, **kwargs):
        self.require_runtime_api_key(request)
        return super().post(request, *args, **kwargs)


class HVTPasswordResetConfirmView(PasswordResetConfirmView):
    """Accept reset uid/token from the URL as well as the POST body."""

    throttle_classes = PASSWORD_RESET_CONFIRM_THROTTLES

    def post(self, request, *args, **kwargs):
        payload = request.data.copy()
        payload.setdefault("uid", kwargs.get("uidb64", ""))
        payload.setdefault("token", kwargs.get("token", ""))

        serializer = self.get_serializer(data=payload)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "Password has been reset with the new password."},
            status=status.HTTP_200_OK,
        )


@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        summary="Validate password reset token",
        description="Checks whether a password reset uid/token pair is still valid.",
        request=PasswordResetTokenValidationSerializer,
    ),
)
class PasswordResetTokenValidationView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetTokenValidationSerializer
    throttle_classes = PASSWORD_RESET_VALIDATE_THROTTLES

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"detail": "Password reset token is valid."},
            status=status.HTTP_200_OK,
        )


class HVTRegisterView(RegisterView):
    """Register view with provider-aware error handling for email delivery failures."""

    serializer_class = ControlPlaneRegisterSerializer
    throttle_classes = CONTROL_PLANE_REGISTER_THROTTLES

    def perform_create(self, serializer):
        try:
            user = serializer.save(self.request)
            if (
                allauth_account_settings.EMAIL_VERIFICATION
                != allauth_account_settings.EmailVerificationMethod.MANDATORY
            ):
                return user

            complete_signup(
                self.request._request,
                user,
                allauth_account_settings.EMAIL_VERIFICATION,
                None,
            )
            return user
        except Exception as exc:
            if exc.__class__.__module__.startswith("resend.exceptions"):
                raise serializers.ValidationError(
                    (
                        "Verification email could not be sent. "
                        "Resend currently allows only your verified test recipient or a verified sender domain/API key pair."
                    )
                ) from exc
            raise


class HVTVerifyEmailView(VerifyEmailView):
    throttle_classes = VERIFY_EMAIL_THROTTLES


class HVTResendEmailVerificationView(ResendEmailVerificationView):
    throttle_classes = RESEND_EMAIL_THROTTLES


@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        summary="Runtime resend verification email",
        description=(
            "Resend an email verification message for a runtime user within the "
            "organization and project resolved from the provided X-API-Key."
        ),
        request=RuntimeResendEmailVerificationSerializer,
    ),
)
class HVTRuntimeResendEmailVerificationView(
    RuntimeAPIKeyScopedRequestMixin,
    generics.GenericAPIView,
):
    permission_classes = [permissions.AllowAny]
    serializer_class = RuntimeResendEmailVerificationSerializer
    throttle_classes = RUNTIME_RESEND_EMAIL_THROTTLES

    def post(self, request, *args, **kwargs):
        from hvt.apps.authentication.serializers import _user_matches_runtime_api_key

        api_key = self.require_runtime_api_key(request)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email_value = serializer.validated_data["email"]
        email_address = next(
            (
                item
                for item in EmailAddress.objects.select_related("user").filter(
                    email__iexact=email_value,
                    verified=False,
                )
                if _user_matches_runtime_api_key(item.user, api_key)
            ),
            None,
        )
        if email_address:
            email_address.send_confirmation(request)

        return Response({"detail": "ok"}, status=status.HTTP_200_OK)


class HVTPasswordChangeView(PasswordChangeView):
    throttle_classes = PASSWORD_CHANGE_THROTTLES


@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        summary="Runtime register",
        description=(
            "Register an end user within the organization and project identified by "
            "the provided X-API-Key.\n\n"
            "Verification emails are currently sent from HVT's email infrastructure. "
            "Per-project sender branding — custom domain, sender name, and templates — "
            "is planned for Builder tier and above."
        ),
    ),
)
class HVTRuntimeRegisterView(HVTRegisterView):
    """API-key-scoped runtime register view for customer-facing app users."""

    serializer_class = RuntimeRegisterSerializer
    throttle_classes = RUNTIME_REGISTER_THROTTLES


@csrf_exempt
def resend_webhook(request):
    """
    Handle Resend webhook events for email delivery status tracking.

    Verifies the webhook signature and processes events like:
    - email.delivered
    - email.bounced
    - email.complained
    - email.opened
    - email.clicked
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    # Verify signature header
    raw = request.body
    sig = request.headers.get("Resend-Signature", "")
    secret = os.getenv("RESEND_WEBHOOK_SIGNING_KEY", "")

    if secret:
        expected = hmac.HMAC(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return JsonResponse({"error": "Invalid signature"}, status=403)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    event_type = payload.get("type", "")

    # Process events - extend this based on your needs
    # You can log to audit trail, update email status, trigger alerts, etc.
    if event_type == "email.bounced":
        # Handle bounce - maybe mark user email as invalid
        pass
    elif event_type == "email.delivered":
        # Handle delivery confirmation
        pass
    elif event_type == "email.complained":
        # Handle spam complaint
        pass

    return JsonResponse({"ok": True})
