import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.db import transaction
from django.utils import timezone
import pyotp
from rest_framework import permissions, status, views
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse

from hvt.apps.authentication.email import render_email_template, send_email_async
from hvt.apps.authentication.identity import (
    get_control_plane_users_by_email,
    get_runtime_user_for_api_key,
)
from hvt.apps.authentication.models import AuditLog, MagicLinkToken, TOTPDevice
from hvt.apps.authentication.tokens import build_hvt_token_pair
from hvt.apps.authentication.views import (
    CONTROL_PLANE_LOGIN_THROTTLES,
    PASSWORD_RESET_REQUEST_THROTTLES,
    RUNTIME_LOGIN_THROTTLES,
    RUNTIME_PASSWORD_RESET_REQUEST_THROTTLES,
)
from hvt.apps.organizations.models import APIKey, ProjectRole, UserProjectRole
from hvt.apps.organizations.access import assign_default_signup_roles
from hvt.apps.users.models import User


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _create_magic_link_token(user: User, project=None) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    # Invalidate previous unused tokens
    MagicLinkToken.objects.filter(
        user=user,
        project=project,
        is_used=False,
    ).update(is_used=True)

    expires_at = timezone.now() + timedelta(minutes=15)
    MagicLinkToken.objects.create(
        user=user,
        project=project,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    return raw_token


def _send_magic_link(user: User, raw_token: str, request, project=None):
    if project and project.frontend_url:
        base_url = project.frontend_url.rstrip("/")
    else:
        base_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173").rstrip("/")

    verify_url = f"{base_url}/auth/magic-link/verify?token={raw_token}"
    context = {
        "request": request,
        "project": project,
        "user": user,
        "verify_url": verify_url,
    }
    subject, text_content, html_content = render_email_template("account/email/magic_link", context)

    send_email_async(
        to_email=user.email,
        subject=subject,
        html_content=html_content,
        text_content=text_content,
    )


# ----------------------------------------------------------------------
# Control Plane Magic Link Views
# ----------------------------------------------------------------------

class MagicLinkRequestView(views.APIView):
    """Request a passwordless sign-in magic link for control plane."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = PASSWORD_RESET_REQUEST_THROTTLES

    @extend_schema(summary="Request control-plane magic link", tags=["Magic Links"])
    def post(self, request):
        email = str(request.data.get("email", "")).strip().lower()
        if not email:
            return Response({"error": "Email is required.", "code": "email_required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_control_plane_users_by_email(email).first()
        if user and user.is_active:
            raw_token = _create_magic_link_token(user)
            _send_magic_link(user, raw_token, request)

            AuditLog.log(
                event_type=AuditLog.EventType.MAGIC_LINK_REQUESTED,
                request=request,
                user=user,
                event_data={"email": email},
            )

        # Always return generic success message to prevent user enumeration
        return Response(
            {"detail": "If an account exists with this email, a sign-in link has been sent."},
            status=status.HTTP_200_OK,
        )


class MagicLinkVerifyView(views.APIView):
    """Verify magic link token and log in to control plane."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = CONTROL_PLANE_LOGIN_THROTTLES

    @extend_schema(summary="Verify control-plane magic link", tags=["Magic Links"])
    def post(self, request):
        token = str(request.data.get("token", "")).strip()
        if not token:
            return Response({"error": "Token is required.", "code": "token_required"}, status=status.HTTP_400_BAD_REQUEST)

        token_hash = _hash_token(token)
        with transaction.atomic():
            record = (
                MagicLinkToken.objects.select_for_update()
                .filter(
                    token_hash=token_hash,
                    project__isnull=True,
                )
                .select_related("user")
                .first()
            )

            if not record or not record.is_valid():
                return Response(
                    {"error": "Sign-in link is invalid, expired, or has already been used.", "code": "invalid_token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            record.is_used = True
            record.save(update_fields=["is_used"])

        user = record.user
        device = TOTPDevice.objects.filter(user=user, is_confirmed=True).first()
        if device and device.secret:
            code = str(request.data.get("code") or request.data.get("mfa_code") or "").strip().replace(" ", "")
            if not code:
                mfa_token = signing.dumps(
                    {"user_id": str(user.id), "purpose": "mfa_login"},
                    salt="hvt_mfa_login_salt",
                )
                return Response(
                    {
                        "mfa_required": True,
                        "mfa_token": mfa_token,
                        "detail": "Two-factor authentication code required.",
                    },
                    status=status.HTTP_200_OK,
                )

            totp = pyotp.TOTP(device.secret)
            if not totp.verify(code, valid_window=1):
                AuditLog.log(
                    event_type=AuditLog.EventType.LOGIN_FAILED,
                    request=request,
                    user=user,
                    success=False,
                    error_message="Invalid 2FA code during magic link verification",
                )
                return Response(
                    {"error": "Invalid or expired two-factor authentication code.", "code": "invalid_code"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            device.last_verified_at = timezone.now()
            device.save(update_fields=["last_verified_at"])
            AuditLog.log(
                event_type=AuditLog.EventType.MFA_VERIFIED,
                request=request,
                user=user,
                event_data={"email": user.email, "method": "totp"},
            )

        access_token, refresh_token = build_hvt_token_pair(user, request=request)

        AuditLog.log(
            event_type=AuditLog.EventType.MAGIC_LINK_VERIFIED,
            request=request,
            user=user,
            event_data={"email": user.email},
        )

        return Response(
            {
                "access": str(access_token),
                "refresh": str(refresh_token),
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "role": user.role,
                },
            },
            status=status.HTTP_200_OK,
        )


# ----------------------------------------------------------------------
# Runtime Plane Magic Link Views
# ----------------------------------------------------------------------

class RuntimeMagicLinkRequestView(views.APIView):
    """Request a passwordless sign-in magic link for project runtime."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = RUNTIME_PASSWORD_RESET_REQUEST_THROTTLES

    @extend_schema(summary="Request runtime magic link", tags=["Runtime Magic Links"])
    def post(self, request):
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey) or not api_key.has_scope("auth:runtime"):
            return Response({"error": "Valid X-API-Key with auth:runtime required."}, status=status.HTTP_401_UNAUTHORIZED)

        project = api_key.project
        email = str(request.data.get("email", "")).strip().lower()
        if not email:
            return Response({"error": "Email is required.", "code": "email_required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_runtime_user_for_api_key(email, api_key)
        if not user:
            if not project.allow_signup:
                return Response({"error": "Public signup is disabled for this project.", "code": "signup_disabled"}, status=status.HTTP_403_FORBIDDEN)

            # Auto-provision runtime user
            user = User.objects.create(
                email=email,
                organization=project.organization,
                project=project,
                role=User.Role.MEMBER,
            )
            role_slug = request.data.get("role_slug")
            assigned = False
            if role_slug:
                role_obj = ProjectRole.objects.filter(project=project, slug=role_slug, is_self_assignable=True).first()
                if role_obj:
                    UserProjectRole.objects.create(user=user, role=role_obj)
                    assigned = True
            if not assigned:
                assign_default_signup_roles(user, project)

        raw_token = _create_magic_link_token(user, project=project)
        _send_magic_link(user, raw_token, request, project=project)

        AuditLog.log(
            event_type=AuditLog.EventType.MAGIC_LINK_REQUESTED,
            request=request,
            user=user,
            project=project,
            event_data={"email": user.email, "project_id": str(project.id)},
            success=True,
        )

        return Response(
            {"detail": "If an account exists with this email, a sign-in link has been sent."},
            status=status.HTTP_200_OK,
        )


class RuntimeMagicLinkVerifyView(views.APIView):
    """Verify runtime magic link token and log in."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = RUNTIME_LOGIN_THROTTLES

    @extend_schema(summary="Verify runtime magic link", tags=["Runtime Magic Links"])
    def post(self, request):
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            return Response({"error": "Valid X-API-Key required."}, status=status.HTTP_401_UNAUTHORIZED)
        if not api_key.has_scope("auth:runtime"):
            return Response(
                {"detail": "This API key does not have the required auth:runtime scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        project = api_key.project
        token = str(request.data.get("token", "")).strip()
        if not token:
            return Response({"error": "Token is required.", "code": "token_required"}, status=status.HTTP_400_BAD_REQUEST)

        token_hash = _hash_token(token)
        with transaction.atomic():
            record = (
                MagicLinkToken.objects.select_for_update()
                .filter(
                    token_hash=token_hash,
                    project=project,
                )
                .select_related("user")
                .first()
            )

            if not record or not record.is_valid():
                AuditLog.log(
                    event_type=AuditLog.EventType.MAGIC_LINK_FAILED,
                    request=request,
                    user=record.user if record else None,
                    project=project,
                    success=False,
                    error_message="Invalid or expired magic link token",
                )
                return Response(
                    {"error": "Sign-in link is invalid, expired, or has already been used.", "code": "invalid_token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            record.is_used = True
            record.save(update_fields=["is_used"])

        user = record.user
        device = TOTPDevice.objects.filter(user=user, is_confirmed=True).first()
        if device and device.secret:
            code = str(request.data.get("code") or request.data.get("mfa_code") or "").strip().replace(" ", "")
            if not code:
                mfa_token = signing.dumps(
                    {"user_id": str(user.id), "project_id": str(project.id), "purpose": "mfa_login"},
                    salt="hvt_mfa_login_salt",
                )
                return Response(
                    {
                        "mfa_required": True,
                        "mfa_token": mfa_token,
                        "detail": "Two-factor authentication code required.",
                    },
                    status=status.HTTP_200_OK,
                )

            totp = pyotp.TOTP(device.secret)
            if not totp.verify(code, valid_window=1):
                AuditLog.log(
                    event_type=AuditLog.EventType.LOGIN_FAILED,
                    request=request,
                    user=user,
                    project=project,
                    success=False,
                    error_message="Invalid 2FA code during runtime magic link verification",
                )
                return Response(
                    {"error": "Invalid or expired two-factor authentication code.", "code": "invalid_code"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            device.last_verified_at = timezone.now()
            device.save(update_fields=["last_verified_at"])
            AuditLog.log(
                event_type=AuditLog.EventType.MFA_VERIFIED,
                request=request,
                user=user,
                project=project,
                event_data={"email": user.email, "method": "totp", "project_id": str(project.id)},
            )

        access_token, refresh_token = build_hvt_token_pair(user, project=project, request=request)

        AuditLog.log(
            event_type=AuditLog.EventType.MAGIC_LINK_VERIFIED,
            request=request,
            user=user,
            project=project,
            event_data={"email": user.email, "project_id": str(project.id)},
            success=True,
        )

        return Response(
            {
                "access": str(access_token),
                "refresh": str(refresh_token),
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "app_roles": list(
                        UserProjectRole.objects.filter(user=user, role__project=project).values_list("role__slug", flat=True)
                    ),
                },
            },
            status=status.HTTP_200_OK,
        )
