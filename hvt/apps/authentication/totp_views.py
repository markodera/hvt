import pyotp
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiResponse

from hvt.apps.authentication.models import AuditLog, TOTPDevice
from hvt.apps.authentication.views import CONTROL_PLANE_LOGIN_THROTTLES


class TOTPStatusView(APIView):
    """Get MFA status for the current user."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Get MFA TOTP status",
        responses={200: OpenApiResponse(description="MFA status returned")},
    )
    def get(self, request):
        device = TOTPDevice.objects.filter(user=request.user, is_confirmed=True).first()
        return Response(
            {
                "is_mfa_enabled": bool(device),
                "last_verified_at": device.last_verified_at if device else None,
            },
            status=status.HTTP_200_OK,
        )


class TOTPSetupView(APIView):
    """Initiate TOTP MFA setup by generating a secret and otpauth URI."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Initiate MFA TOTP setup",
        responses={200: OpenApiResponse(description="Secret and QR URI returned")},
    )
    def post(self, request):
        secret = pyotp.random_base32()
        device, _ = TOTPDevice.objects.update_or_create(
            user=request.user,
            defaults={"secret": secret, "is_confirmed": False},
        )

        issuer = "HVT"
        if request.user.organization:
            issuer = f"HVT ({request.user.organization.name})"

        totp = pyotp.TOTP(secret)
        otpauth_url = totp.provisioning_uri(name=request.user.email, issuer_name=issuer)

        AuditLog.log(
            event_type=AuditLog.EventType.MFA_SETUP,
            request=request,
            user=request.user,
            event_data={"email": request.user.email},
        )

        return Response(
            {
                "secret": secret,
                "otpauth_url": otpauth_url,
                "detail": "Scan the QR code or enter the secret key into your authenticator app.",
            },
            status=status.HTTP_200_OK,
        )


class TOTPVerifyView(APIView):
    """Verify and confirm TOTP code to activate MFA."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Verify and enable MFA TOTP",
        responses={
            200: OpenApiResponse(description="MFA activated successfully"),
            400: OpenApiResponse(description="Invalid verification code"),
        },
    )
    def post(self, request):
        code = str(request.data.get("code", "")).strip().replace(" ", "")
        if not code:
            return Response(
                {"error": "Verification code is required.", "code": "code_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        device = TOTPDevice.objects.filter(user=request.user).first()
        if not device or not device.secret:
            return Response(
                {
                    "error": "MFA setup has not been initiated. Call setup first.",
                    "code": "mfa_not_initiated",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        totp = pyotp.TOTP(device.secret)
        if not totp.verify(code, valid_window=1):
            return Response(
                {
                    "error": "Invalid or expired verification code. Check your authenticator app and system clock.",
                    "code": "invalid_totp_code",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()
        device.is_confirmed = True
        device.last_verified_at = now
        device.save(update_fields=["is_confirmed", "last_verified_at"])

        AuditLog.log(
            event_type=AuditLog.EventType.MFA_ENABLED,
            request=request,
            user=request.user,
            event_data={"email": request.user.email},
        )

        return Response(
            {
                "detail": "Two-factor authentication successfully enabled.",
                "is_mfa_enabled": True,
                "last_verified_at": now,
            },
            status=status.HTTP_200_OK,
        )


class TOTPDisableView(APIView):
    """Disable MFA TOTP device after verifying password or current code."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Disable MFA TOTP",
        responses={
            200: OpenApiResponse(description="MFA disabled successfully"),
            400: OpenApiResponse(description="Password or code verification failed"),
        },
    )
    def post(self, request):
        password = str(request.data.get("password", ""))
        code = str(request.data.get("code", "")).strip().replace(" ", "")

        device = TOTPDevice.objects.filter(user=request.user, is_confirmed=True).first()
        if not device:
            return Response(
                {"detail": "Two-factor authentication is not active on this account.", "is_mfa_enabled": False},
                status=status.HTTP_200_OK,
            )

        is_valid = False

        if password and request.user.check_password(password):
            is_valid = True
        elif code:
            totp = pyotp.TOTP(device.secret)
            if totp.verify(code, valid_window=1):
                is_valid = True

        if not is_valid:
            return Response(
                {
                    "error": "Provide your current account password or valid authenticator code to disable MFA.",
                    "code": "invalid_credentials",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        device.delete()

        AuditLog.log(
            event_type=AuditLog.EventType.MFA_DISABLED,
            request=request,
            user=request.user,
            event_data={"email": request.user.email},
        )

        return Response(
            {
                "detail": "Two-factor authentication has been disabled.",
                "is_mfa_enabled": False,
            },
            status=status.HTTP_200_OK,
        )


class TOTPLoginView(APIView):
    """Verify ephemeral MFA token and 6-digit TOTP code to complete login."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = CONTROL_PLANE_LOGIN_THROTTLES

    @extend_schema(
        summary="Complete MFA TOTP login",
        responses={
            200: OpenApiResponse(description="Login successful with tokens"),
            400: OpenApiResponse(description="Invalid or expired code/token"),
        },
    )
    def post(self, request):
        from django.core import signing
        from hvt.apps.authentication.tokens import build_hvt_token_pair
        from hvt.apps.users.models import User

        mfa_token = str(request.data.get("mfa_token", "")).strip()
        code = str(request.data.get("code", "")).strip().replace(" ", "")

        if not mfa_token or not code:
            return Response(
                {"error": "Both mfa_token and 6-digit code are required.", "code": "missing_fields"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = signing.loads(mfa_token, salt="hvt_mfa_login_salt", max_age=300)
        except (signing.BadSignature, signing.SignatureExpired):
            return Response(
                {"error": "The two-factor authentication session has expired. Please sign in again.", "code": "mfa_session_expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_id = payload.get("user_id")
        user = User.objects.filter(id=user_id, is_active=True).first()
        if not user:
            return Response(
                {"error": "User account not found or disabled.", "code": "user_not_found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        device = TOTPDevice.objects.filter(user=user, is_confirmed=True).first()
        if not device or not device.secret:
            return Response(
                {"error": "Two-factor authentication is not active for this account.", "code": "mfa_not_active"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        totp = pyotp.TOTP(device.secret)
        if not totp.verify(code, valid_window=1):
            AuditLog.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                request=request,
                user=user,
                success=False,
                error_message="Invalid 2FA authenticator code",
            )
            return Response(
                {"error": "Invalid or expired authenticator code. Check your authenticator app and device time.", "code": "invalid_code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()
        device.last_verified_at = now
        device.save(update_fields=["last_verified_at"])

        project_id = payload.get("project_id")
        project = None
        if project_id:
            from hvt.apps.organizations.models import Project
            project = Project.objects.filter(id=project_id).first()

        access_token, refresh_token = build_hvt_token_pair(user, project=project)

        AuditLog.log(
            event_type=AuditLog.EventType.MFA_VERIFIED,
            request=request,
            user=user,
            event_data={"email": user.email, "method": "totp"},
        )
        AuditLog.log(
            event_type=AuditLog.EventType.USER_LOGIN,
            request=request,
            user=user,
            event_data={"method": "mfa_totp"},
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
                    "role": getattr(user, "role", "member"),
                },
            },
            status=status.HTTP_200_OK,
        )
