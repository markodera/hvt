import hashlib
import secrets
import pyotp
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiResponse

from hvt.apps.authentication.models import AuditLog, TOTPDevice, TOTPBackupCode
from hvt.apps.authentication.views import CONTROL_PLANE_LOGIN_THROTTLES


def generate_backup_codes(count=10) -> list:
    codes = set()
    while len(codes) < count:
        codes.add(secrets.token_hex(4))
    return sorted(list(codes))


def hash_backup_code(raw_code: str) -> str:
    cleaned = raw_code.strip().replace("-", "").replace(" ", "").lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


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

        # Generate 10 single-use backup codes shown once
        device.backup_codes.all().delete()
        raw_backup_codes = generate_backup_codes(10)
        TOTPBackupCode.objects.bulk_create([
            TOTPBackupCode(device=device, hashed_code=hash_backup_code(c))
            for c in raw_backup_codes
        ])

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
                "backup_codes": raw_backup_codes,
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
        code_verified = False
        used_backup_code = False

        if totp.verify(code, valid_window=1):
            code_verified = True
        else:
            hashed = hash_backup_code(code)
            backup_code_obj = device.backup_codes.filter(hashed_code=hashed, used_at__isnull=True).first()
            if backup_code_obj:
                backup_code_obj.used_at = timezone.now()
                backup_code_obj.save(update_fields=["used_at"])
                code_verified = True
                used_backup_code = True

        if not code_verified:
            AuditLog.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                request=request,
                user=user,
                success=False,
                error_message="Invalid 2FA authenticator code or backup code",
            )
            return Response(
                {"error": "Invalid or expired authenticator code or backup code. Check your authenticator app or backup codes.", "code": "invalid_code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()
        device.last_verified_at = now
        device.save(update_fields=["last_verified_at"])

        if used_backup_code:
            AuditLog.log(
                event_type=AuditLog.EventType.TOTP_BACKUP_CODE_USED,
                request=request,
                user=user,
                event_data={"email": user.email, "method": "backup_code"},
            )

        project_id = payload.get("project_id")
        project = None
        if project_id:
            from hvt.apps.organizations.models import Project
            project = Project.objects.filter(id=project_id).first()

        access_token, refresh_token = build_hvt_token_pair(user, project=project, request=request)

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


class TOTPRegenerateBackupCodesView(APIView):
    """
    Regenerate single-use backup codes for an active TOTP device.
    Requires fresh re-authentication via password.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Regenerate MFA TOTP backup codes",
        responses={
            200: OpenApiResponse(description="New backup codes returned"),
            400: OpenApiResponse(description="Re-authentication failed or MFA not active"),
        },
    )
    def post(self, request):
        password = str(request.data.get("password", ""))
        if not password or not request.user.check_password(password):
            return Response(
                {
                    "error": "Password re-authentication required to regenerate backup codes.",
                    "code": "invalid_password",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        device = TOTPDevice.objects.filter(user=request.user, is_confirmed=True).first()
        if not device:
            return Response(
                {
                    "error": "Two-factor authentication is not active on this account.",
                    "code": "mfa_not_active",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        device.backup_codes.all().delete()
        raw_codes = generate_backup_codes(10)
        objs = [
            TOTPBackupCode(device=device, hashed_code=hash_backup_code(c))
            for c in raw_codes
        ]
        TOTPBackupCode.objects.bulk_create(objs)

        AuditLog.log(
            event_type=AuditLog.EventType.TOTP_BACKUP_CODES_REGENERATED,
            request=request,
            user=request.user,
            event_data={"email": request.user.email},
        )

        return Response(
            {
                "detail": "Backup codes regenerated successfully. Store these in a safe place.",
                "backup_codes": raw_codes,
            },
            status=status.HTTP_200_OK,
        )
