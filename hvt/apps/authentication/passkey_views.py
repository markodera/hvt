import base64
import json
import uuid
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework import permissions, status, views
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse

import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
    AttestationConveyancePreference,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from hvt.apps.authentication.identity import (
    get_control_plane_users_by_email,
    get_runtime_user_for_api_key,
)
from hvt.apps.authentication.models import AuditLog, UserPasskeyCredential
from hvt.apps.authentication.tokens import build_hvt_token_pair
from hvt.apps.authentication.views import (
    CONTROL_PLANE_LOGIN_THROTTLES,
    RUNTIME_LOGIN_THROTTLES,
)
from hvt.apps.organizations.models import APIKey, UserProjectRole


def _resolve_rp_id(request, project=None) -> str:
    """Resolve RP ID (hostname) for WebAuthn."""
    custom_rp_id = getattr(settings, "WEBAUTHN_RP_ID", None)
    if custom_rp_id:
        return custom_rp_id

    if project and project.frontend_url:
        parsed_project = urlparse(project.frontend_url)
        if parsed_project.hostname:
            return parsed_project.hostname

    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if origin:
        parsed = urlparse(origin)
        hostname = (parsed.hostname or "").lower()
        if hostname in ("testserver", "localhost", "127.0.0.1"):
            return "localhost"
        if hostname:
            return hostname

    try:
        host = request.get_host().split(":")[0].lower()
    except Exception:
        host = "localhost"
    if host in ("testserver", "localhost", "127.0.0.1"):
        return "localhost"
    return host or "localhost"


def _resolve_expected_origin(request, project=None) -> str | list[str]:
    """Resolve and validate expected browser Origin for WebAuthn validation."""
    allowed_origins = set()
    frontend_url = getattr(settings, "FRONTEND_URL", "").rstrip("/")
    if frontend_url:
        allowed_origins.add(frontend_url)

    cors_origins = getattr(settings, "CORS_ALLOWED_ORIGINS", [])
    for co in cors_origins:
        if co:
            allowed_origins.add(co.rstrip("/"))

    if project and project.frontend_url:
        allowed_origins.add(project.frontend_url.rstrip("/"))

    if settings.DEBUG:
        allowed_origins.update([
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ])

    origin = (request.headers.get("origin") or "").rstrip("/")
    if origin and origin in allowed_origins:
        return origin

    if project and project.frontend_url:
        return project.frontend_url.rstrip("/")

    if frontend_url:
        return frontend_url

    return list(allowed_origins) if allowed_origins else "http://localhost:5173"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data + padding)


# ----------------------------------------------------------------------
# Control Plane Passkey Views
# ----------------------------------------------------------------------

class PasskeyRegisterOptionsView(views.APIView):
    """Generate WebAuthn registration challenge for control plane user."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="Generate Passkey registration options", tags=["Passkeys"])
    def post(self, request):
        user = request.user
        rp_id = _resolve_rp_id(request)
        rp_name = getattr(settings, "WEBAUTHN_RP_NAME", "HVT Identity")

        existing_creds = UserPasskeyCredential.objects.filter(user=user)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=_b64url_decode(cred.credential_id))
            for cred in existing_creds
        ]

        options = webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(user.id).encode("utf-8"),
            user_name=user.email,
            user_display_name=user.full_name or user.email,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
            ],
            exclude_credentials=exclude_credentials if exclude_credentials else None,
            timeout=60000,
        )

        challenge_b64 = _b64url_encode(options.challenge)
        cache.set(f"passkey_reg_{user.id}", challenge_b64, timeout=300)

        AuditLog.log(
            event_type=AuditLog.EventType.PASSKEY_REGISTER_INITIATED,
            request=request,
            user=user,
            event_data={"rp_id": rp_id},
        )

        options_json = json.loads(webauthn.options_to_json(options))
        return Response(options_json, status=status.HTTP_200_OK)


class PasskeyRegisterVerifyView(views.APIView):
    """Verify WebAuthn registration attestation and store public key."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="Verify Passkey registration", tags=["Passkeys"])
    def post(self, request):
        user = request.user
        expected_challenge = cache.get(f"passkey_reg_{user.id}")
        if not expected_challenge:
            return Response(
                {"error": "Passkey registration challenge expired or not found. Please retry.", "code": "challenge_expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        rp_id = _resolve_rp_id(request)
        expected_origin = _resolve_expected_origin(request)

        try:
            credential_data = request.data
            credential_json = json.dumps(credential_data) if isinstance(credential_data, dict) else credential_data

            verification = webauthn.verify_registration_response(
                credential=credential_json,
                expected_challenge=_b64url_decode(expected_challenge),
                expected_rp_id=rp_id,
                expected_origin=expected_origin,
                require_user_verification=False,
            )

            cache.delete(f"passkey_reg_{user.id}")

            credential_id_b64 = _b64url_encode(verification.credential_id)
            public_key_b64 = _b64url_encode(verification.credential_public_key)

            name = str(request.data.get("name", "")).strip() or "Passkey"

            cred = UserPasskeyCredential.objects.create(
                user=user,
                name=name,
                credential_id=credential_id_b64,
                public_key=public_key_b64,
                sign_count=verification.sign_count,
                aaguid=str(verification.aaguid) if verification.aaguid else "",
                backed_up=bool(verification.credential_backed_up),
                transports=request.data.get("transports", []),
            )

            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_REGISTERED,
                request=request,
                user=user,
                event_data={"credential_id": cred.id, "name": cred.name},
            )

            return Response(
                {
                    "id": str(cred.id),
                    "name": cred.name,
                    "created_at": cred.created_at,
                    "detail": "Passkey registered successfully.",
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as exc:
            return Response(
                {"error": f"Passkey verification failed: {str(exc)}", "code": "verification_failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasskeyAuthOptionsView(views.APIView):
    """Generate WebAuthn authentication challenge for login."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = CONTROL_PLANE_LOGIN_THROTTLES

    @extend_schema(summary="Generate Passkey authentication options", tags=["Passkeys"])
    def post(self, request):
        email = str(request.data.get("email", "")).strip()
        rp_id = _resolve_rp_id(request)

        allow_credentials = None
        if email:
            user = get_control_plane_users_by_email(email).first()
            if user:
                creds = UserPasskeyCredential.objects.filter(user=user)
                if creds.exists():
                    allow_credentials = [
                        PublicKeyCredentialDescriptor(id=_b64url_decode(c.credential_id))
                        for c in creds
                    ]

        options = webauthn.generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=60000,
        )

        challenge_b64 = _b64url_encode(options.challenge)
        session_challenge_key = str(uuid.uuid4())
        cache.set(f"passkey_auth_{session_challenge_key}", challenge_b64, timeout=300)

        options_json = json.loads(webauthn.options_to_json(options))
        options_json["challenge_key"] = session_challenge_key
        return Response(options_json, status=status.HTTP_200_OK)


class PasskeyAuthVerifyView(views.APIView):
    """Verify WebAuthn authentication assertion and issue JWT session."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = CONTROL_PLANE_LOGIN_THROTTLES

    @extend_schema(summary="Verify Passkey assertion and log in", tags=["Passkeys"])
    def post(self, request):
        challenge_key = request.data.get("challenge_key")
        expected_challenge = cache.get(f"passkey_auth_{challenge_key}") if challenge_key else None
        if not expected_challenge:
            return Response(
                {"error": "Authentication challenge expired or invalid. Please retry.", "code": "challenge_expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        credential_data = request.data.get("credential", request.data)
        raw_cred_id = credential_data.get("id") or credential_data.get("rawId")
        if not raw_cred_id:
            return Response(
                {"error": "Credential ID is required.", "code": "credential_id_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cred_record = UserPasskeyCredential.objects.filter(
            credential_id=raw_cred_id,
            user__project__isnull=True,
        ).select_related("user").first()

        if not cred_record:
            return Response(
                {"error": "Passkey credential not recognized.", "code": "credential_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        rp_id = _resolve_rp_id(request)
        expected_origin = _resolve_expected_origin(request)

        try:
            credential_json = json.dumps(credential_data) if isinstance(credential_data, dict) else credential_data

            verification = webauthn.verify_authentication_response(
                credential=credential_json,
                expected_challenge=_b64url_decode(expected_challenge),
                expected_rp_id=rp_id,
                expected_origin=expected_origin,
                credential_public_key=_b64url_decode(cred_record.public_key),
                credential_current_sign_count=cred_record.sign_count,
                require_user_verification=False,
            )

            cache.delete(f"passkey_auth_{challenge_key}")

            # Update signature counter & last used
            cred_record.sign_count = verification.new_sign_count
            cred_record.last_used_at = timezone.now()
            cred_record.save(update_fields=["sign_count", "last_used_at"])

            user = cred_record.user
            access_token, refresh_token = build_hvt_token_pair(user)

            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_LOGIN,
                request=request,
                user=user,
                event_data={"credential_id": str(cred_record.id), "name": cred_record.name},
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
        except Exception as exc:
            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_LOGIN_FAILED,
                request=request,
                user=cred_record.user,
                success=False,
                error_message=str(exc),
            )
            return Response(
                {"error": f"Passkey authentication failed: {str(exc)}", "code": "authentication_failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasskeyCredentialListView(views.APIView):
    """List registered passkeys for the current user."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="List user passkeys", tags=["Passkeys"])
    def get(self, request):
        creds = UserPasskeyCredential.objects.filter(user=request.user).values(
            "id", "name", "created_at", "last_used_at", "backed_up", "aaguid"
        )
        return Response({"passkeys": list(creds)}, status=status.HTTP_200_OK)


class PasskeyCredentialDeleteView(views.APIView):
    """Delete a registered passkey."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="Delete passkey", tags=["Passkeys"])
    def delete(self, request, pk):
        cred = UserPasskeyCredential.objects.filter(id=pk, user=request.user).first()
        if not cred:
            return Response({"error": "Passkey not found.", "code": "not_found"}, status=status.HTTP_404_NOT_FOUND)

        cred_name = cred.name
        cred.delete()

        AuditLog.log(
            event_type=AuditLog.EventType.PASSKEY_DELETED,
            request=request,
            user=request.user,
            event_data={"name": cred_name},
        )
        return Response({"detail": "Passkey removed.", "id": str(pk)}, status=status.HTTP_200_OK)


# ----------------------------------------------------------------------
# Runtime Plane Passkey Views (API-Key Scoped)
# ----------------------------------------------------------------------

class RuntimePasskeyRegisterOptionsView(views.APIView):
    """Generate runtime passkey registration options scoped to project API key."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="Generate Runtime Passkey registration options", tags=["Runtime Passkeys"])
    def post(self, request):
        api_key = getattr(request, "auth", None)
        user = request.user
        project = getattr(api_key, "project", None) or user.project

        rp_id = _resolve_rp_id(request, project)
        rp_name = project.name if project else "HVT App"

        existing_creds = UserPasskeyCredential.objects.filter(user=user)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=_b64url_decode(cred.credential_id))
            for cred in existing_creds
        ]

        options = webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(user.id).encode("utf-8"),
            user_name=user.email,
            user_display_name=user.full_name or user.email,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
            ],
            exclude_credentials=exclude_credentials if exclude_credentials else None,
            timeout=60000,
        )

        challenge_b64 = _b64url_encode(options.challenge)
        cache.set(f"runtime_passkey_reg_{user.id}", challenge_b64, timeout=300)

        options_json = json.loads(webauthn.options_to_json(options))
        return Response(options_json, status=status.HTTP_200_OK)


class RuntimePasskeyRegisterVerifyView(views.APIView):
    """Verify runtime passkey registration."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(summary="Verify Runtime Passkey registration", tags=["Runtime Passkeys"])
    def post(self, request):
        user = request.user
        expected_challenge = cache.get(f"runtime_passkey_reg_{user.id}")
        if not expected_challenge:
            return Response(
                {"error": "Challenge expired or invalid.", "code": "challenge_expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        api_key = getattr(request, "auth", None)
        project = getattr(api_key, "project", None) or user.project

        rp_id = _resolve_rp_id(request, project)
        expected_origin = _resolve_expected_origin(request, project)

        try:
            credential_data = request.data
            credential_json = json.dumps(credential_data) if isinstance(credential_data, dict) else credential_data

            verification = webauthn.verify_registration_response(
                credential=credential_json,
                expected_challenge=_b64url_decode(expected_challenge),
                expected_rp_id=rp_id,
                expected_origin=expected_origin,
                require_user_verification=False,
            )

            cache.delete(f"runtime_passkey_reg_{user.id}")

            credential_id_b64 = _b64url_encode(verification.credential_id)
            public_key_b64 = _b64url_encode(verification.credential_public_key)

            name = str(request.data.get("name", "")).strip() or "Passkey"

            cred = UserPasskeyCredential.objects.create(
                user=user,
                name=name,
                credential_id=credential_id_b64,
                public_key=public_key_b64,
                sign_count=verification.sign_count,
                aaguid=str(verification.aaguid) if verification.aaguid else "",
                backed_up=bool(verification.credential_backed_up),
                transports=request.data.get("transports", []),
            )

            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_REGISTERED,
                request=request,
                user=user,
                event_data={
                    "credential_id": str(cred.id),
                    "name": cred.name,
                    "project_id": str(project.id) if project else None,
                },
            )

            return Response(
                {
                    "id": str(cred.id),
                    "name": cred.name,
                    "created_at": cred.created_at,
                    "detail": "Passkey registered successfully.",
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as exc:
            return Response(
                {"error": f"Passkey registration failed: {str(exc)}", "code": "verification_failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class RuntimePasskeyAuthOptionsView(views.APIView):
    """Generate runtime passkey authentication options."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = RUNTIME_LOGIN_THROTTLES

    @extend_schema(summary="Generate Runtime Passkey auth options", tags=["Runtime Passkeys"])
    def post(self, request):
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            return Response({"error": "X-API-Key required."}, status=status.HTTP_401_UNAUTHORIZED)
        if not api_key.has_scope("auth:runtime"):
            return Response(
                {"detail": "This API key does not have the required auth:runtime scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        project = api_key.project
        email = str(request.data.get("email", "")).strip()
        rp_id = _resolve_rp_id(request, project)

        allow_credentials = None
        if email:
            user = get_runtime_user_for_api_key(email, api_key)
            if user:
                creds = UserPasskeyCredential.objects.filter(user=user)
                if creds.exists():
                    allow_credentials = [
                        PublicKeyCredentialDescriptor(id=_b64url_decode(c.credential_id))
                        for c in creds
                    ]

        options = webauthn.generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=60000,
        )

        challenge_b64 = _b64url_encode(options.challenge)
        session_challenge_key = str(uuid.uuid4())
        cache.set(f"runtime_passkey_auth_{session_challenge_key}", challenge_b64, timeout=300)

        options_json = json.loads(webauthn.options_to_json(options))
        options_json["challenge_key"] = session_challenge_key
        return Response(options_json, status=status.HTTP_200_OK)


class RuntimePasskeyAuthVerifyView(views.APIView):
    """Verify runtime passkey assertion and issue project-scoped token."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = RUNTIME_LOGIN_THROTTLES

    @extend_schema(summary="Verify Runtime Passkey and log in", tags=["Runtime Passkeys"])
    def post(self, request):
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            return Response({"error": "X-API-Key required."}, status=status.HTTP_401_UNAUTHORIZED)
        if not api_key.has_scope("auth:runtime"):
            return Response(
                {"detail": "This API key does not have the required auth:runtime scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        challenge_key = request.data.get("challenge_key")
        expected_challenge = cache.get(f"runtime_passkey_auth_{challenge_key}") if challenge_key else None
        if not expected_challenge:
            return Response(
                {"error": "Challenge expired or invalid.", "code": "challenge_expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        credential_data = request.data.get("credential", request.data)
        raw_cred_id = credential_data.get("id") or credential_data.get("rawId")

        cred_record = UserPasskeyCredential.objects.filter(
            credential_id=raw_cred_id,
            user__project=api_key.project,
        ).select_related("user").first()

        if not cred_record:
            return Response(
                {"error": "Passkey not found in this project.", "code": "credential_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        project = api_key.project
        rp_id = _resolve_rp_id(request, project)
        expected_origin = _resolve_expected_origin(request, project)

        try:
            credential_json = json.dumps(credential_data) if isinstance(credential_data, dict) else credential_data

            verification = webauthn.verify_authentication_response(
                credential=credential_json,
                expected_challenge=_b64url_decode(expected_challenge),
                expected_rp_id=rp_id,
                expected_origin=expected_origin,
                credential_public_key=_b64url_decode(cred_record.public_key),
                credential_current_sign_count=cred_record.sign_count,
                require_user_verification=False,
            )

            cache.delete(f"runtime_passkey_auth_{challenge_key}")

            cred_record.sign_count = verification.new_sign_count
            cred_record.last_used_at = timezone.now()
            cred_record.save(update_fields=["sign_count", "last_used_at"])

            user = cred_record.user
            access_token, refresh_token = build_hvt_token_pair(user, project=project)

            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_LOGIN,
                request=request,
                user=user,
                event_data={
                    "credential_id": str(cred_record.id),
                    "name": cred_record.name,
                    "project_id": str(project.id) if project else None,
                },
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
        except Exception as exc:
            AuditLog.log(
                event_type=AuditLog.EventType.PASSKEY_LOGIN_FAILED,
                request=request,
                user=cred_record.user if 'cred_record' in locals() and cred_record else None,
                event_data={
                    "error": str(exc),
                    "project_id": str(project.id) if 'project' in locals() and project else None,
                },
            )
            return Response(
                {"error": f"Passkey authentication failed: {str(exc)}", "code": "authentication_failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )
