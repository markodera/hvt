from rest_framework import serializers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from django.core.exceptions import ImproperlyConfigured, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from requests.exceptions import RequestException
import logging
import sys
from hvt.apps.authentication.models import AuditLog
from hvt.apps.users.models import User
from hvt.apps.organizations.models import APIKey, SocialProviderConfig
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.registration.serializers import SocialLoginSerializer
from dj_rest_auth.serializers import LoginSerializer
from drf_spectacular.utils import extend_schema_field


logger = logging.getLogger(__name__)


def _sync_runtime_user_project(user: User, api_key: APIKey) -> User:
    """Attach or validate a runtime user's project against the calling API key."""
    if not api_key.project_id:
        return user

    if user.project_id is None and user.role == User.Role.MEMBER:
        user.project = api_key.project
        user.save(update_fields=["project"])
        return user

    if user.project_id != api_key.project_id:
        raise serializers.ValidationError(
            "These credentials do not belong to the API key project."
        )

    return user


def _require_runtime_scope(api_key: APIKey) -> None:
    if isinstance(api_key, APIKey) and not api_key.has_scope("auth:runtime"):
        raise serializers.ValidationError(
            {"detail": "This API key does not have the required auth:runtime scope."}
        )


def _create_registered_user(serializer: RegisterSerializer, request):
    """Persist a new user with consistent error handling for register flows."""
    try:
        with transaction.atomic():
            return super(serializer.__class__, serializer).save(request)
    except IntegrityError as exc:
        logger.exception(
            "User registration failed due to integrity error",
            extra={
                "path": getattr(request, "path", ""),
                "method": getattr(request, "method", ""),
            },
        )
        raise serializers.ValidationError(
            {"email": ["A user with this email already exists."]}
        ) from exc
    except Exception:
        request_email = ""
        try:
            request_email = serializer.validated_data.get("email", "")
        except Exception:
            request_email = ""
        exc = sys.exc_info()[1]
        logger.exception(
            "User registration failed during serializer save",
            extra={
                "email": request_email,
                "path": getattr(request, "path", ""),
                "method": getattr(request, "method", ""),
            },
        )
        if exc and exc.__class__.__module__.startswith("resend.exceptions"):
            raise serializers.ValidationError(
                (
                    "Verification email could not be sent. "
                    "Resend test mode only allows delivery to your own verified email address."
                )
            ) from exc
        raise


def _log_registration_event(request, user: User, organization=None, project=None) -> None:
    """Write a consistent audit event for both control-plane and runtime signup."""
    AuditLog.log(
        event_type=AuditLog.EventType.USER_REGISTER,
        request=request,
        user=user,
        organization=organization or user.organization,
        project=project or user.project,
        event_data={
            "email": user.email,
            "has_organization": user.organization is not None,
            "project_id": str((project or user.project).id)
            if (project or user.project)
            else None,
        },
        success=True,
    )


def _trigger_registration_webhook(
    user: User,
    organization=None,
    project=None,
    registration_method: str = "email",
) -> None:
    """Emit the runtime registration webhook when the new user belongs to an org."""
    target_org = organization or user.organization
    target_project = project or user.project
    if not target_org:
        return

    from hvt.apps.organizations.webhooks import trigger_webhook_event

    trigger_webhook_event(
        organization=target_org,
        project=target_project,
        event_type="user.registered",
        payload={
            "user_id": str(user.id),
            "email": user.email,
            "registration_method": registration_method,
        },
    )


class BaseRegisterSerializer(RegisterSerializer):
    """Shared register serializer behavior without usernames."""

    username = None

    class Meta:
        model = User
        fields = ["email", "password1", "password2", "first_name", "last_name"]

    def validate_email(self, value):
        normalized_email = (value or "").strip().lower()
        if User.objects.filter(email__iexact=normalized_email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return normalized_email

    def get_cleaned_data(self):
        return {
            "email": self.validated_data.get("email", ""),
            "password1": self.validated_data.get("password1", ""),
            "first_name": self.validated_data.get("first_name", ""),
            "last_name": self.validated_data.get("last_name", ""),
        }


class ControlPlaneRegisterSerializer(BaseRegisterSerializer):
    """Control-plane signup for HVT dashboard users."""

    default_error_messages = {
        "runtime_route_required": (
            "Use /api/v1/auth/runtime/register/ with X-API-Key for runtime registration."
        )
    }

    def save(self, request):
        """Create an HVT dashboard user without runtime API-key context."""
        api_key = getattr(request, "auth", None)
        if isinstance(api_key, APIKey):
            raise serializers.ValidationError(
                {"detail": self.error_messages["runtime_route_required"]}
            )

        user = _create_registered_user(self, request)
        _log_registration_event(request, user)
        return user


class RuntimeRegisterSerializer(BaseRegisterSerializer):
    """API-key-scoped runtime registration for customer-facing app users."""

    default_error_messages = {
        "api_key_required": "A valid X-API-Key header is required.",
    }

    def save(self, request):
        """Register a runtime user inside the org/project resolved from the API key."""
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise serializers.ValidationError(
                {"detail": self.error_messages["api_key_required"]}
            )

        api_key_org = getattr(api_key, "organization", None)
        api_key_project = getattr(api_key, "project", None)
        _require_runtime_scope(api_key)

        if api_key_project and not api_key_project.allow_signup:
            raise serializers.ValidationError(
                {
                    "detail": "Self-service signup is disabled for this organization."
                }
            )
        if api_key_org and api_key_project is None and not api_key_org.allow_signup:
            raise serializers.ValidationError(
                {
                    "detail": "Self-service signup is disabled for this organization."
                }
            )

        user = _create_registered_user(self, request)

        if api_key_org:
            user.organization = api_key_org
            user.role = User.Role.MEMBER
            user.project = api_key_project
            user.save(update_fields=["organization", "role", "project"])

        _log_registration_event(request, user, organization=user.organization, project=api_key_project)
        _trigger_registration_webhook(
            user,
            organization=user.organization,
            project=api_key_project,
            registration_method="email",
        )
        return user


class CustomLoginSerializer(LoginSerializer):
    """
    Custom login serializer to use email only and extract user info
    """

    username = None

    def get_fields(self):
        fields = super().get_fields()
        fields.pop("username", None)
        return fields


class RuntimeLoginSerializer(CustomLoginSerializer):
    """Login serializer for app-runtime auth scoped by API key org."""

    default_error_messages = {
        "api_key_required": "A valid X-API-Key header is required.",
        "missing_scope": "This API key does not have the required auth:runtime scope.",
        "no_org": "This user is not assigned to an organization.",
        "wrong_org": "These credentials do not belong to the API key organization.",
        "wrong_project": "These credentials do not belong to the API key project.",
    }

    def validate(self, attrs):
        attrs = super().validate(attrs)

        request = self.context.get("request")
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise serializers.ValidationError(self.error_messages["api_key_required"])
        if not api_key.has_scope("auth:runtime"):
            raise serializers.ValidationError(self.error_messages["missing_scope"])

        user = attrs["user"]
        if not user.organization_id:
            raise serializers.ValidationError(self.error_messages["no_org"])

        if user.organization_id != api_key.organization_id:
            raise serializers.ValidationError(self.error_messages["wrong_org"])

        try:
            user = _sync_runtime_user_project(user, api_key)
        except serializers.ValidationError as exc:
            raise serializers.ValidationError(self.error_messages["wrong_project"]) from exc

        attrs["user"] = user
        return attrs


class CustomSocialLoginSerializer(SocialLoginSerializer):
    """Normalize provider/setup errors into 400 responses for social login."""

    callback_url = serializers.URLField(required=False)

    def _get_provider_label(self) -> str:
        """Best-effort provider label from the current social login view."""
        view = self.context.get("view")
        adapter_class = getattr(view, "adapter_class", None)
        provider_id = getattr(adapter_class, "provider_id", "")
        return provider_id or "requested"

    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except SocialApp.DoesNotExist as exc:
            provider_label = self._get_provider_label()
            raise serializers.ValidationError(
                f"Social login provider '{provider_label}' is not configured."
            ) from exc
        except MultipleObjectsReturned as exc:
            provider_label = self._get_provider_label()
            raise serializers.ValidationError(
                (
                    f"Social login provider '{provider_label}' configuration is ambiguous. "
                    "Multiple SocialApp entries match this provider. "
                    "Keep only one app per provider/site or provide a unique client_id."
                )
            ) from exc
        except ImproperlyConfigured as exc:
            provider_label = self._get_provider_label()
            raise serializers.ValidationError(
                f"Social login provider '{provider_label}' is misconfigured."
            ) from exc
        except OAuth2Error as exc:
            raise serializers.ValidationError(
                "Social login failed. Please try again."
            ) from exc
        except RequestException as exc:
            raise serializers.ValidationError(
                "Social login failed. Please try again."
            ) from exc

    def set_callback_url(self, view, adapter_class):
        callback_url = self.initial_data.get("callback_url")
        if callback_url:
            self.callback_url = callback_url
            return
        super().set_callback_url(view, adapter_class)


class RuntimeSocialLoginSerializer(CustomSocialLoginSerializer):
    """Social login serializer for runtime app users scoped by API key/project."""

    default_error_messages = {
        "api_key_required": "A valid X-API-Key header is required.",
        "missing_scope": "This API key does not have the required auth:runtime scope.",
        "no_org": "This user is not assigned to an organization.",
        "wrong_org": "These credentials do not belong to the API key organization.",
        "wrong_project": "These credentials do not belong to the API key project.",
        "callback_required": "A valid callback_url is required for runtime social login.",
        "callback_not_allowed": "This callback URL is not allowed for the configured provider.",
    }

    def validate(self, attrs):
        request = self.context.get("request")
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise serializers.ValidationError(self.error_messages["api_key_required"])
        if not api_key.has_scope("auth:runtime"):
            raise serializers.ValidationError(self.error_messages["missing_scope"])

        callback_url = self.initial_data.get("callback_url")
        if not callback_url:
            raise serializers.ValidationError(self.error_messages["callback_required"])

        view = self.context.get("view")
        adapter_class = getattr(view, "adapter_class", None)
        provider_id = getattr(adapter_class, "provider_id", None)
        if provider_id:
            config = SocialProviderConfig.objects.filter(
                project=api_key.project,
                provider=provider_id,
                is_active=True,
            ).first()
            if config and callback_url not in config.redirect_uris:
                raise serializers.ValidationError(
                    self.error_messages["callback_not_allowed"]
                )

        attrs = super().validate(attrs)
        user = attrs["user"]

        if not user.organization_id:
            raise serializers.ValidationError(self.error_messages["no_org"])

        if user.organization_id != api_key.organization_id:
            raise serializers.ValidationError(self.error_messages["wrong_org"])

        try:
            user = _sync_runtime_user_project(user, api_key)
        except serializers.ValidationError as exc:
            raise serializers.ValidationError(self.error_messages["wrong_project"]) from exc

        attrs["user"] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""

    full_name = serializers.ReadOnlyField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_slug = serializers.CharField(source="project.slug", read_only=True, allow_null=True)
    is_project_scoped = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "organization",
            "project",
            "project_slug",
            "role",
            "role_display",
            "is_project_scoped",
            "is_active",
            "is_test",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "email",
            "organization",
            "project",
            "project_slug",
            "is_project_scoped",
            "is_test",
            "created_at",
        ]


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating users (Admin only)."""

    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "first_name",
            "last_name",
            "organization",
            "role",
        ]

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserRoleUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user role only."""

    class Meta:
        model = User
        fields = ["role"]

        def validate_role(self, value):
            if value not in [choice[0] for choice in User.Role.choices]:
                raise serializers.ValidationError(
                    f"Invalid role must be one of: {', '.join([c[0] for c in User.Role.choices])}"
                )
            return value


class OrganizationMemberSerializer(serializers.ModelSerializer):
    """Serializer for listing organization members when role with info."""

    full_name = serializers.ReadOnlyField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_slug = serializers.CharField(source="project.slug", read_only=True, allow_null=True)
    can_be_promoted = serializers.SerializerMethodField()
    can_be_demoted = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "organization",
            "project",
            "project_slug",
            "role",
            "role_display",
            "is_active",
            "is_test",
            "created_at",
            "can_be_promoted",
            "can_be_demoted",
        ]

        read_only_fields = fields

    @extend_schema_field(serializers.BooleanField())
    def get_can_be_promoted(self, obj) -> bool:
        """Check if a user can be promoted to a higher role."""
        return obj.role in ["member", "admin"]
    
    @extend_schema_field(serializers.BooleanField())
    def get_can_be_demoted(self, obj) -> bool:
        """Check if a user can be demoted to a lower role."""
        return obj.role in ["owner", "admin"]
