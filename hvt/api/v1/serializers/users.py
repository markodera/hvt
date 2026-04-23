from rest_framework import exceptions, serializers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from django.core.exceptions import (
    ImproperlyConfigured,
    MultipleObjectsReturned,
    ValidationError as DjangoValidationError,
)
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils.translation import gettext_lazy as _
from requests.exceptions import RequestException
import logging
import sys
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from hvt.apps.authentication.models import AuditLog
from hvt.apps.authentication.identity import (
    get_control_plane_users_by_email,
    get_runtime_legacy_users_by_email,
    get_runtime_project_users_by_email,
    get_runtime_user_for_api_key,
    normalize_email,
)
from hvt.apps.organizations.access import (
    assign_default_signup_roles,
    get_user_project_permission_slugs,
    get_user_project_roles,
    user_has_project_access,
)
from hvt.apps.users.models import User
from hvt.apps.organizations.models import APIKey, SocialProviderConfig, UserProjectRole
from hvt.apps.organizations.runtime_roles import assign_requested_registration_role
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.registration.serializers import SocialLoginSerializer
from dj_rest_auth.serializers import LoginSerializer
from drf_spectacular.utils import extend_schema_field


logger = logging.getLogger(__name__)


def _sync_runtime_user_project(user: User, api_key: APIKey) -> User:
    """Attach or validate a runtime user's project against the calling API key."""
    if not api_key.project_id:
        return user

    # Backward compatibility for legacy member rows created before project access
    # became role-driven: bind first-time runtime login to the API-key project.
    if user.role == User.Role.MEMBER and user.project_id is None:
        has_role_assignments = UserProjectRole.objects.filter(
            user=user,
            role__project__organization_id=api_key.organization_id,
        ).exists()
        if not has_role_assignments:
            user.project = api_key.project
            user.save(update_fields=["project"])
            return user

    if not user_has_project_access(user, api_key.project):
        raise serializers.ValidationError(
            "These credentials do not belong to the API key project."
        )

    return user


def _hydrate_runtime_user_organization(user: User) -> User:
    """
    Heal legacy owner rows that own an organization but were never linked back to it.

    This avoids dead-end auth failures for accounts created during earlier onboarding
    flows where the owner relation existed but user.organization stayed null.
    """
    if user.organization_id:
        return user

    owned_org = user.owned_organization.first()
    if not owned_org:
        return user

    user.organization = owned_org
    if user.role != User.Role.OWNER:
        user.role = User.Role.OWNER
        user.save(update_fields=["organization", "role"])
        return user

    user.save(update_fields=["organization"])
    return user


def _require_runtime_scope(api_key: APIKey) -> None:
    if isinstance(api_key, APIKey) and not api_key.has_scope("auth:runtime"):
        raise serializers.ValidationError(
            {"detail": "This API key does not have the required auth:runtime scope."}
        )


from hvt.exceptions import EmailInUseException


def _create_registered_user(
    serializer: RegisterSerializer,
    request,
    *,
    organization=None,
    project=None,
    role=None,
):
    """Persist a new user with consistent error handling for register flows."""
    try:
        with transaction.atomic():
            adapter = get_adapter()
            user = adapter.new_user(request)
            serializer.cleaned_data = serializer.get_cleaned_data()
            user = adapter.save_user(request, user, serializer, commit=False)
            if "password1" in serializer.cleaned_data:
                try:
                    adapter.clean_password(serializer.cleaned_data["password1"], user=user)
                except DjangoValidationError as exc:
                    raise serializers.ValidationError(
                        detail=serializers.as_serializer_error(exc)
                    ) from exc

            if organization is not None:
                user.organization = organization
            if project is not None:
                user.project = project
            if role is not None:
                user.role = role

            user.save()
            serializer.custom_signup(request, user)
            setup_user_email(request, user, [])
            return user
    except IntegrityError as exc:
        logger.exception(
            "User registration failed due to integrity error",
            extra={
                "path": getattr(request, "path", ""),
                "method": getattr(request, "method", ""),
            },
        )
        raise EmailInUseException() from exc
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
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ["email", "password1", "password2", "first_name", "last_name"]

    def validate_email(self, value):
        return normalize_email(value)

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

    def validate_email(self, value):
        normalized_email = super().validate_email(value)
        if get_control_plane_users_by_email(normalized_email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return normalized_email


class RuntimeRegisterSerializer(BaseRegisterSerializer):
    """API-key-scoped runtime registration for customer-facing app users."""

    default_error_messages = {
        "api_key_required": "A valid X-API-Key header is required.",
    }
    role_slug = serializers.CharField(required=False, allow_blank=False)

    def validate_email(self, value):
        normalized_email = super().validate_email(value)
        request = self.context.get("request")
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            return normalized_email

        if get_runtime_project_users_by_email(normalized_email, api_key).exists():
            raise serializers.ValidationError(
                "A user with this email already exists for this project."
            )
        if get_runtime_legacy_users_by_email(normalized_email, api_key).exists():
            raise serializers.ValidationError(
                "A user with this email already exists for this project."
            )
        return normalized_email

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

        with transaction.atomic():
            user = _create_registered_user(
                self,
                request,
                organization=api_key_org,
                project=api_key_project,
                role=User.Role.MEMBER if api_key_org else None,
            )

            if api_key_org:
                if "role_slug" in request.data:
                    assign_requested_registration_role(
                        user=user,
                        project=api_key_project,
                        role_slug=request.data.get("role_slug"),
                    )
                else:
                    assign_default_signup_roles(user, api_key_project)

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

    @staticmethod
    def validate_email_verification_status(user, email=None):
        if (
            "dj_rest_auth.registration" in settings.INSTALLED_APPS
            and not user.emailaddress_set.filter(email__iexact=user.email, verified=True).exists()
        ):
            raise exceptions.PermissionDenied(
                "E-mail is not verified. Please verify your email before logging in."
            )

    def get_login_user(self, email, password):
        user = get_control_plane_users_by_email(email).first()
        if not user or not user.check_password(password):
            return None
        return user

    def validate(self, attrs):
        email = normalize_email(attrs.get("email", ""))
        password = attrs.get("password")
        if not email or not password:
            raise exceptions.ValidationError(_('Must include "email" and "password".'))

        user = self.get_login_user(email, password)
        if not user:
            raise exceptions.ValidationError(
                _("Unable to log in with provided credentials.")
            )

        self.validate_auth_user_status(user)
        self.validate_email_verification_status(user, email=email)
        attrs["email"] = email
        attrs["user"] = user
        return attrs


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
        email = normalize_email(attrs.get("email", ""))
        password = attrs.get("password")
        if not email or not password:
            raise exceptions.ValidationError(_('Must include "email" and "password".'))
        request = self.context.get("request")
        api_key = getattr(request, "auth", None)
        if not isinstance(api_key, APIKey):
            raise serializers.ValidationError(self.error_messages["api_key_required"])
        if not api_key.has_scope("auth:runtime"):
            raise serializers.ValidationError(self.error_messages["missing_scope"])

        user = get_runtime_user_for_api_key(email, api_key)
        if user:
            if not user.check_password(password):
                user = None
        else:
            for candidate in User.objects.select_related("organization", "project").filter(
                email__iexact=email
            ):
                if not candidate.check_password(password):
                    continue
                candidate = _hydrate_runtime_user_organization(candidate)
                if not candidate.organization_id:
                    raise serializers.ValidationError(
                        "This email does not belong to a runtime user in any organization. "
                        "Register through /api/v1/auth/runtime/register/ with an API key first."
                    )
                if candidate.organization_id != api_key.organization_id:
                    raise serializers.ValidationError(self.error_messages["wrong_org"])
                if candidate.project_id is None:
                    user = candidate
                    break
                raise serializers.ValidationError(self.error_messages["wrong_project"])

        if not user:
            raise exceptions.ValidationError(
                _("Unable to log in with provided credentials.")
            )

        self.validate_auth_user_status(user)
        self.validate_email_verification_status(user, email=email)
        user = _hydrate_runtime_user_organization(user)
        if not user.organization_id:
            raise serializers.ValidationError(
                "This email does not belong to a runtime user in any organization. "
                "Register through /api/v1/auth/runtime/register/ with an API key first."
            )

        if user.organization_id != api_key.organization_id:
            raise serializers.ValidationError(self.error_messages["wrong_org"])

        try:
            user = _sync_runtime_user_project(user, api_key)
        except serializers.ValidationError as exc:
            raise serializers.ValidationError(self.error_messages["wrong_project"]) from exc

        attrs["email"] = email
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

    def _is_runtime_social_request(self) -> bool:
        request = self.context.get("request")
        return isinstance(getattr(request, "auth", None), APIKey)

    def _unexpected_social_error_message(self, exc: Exception) -> str:
        if not (settings.DEBUG and self._is_runtime_social_request()):
            return "Social login failed. Please try again."

        error_type = type(exc).__name__
        error_text = str(exc).strip()
        if error_text:
            return f"Social login failed: {error_type}: {error_text}"
        return f"Social login failed: {error_type}"

    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except exceptions.PermissionDenied:
            raise
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
        except Exception as exc:
            logger.exception(
                "Unexpected social login provider failure",
                extra={
                    "provider": self._get_provider_label(),
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "runtime_social_request": self._is_runtime_social_request(),
                },
            )
            raise serializers.ValidationError(
                self._unexpected_social_error_message(exc)
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

        # If dj-rest-auth and allauth caching returns a stale user instance that doesn't reflect 
        # the save_user modifications, safely refresh it from the database.
        if user.pk and not user.organization_id:
            user.refresh_from_db()

        # Failsafe: if allauth stripped the DRF request down to a plain HttpRequest deep in its stack,
        # the CustomSocialAccountAdapter.save_user would have failed to pull request.auth to assign
        # the organization natively. If the user was just created and still lacks an org, we assign it here.
        if not user.organization_id and user.pk:
            user.organization = api_key.organization
            user.project = api_key.project
            user.role = user.Role.MEMBER
            user.save(update_fields=["organization", "project", "role"])

        # Heal API-bound users that originated from the dashboard without an organization link
        user = _hydrate_runtime_user_organization(user)

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


class UserProjectRoleSummarySerializer(serializers.Serializer):
    """Compact project-role payload for user list and detail views."""

    id = serializers.UUIDField(read_only=True)
    slug = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True)
    project_slug = serializers.CharField(source="project.slug", read_only=True)


class UserAppRolesMixin:
    """Expose a user's assigned app roles with project context."""

    @extend_schema_field(UserProjectRoleSummarySerializer(many=True))
    def get_app_roles(self, obj):
        assignments = getattr(obj, "project_role_assignments", None)
        if assignments is None:
            return []

        seen_role_ids = set()
        roles = []
        for assignment in assignments.all():
            role = getattr(assignment, "role", None)
            if role is None or role.id in seen_role_ids:
                continue
            seen_role_ids.add(role.id)
            roles.append(role)

        roles.sort(
            key=lambda role: (
                (getattr(getattr(role, "project", None), "slug", "") or ""),
                (role.name or ""),
                (role.slug or ""),
            )
        )
        return UserProjectRoleSummarySerializer(roles, many=True).data


class UserSerializer(UserAppRolesMixin, serializers.ModelSerializer):
    """Serializer for User model"""

    app_roles = serializers.SerializerMethodField()
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
            "app_roles",
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
            "app_roles",
            "is_project_scoped",
            "is_test",
            "created_at",
        ]


class RuntimeCurrentUserSerializer(serializers.ModelSerializer):
    """Serializer for runtime session bootstrap tied to the token's project context."""

    full_name = serializers.ReadOnlyField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)
    organization = serializers.UUIDField(source="organization_id", read_only=True, allow_null=True)
    organization_slug = serializers.CharField(
        source="organization.slug",
        read_only=True,
        allow_null=True,
    )
    project = serializers.SerializerMethodField()
    project_slug = serializers.SerializerMethodField()
    app_roles = serializers.SerializerMethodField()
    app_permissions = serializers.SerializerMethodField()
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
            "organization_slug",
            "project",
            "project_slug",
            "app_roles",
            "app_permissions",
            "role",
            "role_display",
            "is_project_scoped",
            "is_active",
            "is_test",
            "created_at",
        ]
        read_only_fields = fields

    def _get_runtime_project(self):
        return self.context.get("project")

    @extend_schema_field(serializers.UUIDField(allow_null=True))
    def get_project(self, obj):
        project = self._get_runtime_project()
        return str(project.id) if project else None

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_project_slug(self, obj):
        project = self._get_runtime_project()
        return project.slug if project else None

    @extend_schema_field(UserProjectRoleSummarySerializer(many=True))
    def get_app_roles(self, obj):
        project = self._get_runtime_project()
        if not project:
            return []
        return UserProjectRoleSummarySerializer(
            get_user_project_roles(obj, project),
            many=True,
        ).data

    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_app_permissions(self, obj):
        project = self._get_runtime_project()
        if not project:
            return []
        return get_user_project_permission_slugs(obj, project)


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


class OrganizationMemberSerializer(UserAppRolesMixin, serializers.ModelSerializer):
    """Serializer for listing organization members when role with info."""

    app_roles = serializers.SerializerMethodField()
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
            "app_roles",
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
