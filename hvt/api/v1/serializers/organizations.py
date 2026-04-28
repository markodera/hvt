from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from allauth.account.adapter import get_adapter
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from hvt.apps.organizations.models import (
    Organization,
    Project,
    APIKey,
    ProjectPermission,
    ProjectRole,
    SocialProviderConfig,
    Webhook,
    WebhookDelivery,
    OrganizationInvitation,
    RuntimeInvitation,
)
from hvt.apps.organizations.runtime_origins import normalize_runtime_origin, normalize_runtime_origins
from hvt.apps.organizations.runtime_roles import (
    resolve_project_roles_or_error,
    validate_no_control_plane_role_slugs,
)


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for organization Model"""

    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "is_active",
            "allow_signup",
            "owner",
            "user_count",
            "created_at",
        ]
        read_only_fields = ["id", "user_count", "created_at"]
        
    @extend_schema_field(serializers.IntegerField())
    def get_user_count(self, obj) -> int:
        return obj.users.count()


class ProjectSerializer(serializers.ModelSerializer):
    """Serializer for organization projects."""

    allowed_origins = serializers.ListField(
        child=serializers.CharField(max_length=500),
        required=False,
        allow_empty=True,
    )

    def validate_frontend_url(self, value):
        return (value or "").strip().rstrip("/")

    def validate_allowed_origins(self, value):
        normalized_origins = []
        invalid_values = []

        for item in value or []:
            normalized_origin = normalize_runtime_origin(item)
            if not normalized_origin:
                invalid_values.append(str(item))
                continue
            if normalized_origin not in normalized_origins:
                normalized_origins.append(normalized_origin)

        if invalid_values:
            raise serializers.ValidationError(
                "Enter full origins like https://app.example.com or http://localhost:3000."
            )

        return normalize_runtime_origins(normalized_origins)

    class Meta:
        model = Project
        fields = [
            "id",
            "name",
            "slug",
            "is_default",
            "is_active",
            "allow_signup",
            "frontend_url",
            "allowed_origins",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "is_default", "created_at", "updated_at"]


class ProjectPermissionSerializer(serializers.ModelSerializer):
    """Serializer for project-scoped app permissions."""

    project = serializers.UUIDField(source="project_id", read_only=True)

    class Meta:
        model = ProjectPermission
        fields = [
            "id",
            "project",
            "slug",
            "name",
            "description",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "project", "created_at", "updated_at"]

    def validate_slug(self, value):
        return (value or "").strip().lower()


class ProjectRoleSummarySerializer(serializers.ModelSerializer):
    """Compact serializer for role assignments and access responses."""

    class Meta:
        model = ProjectRole
        fields = ["id", "slug", "name"]
        read_only_fields = fields


class ProjectRoleSerializer(serializers.ModelSerializer):
    """Serializer for project-scoped roles and their attached permissions."""

    project = serializers.UUIDField(source="project_id", read_only=True)
    permissions = ProjectPermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(),
        write_only=True,
        required=False,
        allow_empty=True,
    )

    class Meta:
        model = ProjectRole
        fields = [
            "id",
            "project",
            "slug",
            "name",
            "description",
            "is_default_signup",
            "is_self_assignable",
            "permissions",
            "permission_ids",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "project", "permissions", "created_at", "updated_at"]

    def validate_slug(self, value):
        return (value or "").strip().lower()

    def _resolve_permissions(self, permission_ids):
        project = self.context.get("project")
        if project is None:
            raise serializers.ValidationError("Project context is required.")

        if permission_ids is None:
            return None

        permissions = list(
            ProjectPermission.objects.filter(project=project, id__in=permission_ids)
        )
        found_ids = {permission.id for permission in permissions}
        missing = [str(permission_id) for permission_id in permission_ids if permission_id not in found_ids]
        if missing:
            raise serializers.ValidationError(
                {
                    "permission_ids": [
                        "Select valid permissions in the current project."
                    ]
                }
            )
        return permissions

    def create(self, validated_data):
        permissions = self._resolve_permissions(validated_data.pop("permission_ids", None))
        project = self.context.get("project")
        if project is None:
            raise serializers.ValidationError("Project context is required.")

        role = ProjectRole.objects.create(project=project, **validated_data)
        if permissions is not None:
            role.permissions.set(permissions)
        return role

    def update(self, instance, validated_data):
        permissions = self._resolve_permissions(validated_data.pop("permission_ids", None))
        instance = super().update(instance, validated_data)
        if permissions is not None:
            instance.permissions.set(permissions)
        return instance


class ProjectUserRoleAssignmentUpdateSerializer(serializers.Serializer):
    """Replace a user's role assignments for a single project."""

    role_slugs = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=True,
    )

    def validate_role_slugs(self, value):
        return [str(role_slug or "").strip().lower() for role_slug in value]


class ProjectUserRoleAccessSerializer(serializers.Serializer):
    """Read serializer for a user's project access view."""

    user = serializers.UUIDField(read_only=True)
    project = serializers.UUIDField(read_only=True)
    roles = ProjectRoleSummarySerializer(many=True, read_only=True)
    permissions = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
    )


class SocialProviderConfigSerializer(serializers.ModelSerializer):
    """Serializer for per-project social provider configuration."""

    project = serializers.UUIDField(source="project_id", read_only=True)
    client_secret = serializers.CharField(
        write_only=True,
        required=False,
        trim_whitespace=False,
    )
    has_client_secret = serializers.SerializerMethodField()
    client_secret_last4 = serializers.SerializerMethodField()
    redirect_uris = serializers.ListField(
        child=serializers.URLField(),
        allow_empty=False,
    )

    class Meta:
        model = SocialProviderConfig
        fields = [
            "id",
            "project",
            "provider",
            "client_id",
            "client_secret",
            "has_client_secret",
            "client_secret_last4",
            "redirect_uris",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "project",
            "has_client_secret",
            "client_secret_last4",
            "created_at",
            "updated_at",
        ]

    @extend_schema_field(serializers.BooleanField())
    def get_has_client_secret(self, obj) -> bool:
        return bool(obj.client_secret)

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_client_secret_last4(self, obj) -> str:
        return obj.client_secret[-4:] if obj.client_secret else ""

    def validate_redirect_uris(self, value):
        normalized = []
        for uri in value:
            cleaned = (uri or "").strip()
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
        if not normalized:
            raise serializers.ValidationError("At least one redirect URI is required.")
        return normalized

    def create(self, validated_data):
        client_secret = validated_data.pop("client_secret", "")
        instance = super().create(validated_data)
        if client_secret:
            instance.client_secret = client_secret
            instance.save(update_fields=["client_secret", "updated_at"])
        return instance

    def update(self, instance, validated_data):
        client_secret = validated_data.pop("client_secret", None)
        instance = super().update(instance, validated_data)
        if client_secret:
            instance.client_secret = client_secret
            instance.save(update_fields=["client_secret", "updated_at"])
        return instance


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API Keys.  Returns the full key only on creation."""

    key = serializers.CharField(
        read_only=True, help_text="Full API Key (Shown only once)"
    )
    environment = serializers.ChoiceField(
        choices=APIKey.Environment.choices,
        default=APIKey.Environment.TEST,
        help_text="'test' for sandbox, 'live' for production",
    )
    project_id = serializers.UUIDField(
        required=False,
        write_only=True,
        help_text="Project ID. Defaults to the organization's primary project when one exists.",
    )
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_name = serializers.CharField(
        source="project.name",
        read_only=True,
        allow_null=True,
    )
    project_slug = serializers.CharField(
        source="project.slug",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "environment",
            "scopes",
            "expires_at",
            "project_id",
            "project",
            "project_name",
            "project_slug",
            "key",
            "created_at",
        ]
        read_only_fields = ["id", "key", "created_at"]

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Expiration must be in the future.")
        return value

    def validate_scopes(self, value):
        normalized = []
        for scope in value or []:
            cleaned = str(scope).strip().lower()
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)

        if not normalized:
            raise serializers.ValidationError("At least one API key scope is required.")

        supported_scopes = set(APIKey.get_supported_scopes())
        invalid_scopes = [scope for scope in normalized if scope not in supported_scopes]
        if invalid_scopes:
            raise serializers.ValidationError(
                f"Unsupported API key scopes: {', '.join(invalid_scopes)}."
            )

        return normalized

    def validate(self, attrs):
        attrs = super().validate(attrs)
        organization = self.context.get("organization")
        project_id = attrs.pop("project_id", None)

        if organization is None:
            raise serializers.ValidationError("Organization context is required.")

        if project_id is None:
            attrs["project"] = getattr(self.instance, "project", None)
            if attrs["project"] is None:
                attrs["project"] = organization.get_default_project()
            if attrs["project"] is None:
                raise serializers.ValidationError(
                    {
                        "project_id": [
                            "Create a project first, then issue an API key for it."
                        ]
                    }
                )
            self._validate_project_api_key_limit(attrs["project"])
            return attrs

        try:
            project = Project.objects.get(id=project_id, organization=organization)
        except Project.DoesNotExist as exc:
            raise serializers.ValidationError(
                {"project_id": ["Select a valid project in the current organization."]}
            ) from exc

        attrs["project"] = project
        self._validate_project_api_key_limit(project)
        return attrs

    def _validate_project_api_key_limit(self, project):
        if self.instance is not None:
            return

        max_keys = int(getattr(settings, "API_KEY_MAX_PER_PROJECT", 25) or 25)
        if max_keys <= 0:
            return

        existing_count = APIKey.objects.filter(project=project).count()
        if existing_count >= max_keys:
            raise serializers.ValidationError(
                {
                    "detail": (
                        f"This project has reached the API key limit of {max_keys}."
                    )
                }
            )

    def create(self, validated_data):
        environment = validated_data.pop("environment", "test")
        # Generate the key
        prefix, full_key, hashed_key = APIKey.generate_key(environment=environment)

        # Create the API Key object (organization and created_by come from perform_create)
        api_key = APIKey.objects.create(
            prefix=prefix,
            hashed_key=hashed_key,
            environment=environment,
            **validated_data,
        )

        # Attach the full key to the instance for the response(not saved)

        api_key.key = full_key
        return api_key


class APIKeyListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing API Keys (no sensitive data).
    """

    environment_display = serializers.CharField(
        source="get_environment_display", read_only=True
    )
    status = serializers.CharField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_valid = serializers.BooleanField(read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_name = serializers.CharField(
        source="project.name",
        read_only=True,
        allow_null=True,
    )
    project_slug = serializers.CharField(
        source="project.slug",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "prefix",
            "environment",
            "environment_display",
            "project",
            "project_name",
            "project_slug",
            "scopes",
            "is_active",
            "status",
            "is_expired",
            "is_valid",
            "expires_at",
            "last_used_at",
            "created_at",
        ]

        read_only_fields = ["id", "prefix", "environment", "last_used_at", "created_at"]


class WebhookSerializer(serializers.ModelSerializer):
    project_id = serializers.UUIDField(
        required=False,
        write_only=True,
        help_text="Project ID. Defaults to the organization's primary project when one exists.",
    )
    project = serializers.UUIDField(source="project_id", read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)
    project_slug = serializers.CharField(source="project.slug", read_only=True)

    class Meta:
        model = Webhook
        fields = [
            "id",
            "project_id",
            "project",
            "project_name",
            "project_slug",
            "url",
            "events",
            "secret",
            "description",
            "is_active",
            "created_at",
            "last_triggered_at",
            "success_count",
            "failure_count",
            "consecutive_failures",
        ]
        read_only_fields = [
            "id",
            "project",
            "project_name",
            "project_slug",
            "secret",
            "created_at",
            "last_triggered_at",
            "success_count",
            "failure_count",
            "consecutive_failures",
        ]

    def validate_events(self, value):
        normalized = []
        for event_name in value or []:
            cleaned = str(event_name).strip()
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)

        allowed_events = set(Webhook.EventType.values)
        invalid_events = [event_name for event_name in normalized if event_name not in allowed_events]
        if invalid_events:
            raise serializers.ValidationError(
                f"Unsupported webhook events: {', '.join(invalid_events)}."
            )

        return normalized

    def validate(self, attrs):
        attrs = super().validate(attrs)
        organization = self.context.get("organization")
        project_id = attrs.pop("project_id", None)

        if organization is None:
            raise serializers.ValidationError("Organization context is required.")

        if project_id is None:
            attrs["project"] = getattr(self.instance, "project", None)
            if attrs["project"] is None:
                attrs["project"] = organization.get_default_project()
            if attrs["project"] is None:
                raise serializers.ValidationError(
                    {
                        "project_id": [
                            "Create a project first, then add a webhook for it."
                        ]
                    }
                )
            return attrs

        try:
            project = Project.objects.get(id=project_id, organization=organization)
        except Project.DoesNotExist as exc:
            raise serializers.ValidationError(
                {"project_id": ["Select a valid project in the current organization."]}
            ) from exc

        attrs["project"] = project
        return attrs


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Read-only serializer for webhook delivery attempts."""

    class Meta:
        model = WebhookDelivery
        fields = [
            "id",
            "event_type",
            "payload",
            "status",
            "response_status_code",
            "response_body",
            "error_message",
            "attempt_count",
            "max_attempts",
            "next_retry_at",
            "created_at",
            "delivered_at",
        ]
        read_only_fields = fields


class OrganizationInvitationCreateSerializer(serializers.ModelSerializer):
    """Create serializer for organization invitations."""

    accept_url = serializers.SerializerMethodField(read_only=True)
    expires_at = serializers.DateTimeField(required=False)
    project_id = serializers.UUIDField(
        required=False,
        allow_null=True,
        write_only=True,
    )
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_name = serializers.CharField(
        source="project.name",
        read_only=True,
        allow_null=True,
    )
    project_slug = serializers.CharField(
        source="project.slug",
        read_only=True,
        allow_null=True,
    )
    app_role_ids = serializers.ListField(
        child=serializers.UUIDField(),
        write_only=True,
        required=False,
        allow_empty=True,
    )
    app_roles = ProjectRoleSummarySerializer(many=True, read_only=True)

    class Meta:
        model = OrganizationInvitation
        fields = [
            "id",
            "email",
            "role",
            "project_id",
            "project",
            "project_name",
            "project_slug",
            "app_role_ids",
            "app_roles",
            "expires_at",
            "accept_url",
            "created_at",
        ]
        read_only_fields = ["id", "accept_url", "created_at"]

    def validate_email(self, value):
        return (value or "").strip().lower()

    def validate_expires_at(self, value):
        if value <= timezone.now():
            raise serializers.ValidationError("Expiration must be in the future.")
        return value

    def validate(self, attrs):
        organization = self.context["organization"]
        email = attrs.get("email", "").strip().lower()
        project_id = attrs.pop("project_id", None)
        app_role_ids = attrs.pop("app_role_ids", None)

        if OrganizationInvitation.objects.filter(
            organization=organization,
            email=email,
            accepted_at__isnull=True,
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
        ).exists():
            raise serializers.ValidationError(
                {"email": ["There is already a pending invitation for this email."]}
            )

        if organization.owner and organization.owner.email.lower() == email:
            raise serializers.ValidationError(
                {"email": ["The organization owner does not need an invitation."]}
            )

        project = None
        if project_id is not None:
            try:
                project = Project.objects.get(id=project_id, organization=organization)
            except Project.DoesNotExist as exc:
                raise serializers.ValidationError(
                    {"project_id": ["Select a valid project in the current organization."]}
                ) from exc

        if app_role_ids:
            if project is None:
                raise serializers.ValidationError(
                    {"project_id": ["A project is required when inviting app roles."]}
                )
            app_roles = list(ProjectRole.objects.filter(project=project, id__in=app_role_ids))
            found_ids = {role.id for role in app_roles}
            if any(role_id not in found_ids for role_id in app_role_ids):
                raise serializers.ValidationError(
                    {"app_role_ids": ["Select valid app roles in the selected project."]}
                )
            attrs["app_roles"] = app_roles
        else:
            attrs["app_roles"] = []

        attrs["project"] = project
        return attrs

    def create(self, validated_data):
        app_roles = validated_data.pop("app_roles", [])
        if "expires_at" not in validated_data:
            validated_data["expires_at"] = timezone.now() + timedelta(days=7)
        invitation = super().create(validated_data)
        if app_roles:
            invitation.app_roles.set(app_roles)
        return invitation

    @extend_schema_field(serializers.URLField())
    def get_accept_url(self, obj) -> str:
        return f"{settings.FRONTEND_URL}/invite?token={obj.token}"


class OrganizationInvitationSerializer(serializers.ModelSerializer):
    """Read serializer for organization invitations."""

    status = serializers.CharField(read_only=True)
    accept_url = serializers.SerializerMethodField(read_only=True)
    invited_by_email = serializers.EmailField(source="invited_by.email", read_only=True)
    accepted_by_email = serializers.EmailField(source="accepted_by.email", read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_name = serializers.CharField(
        source="project.name",
        read_only=True,
        allow_null=True,
    )
    project_slug = serializers.CharField(
        source="project.slug",
        read_only=True,
        allow_null=True,
    )
    app_roles = ProjectRoleSummarySerializer(many=True, read_only=True)

    class Meta:
        model = OrganizationInvitation
        fields = [
            "id",
            "email",
            "role",
            "project",
            "project_name",
            "project_slug",
            "app_roles",
            "status",
            "accept_url",
            "invited_by_email",
            "accepted_by_email",
            "expires_at",
            "accepted_at",
            "revoked_at",
            "created_at",
        ]
        read_only_fields = fields

    @extend_schema_field(serializers.URLField())
    def get_accept_url(self, obj) -> str:
        return f"{settings.FRONTEND_URL}/invite?token={obj.token}"


class OrganizationInvitationPublicSerializer(serializers.ModelSerializer):
    """Public invitation preview serializer for the frontend accept page."""

    status = serializers.CharField(read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    organization_slug = serializers.CharField(source="organization.slug", read_only=True)
    invited_by_email = serializers.EmailField(source="invited_by.email", read_only=True)
    project = serializers.UUIDField(source="project_id", read_only=True, allow_null=True)
    project_name = serializers.CharField(
        source="project.name",
        read_only=True,
        allow_null=True,
    )
    project_slug = serializers.CharField(
        source="project.slug",
        read_only=True,
        allow_null=True,
    )
    app_roles = ProjectRoleSummarySerializer(many=True, read_only=True)

    class Meta:
        model = OrganizationInvitation
        fields = [
            "email",
            "role",
            "project",
            "project_name",
            "project_slug",
            "app_roles",
            "status",
            "organization_name",
            "organization_slug",
            "invited_by_email",
            "expires_at",
            "accepted_at",
            "revoked_at",
            "created_at",
        ]
        read_only_fields = fields


class OrganizationInvitationAcceptSerializer(serializers.Serializer):
    """Serializer for accepting an invitation by token."""

    token = serializers.CharField(max_length=128)


class RuntimeInvitationCreateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role_slugs = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False,
    )
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)

    def validate_email(self, value):
        return (value or "").strip().lower()

    def validate(self, attrs):
        project = self.context["project"]
        role_slugs = validate_no_control_plane_role_slugs(
            attrs.get("role_slugs", []),
            field_name="role_slugs",
            message="Control plane roles cannot be used in runtime invitations",
        )
        roles, normalized_role_slugs = resolve_project_roles_or_error(
            project,
            role_slugs,
            field_name="role_slugs",
            invalid_message_prefix="These roles do not exist in this project: ",
        )
        attrs["role_slugs"] = normalized_role_slugs
        attrs["roles"] = roles
        return attrs


class RuntimeInvitationSerializer(serializers.ModelSerializer):
    project = serializers.UUIDField(source="project_id", read_only=True)
    project_slug = serializers.CharField(source="project.slug", read_only=True)

    class Meta:
        model = RuntimeInvitation
        fields = [
            "id",
            "project",
            "project_slug",
            "email",
            "role_slugs",
            "status",
            "expires_at",
            "accepted_at",
            "created_at",
        ]
        read_only_fields = fields


class RuntimeInvitationAcceptSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)
    password1 = serializers.CharField(trim_whitespace=False, write_only=True)
    password2 = serializers.CharField(trim_whitespace=False, write_only=True)

    def validate(self, attrs):
        password1 = attrs.get("password1", "")
        password2 = attrs.get("password2", "")
        if password1 != password2:
            raise serializers.ValidationError(
                {"password2": ["The two password fields didn't match."]}
            )

        try:
            get_adapter().clean_password(password1)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(
                serializers.as_serializer_error(exc)
            ) from exc
        return attrs
