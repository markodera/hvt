from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from hvt.apps.organizations.models import (
    Organization,
    Project,
    APIKey,
    SocialProviderConfig,
    Webhook,
    WebhookDelivery,
    OrganizationInvitation,
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

    class Meta:
        model = Project
        fields = [
            "id",
            "name",
            "slug",
            "is_default",
            "is_active",
            "allow_signup",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "is_default", "created_at", "updated_at"]


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
        help_text="Optional project ID. Defaults to the organization's default project.",
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
            attrs["project"] = getattr(
                self.instance,
                "project",
                organization.ensure_default_project(),
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
            "expires_at",
            "last_used_at",
            "created_at",
        ]

        read_only_fields = ["id", "prefix", "environment", "last_used_at", "created_at"]


class WebhookSerializer(serializers.ModelSerializer):
    project_id = serializers.UUIDField(
        required=False,
        write_only=True,
        help_text="Optional project ID. Defaults to the organization's default project.",
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

    def validate(self, attrs):
        attrs = super().validate(attrs)
        organization = self.context.get("organization")
        project_id = attrs.pop("project_id", None)

        if organization is None:
            raise serializers.ValidationError("Organization context is required.")

        if project_id is None:
            attrs["project"] = getattr(
                self.instance,
                "project",
                organization.ensure_default_project(),
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

    class Meta:
        model = OrganizationInvitation
        fields = [
            "id",
            "email",
            "role",
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

        return attrs

    def create(self, validated_data):
        if "expires_at" not in validated_data:
            validated_data["expires_at"] = timezone.now() + timedelta(days=7)
        return super().create(validated_data)

    @extend_schema_field(serializers.URLField())
    def get_accept_url(self, obj) -> str:
        return f"{settings.FRONTEND_URL}/invite?token={obj.token}"


class OrganizationInvitationSerializer(serializers.ModelSerializer):
    """Read serializer for organization invitations."""

    status = serializers.CharField(read_only=True)
    accept_url = serializers.SerializerMethodField(read_only=True)
    invited_by_email = serializers.EmailField(source="invited_by.email", read_only=True)
    accepted_by_email = serializers.EmailField(source="accepted_by.email", read_only=True)

    class Meta:
        model = OrganizationInvitation
        fields = [
            "id",
            "email",
            "role",
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

    class Meta:
        model = OrganizationInvitation
        fields = [
            "email",
            "role",
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
