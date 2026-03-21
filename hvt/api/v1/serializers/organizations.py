from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from hvt.apps.organizations.models import Organization, APIKey, Webhook, WebhookDelivery


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

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "environment",
            "scopes",
            "expires_at",
            "key",
            "created_at",
        ]
        read_only_fields = ["id", "key", "created_at"]

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

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "prefix",
            "environment",
            "environment_display",
            "scopes",
            "is_active",
            "expires_at",
            "last_used_at",
            "created_at",
        ]

        read_only_fields = ["id", "prefix", "environment", "last_used_at", "created_at"]


class WebhookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Webhook
        fields = [
            "id",
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
            "secret",
            "created_at",
            "last_triggered_at",
            "success_count",
            "failure_count",
            "consecutive_failures",
        ]


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
