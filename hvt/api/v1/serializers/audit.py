from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from hvt.apps.authentication.models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for audit log entries."""

    actor_email = serializers.SerializerMethodField()
    actor_api_key_name = serializers.SerializerMethodField()
    target_type = serializers.SerializerMethodField()
    ip_address = serializers.CharField(allow_null=True, read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "event_type",
            "event_data",
            "actor_email",
            "actor_api_key_name",
            "target_type",
            "target_object_id",
            "organization",
            "ip_address",
            "user_agent",
            "success",
            "error_message",
            "created_at",
        ]
        read_only_fields = fields

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_actor_email(self, obj) -> str | None:
        if obj.actor_user:
            return obj.actor_user.email
        return None

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_actor_api_key_name(self, obj) -> str | None:
        if obj.actor_api_key:
            return obj.actor_api_key.name
        return None

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_target_type(self, obj) -> str | None:
        if obj.target_content_type:
            return obj.target_content_type.model
        return None
