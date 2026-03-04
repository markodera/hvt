from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = [
        "created_at",
        "event_type",
        "actor_display",
        "organization",
        "success",
        "ip_address",
    ]
    list_filter = ["event_type", "success", "created_at", "organization"]
    search_fields = ["actor_user__email", "ip_address", "event_data"]
    readonly_fields = [
        "id",
        "event_type",
        "event_data",
        "actor_user",
        "actor_api_key",
        "target_content_type",
        "target_object_id",
        "organization",
        "ip_address",
        "user_agent",
        "success",
        "error_message",
        "created_at",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"

    def actor_display(self, obj):
        if obj.actor_user:
            return f"User: {obj.actor_user.email}"
        elif obj.actor_api_key:
            return f"API Key: {obj.actor_api_key.name}"
        return "Unknown"

    actor_display.short_description = "Actor"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
