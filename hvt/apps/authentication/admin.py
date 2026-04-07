from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = [
        "created_at",
        "event_type",
        "actor_display",
        "organization",
        "project",
        "target_display",
        "success",
        "ip_address",
    ]
    list_filter = ["event_type", "success", "created_at", "organization", "project"]
    search_fields = [
        "actor_user__email",
        "actor_api_key__name",
        "organization__name",
        "project__name",
        "ip_address",
        "event_data",
        "error_message",
    ]
    readonly_fields = [
        "id",
        "event_type",
        "event_data",
        "actor_user",
        "actor_api_key",
        "target_display",
        "target_content_type",
        "target_object_id",
        "organization",
        "project",
        "ip_address",
        "user_agent",
        "success",
        "error_message",
        "created_at",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    list_select_related = [
        "actor_user",
        "actor_api_key",
        "organization",
        "project",
        "target_content_type",
    ]

    @admin.display(description="Actor")
    def actor_display(self, obj):
        if obj.actor_user:
            return f"User: {obj.actor_user.email}"
        if obj.actor_api_key:
            return f"API Key: {obj.actor_api_key.name}"
        return "Unknown"

    @admin.display(description="Target")
    def target_display(self, obj):
        if obj.target_object:
            return str(obj.target_object)
        if obj.target_content_type and obj.target_object_id:
            return f"{obj.target_content_type}: {obj.target_object_id}"
        return "N/A"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
