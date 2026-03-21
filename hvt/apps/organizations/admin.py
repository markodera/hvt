from django.contrib import admin
from .models import Organization, APIKey, Webhook, WebhookDelivery


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "is_active", "allow_signup", "created_at"]
    list_filter = ["is_active", "allow_signup"]
    search_fields = ["name", "slug"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["-created_at"]


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "prefix",
        "organization",
        "is_active",
        "expires_at",
        "last_used_at",
        "created_at",
    ]
    list_filter = ["is_active", "organization"]
    search_fields = ["name", "prefix", "organization__name"]
    readonly_fields = ["prefix", "hashed_key", "last_used_at", "created_by"]
    ordering = ["-created_at"]


@admin.register(Webhook)
class WebhookAdmin(admin.ModelAdmin):
    list_display = [
        "url",
        "organization",
        "is_active",
        "success_count",
        "failure_count",
        "consecutive_failures",
        "last_triggered_at",
        "created_at",
    ]
    list_filter = ["is_active", "organization"]
    search_fields = ["url", "organization__name", "description"]
    readonly_fields = [
        "secret",
        "success_count",
        "failure_count",
        "consecutive_failures",
        "last_triggered_at",
        "created_by",
    ]
    ordering = ["-created_at"]


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = [
        "event_type",
        "webhook",
        "status",
        "response_status_code",
        "attempt_count",
        "created_at",
        "delivered_at",
    ]
    list_filter = ["status", "event_type"]
    search_fields = ["webhook__url", "event_type"]
    readonly_fields = [
        "webhook",
        "event_type",
        "payload",
        "request_headers",
        "request_body",
        "response_status_code",
        "response_headers",
        "response_body",
        "error_message",
        "attempt_count",
        "delivered_at",
    ]
    ordering = ["-created_at"]
