from django.contrib import admin
from .models import Organization, APIKey

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "is_active", "allow_signup", "created_at"]
    list_filter = ["is_active", "allow_signup"]
    search_fields = ["name", "slug"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["-created_at"]

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ["name", "prefix", "organization", "is_active", "expires_at", "last_used_at", "created_at"]
    list_filter = ["is_active", "organization"]
    search_fields = ["name", "prefix", "organization__name"]
    readonly_fields = ["prefix", "hashed_key", "last_used_at", "created_by"]
    ordering= ["-created_at"]