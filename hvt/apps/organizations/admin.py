from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.db.models import Count
from django.utils import timezone
from django.utils.html import format_html

from .models import (
    APIKey,
    Organization,
    OrganizationInvitation,
    Project,
    ProjectPermission,
    ProjectRole,
    ProjectRolePermission,
    SocialProviderConfig,
    UserProjectRole,
    Webhook,
    WebhookDelivery,
)


def render_badge(label, tone="neutral"):
    return format_html(
        '<span class="hvt-admin-badge hvt-admin-badge--{}">{}</span>',
        tone,
        label,
    )


class OrganizationProjectValidationMixin:
    def clean(self):
        cleaned_data = super().clean()
        organization = cleaned_data.get("organization")
        project = cleaned_data.get("project")

        if project and not organization:
            self.add_error(
                "organization",
                "Select an organization when assigning a project.",
            )
        elif project and organization and project.organization_id != organization.id:
            self.add_error(
                "project",
                "Selected project must belong to the selected organization.",
            )

        return cleaned_data


class APIKeyAdminForm(OrganizationProjectValidationMixin, forms.ModelForm):
    class Meta:
        model = APIKey
        fields = "__all__"


class WebhookAdminForm(OrganizationProjectValidationMixin, forms.ModelForm):
    class Meta:
        model = Webhook
        fields = "__all__"


class OrganizationInvitationAdminForm(
    OrganizationProjectValidationMixin,
    forms.ModelForm,
):
    class Meta:
        model = OrganizationInvitation
        fields = "__all__"

    def clean(self):
        cleaned_data = super().clean()
        project = cleaned_data.get("project")
        app_roles = cleaned_data.get("app_roles")

        if app_roles and not project:
            self.add_error(
                "project",
                "Select a project before attaching app roles to the invitation.",
            )
        elif project and app_roles:
            invalid_roles = [
                role.name
                for role in app_roles
                if role.project_id != project.id
            ]
            if invalid_roles:
                self.add_error(
                    "app_roles",
                    "Selected app roles must belong to the chosen project.",
                )

        return cleaned_data


class InvitationStatusFilter(admin.SimpleListFilter):
    title = "status"
    parameter_name = "status"

    def lookups(self, request, model_admin):
        return (
            ("pending", "Pending"),
            ("accepted", "Accepted"),
            ("revoked", "Revoked"),
            ("expired", "Expired"),
        )

    def queryset(self, request, queryset):
        value = self.value()
        now = timezone.now()

        if value == "pending":
            return queryset.filter(
                accepted_at__isnull=True,
                revoked_at__isnull=True,
                expires_at__gt=now,
            )
        if value == "accepted":
            return queryset.filter(accepted_at__isnull=False)
        if value == "revoked":
            return queryset.filter(revoked_at__isnull=False)
        if value == "expired":
            return queryset.filter(
                accepted_at__isnull=True,
                revoked_at__isnull=True,
                expires_at__lte=now,
            )
        return queryset


class ProjectInline(admin.TabularInline):
    model = Project
    extra = 0
    fields = ("name", "slug", "is_default", "is_active", "allow_signup", "created_at")
    readonly_fields = ("created_at",)
    show_change_link = True
    ordering = ("name",)


class SocialProviderConfigInline(admin.TabularInline):
    model = SocialProviderConfig
    extra = 0
    fields = ("provider", "client_id", "is_active", "created_at")
    readonly_fields = ("created_at",)
    show_change_link = True


class ProjectRolePermissionInline(admin.TabularInline):
    model = ProjectRolePermission
    extra = 0
    autocomplete_fields = ("permission",)
    fields = ("permission", "created_at")
    readonly_fields = ("created_at",)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "slug",
        "owner",
        "is_active",
        "allow_signup",
        "project_total",
        "user_total",
        "created_at",
    ]
    list_filter = ["is_active", "allow_signup", "created_at"]
    search_fields = ["name", "slug", "owner__email"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["owner"]
    readonly_fields = ["project_total", "user_total", "created_at", "updated_at"]
    list_select_related = ["owner"]
    inlines = [ProjectInline]
    fieldsets = (
        ("Organization", {"fields": ("name", "slug", "owner")}),
        ("Controls", {"fields": ("is_active", "allow_signup")}),
        ("Summary", {"fields": ("project_total", "user_total")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related("owner").annotate(
            project_total_count=Count("projects", distinct=True),
            user_total_count=Count("users", distinct=True),
        )

    @admin.display(description="Projects", ordering="project_total_count")
    def project_total(self, obj):
        return getattr(obj, "project_total_count", obj.projects.count())

    @admin.display(description="Users", ordering="user_total_count")
    def user_total(self, obj):
        return getattr(obj, "user_total_count", obj.users.count())


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "slug",
        "organization",
        "is_default",
        "is_active",
        "allow_signup",
        "role_total",
        "permission_total",
        "user_total",
        "created_at",
    ]
    list_filter = ["organization", "is_default", "is_active", "allow_signup"]
    search_fields = ["name", "slug", "organization__name", "organization__slug"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["organization__name", "name"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["organization"]
    readonly_fields = [
        "role_total",
        "permission_total",
        "user_total",
        "created_at",
        "updated_at",
    ]
    list_select_related = ["organization"]
    inlines = [SocialProviderConfigInline]
    fieldsets = (
        ("Project", {"fields": ("organization", "name", "slug")}),
        ("Controls", {"fields": ("is_default", "is_active", "allow_signup")}),
        ("Summary", {"fields": ("role_total", "permission_total", "user_total")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related("organization").annotate(
            role_total_count=Count("app_roles", distinct=True),
            permission_total_count=Count("app_permissions", distinct=True),
            user_total_count=Count("users", distinct=True),
        )

    @admin.display(description="Roles", ordering="role_total_count")
    def role_total(self, obj):
        return getattr(obj, "role_total_count", obj.app_roles.count())

    @admin.display(description="Permissions", ordering="permission_total_count")
    def permission_total(self, obj):
        return getattr(obj, "permission_total_count", obj.app_permissions.count())

    @admin.display(description="Users", ordering="user_total_count")
    def user_total(self, obj):
        return getattr(obj, "user_total_count", obj.users.count())


@admin.register(ProjectPermission)
class ProjectPermissionAdmin(admin.ModelAdmin):
    list_display = ["slug", "name", "project", "organization_name", "created_at"]
    list_filter = ["project", "created_at"]
    search_fields = [
        "slug",
        "name",
        "project__name",
        "project__organization__name",
    ]
    ordering = ["project__organization__name", "project__name", "slug"]
    autocomplete_fields = ["project"]
    readonly_fields = ["organization_name", "created_at", "updated_at"]
    list_select_related = ["project", "project__organization"]
    fieldsets = (
        ("Permission", {"fields": ("project", "slug", "name", "description")}),
        ("Context", {"fields": ("organization_name",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="Organization", ordering="project__organization__name")
    def organization_name(self, obj):
        return obj.project.organization


@admin.register(ProjectRole)
class ProjectRoleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "slug",
        "project",
        "organization_name",
        "is_default_signup",
        "permission_total",
        "assignment_total",
        "created_at",
    ]
    list_filter = ["project", "is_default_signup", "created_at"]
    search_fields = [
        "slug",
        "name",
        "description",
        "project__name",
        "project__organization__name",
    ]
    ordering = ["project__organization__name", "project__name", "name", "slug"]
    autocomplete_fields = ["project"]
    exclude = ["permissions"]
    readonly_fields = [
        "organization_name",
        "permission_total",
        "assignment_total",
        "created_at",
        "updated_at",
    ]
    list_select_related = ["project", "project__organization"]
    inlines = [ProjectRolePermissionInline]
    fieldsets = (
        (
            "Role",
            {
                "fields": (
                    "project",
                    "slug",
                    "name",
                    "description",
                    "is_default_signup",
                )
            },
        ),
        ("Summary", {"fields": ("organization_name", "permission_total", "assignment_total")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related("project", "project__organization").annotate(
            permission_total_count=Count("permission_links", distinct=True),
            assignment_total_count=Count("assignments", distinct=True),
        )

    @admin.display(description="Organization", ordering="project__organization__name")
    def organization_name(self, obj):
        return obj.project.organization

    @admin.display(description="Permissions", ordering="permission_total_count")
    def permission_total(self, obj):
        return getattr(obj, "permission_total_count", obj.permission_links.count())

    @admin.display(description="Assignments", ordering="assignment_total_count")
    def assignment_total(self, obj):
        return getattr(obj, "assignment_total_count", obj.assignments.count())


@admin.register(ProjectRolePermission)
class ProjectRolePermissionAdmin(admin.ModelAdmin):
    list_display = [
        "role",
        "permission",
        "project_name",
        "organization_name",
        "created_at",
    ]
    list_filter = ["created_at", "role"]
    search_fields = [
        "role__name",
        "role__slug",
        "permission__name",
        "permission__slug",
        "role__project__name",
        "role__project__organization__name",
    ]
    ordering = ["-created_at"]
    autocomplete_fields = ["role", "permission"]
    readonly_fields = ["project_name", "organization_name", "created_at"]
    list_select_related = [
        "role",
        "role__project",
        "role__project__organization",
        "permission",
    ]
    fieldsets = (
        ("Link", {"fields": ("role", "permission")}),
        ("Context", {"fields": ("project_name", "organization_name")}),
        ("Timestamp", {"fields": ("created_at",)}),
    )

    @admin.display(description="Project", ordering="role__project__name")
    def project_name(self, obj):
        return obj.role.project

    @admin.display(description="Organization", ordering="role__project__organization__name")
    def organization_name(self, obj):
        return obj.role.project.organization


@admin.register(UserProjectRole)
class UserProjectRoleAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "role",
        "project_name",
        "organization_name",
        "assigned_by",
        "created_at",
    ]
    list_filter = ["created_at", "role"]
    search_fields = [
        "user__email",
        "role__name",
        "role__slug",
        "role__project__name",
        "role__project__organization__name",
        "assigned_by__email",
    ]
    ordering = ["-created_at"]
    autocomplete_fields = ["user", "role", "assigned_by"]
    readonly_fields = ["project_name", "organization_name", "created_at"]
    list_select_related = [
        "user",
        "role",
        "role__project",
        "role__project__organization",
        "assigned_by",
    ]
    fieldsets = (
        ("Assignment", {"fields": ("user", "role", "assigned_by")}),
        ("Context", {"fields": ("project_name", "organization_name")}),
        ("Timestamp", {"fields": ("created_at",)}),
    )

    @admin.display(description="Project", ordering="role__project__name")
    def project_name(self, obj):
        return obj.role.project

    @admin.display(description="Organization", ordering="role__project__organization__name")
    def organization_name(self, obj):
        return obj.role.project.organization


@admin.register(SocialProviderConfig)
class SocialProviderConfigAdmin(admin.ModelAdmin):
    list_display = [
        "provider",
        "project",
        "organization_name",
        "client_id",
        "redirect_uri_total",
        "is_active",
        "updated_at",
    ]
    list_filter = ["provider", "is_active", "project"]
    search_fields = [
        "provider",
        "client_id",
        "project__name",
        "project__organization__name",
    ]
    ordering = ["provider", "project__organization__name", "project__name"]
    autocomplete_fields = ["project"]
    readonly_fields = [
        "organization_name",
        "redirect_uri_total",
        "created_at",
        "updated_at",
    ]
    list_select_related = ["project", "project__organization"]
    fieldsets = (
        (
            "Provider",
            {
                "fields": (
                    "project",
                    "provider",
                    "client_id",
                    "client_secret",
                    "redirect_uris",
                    "is_active",
                )
            },
        ),
        ("Context", {"fields": ("organization_name", "redirect_uri_total")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="Organization", ordering="project__organization__name")
    def organization_name(self, obj):
        return obj.project.organization

    @admin.display(description="Redirect URIs")
    def redirect_uri_total(self, obj):
        return len(obj.redirect_uris or [])


@admin.register(OrganizationInvitation)
class OrganizationInvitationAdmin(admin.ModelAdmin):
    form = OrganizationInvitationAdminForm
    list_display = [
        "email",
        "organization",
        "project",
        "role",
        "status_badge",
        "invited_by",
        "accepted_by",
        "expires_at",
        "created_at",
    ]
    list_filter = [InvitationStatusFilter, "organization", "role", "created_at"]
    search_fields = [
        "email",
        "organization__name",
        "project__name",
        "invited_by__email",
        "accepted_by__email",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["organization", "project", "invited_by", "accepted_by"]
    filter_horizontal = ["app_roles"]
    readonly_fields = ["token", "status_badge", "created_at", "updated_at"]
    list_select_related = ["organization", "project", "invited_by", "accepted_by"]
    fieldsets = (
        (
            "Invitation",
            {
                "fields": (
                    "organization",
                    "project",
                    "email",
                    "role",
                    "app_roles",
                    "token",
                    "status_badge",
                )
            },
        ),
        ("Actors", {"fields": ("invited_by", "accepted_by")}),
        ("Lifecycle", {"fields": ("expires_at", "accepted_at", "revoked_at")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="Status")
    @admin.display(description="Status")
    def status_badge(self, obj):
        if obj is None:
            return render_badge("Pending", "info")

        tones = {
            "pending": "info",
            "accepted": "success",
            "revoked": "danger",
            "expired": "warning",
        }
        return render_badge(obj.status.title(), tones.get(obj.status, "neutral"))


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    form = APIKeyAdminForm
    list_display = [
        "name",
        "prefix",
        "organization",
        "project",
        "environment",
        "scope_total",
        "state_badge",
        "expires_at",
        "last_used_at",
        "created_at",
    ]
    list_filter = ["environment", "is_active", "organization", "project"]
    search_fields = [
        "name",
        "prefix",
        "organization__name",
        "project__name",
        "created_by__email",
    ]
    readonly_fields = [
        "prefix",
        "hashed_key",
        "scope_total",
        "last_used_at",
        "created_at",
        "created_by",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["organization", "project", "created_by"]
    list_select_related = ["organization", "project", "created_by"]
    fieldsets = (
        (
            "Key",
            {
                "fields": (
                    "organization",
                    "project",
                    "environment",
                    "name",
                    "prefix",
                    "hashed_key",
                    "scopes",
                    "scope_total",
                    "is_active",
                    "expires_at",
                )
            },
        ),
        ("Activity", {"fields": ("last_used_at", "created_at", "created_by")}),
    )

    @admin.display(description="Scopes")
    def scope_total(self, obj):
        return len(obj.scopes or [])

    @admin.display(description="State")
    def state_badge(self, obj):
        if not obj.is_active:
            return render_badge("Inactive", "danger")
        if obj.expires_at and obj.expires_at <= timezone.now():
            return render_badge("Expired", "warning")
        return render_badge("Active", "success")

    def save_model(self, request, obj, form, change):
        generated_key = None

        if not obj.created_by_id and getattr(request.user, "is_authenticated", False):
            obj.created_by = request.user

        if not change and not obj.prefix and not obj.hashed_key:
            prefix, generated_key, hashed_key = APIKey.generate_key(obj.environment)
            obj.prefix = prefix
            obj.hashed_key = hashed_key

        super().save_model(request, obj, form, change)

        if generated_key:
            self.message_user(
                request,
                f"API key created. Copy this secret now: {generated_key}",
                level=messages.WARNING,
            )


@admin.register(Webhook)
class WebhookAdmin(admin.ModelAdmin):
    form = WebhookAdminForm
    list_display = [
        "url",
        "organization",
        "project",
        "is_active",
        "success_count",
        "failure_count",
        "health_badge",
        "last_triggered_at",
        "created_at",
    ]
    list_filter = ["organization", "project", "is_active"]
    search_fields = ["url", "organization__name", "project__name", "description"]
    readonly_fields = [
        "secret",
        "success_count",
        "failure_count",
        "consecutive_failures",
        "last_triggered_at",
        "created_at",
        "created_by",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["organization", "project", "created_by"]
    list_select_related = ["organization", "project", "created_by"]
    fieldsets = (
        (
            "Webhook",
            {
                "fields": (
                    "organization",
                    "project",
                    "url",
                    "events",
                    "secret",
                    "description",
                    "is_active",
                )
            },
        ),
        (
            "Delivery Health",
            {
                "fields": (
                    "success_count",
                    "failure_count",
                    "consecutive_failures",
                    "last_triggered_at",
                )
            },
        ),
        ("Created", {"fields": ("created_at", "created_by")}),
    )

    @admin.display(description="Health")
    def health_badge(self, obj):
        if not obj.is_active:
            return render_badge("Disabled", "neutral")
        if obj.consecutive_failures >= 5:
            return render_badge("Degraded", "warning")
        return render_badge("Healthy", "success")

    def save_model(self, request, obj, form, change):
        generated_secret = None

        if not obj.created_by_id and getattr(request.user, "is_authenticated", False):
            obj.created_by = request.user

        if not change and not obj.secret:
            generated_secret = Webhook.generate_secret()
            obj.secret = generated_secret

        super().save_model(request, obj, form, change)

        if generated_secret:
            self.message_user(
                request,
                f"Webhook created. Copy this signing secret now: {generated_secret}",
                level=messages.WARNING,
            )


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = [
        "event_type",
        "webhook",
        "status_badge",
        "response_status_code",
        "attempt_count",
        "next_retry_at",
        "created_at",
        "delivered_at",
    ]
    list_filter = ["status", "event_type", "created_at"]
    search_fields = [
        "webhook__url",
        "webhook__project__name",
        "webhook__organization__name",
        "event_type",
    ]
    readonly_fields = [
        "webhook",
        "event_type",
        "payload",
        "request_headers",
        "request_body",
        "status",
        "response_status_code",
        "response_headers",
        "response_body",
        "error_message",
        "attempt_count",
        "max_attempts",
        "next_retry_at",
        "created_at",
        "delivered_at",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    list_select_related = ["webhook", "webhook__organization", "webhook__project"]

    @admin.display(description="Status")
    def status_badge(self, obj):
        tones = {
            WebhookDelivery.Status.PENDING: "neutral",
            WebhookDelivery.Status.SUCCESS: "success",
            WebhookDelivery.Status.FAILED: "danger",
            WebhookDelivery.Status.RETRYING: "warning",
        }
        return render_badge(obj.get_status_display(), tones.get(obj.status, "neutral"))

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.site_header = "HVT Control Plane"
admin.site.site_title = "HVT Admin"
admin.site.index_title = "Control plane operations"
admin.site.site_url = getattr(settings, "FRONTEND_URL", "").rstrip("/") or None
admin.site.empty_value_display = "N/A"
