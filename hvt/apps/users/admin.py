from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import AdminUserCreationForm

from .models import User


class UserScopeValidationMixin:
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


class UserAdminChangeForm(UserScopeValidationMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = "__all__"


class UserAdminCreationForm(UserScopeValidationMixin, AdminUserCreationForm):
    class Meta(AdminUserCreationForm.Meta):
        model = User
        fields = (
            "email",
            "organization",
            "project",
            "role",
            "is_test",
            "is_active",
            "is_staff",
            "is_superuser",
        )


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    add_form = UserAdminCreationForm
    form = UserAdminChangeForm
    list_display = [
        "email",
        "full_name_display",
        "organization",
        "project",
        "role",
        "is_test",
        "is_active",
        "is_staff",
        "last_login",
        "created_at",
    ]
    list_filter = [
        "role",
        "is_test",
        "is_active",
        "is_staff",
        "is_superuser",
        "organization",
        "project",
    ]
    search_fields = [
        "email",
        "first_name",
        "last_name",
        "organization__name",
        "project__name",
    ]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    autocomplete_fields = ["organization", "project"]
    readonly_fields = ["last_login", "created_at", "updated_at"]
    list_select_related = ["organization", "project"]
    filter_horizontal = ["groups", "user_permissions"]

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Profile", {"fields": ("first_name", "last_name")}),
        ("Access", {"fields": ("organization", "project", "role", "is_test")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Activity", {"fields": ("last_login", "created_at", "updated_at")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "organization",
                    "project",
                    "role",
                    "is_test",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
    )

    @admin.display(description="Name", ordering="first_name")
    def full_name_display(self, obj):
        full_name = obj.full_name.strip()
        return full_name or "N/A"
