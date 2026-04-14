from django.conf import settings
from rest_framework import serializers
from allauth.account.adapter import get_adapter
from allauth.account.utils import filter_users_by_email
from dj_rest_auth.serializers import PasswordResetSerializer
from dj_rest_auth.forms import AllAuthPasswordResetForm
from allauth.account.utils import user_pk_to_url_str

from hvt.apps.authentication.email import build_frontend_url
from hvt.apps.organizations.access import user_has_project_access
from hvt.apps.organizations.models import APIKey


def _effective_user_organization_id(user):
    organization_id = getattr(user, "organization_id", None)
    if organization_id:
        return organization_id

    owned_org_manager = getattr(user, "owned_organization", None)
    if owned_org_manager is None:
        return None

    owned_org = owned_org_manager.first()
    return getattr(owned_org, "id", None)


def _user_matches_runtime_api_key(user, api_key: APIKey) -> bool:
    if _effective_user_organization_id(user) != getattr(api_key, "organization_id", None):
        return False

    if not getattr(api_key, "project_id", None):
        return True

    return user_has_project_access(user, api_key.project)


class HVTPasswordResetSerializer(PasswordResetSerializer):
    """Password reset serializer that emits frontend reset links."""

    def get_email_options(self):
        options = super().get_email_options()

        def url_generator(request, user, temp_key):
            uid = user_pk_to_url_str(user)
            return build_frontend_url(
                f"/auth/password-reset/{uid}/{temp_key}",
                request=request,
            )

        options["url_generator"] = url_generator
        return options

    def save(self):
        try:
            return super().save()
        except Exception as exc:
            if exc.__class__.__module__.startswith("resend.exceptions"):
                raise serializers.ValidationError(
                    (
                        "Password reset email could not be sent. "
                        "Check your Resend sender domain and API key configuration."
                    )
                ) from exc
            raise


class RuntimePasswordResetForm(AllAuthPasswordResetForm):
    """Password reset form that only resolves users visible to the runtime API key."""

    def __init__(self, *args, request=None, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data["email"]
        email = get_adapter().clean_email(email)
        api_key = getattr(self.request, "auth", None)
        users = filter_users_by_email(email, is_active=True, prefer_verified=True)
        self.users = [
            user
            for user in users
            if isinstance(api_key, APIKey) and _user_matches_runtime_api_key(user, api_key)
        ]
        return self.cleaned_data["email"]


class RuntimePasswordResetSerializer(HVTPasswordResetSerializer):
    """Password reset serializer scoped to the runtime API key organization/project."""

    @property
    def password_reset_form_class(self):
        return RuntimePasswordResetForm

    def validate_email(self, value):
        self.reset_form = self.password_reset_form_class(
            data=self.initial_data,
            request=self.context.get("request"),
        )
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)
        return value

    def get_email_options(self):
        options = super().get_email_options()
        request = self.context.get("request")
        project = getattr(getattr(request, "auth", None), "project", None)

        def url_generator(request, user, temp_key):
            uid = user_pk_to_url_str(user)
            query = None
            if project:
                query = {"runtime": "1", "project": project.slug}
            return build_frontend_url(
                f"/auth/password-reset/{uid}/{temp_key}",
                request=request,
                project=project,
                query=query,
            )

        options["url_generator"] = url_generator
        return options


class RuntimeResendEmailVerificationSerializer(serializers.Serializer):
    """Serializer for runtime resend-verification requests."""

    email = serializers.EmailField()

    def validate_email(self, value):
        return (value or "").strip().lower()
