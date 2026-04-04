from django.conf import settings
from rest_framework import serializers
from dj_rest_auth.serializers import PasswordResetSerializer
from allauth.account.utils import user_pk_to_url_str


class HVTPasswordResetSerializer(PasswordResetSerializer):
    """Password reset serializer that emits frontend reset links."""

    def get_email_options(self):
        options = super().get_email_options()

        def url_generator(request, user, temp_key):
            uid = user_pk_to_url_str(user)
            return (
                f"{settings.FRONTEND_URL.rstrip('/')}"
                f"/auth/password-reset/{uid}/{temp_key}"
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
