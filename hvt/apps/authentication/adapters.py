from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.conf import settings
import logging

from hvt.apps.organizations.models import APIKey, SocialProviderConfig
from .email import ResendEmailService, build_email_context, render_email_template


logger = logging.getLogger(__name__)


class FrontendAccountAdapter(DefaultAccountAdapter):
    """
    Custom account adapter to ensure email verification links 
    point to the frontend instead of the backend API.
    """
    def get_email_confirmation_url(self, request, emailconfirmation):
        """
        Constructs the email confirmation URL pointing to the frontend app.
        """
        # settings.FRONTEND_URL should be set in settings.py (e.g., http://localhost:5173)
        return f"{settings.FRONTEND_URL}/auth/verify-email/{emailconfirmation.key}"

    def get_reset_password_from_key_url(self, key):
        """
        Construct password reset URLs for the frontend SPA instead of relying on
        allauth's default server-side route name.
        """
        uid, separator, token = str(key).partition("-")
        if separator and uid and token:
            return f"{settings.FRONTEND_URL}/auth/password-reset/{uid}/{token}"
        return f"{settings.FRONTEND_URL}/auth/password-reset/{key}"


class ResendAccountAdapter(FrontendAccountAdapter):
    """
    Custom account adapter that uses Resend for sending emails.

    Leverages allauth's existing email templates while routing
    the actual email delivery through the Resend API.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.email_service = ResendEmailService()

    def send_mail(self, template_prefix, email, context):
        """
        Override the default send_mail method to use Resend.

        Uses allauth's template system for email content while
        sending via Resend API.

        Args:
            template_prefix: The template prefix (e.g., 'account/email/email_confirmation')
            email: The recipient email address
            context: Context dictionary for the email template
        """
        try:
            email_context = build_email_context({"email": email, **context})
            subject, text_body, html_body = render_email_template(
                template_prefix,
                email_context,
            )
            self.email_service.send(
                to=email,
                subject=subject,
                html=html_body,
                text=text_body,
            )
            logger.info(
                "Account email queued via Resend",
                extra={
                    "template_prefix": template_prefix,
                    "to": email,
                    "subject": subject,
                },
            )
        except Exception:
            logger.exception(
                "Account email send failed",
                extra={
                    "template_prefix": template_prefix,
                    "to": email,
                },
            )
            raise


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter for social login with email-only User model.
    - No username required
    - Auto-verifies required (provider already verified)
    - Populates first_name/last_name from provider data
    """

    def populate_user(self, request, sociallogin, data):
        """
        Populate user instance with data from social provider.
        """
        user = super().populate_user(request, sociallogin, data)

        # Set email
        user.email = data.get("email", "")

        # Set name fields from provider data
        user.first_name = data.get("first_name", "")
        user.last_name = data.get("last_name", "")

        # If provider gives full name but not first/last split it
        if not user.first_name and not user.last_name:
            full_name = data.get("name", "")
            if full_name:
                parts = full_name.split(" ", 1)
                user.first_name = parts[0]
                user.last_name = parts[1] if len(parts) > 1 else ""

        return user

    def get_app(self, request, provider, client_id=None):
        api_key = getattr(request, "auth", None)
        if isinstance(api_key, APIKey):
            queryset = SocialProviderConfig.objects.select_related(
                "project",
                "project__organization",
            ).filter(
                project=api_key.project,
                provider=provider,
                is_active=True,
            )
            if client_id:
                queryset = queryset.filter(client_id=client_id)

            config = queryset.first()
            if not config:
                raise SocialApp.DoesNotExist()

            app = SocialApp(
                provider=config.provider,
                name=f"{config.project.slug}-{config.provider}",
                client_id=config.client_id,
                secret=config.client_secret,
            )
            app.settings = {}
            return app

        return super().get_app(request, provider, client_id=client_id)

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        api_key = getattr(request, "auth", None)
        update_fields = []
        if isinstance(api_key, APIKey):
            user.organization = api_key.organization
            user.project = api_key.project
            user.role = user.Role.MEMBER
            update_fields.extend(["organization", "project", "role"])
        user.is_active = True
        update_fields.append("is_active")
        user.save(update_fields=update_fields)
        return user
