from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from django.template.loader import render_to_string
from django.conf import settings

from .email import ResendEmailService


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
        subject = render_to_string(f"{template_prefix}_subject.txt", context).strip()
        html = render_to_string(f"{template_prefix}_message.html", context)
        self.email_service.send(to=email, subject=subject, html=html)


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

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        user.is_active = True
        user.save()
        return user
