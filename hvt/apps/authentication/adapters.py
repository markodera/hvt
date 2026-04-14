from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
import logging

from hvt.apps.organizations.models import APIKey, SocialProviderConfig
from hvt.apps.organizations.access import assign_default_signup_roles
from .email import (
    ResendEmailService,
    build_email_context,
    build_frontend_url,
    render_email_template,
)


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
        project = getattr(getattr(request, "auth", None), "project", None) if request else None
        query = None
        if project:
            query = {"runtime": "1", "project": project.slug}
        return build_frontend_url(
            f"/auth/verify-email/{emailconfirmation.key}",
            request=request,
            project=project,
            query=query,
        )

    def get_reset_password_from_key_url(self, key):
        """
        Construct password reset URLs for the frontend SPA instead of relying on
        allauth's default server-side route name.
        """
        uid, separator, token = str(key).partition("-")
        if separator and uid and token:
            return build_frontend_url(f"/auth/password-reset/{uid}/{token}")
        return build_frontend_url(f"/auth/password-reset/{key}")


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
            # Extract App/Project name if this is a runtime auth flow
            project_name = None
            project = None
            request = context.get('request') or getattr(self, 'request', None)
            if request:
                api_key = getattr(request, 'auth', None)
                if api_key and hasattr(api_key, 'project') and api_key.project:
                    project = api_key.project
                    project_name = api_key.project.name

            email_context = build_email_context({
                "email": email, 
                "project": project,
                "project_name": project_name, 
                **context
            })
            
            subject, text_body, html_body = render_email_template(
                template_prefix,
                email_context,
            )
            
            # Format the sender identity like "HVT Auth on behalf of AppName <noreply@...>"
            from_name = email_context.get("from_display_name") or "HVT"
            from_address = email_context.get("from_email") or "noreply@notify.hvts.app"
            from_header = f"{from_name} <{from_address}>"

            self.email_service.send(
                to=email,
                subject=subject,
                html=html_body,
                text=text_body,
                from_email=from_header,
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

    @staticmethod
    def _is_runtime_social_app(app: SocialApp) -> bool:
        return str(getattr(app, "name", "") or "").startswith("rt-")

    def _ensure_runtime_social_app_isolated(self, app: SocialApp) -> SocialApp:
        """
        Runtime social apps exist only to give allauth a persisted app for token
        storage during API-key-scoped runtime auth. They must never be discoverable
        through site-level control-plane provider lookup.
        """
        if hasattr(app, "sites") and self._is_runtime_social_app(app):
            app.sites.clear()
        return app

    def _isolate_runtime_apps_for_provider(self, request, provider: str) -> None:
        """
        Older runtime logins may already have linked rt-* apps to the default site.
        Strip those links before control-plane provider discovery so stale runtime
        rows cannot hijack or duplicate dashboard social-auth config.
        """
        current_site = get_current_site(request)
        if not current_site:
            return

        runtime_apps = SocialApp.objects.filter(
            provider=provider,
            name__startswith="rt-",
            sites=current_site,
        )
        for app in runtime_apps:
            app.sites.remove(current_site)

    def populate_user(self, request, sociallogin, data):
        """
        Populate user instance with data from social provider.
        """
        user = super().populate_user(request, sociallogin, data)

        # Set email
        user.email = data.get("email") or ""

        # Set name fields from provider data
        user.first_name = data.get("first_name") or ""
        user.last_name = data.get("last_name") or ""

        # If provider gives full name but not first/last split it
        if not user.first_name and not user.last_name:
            full_name = data.get("name") or ""
            if full_name:
                parts = full_name.split(" ", 1)
                user.first_name = parts[0]
                user.last_name = parts[1] if len(parts) > 1 else ""

        return user

    def _get_or_create_runtime_social_app(self, request, config: SocialProviderConfig) -> SocialApp:
        """
        Materialize a real SocialApp row for runtime provider configs.

        allauth may persist SocialToken rows during first-time social signup. That path
        expects token.app to either be null or point at a saved SocialApp instance with
        a primary key. Returning an unsaved in-memory SocialApp causes provider-specific
        500s during token storage.
        """
        app_name = f"rt-{str(config.project_id)[:8]}-{config.provider}"
        app_defaults = {
            "secret": config.client_secret,
            "key": "",
            "settings": {},
        }
        app, created = SocialApp.objects.get_or_create(
            provider=config.provider,
            name=app_name,
            client_id=config.client_id,
            defaults=app_defaults,
        )

        update_fields = []
        if app.secret != config.client_secret:
            app.secret = config.client_secret
            update_fields.append("secret")
        if app.settings != {}:
            app.settings = {}
            update_fields.append("settings")
        if update_fields:
            app.save(update_fields=update_fields)

        return self._ensure_runtime_social_app_isolated(app)

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
            return self._get_or_create_runtime_social_app(request, config)

        self._isolate_runtime_apps_for_provider(request, provider)
        return super().get_app(request, provider, client_id=client_id)

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"DEBUG SAVE_USER request type: {type(request)}")
        logger.error(f"DEBUG SAVE_USER request.auth: {getattr(request, 'auth', 'MISSING')}")
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
        assign_default_signup_roles(user, api_key.project if isinstance(api_key, APIKey) else None)
        return user
