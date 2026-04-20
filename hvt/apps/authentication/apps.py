from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "hvt.apps.authentication"

    def ready(self):
        # Register the drf-spectacular OpenAPI extension for APIKeyAuthentication
        import hvt.apps.authentication.schema  # noqa: F401
        # Connect login signal for webhook triggers
        import hvt.apps.authentication.signals  # noqa: F401
        self._patch_allauth_unique_email_check()
        self._patch_allauth_email_verification_rate_limit()

    def _patch_allauth_unique_email_check(self):
        """
        HVT resolves control-plane and runtime identities in separate pools.

        allauth assumes global email uniqueness when email-based login is enabled,
        but HVT scopes email login itself before allauth is involved. Remove only
        that specific system-check error while keeping the rest of allauth's checks.
        """
        from django.core.checks.registry import registry

        try:
            from allauth.account.checks import settings_check as allauth_settings_check
        except ImportError:
            return

        if allauth_settings_check not in registry.registered_checks:
            return

        registry.registered_checks.remove(allauth_settings_check)

        @registry.register()
        def hvt_allauth_settings_check(app_configs, **kwargs):
            return [
                issue
                for issue in allauth_settings_check(app_configs, **kwargs)
                if getattr(issue, "msg", "")
                != "Using email as a login method requires ACCOUNT_UNIQUE_EMAIL"
            ]

    def _patch_allauth_email_verification_rate_limit(self):
        """Scope allauth verification-email cooldowns to HVT's identity pools."""
        try:
            from allauth.account import app_settings as account_app_settings
            from allauth.account.internal.flows import email_verification
            from allauth.core import ratelimit
        except ImportError:
            return

        from hvt.apps.authentication.identity import normalize_email
        from hvt.apps.organizations.models import APIKey

        def hvt_consume_email_verification_rate_limit(
            request,
            email: str,
            dry_run: bool = False,
            raise_exception: bool = False,
        ) -> bool:
            scoped_key = normalize_email(email)
            api_key = getattr(request, "auth", None) if request else None
            if api_key is None and request:
                raw_api_key = request.META.get("HTTP_X_API_KEY", "")
                if raw_api_key:
                    try:
                        from hvt.apps.authentication.backends import APIKeyAuthentication

                        _, api_key = APIKeyAuthentication().validate_key(raw_api_key)
                    except Exception:
                        api_key = None
            if isinstance(api_key, APIKey) and api_key.project_id:
                scoped_key = f"runtime:{api_key.project_id}:{scoped_key}"
            else:
                scoped_key = f"control:{scoped_key}"

            return bool(
                ratelimit.consume(
                    request,
                    action="confirm_email",
                    key=scoped_key,
                    dry_run=dry_run,
                    raise_exception=raise_exception,
                )
            )

        email_verification.consume_email_verification_rate_limit = (
            hvt_consume_email_verification_rate_limit
        )
