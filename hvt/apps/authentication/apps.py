from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "hvt.apps.authentication"
    
    def ready(self):
        # Register the drf-spectacular OpenAPI extension for APIKeyAuthentication
        import hvt.apps.authentication.schema  # noqa: F401
        # Connect login signal for webhook triggers
        import hvt.apps.authentication.signals  # noqa: F401