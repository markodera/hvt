from drf_spectacular.extensions import OpenApiAuthenticationExtension


class APIKeyAuthenticationSchema(OpenApiAuthenticationExtension):
    """Register APIKeyAuthentication with drf-spectacular."""

    target_class = "hvt.apps.authentication.backends.APIKeyAuthentication"
    name = "APIKeyAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Organization API Key (hvt_live_* or hvt_test_*)",
        }