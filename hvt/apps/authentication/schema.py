from drf_spectacular.extensions import OpenApiAuthenticationExtension
from hvt.apps.authentication.backends import (
    APIKeyAuthentication,
    HVTJWTAuthentication,
    HVTJWTCookieAuthentication,
)


class APIKeyAuthenticationSchema(OpenApiAuthenticationExtension):
    """Register APIKeyAuthentication with drf-spectacular."""

    target_class = APIKeyAuthentication
    name = "APIKeyAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Organization API Key (hvt_live_* or hvt_test_*)",
        }


class HVTJWTAuthenticationSchema(OpenApiAuthenticationExtension):
    target_class = HVTJWTAuthentication
    name = "BearerAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT Access Token",
        }


class HVTJWTCookieAuthenticationSchema(OpenApiAuthenticationExtension):
    target_class = HVTJWTCookieAuthentication
    name = "jwtCookieAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "cookie",
            "name": "hvt_access",
            "description": "JWT Access Token Cookie",
        }
