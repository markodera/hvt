"""
Rate limting/throttling classes for HVT API.
Implements per-organization and per-API-key rate limits.
"""

from rest_framework.throttling import SimpleRateThrottle
from hvt.apps.organizations.models import APIKey


class OrganizationRateThrottle(SimpleRateThrottle):
    """
    Rate limit based on organiization.
    Works with both JWT(user.organization) and API Keys.

    Default: 1000 requests/hour per organization
    """

    scope = "organization"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, APIKey):
            org_id = request.auth.organization.id
        elif (
            request.user and request.user.is_authenticated and request.user.organization
        ):
            org_id = request.user.organization.id
        else:
            return self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": str(org_id)}


class APIKeyRateThrottle(SimpleRateThrottle):
    """Rate limit per API Key - 100 req/min"""

    scope = "api_key"

    def get_cache_key(self, request, view):
        if not isinstance(request.auth, APIKey):
            return None

        return self.cache_format % {"scope": self.scope, "ident": str(request.auth.id)}


class BurstRateThrottle(SimpleRateThrottle):
    """Burst protection - 20 req/sec"""

    scope = "burst"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, APIKey):
            ident = str(request.auth.organization.id)
        elif (
            request.user and request.user.is_authenticated and request.user.organization
        ):
            ident = str(request.user.organization.id)
        else:
            ident = self.get_ident(request)

        return self.cache_format % {"scope": self.scope, "ident": ident}


class AnonRateThrottle(SimpleRateThrottle):
    """Anonymous requests - 10 req/min per IP"""

    scope = "anon"

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            return None
        if isinstance(request.auth, APIKey):
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }
