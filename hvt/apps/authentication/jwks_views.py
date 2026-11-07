# SPDX-License-Identifier: Apache-2.0
import os
from django.conf import settings
from rest_framework import permissions, status, views
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from hvt.apps.authentication.jwt_keys import get_jwks, get_jwt_issuer


class JWKSView(views.APIView):
    """
    Public JWKS endpoint conforming to RFC 7517.
    Returns the JSON Web Key Set containing active and rotated RSA public verification keys.
    """

    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    @extend_schema(summary="Get JSON Web Key Set (JWKS)", tags=["Tokens & JWKS"])
    def get(self, request):
        jwks = get_jwks()
        response = Response(jwks, status=status.HTTP_200_OK)
        response["Cache-Control"] = "public, max-age=3600, must-revalidate"
        response["Access-Control-Allow-Origin"] = "*"
        return response


class OpenIDConfigurationView(views.APIView):
    """
    Standard OpenID Connect 1.0 Discovery endpoint (.well-known/openid-configuration).
    Allows client libraries to automatically discover issuer and jwks_uri.
    """

    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    @extend_schema(summary="OpenID Connect Discovery", tags=["Tokens & JWKS"])
    def get(self, request):
        base_host = request.build_absolute_uri("/").rstrip("/")
        issuer = get_jwt_issuer()
        if not getattr(settings, "HVT_JWT_ISSUER", None) and not os.getenv("HVT_JWT_ISSUER"):
            issuer = base_host
        jwks_uri = f"{base_host}/.well-known/jwks.json"

        config = {
            "issuer": issuer,
            "jwks_uri": jwks_uri,
            "response_types_supported": ["token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        }
        response = Response(config, status=status.HTTP_200_OK)
        response["Cache-Control"] = "public, max-age=3600, must-revalidate"
        response["Access-Control-Allow-Origin"] = "*"
        return response
