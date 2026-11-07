"""
URL configuration for hvt project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import os
from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from hvt.apps.authentication.jwks_views import JWKSView, OpenIDConfigurationView
from hvt.health import healthz, readyz


urlpatterns = [
    path(".well-known/jwks.json", JWKSView.as_view(), name="jwks"),
    path(".well-known/openid-configuration", OpenIDConfigurationView.as_view(), name="openid_configuration"),
    path("healthz/", healthz, name="healthz"),
    path("readyz/", readyz, name="readyz"),
    path("api/v1/", include("hvt.api.v1.urls")),
]
admin_url = os.environ.get('ADMIN_URL', 'admin/')
if settings.EXPOSE_ADMIN:
    urlpatterns.append(path(admin_url, admin.site.urls))

if settings.EXPOSE_API_DOCS:
    urlpatterns.extend(
        [
            path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
            path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
            path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
        ]
    )
