# SPDX-License-Identifier: Apache-2.0
from django.apps import AppConfig


class OrganizationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "hvt.apps.organizations"

    def ready(self):
        import hvt.crypto  # noqa: F401
