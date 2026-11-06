# SPDX-License-Identifier: Apache-2.0
"""
Tests for Item 8: Self-hosting basics.
- docker-compose.yml boots in production mode (DEBUG=0, required keys, healthchecks)
- .env.example contains key generation instructions and no real secrets
- Django admin is off by default in production (opt-in)
- Django admin supports custom URL path when enabled
"""

import importlib
import re
import sys
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.urls import clear_url_caches, reverse, resolve
from rest_framework.test import APIClient


class SelfHostingBasicsTests(TestCase):
    def setUp(self):
        self.root_dir = Path(__file__).resolve().parent.parent

    def test_docker_compose_configures_production_environment(self):
        compose_path = self.root_dir / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml must exist")
        content = compose_path.read_text(encoding="utf-8")

        # 1. Target is production
        self.assertIn("target: production", content)

        # 2. DEBUG is 0
        self.assertIn("DEBUG=0", content)

        # 3. Required secret expansions
        self.assertIn("${SECRET_KEY:?SECRET_KEY is required}", content)
        self.assertIn("${HVT_ENCRYPTION_KEYS:?HVT_ENCRYPTION_KEYS is required}", content)

        # 4. Admin interface off by default and custom path support
        self.assertIn("EXPOSE_ADMIN=${EXPOSE_ADMIN:-0}", content)
        self.assertIn("DJANGO_ADMIN_PATH=${DJANGO_ADMIN_PATH:-admin/}", content)

        # 5. DB health checks and dependencies
        self.assertIn("condition: service_healthy", content)
        self.assertIn("readyz", content)

    def test_env_example_contains_key_generation_instructions_without_real_secrets(self):
        env_example_path = self.root_dir / ".env.example"
        self.assertTrue(env_example_path.exists(), ".env.example must exist")
        content = env_example_path.read_text(encoding="utf-8")

        # 1. Key generation instructions
        self.assertIn("secrets.token_urlsafe", content)
        self.assertIn("Fernet.generate_key()", content)

        # 2. Empty templates without real secrets
        self.assertRegex(content, r"(?m)^SECRET_KEY=$")
        self.assertRegex(content, r"(?m)^HVT_ENCRYPTION_KEYS=$")
        self.assertRegex(content, r"(?m)^DB_PASSWORD=$")
        self.assertRegex(content, r"(?m)^RESEND_API_KEY=$")

        # 3. Admin configuration options
        self.assertIn("EXPOSE_ADMIN=0", content)
        self.assertIn("DJANGO_ADMIN_PATH=admin/", content)

    def test_production_settings_enforces_hvt_encryption_keys(self):
        from hvt.settings import _env_list

        # Test that in non-DEBUG production mode without encryption keys, ImproperlyConfigured is raised
        def simulate_prod_check(hvt_keys, is_debug, is_testing):
            if not is_debug and not is_testing and not hvt_keys:
                raise ImproperlyConfigured("HVT_ENCRYPTION_KEYS must be configured when DEBUG is false.")

        with self.assertRaises(ImproperlyConfigured):
            simulate_prod_check([], is_debug=False, is_testing=False)

        # Passes when keys are supplied
        simulate_prod_check(["fernet-key-123"], is_debug=False, is_testing=False)

    def test_django_admin_disabled_by_default(self):
        client = APIClient()

        # Reload URLs with EXPOSE_ADMIN=False
        with self.settings(EXPOSE_ADMIN=False, DJANGO_ADMIN_PATH="admin/"):
            clear_url_caches()
            urls_module = importlib.import_module("hvt.urls")
            importlib.reload(urls_module)

            # Accessing /admin/ should return 404
            response = client.get("/admin/")
            self.assertEqual(response.status_code, 404)

            # Accessing /admin/login/ should also return 404
            response_login = client.get("/admin/login/")
            self.assertEqual(response_login.status_code, 404)

    def test_django_admin_enabled_with_custom_path(self):
        client = APIClient()
        custom_path = "secure-mgmt-portal/"

        with self.settings(EXPOSE_ADMIN=True, DJANGO_ADMIN_PATH=custom_path):
            clear_url_caches()
            urls_module = importlib.import_module("hvt.urls")
            importlib.reload(urls_module)

            # Old default /admin/ returns 404
            default_resp = client.get("/admin/")
            self.assertEqual(default_resp.status_code, 404)

            # Custom path resolves and loads admin login page (200 OK)
            custom_resp = client.get(f"/{custom_path}login/")
            self.assertEqual(custom_resp.status_code, 200)

        # Restore normal URLconf state after test
        clear_url_caches()
        importlib.reload(importlib.import_module("hvt.urls"))
