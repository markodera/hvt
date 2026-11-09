# SPDX-License-Identifier: Apache-2.0
"""
Tests for Webhook SSRF protection, DNS rebinding prevention, and response body privacy.
"""

from unittest.mock import MagicMock, patch
import socket
from django.test import TestCase, override_settings
from rest_framework.test import APITestCase, APIClient
from rest_framework import status as http_status

from hvt.apps.organizations.models import Organization, Webhook, WebhookDelivery
from hvt.apps.organizations.webhooks import send_webhook
from hvt.apps.organizations.ssrf import (
    validate_webhook_url,
    is_safe_ip,
    SSRFValidationError,
    SSRFBlockedError,
    ssrf_create_connection,
)
from hvt.api.v1.serializers.organizations import WebhookDeliverySerializer
from django.contrib.auth import get_user_model

User = get_user_model()


class WebhookSSRFValidationTests(TestCase):
    """Test URL parsing, scheme enforcement, credentials, and disallowed IP checks."""

    @override_settings(DEBUG=False)
    def test_http_scheme_rejected_in_production(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("http://example.com/hook")
        self.assertIn("HTTPS in production", str(ctx.exception))

    @override_settings(DEBUG=True)
    def test_http_scheme_allowed_in_debug(self):
        # example.com resolves to public IP
        try:
            validate_webhook_url("http://example.com/hook")
        except SSRFValidationError as e:
            self.fail(f"HTTP should be permitted when DEBUG=True: {e}")

    def test_embedded_credentials_rejected(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("https://user:password@example.com/hook")
        self.assertIn("user credentials", str(ctx.exception))

    def test_loopback_ipv4_127_0_0_1_rejected(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("https://127.0.0.1/hook")
        self.assertIn("disallowed", str(ctx.exception))

    def test_link_local_metadata_169_254_169_254_rejected(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("https://169.254.169.254/latest/meta-data")
        self.assertIn("disallowed", str(ctx.exception))

    def test_private_ip_10_0_0_1_rejected(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("https://10.0.0.1/hook")
        self.assertIn("disallowed", str(ctx.exception))

    def test_loopback_ipv6_colons_1_rejected(self):
        with self.assertRaises(SSRFValidationError) as ctx:
            validate_webhook_url("https://[::1]/hook")
        self.assertIn("disallowed", str(ctx.exception))

    def test_hostname_resolving_to_private_ip_rejected(self):
        # Mock getaddrinfo returning private IP 192.168.1.50
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 443))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(SSRFValidationError) as ctx:
                validate_webhook_url("https://internal-service.local/webhook")
            self.assertIn("disallowed IP 192.168.1.50", str(ctx.exception))


class WebhookConnectionTimeSSRFTests(TestCase):
    """Test connection-time validation preventing DNS rebinding attacks."""

    def test_connect_to_private_ip_blocked_at_socket_level(self):
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(SSRFBlockedError) as ctx:
                ssrf_create_connection(("evil-rebound.com", 80))
            self.assertIn("127.0.0.1", str(ctx.exception))

    def test_connect_to_metadata_blocked_at_socket_level(self):
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(SSRFBlockedError) as ctx:
                ssrf_create_connection(("metadata-alias.com", 80))
            self.assertIn("169.254.169.254", str(ctx.exception))

    def test_connect_to_ipv6_loopback_blocked_at_socket_level(self):
        fake_addrinfo = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(SSRFBlockedError) as ctx:
                ssrf_create_connection(("ipv6-rebound.com", 80))
            self.assertIn("::1", str(ctx.exception))


class WebhookDeliveryEngineSSRFTests(TestCase):
    """Test full dispatch engine behavior with SSRF, redirects, and body privacy."""

    def setUp(self):
        self.owner = User.objects.create_user(email="wh_owner@example.com", password="StrongPassword123!")
        self.org = Organization.objects.create(name="SSRF Org", slug="ssrf-org", owner=self.owner)
        self.project = self.org.ensure_default_project()
        self.owner.organization = self.org
        self.owner.save()

    def test_delivery_to_127_0_0_1_fails_and_records_ssrf_blocked(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://127.0.0.1/hook",
            events=["user.created"],
            secret="test-secret",
        )
        send_webhook(wh, "user.created", {"user_id": "test"})
        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_message, "SSRF_BLOCKED")
        self.assertEqual(delivery.response_body, "")

    def test_delivery_to_169_254_169_254_fails_and_records_ssrf_blocked(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://169.254.169.254/latest/meta-data",
            events=["user.created"],
            secret="test-secret",
        )
        send_webhook(wh, "user.created", {"user_id": "test"})
        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_message, "SSRF_BLOCKED")
        self.assertEqual(delivery.response_body, "")

    def test_delivery_to_10_0_0_1_fails_and_records_ssrf_blocked(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://10.0.0.1/webhook",
            events=["user.created"],
            secret="test-secret",
        )
        send_webhook(wh, "user.created", {"user_id": "test"})
        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_message, "SSRF_BLOCKED")
        self.assertEqual(delivery.response_body, "")

    def test_delivery_to_ipv6_loopback_fails_and_records_ssrf_blocked(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://[::1]/webhook",
            events=["user.created"],
            secret="test-secret",
        )
        send_webhook(wh, "user.created", {"user_id": "test"})
        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_message, "SSRF_BLOCKED")
        self.assertEqual(delivery.response_body, "")

    def test_delivery_to_hostname_resolving_to_private_ip(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://private-endpoint.corp/webhook",
            events=["user.created"],
            secret="test-secret",
        )
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.200.1.1", 443))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            send_webhook(wh, "user.created", {"user_id": "test"})

        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_message, "SSRF_BLOCKED")
        self.assertEqual(delivery.response_body, "")

    def test_redirect_to_private_ip_is_refused_and_not_followed(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://example.com/redirect-to-private",
            events=["user.created"],
            secret="test-secret",
        )
        # Mock initial response as 302 redirecting to http://127.0.0.1/secret
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "http://127.0.0.1/secret"}
        mock_response.text = "Redirecting..."

        with patch("hvt.apps.organizations.webhooks.requests.post", return_value=mock_response) as mock_post:
            send_webhook(wh, "user.created", {"user_id": "test"})

        call_kwargs = mock_post.call_args[1]
        self.assertFalse(call_kwargs.get("allow_redirects", True))

        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.response_status_code, 302)
        self.assertEqual(delivery.error_message, "REDIRECT_REFUSED")
        self.assertEqual(delivery.response_body, "")

    def test_successful_delivery_does_not_store_response_body(self):
        wh = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://example.com/valid-hook",
            events=["user.created"],
            secret="test-secret",
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"sensitive_backend_data": "secret_tokens"}'

        with patch("hvt.apps.organizations.webhooks.requests.post", return_value=mock_response):
            send_webhook(wh, "user.created", {"user_id": "test"})

        delivery = WebhookDelivery.objects.filter(webhook=wh).latest("created_at")
        self.assertEqual(delivery.status, "success")
        self.assertEqual(delivery.response_status_code, 200)
        self.assertEqual(delivery.response_body, "")
        self.assertEqual(delivery.error_message, "")

    def test_webhook_delivery_serializer_omits_response_body(self):
        delivery = WebhookDelivery.objects.create(
            webhook=Webhook.objects.create(
                organization=self.org,
                project=self.project,
                url="https://example.com/hook",
                secret="secret",
            ),
            event_type="user.created",
            payload={"test": 1},
            status="success",
            response_status_code=200,
            response_body="secret_leak",
        )
        serializer = WebhookDeliverySerializer(instance=delivery)
        self.assertNotIn("response_body", serializer.data)
