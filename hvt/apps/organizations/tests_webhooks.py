"""
Tests for the webhook system: models, delivery engine, management command,
signals, and API endpoints.
"""

import hashlib
import hmac
import json
import uuid
from datetime import timedelta
from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status as http_status

from hvt.apps.organizations.models import (
    Organization,
    APIKey,
    Webhook,
    WebhookDelivery,
)
from hvt.apps.organizations.api_key_expiry import emit_api_key_expiry_webhook
from hvt.apps.organizations.webhooks import (
    generate_webhook_signature,
    send_webhook,
    trigger_webhook_event,
)
from hvt.apps.authentication.models import AuditLog
from django.contrib.auth import get_user_model

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_org_and_owner(email="owner@example.com"):
    """Create an organization with an owner user."""
    user = User.objects.create_user(email=email, password="Str0ng!Pass")
    org = Organization.objects.create(name="Test Org", slug="test-org", owner=user)
    user.organization = org
    user.role = "owner"
    user.save()
    return org, user


def _create_webhook(org, user=None, events=None, url="https://example.com/hook"):
    """Create a Webhook for the given org."""
    return Webhook.objects.create(
        organization=org,
        project=org.ensure_default_project(),
        url=url,
        events=events or ["user.created", "user.updated", "user.deleted"],
        secret=Webhook.generate_secret(),
        is_active=True,
        created_by=user,
    )


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class WebhookModelTest(TestCase):
    """Tests for the Webhook model."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()

    def test_create_webhook(self):
        wh = _create_webhook(self.org, self.owner)
        self.assertIsNotNone(wh.id)
        self.assertTrue(wh.is_active)
        self.assertEqual(wh.organization, self.org)
        self.assertEqual(wh.project, self.org.ensure_default_project())
        self.assertEqual(wh.consecutive_failures, 0)

    def test_generate_secret_is_64_hex(self):
        secret = Webhook.generate_secret()
        self.assertEqual(len(secret), 64)
        int(secret, 16)  # Should not raise — valid hex

    def test_webhook_str(self):
        wh = _create_webhook(self.org)
        self.assertIn(self.org.ensure_default_project().slug, str(wh))
        self.assertIn("https://example.com/hook", str(wh))

    def test_events_field_stores_list(self):
        wh = _create_webhook(self.org, events=["user.login", "api_key.created"])
        wh.refresh_from_db()
        self.assertEqual(wh.events, ["user.login", "api_key.created"])

    def test_default_counters(self):
        wh = _create_webhook(self.org)
        self.assertEqual(wh.success_count, 0)
        self.assertEqual(wh.failure_count, 0)
        self.assertEqual(wh.consecutive_failures, 0)
        self.assertIsNone(wh.last_triggered_at)


class WebhookDeliveryModelTest(TestCase):
    """Tests for the WebhookDelivery model."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.webhook = _create_webhook(self.org, self.owner)

    def test_create_delivery(self):
        delivery = WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"user_id": str(uuid.uuid4())},
            status="pending",
        )
        self.assertIsNotNone(delivery.id)
        self.assertEqual(delivery.status, "pending")
        self.assertEqual(delivery.attempt_count, 0)

    def test_delivery_str(self):
        delivery = WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={},
        )
        s = str(delivery)
        self.assertIn("user.created", s)
        self.assertIn(self.webhook.url, s)


# ---------------------------------------------------------------------------
# Signature Tests
# ---------------------------------------------------------------------------

class WebhookSignatureTest(TestCase):
    """Tests for HMAC-SHA256 signature generation."""

    def test_signature_format(self):
        sig = generate_webhook_signature('{"key":"value"}', "mysecret")
        self.assertTrue(sig.startswith("sha256="))

    def test_signature_is_deterministic(self):
        payload = '{"a":1}'
        secret = "test-secret"
        sig1 = generate_webhook_signature(payload, secret)
        sig2 = generate_webhook_signature(payload, secret)
        self.assertEqual(sig1, sig2)

    def test_signature_changes_with_payload(self):
        secret = "test-secret"
        sig1 = generate_webhook_signature('{"a":1}', secret)
        sig2 = generate_webhook_signature('{"a":2}', secret)
        self.assertNotEqual(sig1, sig2)

    def test_signature_changes_with_secret(self):
        payload = '{"a":1}'
        sig1 = generate_webhook_signature(payload, "secret-a")
        sig2 = generate_webhook_signature(payload, "secret-b")
        self.assertNotEqual(sig1, sig2)

    def test_signature_verifiable(self):
        """Verify that a receiver can validate the signature."""
        payload = '{"event":"user.created"}'
        secret = "webhook-secret-123"
        sig = generate_webhook_signature(payload, secret)
        # Receiver-side verification
        expected = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(sig, f"sha256={expected}")


# ---------------------------------------------------------------------------
# Delivery Engine Tests
# ---------------------------------------------------------------------------

class SendWebhookTest(TestCase):
    """Tests for the webhook delivery engine."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.webhook = _create_webhook(self.org, self.owner)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    def test_successful_delivery(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {"Content-Type": "application/json"}
        mock_post.return_value = mock_response

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        # Verify delivery record created with success
        delivery = WebhookDelivery.objects.filter(webhook=self.webhook).latest("created_at")
        self.assertEqual(delivery.status, "success")
        self.assertEqual(delivery.response_status_code, 200)
        self.assertIsNotNone(delivery.delivered_at)

        # Verify webhook counters updated
        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.success_count, 1)
        self.assertEqual(self.webhook.consecutive_failures, 0)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    @patch("hvt.apps.organizations.webhooks.time.sleep")  # Speed up
    def test_failed_delivery_after_retries(self, mock_sleep, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_post.return_value = mock_response

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        delivery = WebhookDelivery.objects.filter(webhook=self.webhook).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.attempt_count, 3)

        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.failure_count, 1)
        self.assertEqual(self.webhook.consecutive_failures, 1)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    @patch("hvt.apps.organizations.webhooks.time.sleep")
    def test_network_error_retry(self, mock_sleep, mock_post):
        """Connection errors should be retried."""
        import requests as req
        mock_post.side_effect = req.ConnectionError("Connection refused")

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        delivery = WebhookDelivery.objects.filter(webhook=self.webhook).latest("created_at")
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.attempt_count, 3)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    @patch("hvt.apps.organizations.webhooks.time.sleep")
    def test_auto_disable_after_10_consecutive_failures(self, mock_sleep, mock_post):
        """Webhook should be auto-disabled after 10 consecutive failures."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "error"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        # Set webhook to 9 consecutive failures
        self.webhook.consecutive_failures = 9
        self.webhook.save()

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        self.webhook.refresh_from_db()
        self.assertFalse(self.webhook.is_active)
        self.assertGreaterEqual(self.webhook.consecutive_failures, 10)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    def test_delivery_includes_correct_headers(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")

        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["X-HVT-Event"], "user.created")
        self.assertTrue(headers["X-HVT-Signature"].startswith("sha256="))
        self.assertEqual(headers["User-Agent"], "HVT-Webhook/1.0")
        self.assertIn("X-HVT-Delivery", headers)

    @patch("hvt.apps.organizations.webhooks.requests.post")
    def test_success_resets_consecutive_failures(self, mock_post):
        """A successful delivery should reset consecutive_failures to 0."""
        self.webhook.consecutive_failures = 5
        self.webhook.save()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        send_webhook(self.webhook, "user.created", {"user_id": "abc"})

        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.consecutive_failures, 0)


# ---------------------------------------------------------------------------
# Trigger (Event Routing) Tests
# ---------------------------------------------------------------------------

class TriggerWebhookEventTest(TestCase):
    """Tests for trigger_webhook_event routing logic."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()

    @patch("hvt.apps.organizations.webhooks.send_webhook")
    def test_triggers_matching_webhook(self, mock_send):
        wh = _create_webhook(self.org, events=["user.created"])
        trigger_webhook_event(self.org, "user.created", {"user_id": "abc"})
        # Give daemon thread a moment
        import time
        time.sleep(0.5)
        mock_send.assert_called_once_with(wh, "user.created", {"user_id": "abc"})

    @patch("hvt.apps.organizations.webhooks.send_webhook")
    def test_skips_non_matching_event(self, mock_send):
        _create_webhook(self.org, events=["api_key.created"])
        trigger_webhook_event(self.org, "user.created", {"user_id": "abc"})
        import time
        time.sleep(0.5)
        mock_send.assert_not_called()

    @patch("hvt.apps.organizations.webhooks.send_webhook")
    def test_skips_inactive_webhook(self, mock_send):
        wh = _create_webhook(self.org, events=["user.created"])
        wh.is_active = False
        wh.save()
        trigger_webhook_event(self.org, "user.created", {"user_id": "abc"})
        import time
        time.sleep(0.5)
        mock_send.assert_not_called()

    @patch("hvt.apps.organizations.webhooks.send_webhook")
    def test_empty_events_matches_all(self, mock_send):
        """A webhook with empty events list should receive ALL events."""
        _create_webhook(self.org, events=[])
        trigger_webhook_event(self.org, "user.created", {"user_id": "abc"})
        import time
        time.sleep(0.5)
        mock_send.assert_called_once()


class APIKeyExpiryWebhookTest(TestCase):
    """Tests for emitting api_key.expired exactly once."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.project = self.org.ensure_default_project()
        prefix, self.full_key, hashed_key = APIKey.generate_key(environment="test")
        self.api_key = APIKey.objects.create(
            organization=self.org,
            project=self.project,
            name="Expired runtime key",
            environment="test",
            prefix=prefix,
            hashed_key=hashed_key,
            is_active=True,
            scopes=["auth:runtime"],
            expires_at=timezone.now() - timedelta(minutes=5),
        )

    @patch("hvt.apps.organizations.api_key_expiry.trigger_webhook_event")
    def test_emit_api_key_expired_webhook_only_once(self, mock_trigger):
        emitted = emit_api_key_expiry_webhook(self.api_key)

        self.assertTrue(emitted)
        self.api_key.refresh_from_db()
        self.assertIsNotNone(self.api_key.expired_webhook_sent_at)
        mock_trigger.assert_called_once()
        self.assertEqual(
            mock_trigger.call_args.kwargs["event_type"],
            Webhook.EventType.API_KEY_EXPIRED,
        )

        mock_trigger.reset_mock()
        emitted_again = emit_api_key_expiry_webhook(self.api_key)
        self.assertFalse(emitted_again)
        mock_trigger.assert_not_called()

    @patch("hvt.apps.organizations.management.commands.emit_api_key_expiry_webhooks.emit_api_key_expiry_webhook")
    def test_emit_api_key_expiry_webhooks_command_processes_matching_keys(self, mock_emit):
        out = StringIO()

        call_command("emit_api_key_expiry_webhooks", stdout=out)

        self.assertIn("Found 1 expired API key", out.getvalue())
        mock_emit.assert_called_once()


# ---------------------------------------------------------------------------
# Login Signal Tests
# ---------------------------------------------------------------------------

class LoginSignalWebhookTest(TestCase):
    """Tests for the user_logged_in signal triggering webhooks."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        _create_webhook(self.org, events=["user.login"])

    @patch("hvt.apps.organizations.webhooks.trigger_webhook_event")
    def test_login_signal_fires_webhook(self, mock_trigger):
        from django.contrib.auth.signals import user_logged_in

        request = MagicMock()
        request.META = {}
        user_logged_in.send(sender=self.owner.__class__, request=request, user=self.owner)

        mock_trigger.assert_called_once()
        call_kwargs = mock_trigger.call_args.kwargs
        self.assertEqual(call_kwargs["event_type"], "user.login")
        self.assertEqual(call_kwargs["organization"], self.org)

    @patch("hvt.apps.organizations.webhooks.trigger_webhook_event")
    def test_login_signal_skips_user_without_org(self, mock_trigger):
        from django.contrib.auth.signals import user_logged_in

        no_org_user = User.objects.create_user(
            email="noorg@example.com", password="Str0ng!Pass"
        )
        request = MagicMock()
        request.META = {}
        user_logged_in.send(sender=no_org_user.__class__, request=request, user=no_org_user)

        mock_trigger.assert_not_called()


# ---------------------------------------------------------------------------
# Webhook API Endpoint Tests
# ---------------------------------------------------------------------------

class WebhookAPITest(APITestCase):
    """Tests for the webhook CRUD API endpoints."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)
        self.base_url = "/api/v1/organizations/current/webhooks/"

    def test_list_webhooks_empty(self):
        resp = self.client.get(self.base_url)
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 0)

    def test_create_webhook(self):
        data = {
            "url": "https://example.com/hook",
            "events": ["user.created", "user.deleted"],
            "description": "Test webhook",
        }
        resp = self.client.post(self.base_url, data, format="json")
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        self.assertIn("secret", resp.data)
        self.assertEqual(resp.data["url"], data["url"])
        self.assertEqual(resp.data["events"], data["events"])

    def test_create_webhook_generates_secret(self):
        data = {"url": "https://example.com/hook", "events": ["user.created"]}
        resp = self.client.post(self.base_url, data, format="json")
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        self.assertTrue(len(resp.data["secret"]) > 0)

    def test_create_webhook_accepts_expanded_event_catalogue(self):
        data = {
            "url": "https://example.com/hook",
            "events": [
                "project.updated",
                "org.invitation.created",
                "api_key.expired",
                "user.role.changed",
            ],
        }
        resp = self.client.post(self.base_url, data, format="json")
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        self.assertEqual(resp.data["events"], data["events"])

    def test_list_webhooks_returns_created(self):
        _create_webhook(self.org, self.owner)
        resp = self.client.get(self.base_url)
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)

    def test_retrieve_webhook(self):
        wh = _create_webhook(self.org, self.owner)
        resp = self.client.get(f"{self.base_url}{wh.id}/")
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(resp.data["id"], str(wh.id))

    def test_update_webhook(self):
        wh = _create_webhook(self.org, self.owner)
        resp = self.client.patch(
            f"{self.base_url}{wh.id}/",
            {"description": "Updated"},
            format="json",
        )
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        wh.refresh_from_db()
        self.assertEqual(wh.description, "Updated")

    def test_delete_webhook(self):
        wh = _create_webhook(self.org, self.owner)
        resp = self.client.delete(f"{self.base_url}{wh.id}/")
        self.assertEqual(resp.status_code, http_status.HTTP_204_NO_CONTENT)
        self.assertFalse(Webhook.objects.filter(id=wh.id).exists())

    def test_unauthenticated_cannot_access(self):
        self.client.force_authenticate(user=None)
        resp = self.client.get(self.base_url)
        self.assertIn(resp.status_code, [401, 403])

    def test_other_org_member_cannot_access(self):
        """User from another org cannot list this org's webhooks."""
        other_user = User.objects.create_user(
            email="other@example.com", password="Str0ng!Pass"
        )
        other_org = Organization.objects.create(
            name="Other Org", slug="other-org", owner=other_user
        )
        other_user.organization = other_org
        other_user.save()

        self.client.force_authenticate(user=other_user)
        resp = self.client.get(self.base_url)
        self.assertIn(resp.status_code, [200, 403])
        # If 200, should return empty because of org filtering
        if resp.status_code == 200:
            self.assertEqual(len(resp.data["results"]), 0)


class WebhookDeliveryAPITest(APITestCase):
    """Tests for the webhook delivery log endpoint."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.webhook = _create_webhook(self.org, self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    def test_list_deliveries_empty(self):
        url = f"/api/v1/organizations/current/webhooks/{self.webhook.id}/deliveries/"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 0)

    def test_list_deliveries_returns_records(self):
        WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"user_id": str(uuid.uuid4())},
            status="success",
            response_status_code=200,
        )
        url = f"/api/v1/organizations/current/webhooks/{self.webhook.id}/deliveries/"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)
        self.assertEqual(resp.data["results"][0]["status"], "success")

    def test_webhook_summary(self):
        # Create successful delivery within 24h
        WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"user_id": str(uuid.uuid4())},
            status="success",
        )
        # Create failed delivery within 24h
        WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"user_id": str(uuid.uuid4())},
            status="failed",
        )
        
        # Create older delivery (outside 24h window) - Should not be included
        old_delivery = WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"user_id": str(uuid.uuid4())},
            status="success",
        )
        old_delivery.created_at = timezone.now() - timedelta(hours=48)
        old_delivery.save()

        url = "/api/v1/organizations/current/webhooks/summary/"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, http_status.HTTP_200_OK)
        self.assertEqual(resp.data["total_deliveries_24h"], 2)
        self.assertEqual(resp.data["successful_24h"], 1)
        self.assertEqual(resp.data["failed_24h"], 1)

# ---------------------------------------------------------------------------
# Management Command Tests
# ---------------------------------------------------------------------------

class RetryWebhooksCommandTest(TestCase):
    """Tests for the retry_webhooks management command."""

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.webhook = _create_webhook(self.org, self.owner)

    def _create_failed_delivery(self):
        return WebhookDelivery.objects.create(
            webhook=self.webhook,
            event_type="user.created",
            payload={"data": {"user_id": "abc"}},
            status="failed",
        )

    @patch("hvt.apps.organizations.webhooks.requests.post")
    def test_retries_failed_deliveries(self, mock_post):
        from django.core.management import call_command
        from io import StringIO

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        mock_resp.headers = {}
        mock_post.return_value = mock_resp

        self._create_failed_delivery()

        out = StringIO()
        call_command("retry_webhooks", stdout=out)
        output = out.getvalue()

        self.assertIn("Retried successfully", output)

    def test_dry_run_does_not_send(self):
        from django.core.management import call_command
        from io import StringIO

        self._create_failed_delivery()

        out = StringIO()
        call_command("retry_webhooks", "--dry-run", stdout=out)
        output = out.getvalue()

        self.assertIn("dry run", output)
        # Original delivery should still be failed
        delivery = WebhookDelivery.objects.filter(webhook=self.webhook).first()
        self.assertEqual(delivery.status, "failed")

    def test_no_failed_deliveries(self):
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("retry_webhooks", stdout=out)
        output = out.getvalue()

        self.assertIn("No failed deliveries", output)

    def test_re_enable_disabled_webhook(self):
        from django.core.management import call_command
        from io import StringIO

        self.webhook.is_active = False
        self.webhook.consecutive_failures = 10
        self.webhook.save()

        out = StringIO()
        call_command("retry_webhooks", "--re-enable", stdout=out)
        output = out.getvalue()

        self.assertIn("Re-enabled", output)
        self.webhook.refresh_from_db()
        self.assertTrue(self.webhook.is_active)
        self.assertEqual(self.webhook.consecutive_failures, 0)


# ---------------------------------------------------------------------------
# Integration: Views fire webhooks
# ---------------------------------------------------------------------------

class ViewWebhookIntegrationTest(APITestCase):
    """
    Verify that user CRUD views trigger the correct webhook events.
    Mocks trigger_webhook_event at the view-import site so daemon threads
    never fire inside the test transaction.
    """

    def setUp(self):
        self.org, self.owner = _create_org_and_owner()
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    @patch("hvt.apps.users.views.trigger_webhook_event")
    def test_user_create_triggers_webhook(self, mock_trigger):
        resp = self.client.post(
            "/api/v1/users/",
            {
                "email": "newuser@example.com",
                "password": "Str0ng!Pass123",
                "first_name": "New",
                "last_name": "User",
                "role": "member",
            },
            format="json",
        )

        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        mock_trigger.assert_called_once()
        call_kwargs = mock_trigger.call_args.kwargs
        self.assertEqual(call_kwargs["event_type"], "user.created")
        self.assertEqual(call_kwargs["organization"], self.org)

    @patch("hvt.apps.users.views.trigger_webhook_event")
    def test_user_delete_triggers_webhook(self, mock_trigger):
        # Create a member to delete
        member = User.objects.create_user(
            email="member@example.com",
            password="Str0ng!Pass123",
            organization=self.org,
            role="member",
        )

        resp = self.client.delete(
            f"/api/v1/users/{member.id}/"
        )

        self.assertEqual(resp.status_code, http_status.HTTP_204_NO_CONTENT)
        # trigger_webhook_event should have been called for user.deleted
        called_events = [
            c.kwargs["event_type"] for c in mock_trigger.call_args_list
        ]
        self.assertIn("user.deleted", called_events)
