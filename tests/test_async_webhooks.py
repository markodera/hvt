"""
Unit and integration tests for Asynchronous Webhook Delivery Engine and Outbox Integration.
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from rest_framework import status
import requests

from hvt.apps.organizations.models import (
    Organization,
    OutboxTask,
    Project,
    Webhook,
    WebhookDelivery,
)
from hvt.apps.organizations.tasks import process_outbox_tasks
from hvt.apps.organizations.webhooks import (
    generate_webhook_signature,
    trigger_webhook_event,
)


class AsyncWebhooksUnitTests(TestCase):
    def setUp(self):
        OutboxTask.objects.all().delete()
        WebhookDelivery.objects.all().delete()
        self.org = Organization.objects.create(name="Webhook Org", slug="webhook-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Webhook App",
            slug="webhook-app",
        )
        self.webhook = Webhook.objects.create(
            organization=self.org,
            project=self.project,
            url="https://api.customer.com/webhooks/hvt",
            events=["user.created", "user.login"],
            secret="whsec_test_secret_1234567890abcdef",
        )

    def test_generate_webhook_signature(self):
        sig = generate_webhook_signature('{"test": true}', "my_secret")
        self.assertTrue(sig.startswith("sha256="))
        self.assertEqual(len(sig), 7 + 64)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    def test_trigger_webhook_event_enqueues_outbox_task(self):
        deliveries = trigger_webhook_event(
            organization=self.org,
            event_type="user.created",
            payload={"user_id": "usr-123", "email": "alice@customer.com"},
            project=self.project,
        )

        self.assertEqual(len(deliveries), 1)
        delivery = deliveries[0]
        self.assertEqual(delivery.status, "pending")
        self.assertEqual(delivery.event_type, "user.created")
        self.assertIn("X-HVT-Signature", delivery.request_headers)

        task = OutboxTask.objects.filter(
            task_type=OutboxTask.TaskType.WEBHOOK_DELIVERY,
            payload__delivery_id=str(delivery.id),
        ).first()
        self.assertIsNotNone(task)
        self.assertEqual(task.status, OutboxTask.Status.PENDING)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("requests.post")
    def test_outbox_worker_processes_webhook_delivery_success(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            headers={"content-type": "application/json"},
            text='{"received": true}',
        )

        trigger_webhook_event(
            organization=self.org,
            event_type="user.login",
            payload={"user_id": "usr-456"},
            project=self.project,
        )

        processed = process_outbox_tasks(max_tasks=5, worker_id="webhook-worker")
        self.assertEqual(processed, 1)

        delivery = WebhookDelivery.objects.first()
        self.assertEqual(delivery.status, "success")
        self.assertEqual(delivery.response_status_code, 200)

        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.success_count, 1)
        self.assertEqual(self.webhook.consecutive_failures, 0)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("requests.post")
    def test_outbox_worker_processes_webhook_delivery_failure_and_retries(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=500,
            headers={},
            text="Internal Server Error",
        )

        trigger_webhook_event(
            organization=self.org,
            event_type="user.created",
            payload={"user_id": "usr-fail"},
            project=self.project,
        )

        processed = process_outbox_tasks(max_tasks=5, worker_id="webhook-worker")
        self.assertEqual(processed, 1)

        delivery = WebhookDelivery.objects.order_by("-created_at").first()
        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.response_status_code, 500)

        task = OutboxTask.objects.order_by("-created_at").first()
        self.assertEqual(task.status, OutboxTask.Status.PENDING)
        self.assertEqual(task.attempt_count, 1)

        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.failure_count, 1)
        self.assertEqual(self.webhook.consecutive_failures, 1)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("requests.post")
    def test_webhook_auto_disabled_after_10_consecutive_failures(self, mock_post):
        mock_post.side_effect = requests.RequestException("Connection refused")
        self.webhook.consecutive_failures = 9
        self.webhook.save()

        trigger_webhook_event(
            organization=self.org,
            event_type="user.created",
            payload={"user_id": "usr-fail-10"},
            project=self.project,
        )

        process_outbox_tasks(max_tasks=5, worker_id="webhook-worker")

        self.webhook.refresh_from_db()
        self.assertEqual(self.webhook.consecutive_failures, 10)
        self.assertFalse(self.webhook.is_active)
