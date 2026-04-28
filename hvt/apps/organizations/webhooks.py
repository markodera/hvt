"""
Webhook delivery engine for HVT.

Handles sending webhook notifications when authentication and organization
events occur within an organization and project boundary.
"""

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from datetime import timedelta

import requests
from django.utils import timezone

logger = logging.getLogger(__name__)


def generate_webhook_signature(payload_json: str, secret: str) -> str:
    """
    Generate an HMAC-SHA256 signature for a webhook payload.
    """
    signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_json.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"sha256={signature}"


def send_webhook(webhook, event_type: str, payload: dict) -> None:
    """
    Send a single webhook delivery attempt.
    """
    from .models import WebhookDelivery

    delivery_id = uuid.uuid4()
    timestamp = timezone.now().isoformat()

    delivery_payload = {
        "event": event_type,
        "delivery_id": str(delivery_id),
        "timestamp": timestamp,
        "organization_id": str(webhook.organization_id),
        "project_id": str(webhook.project_id),
        "project_slug": webhook.project.slug,
        "data": payload,
    }

    payload_json = json.dumps(delivery_payload, default=str)
    signature = generate_webhook_signature(payload_json, webhook.secret)

    headers = {
        "Content-Type": "application/json",
        "X-HVT-Signature": signature,
        "X-HVT-Event": event_type,
        "X-HVT-Delivery": str(delivery_id),
        "User-Agent": "HVT-Webhook/1.0",
    }

    delivery = WebhookDelivery.objects.create(
        webhook=webhook,
        event_type=event_type,
        payload=delivery_payload,
        request_headers=headers,
        request_body=payload_json,
        status="pending",
    )

    _attempt_delivery(delivery, webhook, headers, payload_json)


def _attempt_delivery(delivery, webhook, headers: dict, payload_json: str) -> None:
    """
    Attempt to deliver a webhook payload with retry logic.
    """
    max_retries = 3

    for attempt in range(max_retries):
        try:
            response = requests.post(
                webhook.url,
                data=payload_json,
                headers=headers,
                timeout=10,
            )

            delivery.response_status_code = response.status_code
            delivery.response_headers = dict(response.headers)
            delivery.response_body = response.text[:5000]
            delivery.attempt_count = attempt + 1

            if 200 <= response.status_code < 300:
                delivery.status = "success"
                delivery.delivered_at = timezone.now()
                delivery.save()

                webhook.success_count += 1
                webhook.last_triggered_at = timezone.now()
                webhook.consecutive_failures = 0
                webhook.save(
                    update_fields=[
                        "success_count",
                        "last_triggered_at",
                        "consecutive_failures",
                    ]
                )
                logger.info(
                    "Webhook delivered successfully: webhook=%s event=%s delivery=%s",
                    webhook.id,
                    delivery.event_type,
                    delivery.id,
                )
                return

            logger.warning(
                "Webhook delivery got %d: webhook=%s event=%s attempt=%d",
                response.status_code,
                webhook.id,
                delivery.event_type,
                attempt + 1,
            )
        except requests.RequestException as exc:
            delivery.response_body = str(exc)[:5000]
            delivery.attempt_count = attempt + 1
            logger.warning(
                "Webhook delivery failed: webhook=%s event=%s attempt=%d error=%s",
                webhook.id,
                delivery.event_type,
                attempt + 1,
                str(exc),
            )

        if attempt < max_retries - 1:
            backoff = (attempt + 1) ** 2
            delivery.status = "retrying"
            delivery.next_retry_at = timezone.now() + timedelta(seconds=backoff)
            delivery.save()
            time.sleep(backoff)

    delivery.status = "failed"
    delivery.save()

    webhook.failure_count += 1
    webhook.consecutive_failures += 1
    webhook.last_triggered_at = timezone.now()

    if webhook.consecutive_failures >= 10:
        webhook.is_active = False
        logger.error(
            "Webhook auto-disabled after %d consecutive failures: webhook=%s url=%s",
            webhook.consecutive_failures,
            webhook.id,
            webhook.url,
        )

    webhook.save(
        update_fields=[
            "failure_count",
            "consecutive_failures",
            "last_triggered_at",
            "is_active",
        ]
    )


def trigger_webhook_event(organization, event_type: str, payload: dict, project=None) -> None:
    """
    Trigger all active webhooks for the target organization/project.
    """
    from .models import Webhook

    try:
        target_project = project or organization.get_default_project()
        if target_project is None:
            return
        webhooks = Webhook.objects.select_related("project").filter(
            organization=organization,
            project=target_project,
            is_active=True,
        )

        for webhook in webhooks:
            if webhook.events and event_type not in webhook.events:
                continue

            thread = threading.Thread(
                target=_safe_send_webhook,
                args=(webhook, event_type, payload),
                daemon=True,
            )
            thread.start()

    except Exception as exc:
        logger.error(
            "Failed to trigger webhook event %s for org %s: %s",
            event_type,
            getattr(organization, "id", "unknown"),
            str(exc),
            exc_info=True,
        )


def _safe_send_webhook(webhook, event_type: str, payload: dict) -> None:
    """
    Thread-safe wrapper around send_webhook.
    """
    try:
        send_webhook(webhook, event_type, payload)
    except Exception as exc:
        logger.error(
            "Unhandled error in webhook delivery thread: webhook=%s event=%s error=%s",
            webhook.id,
            event_type,
            str(exc),
            exc_info=True,
        )
