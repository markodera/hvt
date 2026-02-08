"""
Webhook delivery system with retry logic.
"""
import hmac
import hashlib
import json
import logging
from datetime import timedelta
from django.utils import timezone
import requests

logger = logging.getLogger(__name__)


def send_webhook(webhook, event_type, payload):
    """
    Send webhook event with retry logic.
    
    Args:
        webhook: Webhook instance
        event_type: Event type string
        payload: Dict containing event data
    """
    from hvt.apps.organizations.models import WebhookDelivery
    
    # Create delivery record
    delivery = WebhookDelivery.objects.create(
        webhook=webhook,
        event_type=event_type,
        payload=payload
    )
    
    # Attempt delivery
    _attempt_delivery(delivery)
    
    return delivery


def _attempt_delivery(delivery):
    """
    Attempt to deliver a webhook.
    """
    from hvt.apps.organizations.models import WebhookDelivery
    
    delivery.attempt_count += 1
    delivery.status = WebhookDelivery.Status.RETRYING if delivery.attempt_count > 1 else WebhookDelivery.Status.PENDING
    delivery.save()
    
    try:
        # Prepare payload
        payload_str = json.dumps(delivery.payload)
        
        # Generate signature
        signature = hmac.new(
            delivery.webhook.secret.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Send request
        headers = {
            'Content-Type': 'application/json',
            'X-HVT-Signature': signature,
            'X-HVT-Event': delivery.event_type,
            'X-HVT-Delivery-ID': str(delivery.id)
        }
        
        response = requests.post(
            delivery.webhook.url,
            data=payload_str,
            headers=headers,
            timeout=10
        )
        
        # Update delivery record
        delivery.response_status_code = response.status_code
        delivery.response_body = response.text[:1000]
        
        if 200 <= response.status_code < 300:
            delivery.status = WebhookDelivery.Status.SUCCESS
            delivery.delivered_at = timezone.now()
            delivery.webhook.success_count += 1
            delivery.webhook.last_triggered_at = timezone.now()
            delivery.webhook.save(update_fields=['success_count', 'last_triggered_at'])
            logger.info(f"Webhook delivered successfully: {delivery.id}")
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text[:200]}")
    
    except Exception as e:
        delivery.error_message = str(e)[:1000]
        delivery.webhook.failure_count += 1
        delivery.webhook.save(update_fields=['failure_count'])
        
        # Schedule retry with exponential backoff
        if delivery.attempt_count < delivery.max_attempts:
            retry_delay = timedelta(minutes=2 ** delivery.attempt_count)
            delivery.next_retry_at = timezone.now() + retry_delay
            delivery.status = WebhookDelivery.Status.RETRYING
            logger.warning(f"Webhook delivery failed, will retry: {delivery.id}")
        else:
            delivery.status = WebhookDelivery.Status.FAILED
            logger.error(f"Webhook delivery failed permanently: {delivery.id}")
    
    delivery.save()


def trigger_webhook_event(organization, event_type, payload):
    """
    Trigger webhooks for an organization.
    
    Usage:
        trigger_webhook_event(
            organization=user.organization,
            event_type="user.created",
            payload={"user_id": str(user.id), "email": user.email}
        )
    """
    from hvt.apps.organizations.models import Webhook
    
    webhooks = Webhook.objects.filter(
        organization=organization,
        is_active=True,
        events__contains=[event_type]
    )
    
    for webhook in webhooks:
        send_webhook(webhook, event_type, payload)
    
    return webhooks.count()