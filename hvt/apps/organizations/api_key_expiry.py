import logging

from django.db import transaction
from django.utils import timezone

from hvt.apps.organizations.models import APIKey, Webhook
from hvt.apps.organizations.webhooks import trigger_webhook_event

logger = logging.getLogger(__name__)


def emit_api_key_expiry_webhook(api_key: APIKey) -> bool:
    """
    Emit `api_key.expired` once for an expired key.

    The notification is recorded before dispatch so concurrent callers do not
    send duplicate expiry webhooks for the same key.
    """

    emitted_at = timezone.now()

    with transaction.atomic():
        locked_key = (
            APIKey.objects.select_for_update()
            .select_related("organization")
            .get(pk=api_key.pk)
        )

        if not locked_key.is_expired or locked_key.expired_webhook_sent_at:
            return False

        if locked_key.project_id is None:
            locked_key.project = locked_key.organization.ensure_default_project()

        update_fields = ["expired_webhook_sent_at"]
        if locked_key.project_id:
            update_fields.append("project")

        locked_key.expired_webhook_sent_at = emitted_at
        locked_key.save(update_fields=update_fields)

    project = locked_key.project if locked_key.project_id else locked_key.organization.ensure_default_project()

    trigger_webhook_event(
        organization=locked_key.organization,
        project=project,
        event_type=Webhook.EventType.API_KEY_EXPIRED,
        payload={
            "api_key_id": str(locked_key.id),
            "name": locked_key.name,
            "prefix": locked_key.prefix,
            "environment": locked_key.environment,
            "expires_at": locked_key.expires_at.isoformat() if locked_key.expires_at else None,
            "project_id": str(project.id),
            "project_slug": project.slug,
        },
    )

    logger.info(
        "Emitted api_key.expired webhook for key=%s project=%s",
        locked_key.id,
        project.id,
    )
    return True
