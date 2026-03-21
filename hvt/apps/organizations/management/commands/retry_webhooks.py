"""
Management command to retry failed webhook deliveries.

Usage:
    python manage.py retry_webhooks              # Retry all failed deliveries from last 24h
    python manage.py retry_webhooks --hours 48   # Custom lookback window
    python manage.py retry_webhooks --dry-run    # Preview without sending
    python manage.py retry_webhooks --webhook-id <uuid>  # Retry for a specific webhook
"""

import logging
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from hvt.apps.organizations.models import Webhook, WebhookDelivery
from hvt.apps.organizations.webhooks import send_webhook

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Retry failed webhook deliveries with exponential backoff"

    def add_arguments(self, parser):
        parser.add_argument(
            "--hours",
            type=int,
            default=24,
            help="Lookback window in hours (default: 24)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview which deliveries would be retried without sending",
        )
        parser.add_argument(
            "--webhook-id",
            type=str,
            default=None,
            help="Only retry deliveries for a specific webhook UUID",
        )
        parser.add_argument(
            "--max-retries",
            type=int,
            default=50,
            help="Maximum number of deliveries to retry in one run (default: 50)",
        )
        parser.add_argument(
            "--re-enable",
            action="store_true",
            help="Re-enable auto-disabled webhooks and reset their failure counters",
        )

    def handle(self, *args, **options):
        hours = options["hours"]
        dry_run = options["dry_run"]
        webhook_id = options["webhook_id"]
        max_retries = options["max_retries"]
        re_enable = options["re_enable"]

        cutoff = timezone.now() - timedelta(hours=hours)

        # Optionally re-enable auto-disabled webhooks
        if re_enable:
            self._re_enable_webhooks(webhook_id, dry_run)

        # Build queryset of failed deliveries
        qs = WebhookDelivery.objects.filter(
            status="failed",
            created_at__gte=cutoff,
            webhook__is_active=True,
        ).select_related("webhook", "webhook__organization")

        if webhook_id:
            qs = qs.filter(webhook_id=webhook_id)

        deliveries = qs.order_by("created_at")[:max_retries]
        total = len(deliveries)

        if total == 0:
            self.stdout.write(self.style.SUCCESS("No failed deliveries to retry."))
            return

        self.stdout.write(
            f"Found {total} failed deliveries in the last {hours}h"
            + (" (dry run)" if dry_run else "")
        )

        success_count = 0
        fail_count = 0

        for delivery in deliveries:
            webhook = delivery.webhook
            self.stdout.write(
                f"  [{delivery.id}] event={delivery.event_type} "
                f"webhook={webhook.id} url={webhook.url}"
            )

            if dry_run:
                continue

            try:
                # Re-send the original payload to the same webhook
                send_webhook(webhook, delivery.event_type, delivery.payload.get("data", {}))
                success_count += 1
                self.stdout.write(self.style.SUCCESS(f"    -> Retried successfully"))

                # Mark original delivery as superseded
                delivery.status = "retried"
                delivery.save(update_fields=["status"])

            except Exception as e:
                fail_count += 1
                self.stdout.write(self.style.ERROR(f"    -> Failed: {e}"))
                logger.error(
                    "retry_webhooks: delivery=%s error=%s",
                    delivery.id,
                    str(e),
                    exc_info=True,
                )

        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nDone. Retried: {success_count}, Failed: {fail_count}, "
                    f"Skipped: {total - success_count - fail_count}"
                )
            )

    def _re_enable_webhooks(self, webhook_id, dry_run):
        """Re-enable webhooks that were auto-disabled due to consecutive failures."""
        qs = Webhook.objects.filter(is_active=False, consecutive_failures__gte=10)
        if webhook_id:
            qs = qs.filter(id=webhook_id)

        count = qs.count()
        if count == 0:
            self.stdout.write("No auto-disabled webhooks to re-enable.")
            return

        self.stdout.write(
            f"Found {count} auto-disabled webhook(s)"
            + (" (dry run)" if dry_run else "")
        )

        if not dry_run:
            qs.update(is_active=True, consecutive_failures=0)
            self.stdout.write(
                self.style.SUCCESS(f"Re-enabled {count} webhook(s)")
            )
