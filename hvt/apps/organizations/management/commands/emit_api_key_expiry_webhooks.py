from django.core.management.base import BaseCommand
from django.utils import timezone

from hvt.apps.organizations.api_key_expiry import emit_api_key_expiry_webhook
from hvt.apps.organizations.models import APIKey


class Command(BaseCommand):
    help = "Emit api_key.expired webhooks for newly expired API keys."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=200,
            help="Maximum number of expired keys to process in one run (default: 200).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview matching keys without emitting any webhooks.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        dry_run = options["dry_run"]
        limit = options["limit"]

        queryset = (
            APIKey.objects.select_related("organization", "project")
            .filter(
                is_active=True,
                expires_at__isnull=False,
                expires_at__lte=now,
                expired_webhook_sent_at__isnull=True,
            )
            .order_by("expires_at", "created_at")[:limit]
        )

        keys = list(queryset)
        if not keys:
            self.stdout.write(self.style.SUCCESS("No expired API keys awaiting webhook emission."))
            return

        self.stdout.write(
            f"Found {len(keys)} expired API key(s)"
            + (" (dry run)" if dry_run else "")
        )

        emitted = 0
        for api_key in keys:
            project = api_key.project or api_key.organization.ensure_default_project()
            self.stdout.write(
                f"  [{api_key.id}] {api_key.name} ({api_key.prefix}...) project={project.slug}"
            )
            if dry_run:
                continue
            if emit_api_key_expiry_webhook(api_key):
                emitted += 1

        if not dry_run:
            self.stdout.write(self.style.SUCCESS(f"Emitted {emitted} api_key.expired webhook(s)."))

