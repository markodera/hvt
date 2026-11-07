"""
Management command to run the Transactional Outbox task worker.

Usage:
    python manage.py run_worker                     # Continuous background worker loop
    python manage.py run_worker --once              # Process all pending tasks once and exit
    python manage.py run_worker --poll-interval 2.0 # Custom polling interval (seconds)
    python manage.py run_worker --batch-size 25     # Maximum tasks per batch
"""

import logging
import signal
import sys
import time

from django.core.management.base import BaseCommand

from hvt.apps.organizations.tasks import process_outbox_tasks

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run the Transactional Outbox background task worker."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_requested = False

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Process all currently pending tasks once and exit.",
        )
        parser.add_argument(
            "--poll-interval",
            type=float,
            default=1.0,
            help="Seconds to wait between polls when no tasks are ready (default: 1.0).",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=10,
            help="Maximum tasks to claim per database batch (default: 10).",
        )
        parser.add_argument(
            "--worker-id",
            type=str,
            default=None,
            help="Explicit worker identifier for distributed lock assignment.",
        )

    def handle(self, *args, **options):
        once = options["once"]
        poll_interval = max(0.1, options["poll_interval"])
        batch_size = max(1, options["batch_size"])
        worker_id = options["worker_id"]

        self._setup_signals()

        self.stdout.write(
            self.style.SUCCESS(
                f"[HVT Outbox Worker] Starting worker (batch_size={batch_size}, "
                f"poll_interval={poll_interval}s, mode={'once' if once else 'continuous'})..."
            )
        )

        total_processed = 0

        try:
            while not self.stop_requested:
                processed = process_outbox_tasks(
                    max_tasks=batch_size,
                    worker_id=worker_id,
                )
                total_processed += processed

                if processed > 0:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"[HVT Outbox Worker] Processed {processed} task(s)."
                        )
                    )
                    # When tasks are actively being processed, poll immediately for next batch
                    continue

                if once:
                    break

                time.sleep(poll_interval)

        except KeyboardInterrupt:
            self.stdout.write("\nReceived KeyboardInterrupt.")

        self.stdout.write(
            self.style.SUCCESS(
                f"[HVT Outbox Worker] Worker shutdown complete. Total tasks processed: {total_processed}"
            )
        )

    def _setup_signals(self):
        def _handler(signum, frame):
            self.stdout.write(
                self.style.WARNING(
                    f"\n[HVT Outbox Worker] Received signal {signum}. Requesting graceful shutdown..."
                )
            )
            self.stop_requested = True

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
