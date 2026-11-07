"""
Transactional Outbox Task Engine for HVT.

Provides resilient, background task execution with:
- ACID transactional guarantees (enqueued atomically with DB models)
- Concurrency-safe task claiming via select_for_update(skip_locked=True)
- Automatic retries with exponential backoff
- Stale lock detection and reclamation
"""

from datetime import timedelta
import logging
import os
import socket
import sys
from typing import Any, Callable, Optional

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from hvt.apps.organizations.models import OutboxTask

logger = logging.getLogger(__name__)


def _get_default_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def execute_webhook_delivery_task(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a queued webhook delivery attempt."""
    from hvt.apps.organizations.models import Webhook, WebhookDelivery
    from hvt.apps.organizations.webhooks import execute_delivery_attempt

    delivery_id = payload.get("delivery_id")
    if not delivery_id:
        raise ValueError("Missing delivery_id in webhook delivery task payload.")

    delivery = (
        WebhookDelivery.objects.select_related("webhook")
        .filter(id=delivery_id)
        .first()
    )
    if not delivery:
        raise ValueError(f"WebhookDelivery {delivery_id} not found.")

    return execute_delivery_attempt(delivery)


def execute_email_dispatch_task(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a queued email dispatch task."""
    from hvt.apps.authentication.email_providers import resolve_email_provider
    from hvt.apps.organizations.models import Project

    project_id = payload.get("project_id")
    project = None
    if project_id:
        project = Project.objects.filter(id=project_id).first()

    provider = resolve_email_provider(project)
    return provider.send(
        to=payload.get("to", ""),
        subject=payload.get("subject", "Notification"),
        html=payload.get("html", "<p>Notification</p>"),
        text=payload.get("text"),
        from_email=payload.get("from_email"),
        from_name=payload.get("from_name"),
    )


def get_task_handler(task_type: str) -> Optional[Callable[[dict[str, Any]], Any]]:
    """Resolve the callable handler dynamically from module scope."""
    this_module = sys.modules[__name__]
    if task_type == OutboxTask.TaskType.WEBHOOK_DELIVERY:
        return getattr(this_module, "execute_webhook_delivery_task", execute_webhook_delivery_task)
    elif task_type == OutboxTask.TaskType.EMAIL_DISPATCH:
        return getattr(this_module, "execute_email_dispatch_task", execute_email_dispatch_task)
    return None


def execute_single_task(task: OutboxTask) -> bool:
    """
    Execute a single task and update its lifecycle state.

    Returns True if the task succeeded, False if it failed.
    """
    handler = get_task_handler(task.task_type)
    if not handler:
        task.status = OutboxTask.Status.FAILED
        task.last_error = f"No handler registered for task type '{task.task_type}'."
        task.locked_at = None
        task.locked_by = ""
        task.save(update_fields=["status", "last_error", "locked_at", "locked_by"])
        return False

    task.attempt_count += 1
    try:
        handler(task.payload)
        task.status = OutboxTask.Status.COMPLETED
        task.completed_at = timezone.now()
        task.last_error = ""
        task.locked_at = None
        task.locked_by = ""
        task.save(
            update_fields=[
                "status",
                "attempt_count",
                "completed_at",
                "last_error",
                "locked_at",
                "locked_by",
            ]
        )
        logger.info(
            "Outbox task %s (%s) completed successfully.",
            task.id,
            task.task_type,
        )
        return True
    except Exception as exc:
        logger.warning(
            "Outbox task %s (%s) failed attempt %d/%d: %s",
            task.id,
            task.task_type,
            task.attempt_count,
            task.max_attempts,
            exc,
        )
        task.last_error = str(exc)[:2000]
        if task.attempt_count >= task.max_attempts:
            task.status = OutboxTask.Status.FAILED
        else:
            task.status = OutboxTask.Status.PENDING
            backoff_seconds = min(3600, (2 ** task.attempt_count) * 2)
            task.next_run_at = timezone.now() + timedelta(seconds=backoff_seconds)

        task.locked_at = None
        task.locked_by = ""
        task.save(
            update_fields=[
                "status",
                "attempt_count",
                "next_run_at",
                "last_error",
                "locked_at",
                "locked_by",
            ]
        )
        return False


def enqueue_task(
    task_type: str,
    payload: dict[str, Any],
    *,
    project=None,
    organization=None,
    run_after_seconds: int = 0,
    max_attempts: int = 5,
) -> OutboxTask:
    """
    Enqueue a task into the Outbox table.

    If TASKS_ALWAYS_EAGER is enabled in settings, executes the task immediately.
    """
    if project is not None and organization is None:
        organization = getattr(project, "organization", None)

    now = timezone.now()
    next_run_at = now
    if run_after_seconds > 0:
        next_run_at = now + timedelta(seconds=run_after_seconds)

    task = OutboxTask.objects.create(
        task_type=task_type,
        payload=payload,
        status=OutboxTask.Status.PENDING,
        attempt_count=0,
        max_attempts=max_attempts,
        next_run_at=next_run_at,
        project=project,
        organization=organization,
    )

    if getattr(settings, "TASKS_ALWAYS_EAGER", False):
        execute_single_task(task)
        task.refresh_from_db()

    return task


def process_outbox_tasks(
    max_tasks: int = 10,
    worker_id: Optional[str] = None,
    stale_timeout_minutes: int = 5,
) -> int:
    """
    Claim and execute pending outbox tasks.

    Uses `select_for_update(skip_locked=True)` so multiple worker processes
    can run concurrently without duplicate execution.

    Returns the count of processed tasks.
    """
    resolved_worker_id = worker_id or _get_default_worker_id()
    now = timezone.now()
    stale_cutoff = now - timedelta(minutes=stale_timeout_minutes)

    # 1. Reclaim stale locks left by terminated or crashed workers
    OutboxTask.objects.filter(
        status=OutboxTask.Status.PROCESSING,
        locked_at__lt=stale_cutoff,
    ).update(
        status=OutboxTask.Status.PENDING,
        locked_at=None,
        locked_by="",
    )

    # 2. Concurrency-safe task claiming
    with transaction.atomic():
        pending_candidates = list(
            OutboxTask.objects.select_for_update(skip_locked=True)
            .filter(
                status__in=[OutboxTask.Status.PENDING, OutboxTask.Status.FAILED],
                next_run_at__lte=now,
                attempt_count__lt=models.F("max_attempts"),
            )
            .order_by("next_run_at", "created_at")[:max_tasks]
        )

        if not pending_candidates:
            return 0

        claimed_ids = [t.id for t in pending_candidates]
        OutboxTask.objects.filter(id__in=claimed_ids).update(
            status=OutboxTask.Status.PROCESSING,
            locked_at=now,
            locked_by=resolved_worker_id,
        )

    # 3. Execute claimed tasks outside the transaction block
    processed_count = 0
    for task in pending_candidates:
        task.refresh_from_db()
        execute_single_task(task)
        processed_count += 1

    return processed_count
