"""
Unit and integration tests for the Transactional Outbox Task Worker.
"""

from datetime import timedelta
import io
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from hvt.apps.organizations.models import Organization, OutboxTask, Project
from hvt.apps.organizations.tasks import (
    enqueue_task,
    execute_single_task,
    process_outbox_tasks,
)


class OutboxWorkerUnitTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Task Org", slug="task-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Task App",
            slug="task-app",
        )

    @override_settings(TASKS_ALWAYS_EAGER=False)
    def test_enqueue_task_creates_pending_record(self):
        task = enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "test@example.com", "subject": "Hi", "html": "<p>Hi</p>"},
            project=self.project,
            run_after_seconds=30,
            max_attempts=3,
        )

        self.assertIsInstance(task.id, object)
        self.assertEqual(task.status, OutboxTask.Status.PENDING)
        self.assertEqual(task.attempt_count, 0)
        self.assertEqual(task.max_attempts, 3)
        self.assertGreater(task.next_run_at, timezone.now())

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", return_value={"status": "sent"})
    def test_process_outbox_tasks_completes_successful_job(self, mock_dispatch):
        task = enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "user@example.com", "subject": "Test", "html": "body"},
            project=self.project,
        )

        processed = process_outbox_tasks(max_tasks=10, worker_id="test-worker")
        self.assertEqual(processed, 1)

        task.refresh_from_db()
        self.assertEqual(task.status, OutboxTask.Status.COMPLETED)
        self.assertEqual(task.attempt_count, 1)
        self.assertIsNotNone(task.completed_at)
        self.assertEqual(task.last_error, "")
        mock_dispatch.assert_called_once()

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", side_effect=RuntimeError("SMTP timeout"))
    def test_process_outbox_tasks_retries_with_backoff(self, mock_dispatch):
        task = enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "user@example.com", "subject": "Test", "html": "body"},
            project=self.project,
            max_attempts=3,
        )

        processed = process_outbox_tasks(max_tasks=10, worker_id="test-worker")
        self.assertEqual(processed, 1)

        task.refresh_from_db()
        self.assertEqual(task.status, OutboxTask.Status.PENDING)
        self.assertEqual(task.attempt_count, 1)
        self.assertIn("SMTP timeout", task.last_error)
        self.assertGreater(task.next_run_at, timezone.now())

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", side_effect=RuntimeError("Permanent failure"))
    def test_process_outbox_tasks_marks_failed_after_max_attempts(self, mock_dispatch):
        task = enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "user@example.com", "subject": "Test", "html": "body"},
            project=self.project,
            max_attempts=1,
        )

        processed = process_outbox_tasks(max_tasks=10, worker_id="test-worker")
        self.assertEqual(processed, 1)

        task.refresh_from_db()
        self.assertEqual(task.status, OutboxTask.Status.FAILED)
        self.assertEqual(task.attempt_count, 1)
        self.assertIn("Permanent failure", task.last_error)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    def test_process_outbox_tasks_reclaims_stale_locks(self):
        stale_time = timezone.now() - timedelta(minutes=15)
        stale_task = OutboxTask.objects.create(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "stale@example.com", "subject": "Stale", "html": "body"},
            status=OutboxTask.Status.PROCESSING,
            locked_at=stale_time,
            locked_by="crashed-worker-99",
            next_run_at=timezone.now(),
        )

        with patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", return_value={"status": "ok"}):
            processed = process_outbox_tasks(max_tasks=5, worker_id="fresh-worker")

        self.assertEqual(processed, 1)
        stale_task.refresh_from_db()
        self.assertEqual(stale_task.status, OutboxTask.Status.COMPLETED)

    @override_settings(TASKS_ALWAYS_EAGER=False)
    @patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", return_value={"status": "ok"})
    def test_run_worker_management_command_once(self, mock_dispatch):
        enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "cli@example.com", "subject": "Test", "html": "body"},
            project=self.project,
        )

        out = io.StringIO()
        call_command("run_worker", "--once", "--batch-size=5", stdout=out)
        output = out.getvalue()

        self.assertIn("[HVT Outbox Worker] Starting worker", output)
        self.assertIn("Processed 1 task(s)", output)
        self.assertIn("Total tasks processed: 1", output)

    @override_settings(TASKS_ALWAYS_EAGER=True)
    @patch("hvt.apps.organizations.tasks.execute_email_dispatch_task", return_value={"status": "ok"})
    def test_tasks_always_eager_executes_immediately(self, mock_dispatch):
        task = enqueue_task(
            task_type=OutboxTask.TaskType.EMAIL_DISPATCH,
            payload={"to": "eager@example.com", "subject": "Hi", "html": "<p>Eager</p>"},
            project=self.project,
        )

        task.refresh_from_db()
        self.assertEqual(task.status, OutboxTask.Status.COMPLETED)
        mock_dispatch.assert_called_once()
