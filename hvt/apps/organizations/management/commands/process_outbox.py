"""
Alias command for run_worker.py:
Provides `python manage.py process_outbox` matching Phase 2 Step 6 specification.
"""

from hvt.apps.organizations.management.commands.run_worker import Command

__all__ = ["Command"]
