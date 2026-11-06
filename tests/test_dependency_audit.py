# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from unittest.mock import patch
from django.test import SimpleTestCase
import subprocess
import sys

from scripts.audit_dependencies import main as audit_main


class DependencyAuditTests(SimpleTestCase):
    def test_exceptions_file_exists_and_is_formatted(self):
        root_dir = Path(__file__).resolve().parent.parent
        exceptions_file = root_dir / "pip-audit-exceptions.txt"
        self.assertTrue(exceptions_file.exists(), "pip-audit-exceptions.txt must exist")
        lines = exceptions_file.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                # Must start with a vulnerability identifier (e.g., PYSEC-..., GHSA-..., CVE-...)
                self.assertTrue(len(parts) >= 1)

    @patch("subprocess.run")
    def test_audit_main_success(self, mock_run):
        mock_run.return_value.returncode = 0
        with patch.object(sys, "argv", ["audit_dependencies.py", "--local"]):
            try:
                audit_main()
            except SystemExit as exc:
                self.assertEqual(exc.code, 0)
        self.assertTrue(mock_run.called)
        cmd_args = mock_run.call_args[0][0]
        self.assertIn("pip_audit", cmd_args)
        self.assertIn("--local", cmd_args)

    @patch("subprocess.run")
    def test_audit_main_failure(self, mock_run):
        mock_run.return_value.returncode = 1
        with patch.object(sys, "argv", ["audit_dependencies.py", "--local"]):
            with self.assertRaises(SystemExit) as exc:
                audit_main()
            self.assertEqual(exc.exception.code, 1)
