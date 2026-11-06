#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""
Audit project dependencies for known security vulnerabilities using pip-audit.
Accepted exceptions (e.g., vulnerabilities without upstream fixes) are read from pip-audit-exceptions.txt.
"""
import sys
import subprocess
from pathlib import Path


def main():
    root_dir = Path(__file__).resolve().parent.parent
    req_file = root_dir / "requirements.txt"
    exceptions_file = root_dir / "pip-audit-exceptions.txt"

    ignore_args = []
    if exceptions_file.exists():
        for line in exceptions_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                vuln_id = line.split()[0]
                ignore_args.extend(["--ignore-vuln", vuln_id])

    audit_target = sys.argv[1:] if len(sys.argv) > 1 else ["--local"]

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
    ] + audit_target + [
        "--progress-spinner",
        "off",
    ] + ignore_args

    print(f"Running dependency security audit: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("\n[SECURITY AUDIT FAILED] Known vulnerabilities found in dependencies.", file=sys.stderr)
        print("Upgrade the packages or document accepted exceptions in pip-audit-exceptions.txt with reasons.", file=sys.stderr)
        sys.exit(result.returncode)

    print("\n[SECURITY AUDIT PASSED] No unaccepted vulnerabilities found.")
    sys.exit(0)


if __name__ == "__main__":
    main()
