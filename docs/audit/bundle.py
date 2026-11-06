"""
HVT Audit Report Bundler
------------------------
Combines all 9 audit chapters in docs/audit/ into:
  1. HVT_FULL_AUDIT_REPORT.md (Single consolidated master document with TOC)
  2. HVT_AUDIT_DOCS.zip (Archive containing all individual chapters)

Usage:
  python docs/audit/bundle.py
"""

import os
import subprocess
import zipfile
from datetime import datetime, timezone

AUDIT_DIR = os.path.dirname(os.path.abspath(__file__))
CHAPTERS = [
    "00-summary.md",
    "01-architecture-and-data.md",
    "02-features-and-endpoints.md",
    "03-tokens-sessions-passkeys.md",
    "04-security.md",
    "05-live-behavior.md",
    "06-testing-ops-quality.md",
    "07-roadmap-readiness.md",
    "08-unknowns-and-surprises.md"
]

OUTPUT_MD = os.path.join(AUDIT_DIR, "HVT_FULL_AUDIT_REPORT.md")
OUTPUT_ZIP = os.path.join(AUDIT_DIR, "HVT_AUDIT_DOCS.zip")

def get_git_commit():
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=AUDIT_DIR,
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "Unknown / Uncommitted"

def bundle():
    commit = get_git_commit()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    chapter_stats = []
    total_words = 0
    total_chars = 0
    
    for filename in CHAPTERS:
        path = os.path.join(AUDIT_DIR, filename)
        if not os.path.exists(path):
            print(f"Warning: Missing chapter {filename}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        words = len(content.split())
        chars = len(content)
        total_words += words
        total_chars += chars
        chapter_stats.append((filename, content, words, chars))
        
    # 1. Write HVT_FULL_AUDIT_REPORT.md
    with open(OUTPUT_MD, "w", encoding="utf-8") as out:
        out.write("# HVT Ground-Truth Complete Technical Audit Report\n\n")
        out.write(f"> **Latest Commit:** `{commit}`  \n")
        out.write(f"> **Last Synchronized:** `{now_utc}`  \n")
        out.write(f"> **Total Chapters:** {len(chapter_stats)}  \n")
        out.write(f"> **Total Volume:** {total_words:,} words ({total_chars:,} characters)  \n\n")
        
        out.write("## Table of Contents\n\n")
        out.write("| # | Chapter | Word Count | Direct Link |\n")
        out.write("|---|---|---|---|\n")
        for i, (fname, _, words, _) in enumerate(chapter_stats, 1):
            title = fname.replace(".md", "").replace("-", " ").title()
            anchor = fname.replace(".md", "")
            out.write(f"| {i:02d} | {title} | {words:,} words | [{fname}](#{anchor}) |\n")
        out.write(f"| | **TOTAL** | **{total_words:,} words** | |\n\n")
        out.write("---\n\n")
        
        for fname, content, _, _ in chapter_stats:
            anchor = fname.replace(".md", "")
            out.write(f'<a id="{anchor}"></a>\n\n')
            out.write(content)
            out.write("\n\n---\n\n")
            
    # 2. Write HVT_AUDIT_DOCS.zip
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for fname, _, _, _ in chapter_stats:
            path = os.path.join(AUDIT_DIR, fname)
            zipf.write(path, arcname=fname)
        # Also include the consolidated report in the zip
        zipf.write(OUTPUT_MD, arcname="HVT_FULL_AUDIT_REPORT.md")
        
    print(f"[SUCCESS] Audit Report Synchronized:")
    print(f"  - Master File: {OUTPUT_MD} ({os.path.getsize(OUTPUT_MD):,} bytes, {total_words:,} words)")
    print(f"  - Zip Archive: {OUTPUT_ZIP} ({os.path.getsize(OUTPUT_ZIP):,} bytes)")

if __name__ == "__main__":
    bundle()
