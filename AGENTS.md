# Agent Instructions & Living Audit Rule (HVT)

## 🚨 MANDATORY PROTOCOL: Continuous Audit Synchronization

This repository maintains an active, code-verified ground truth technical audit in `docs/audit/`.
Any AI agent (Antigravity, Claude Code, Cursor, Codex, subagents, or peer agents) working on this codebase **MUST** follow this protocol whenever implementing changes.

---

### 1. Identify Affected Audit Chapter
Whenever you modify, add, fix, delete, or refactor any code, configuration, or test:

| Area of Change | Primary Audit Chapter to Update |
| :--- | :--- |
| **Models, schemas, migrations, env vars, settings, Docker, CI** | `docs/audit/01-architecture-and-data.md` |
| **Endpoints, URLconf, permissions, authenticators, features, SDK, CLI** | `docs/audit/02-features-and-endpoints.md` |
| **Tokens, JWT signing, claims, JWKS, cookies, CORS, WebAuthn** | `docs/audit/03-tokens-sessions-passkeys.md` |
| **Security vulnerabilities, rate limits, hashing, SSRF, auto-linking** | `docs/audit/04-security.md` |
| **Live behavior, error payloads, status codes, lockouts, CLI execution** | `docs/audit/05-live-behavior.md` |
| **Tests, test runner, coverage, slow tests, CI commands, operations** | `docs/audit/06-testing-ops-quality.md` |
| **Roadmap features, architectural blockers, SaaS support readiness** | `docs/audit/07-roadmap-readiness.md` |
| **Document drift, resolved unknowns, newly uncovered assumptions** | `docs/audit/08-unknowns-and-surprises.md` |
| **Top 15 ranked findings or advisor questions** | `docs/audit/00-summary.md` |

---

### 2. Update with Verified Evidence
- Tag every updated claim with an evidence marker: `[VERIFIED file:line]`, `[RAN command -> result]`, `[INFERRED]`, or `[UNKNOWN]`.
- Always redact secrets, tokens, and emails (e.g. `hvt_test_ab12...`, `to***@example.com`).
- Maintain the three core headings in each file:
  1. `## WHAT WE KNOW (verified)`
  2. `## WHAT WE DON'T KNOW (could not verify, and why)`
  3. `## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with our docs, risks nobody asked about)`

---

### 3. Re-bundle the Master Audit Report
After modifying any `docs/audit/` chapter, execute:
```bash
python docs/audit/bundle.py
```
This automatically synchronizes:
*   `docs/audit/HVT_FULL_AUDIT_REPORT.md` (Consolidated master report with Table of Contents)
*   `docs/audit/HVT_AUDIT_DOCS.zip` (Archive containing all individual chapters)

---

### 4. Notify the User
In your turn response, explicitly confirm that the audit documentation has been updated and re-bundled so the user can immediately share the updated `HVT_FULL_AUDIT_REPORT.md` with their online advisor AI.
