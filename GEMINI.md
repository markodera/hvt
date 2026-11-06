# Antigravity Project Rules (HVT)

<!-- This file is automatically loaded by Antigravity and subagents on every invocation. -->

## 🚨 MANDATORY PROTOCOL: Continuous Audit Synchronization

Whenever you or any subagent make changes (bug fixes, feature additions, refactoring, endpoint alterations, model updates, security hardening, or test updates) to this repository, you **MUST**:

1. **Update the Corresponding Audit Chapter(s)** in `docs/audit/`:
   - `00-summary.md`: Top findings and advisor questions.
   - `01-architecture-and-data.md`: Models, migrations, environment variables, settings, Docker, CI.
   - `02-features-and-endpoints.md`: Endpoints table, permission classes, feature statuses.
   - `03-tokens-sessions-passkeys.md`: Token mechanics, JWT signing, claims, JWKS, cookies, CORS, WebAuthn.
   - `04-security.md`: Security issues, rate limits, hashing, token storage, SSRF, AllowAny routes.
   - `05-live-behavior.md`: Live behavior, API responses, CLI executions.
   - `06-testing-ops-quality.md`: Test count, slow tests, CI commands, production dependencies.
   - `07-roadmap-readiness.md`: Roadmap items, blockers, effort estimates.
   - `08-unknowns-and-surprises.md`: Document drift, resolved unknowns, newly uncovered assumptions.

2. **Follow Evidence Rules**:
   - Tag claims with `[VERIFIED file:line]`, `[RAN command -> result]`, `[INFERRED]`, or `[UNKNOWN]`.
   - Never print raw secrets (show prefixes only: `hvt_mgmt_test_ab12...`).
   - Redact all emails and tokens in outputs.

3. **Re-run the Bundler**:
   ```bash
   python docs/audit/bundle.py
   ```
   This automatically updates:
   - `docs/audit/HVT_FULL_AUDIT_REPORT.md`
   - `docs/audit/HVT_AUDIT_DOCS.zip`

4. **Confirm to the User**:
   - Highlight what audit chapter was updated and confirm that `docs/audit/HVT_FULL_AUDIT_REPORT.md` has been refreshed and is ready to share with their online AI.
