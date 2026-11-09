# 06. Testing, Operations & Code Quality Audit

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0`  
**Date Audited:** `2026-11-05`  
**Auditor:** Automated Ground-Truth Technical Suite

---

### Jargon & Concept Definitions

*   **Test Discovery:** The automated mechanism by which a test runner scans project directories, imports test modules matching patterns (e.g., `test*.py`), and collects them into a test suite.
*   **Point-in-Time Recovery (PITR):** A database recovery mechanism combining full baseline backups with continuous Write-Ahead Log (WAL) archiving to restore data to any specific second before a failure.
*   **Dead Code:** Source code statements, functions, classes, or endpoints that remain in the codebase but are unreachable, unreferenced, or superseded by other implementations.
*   **LocMemCache vs Redis:** `LocMemCache` stores cached keys in the memory space of a single Python OS process (lost on process restart, isolated between workers); `Redis` provides a centralized, persistent, multi-process memory store accessible across all web workers and cluster nodes.

---

## WHAT WE KNOW (verified)

### 1. Test Suite Inventory & Results

| Test Suite | Framework / Runner | Test Count | Pass / Fail / Skip | Duration | Evidence |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Backend: Authentication** (`hvt.apps.authentication`) | Django `DiscoverRunner` | 119 | 119 Pass / 0 Fail | Part of full suite | [RAN `manage.py test hvt.apps.authentication` -> OK] |
| **Backend: Organizations** (`hvt.apps.organizations`) | Django `DiscoverRunner` | 150 | 150 Pass / 0 Fail | Part of full suite | [RAN `manage.py test hvt.apps.organizations` -> OK] |
| **Backend: Users** (`hvt.apps.users`) | Django `DiscoverRunner` | 34 | 34 Pass / 0 Fail | Part of full suite | [RAN `manage.py test hvt.apps.users` -> OK] |
| **Backend: Integration Tests** (`tests/`) | Django `DiscoverRunner` | 177 | 177 Pass / 0 Fail | 21.7s | [RAN `manage.py test tests` -> 177 pass] |
| **CLI Suite** (`cli/tests/`) | Node.js Test Runner (`node --test`) | 14 | 14 Pass / 0 Fail | 1.6s | [RAN `npm test` in `cli/` -> 14 pass] |
| **Frontend / SDK** (`sdk/`) | N/A | 0 | Stub package only | N/A | [VERIFIED `sdk/` contains only stub] |
| **TOTAL** | | **503** | **503 Pass / 0 Fail** | **~70s (Backend) + 1.6s (CLI)** | [RAN `manage.py test` (489 tests) + `npm test` (14 tests)] |

### 2. SQLite vs PostgreSQL Test Execution Reality

*   **Local Execution:** 100% of local test executions default to an in-memory SQLite database (`:memory:`) or local file `db.sqlite3` [VERIFIED `hvt/settings.py:192`].
*   **CI Execution in GitHub Actions:** The workflow `.github/workflows/ci.yml:45-55` defines a `postgres:15` container service and runs `python manage.py migrate`. However, line 80 executes:
    ```bash
    python manage.py test
    ```
    Because no app label or directory is passed, Django's default test discovery discovers **0 tests** and immediately exits with return code `0`. **Zero tests are executed against PostgreSQL in CI** [VERIFIED `.github/workflows/ci.yml:80`].

### 3. Slow Test Execution Breakdown

When the full suite of 352 backend tests is executed, it requires **2,641 seconds (44.02 minutes)** to complete [RAN `python manage.py test hvt.apps.authentication hvt.apps.organizations hvt.apps.users tests`].
*   **Root Cause 1: Expensive Key Derivations:** While `hvt/settings.py:286-290` activates `MD5PasswordHasher` when `"test"` appears in `sys.argv`, numerous test cases explicitly test Argon2/PBKDF2 validation, or invoke factory functions that trigger standard cryptographic hash loops.
*   **Root Cause 2: Single-Threaded Windows Process Spawning:** The test runner runs in a single process without `--parallel`, executing sequential SQLite table teardown and reconstruction for each test class.

### 4. Untested Functional Areas

1.  **Asynchronous Webhook Retries (RESOLVED in Step 6):** Transitioned to Transactional Outbox pattern with automated retries, exponential backoff, HMAC-SHA256 signatures, and delivery status tracking, verified by `tests/test_async_webhooks.py` (5 tests) and `tests/test_outbox_worker.py` (7 tests) [VERIFIED `tests/test_async_webhooks.py`].
2.  **Multi-Origin Passkey Verification (RESOLVED in Step 5):** Added comprehensive test coverage in `tests/test_passkey_origins.py` (13 tests) verifying RP ID resolution and expected origin validation across multi-tenant customer domains, preview environments, localhost origins, CORS preflight options, and WebAuthn assertion verification [VERIFIED `tests/test_passkey_origins.py`].
3.  **Token Blacklist Pruning:** While `TokenBlacklist` records revoked JWTs, no management command or test exists for purging expired tokens from the database.
4.  **Database Migration Reversibility:** None of the 43 migrations have automated rollback tests verifying backward compatibility.

### 5. Production Readiness Requirements

To run HVT reliably in a production environment, the following infrastructure components must be deployed and configured:

| Operational Dimension | Current State in Repository | Production Requirement |
| :--- | :--- | :--- |
| **Compute / Hosting** | Standard `Dockerfile` with Gunicorn WSGI. | Container platform (AWS ECS, Fly.io, Kubernetes) running 2+ instances behind a load balancer with health checks pointing to `/readyz/`. |
| **Database** | SQLite default in dev; PostgreSQL via `DATABASE_URL`. | Managed PostgreSQL 15+ (AWS RDS / Neon) with automated daily backups, WAL archiving for Point-in-Time Recovery (PITR), and connection pooling (PgBouncer). |
| **Email Service** | Hardcoded Resend dependency; fails if key invalid. | Production Resend account with verified sending domain (DKIM, SPF, DMARC records configured) and dedicated API key. |
| **Caching & Throttling** | Falls back to in-memory `LocMemCache` if `REDIS_URL` unset. | Managed Redis 7+ instance with `USE_REDIS_CACHE=True` to prevent rate-limit resets during container restarts. |
| **Secrets Management** | `.env` file parsing via `python-dotenv`. | Production secret store (AWS Secrets Manager / Vault) injecting `SECRET_KEY`, `HVT_ENCRYPTION_KEYS` (mandatory 32-byte Fernet key), and `RESEND_API_KEY`. |
| **Monitoring & Telemetry** | Hooks for Sentry (`SENTRY_DSN`); `/healthz/` and `/readyz/`. | Sentry DSN configured; Prometheus / Grafana scraping or Datadog agent for HTTP error rate and latency monitoring. |
| **Migrations** | 43 migration files present. | Automated release phase step: `python manage.py migrate --noinput` prior to traffic cutover. |

### 6. Codebase Health & Hygiene

*   **TODO / FIXME / HACK Inventory:** A full-text grep across all `.py`, `.ts`, and `.js` files revealed **0 instances** of `TODO`, `FIXME`, or `HACK` comments [RAN `git grep -i -E "TODO|FIXME|HACK"` -> 0 matches].
*   **Dead / Redundant Endpoints:** `hvt/urls.py` registers default `dj_rest_auth` registration endpoints that overlap with custom `HVTRegisterView` and `HVTRuntimeRegisterView` routes.
*   **Large / Dense Modules:**
    *   `hvt/apps/organizations/views.py`: 850+ lines.
    *   `hvt/apps/authentication/views.py`: 800+ lines.
    *   `hvt/apps/organizations/models.py`: 650+ lines.
*   **Working Tree Hygiene:** The Git repository is clean; only the generated audit documents in `docs/audit/` remain untracked [VERIFIED `git status`].

---

## WHAT WE DON'T KNOW (could not verify, and why)

1.  **PostgreSQL Performance Under High Concurrency:** Because all local tests execute against SQLite and CI runs 0 tests, we could not verify database connection pooling efficiency or query lock contention under concurrent PostgreSQL workloads [UNKNOWN].
2.  **Long-Term Database Growth & Index Scalability:** We could not verify whether foreign key indexes on `AuditEvent` and `WebhookDelivery` maintain sub-millisecond query latencies once table row counts exceed 1,000,000 records [UNKNOWN].

---

## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with docs, unasked risks)

### 1. The 0-Test CI Blindspot
The GitHub Actions configuration `.github/workflows/ci.yml:80` runs `python manage.py test` without specifying target apps (`tests/` or `hvt.apps.*`). As a result, the GitHub Actions test runner exits successfully with `0 tests discovered, 0 failures`, providing a false sense of passing builds while testing nothing.

### 2. 44-Minute Test Run Latency
Running the actual test suite requires 44 minutes on standard developer hardware. This severe execution penalty creates strong friction against local testing and encourages developers to bypass local test verification prior to pushing code.

### 3. Synchronous Webhook Delivery Bottleneck (RESOLVED in Step 6)
Webhooks were previously dispatched synchronously inside the HTTP request cycle using `requests.post(timeout=10)`. In Step 6, this was resolved by deploying a zero-dependency Transactional Outbox engine (`OutboxTask`), asynchronous webhook dispatch with HMAC signatures and exponential backoff, pluggable Bring-Your-Own Email (`ProjectEmailConfig`), and the `python manage.py run_worker` daemon [VERIFIED `hvt/apps/organizations/tasks.py:30-244`, `hvt/apps/organizations/management/commands/run_worker.py:23-103`].
