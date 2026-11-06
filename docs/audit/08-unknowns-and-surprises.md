# 08. Unknowns, Surprises & Document Contradictions

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0`  
**Date Audited:** `2026-11-05`  
**Auditor:** Automated Ground-Truth Technical Suite

---

### Jargon & Concept Definitions

*   **Ground Truth:** Technical facts verified directly against executing source code and runtime behavior, as opposed to design specifications, marketing copy, or developer memories.
*   **Documentation Drift:** The inevitable divergence between written architecture documentation and the actual running codebase as features evolve under deadline pressure.
*   **Zombie Record:** A database row committed during an un-rolled-back partial transaction whose subsequent steps failed, leaving orphaned or inconsistent state that interferes with future operations.
*   **Verification Classification:**
    *   `[VERIFIED]`: Confirmed directly by inspecting source code line numbers or reading database schema.
    *   `[RAN]`: Confirmed directly by executing a command, test runner, or live API request.
    *   `[INFERRED]`: A logical deduction derived from surrounding evidence but not directly observed in running code.
    *   `[UNKNOWN]`: A question or behavior that could not be determined or exercised with available local tooling.

---

## WHAT WE KNOW (verified)

### 1. Direct Contradictions with Existing Documentation

Our code-verified audit uncovered significant contradictions between HVT's written documentation (`README.md`, `walkthrough_for_expert.md`, `llms.txt`, design specs) and the live repository state:

| Document Claim | Codebase Ground Truth | Severity / Impact | Evidence |
| :--- | :--- | :---: | :--- |
| **"Deployments are manual or pending approval; no automated deploy pipeline on main."** (`walkthrough_for_expert.md`) | `.github/workflows/deploy.yml` actively triggers on every `push` to `main`, establishing an automated SSH connection to a production server to pull code, run migrations, and restart systemd. | **HIGH** | [VERIFIED `.github/workflows/deploy.yml:1-35`] |
| **"Continuous Integration tests every commit across PostgreSQL."** (`README.md` & CI docs) | `.github/workflows/ci.yml:80` runs `python manage.py test` with zero arguments. Django discovers **0 tests** and exits with return code `0`. CI has never tested a single feature against PostgreSQL. | **CRITICAL** | [VERIFIED `.github/workflows/ci.yml:80`] |
| **"Asynchronous task workers handle emails, webhook dispatches, and audit ingestion."** (Architecture specs) | **Celery is completely absent.** HVT contains zero asynchronous background workers. Webhooks and emails execute synchronously in the WSGI request thread using blocking `requests.post()` calls. | **HIGH** | [VERIFIED `hvt/settings.py` & `webhooks.py:85`] |
| **"Run `docker compose up` to start production stack."** (`README.md`) | `docker-compose.yml` omits `HVT_ENCRYPTION_KEYS`. In production mode (`DEBUG=0`), Django system check `hvt.E001` crashes immediately with `ImproperlyConfigured`. The compose stack cannot boot as written. | **HIGH** | [VERIFIED `docker-compose.yml` & `hvt/apps/organizations/apps.py:15`] |
| **"Pass custom schema file with `hvt schema plan -f <file>`."** (CLI docs) | Commander.js parser in `cli/src/config.ts` hardcodes `hvt.schema.json`. Passing `-f` or `--file` crashes with `error: unknown option '-f'`. | **MEDIUM** | [RAN `node dist/index.js schema plan -f ...` -> Exit 1] |
| **"Complete Multi-Factor Authentication with backup recovery."** (Feature spec) | **Zero backup codes exist.** The database has no model or field for recovery codes. Losing a TOTP phone permanently locks the account. | **HIGH** | [VERIFIED `hvt/apps/authentication/models.py`] |
| **"Modern token-based authentication with offline verification."** (Architecture overview) | Tokens are signed with symmetric `HS256` using Django's `SECRET_KEY`. No asymmetric `RS256`, no public JWKS endpoint (`/.well-known/jwks.json`), and no `iss` or `aud` claims exist. | **HIGH** | [RAN live test -> Decoded JWT header `HS256`] |

---

### 2. Half-Finished Features & Stubbed Implementations

1.  **Repository `sdk/` Directory:** The root repository contains an `sdk/` directory, but it is an empty package stub. The active SDK is maintained in a completely separate standalone repository (`hvt-sdk`), causing confusion for new contributors [VERIFIED `sdk/package.json`].
2.  **Duplicate Registration Views:** `hvt/urls.py` mounts both custom HVT registration views (`HVTRegisterView`, `HVTRuntimeRegisterView`) and default `dj_rest_auth` registration endpoints, resulting in 4 separate registration endpoints with overlapping paths [VERIFIED `scratch/allow_any_endpoints.json`].
3.  **Social Login Security Deficits:** The social OAuth REST endpoints accept raw access tokens from client applications without verifying PKCE code verifiers or state tokens [VERIFIED `hvt/apps/authentication/views.py:580-640`].
4.  **Webhook Retries & Poison-Pill Defense:** Webhooks are dispatched synchronously with a 10-second timeout. There is no exponential backoff retry worker or circuit breaker [VERIFIED `hvt/apps/organizations/webhooks.py:85-94`].

---

### 3. Explicit Inventory of Inferences vs Ground-Truth Facts

To strictly preserve our Evidence Rule, every assumption made in this audit that was **INFERRED** rather than directly observed is itemized below:

| Audit Item / Claim | Classification | Reasoning & Ground-Truth Context |
| :--- | :---: | :--- |
| **CI Test Blindspot Intention** | `[INFERRED]` | We infer this was an accidental oversight during initial repo setup rather than an intentional shortcut, as the CI workflow provisions a full PostgreSQL 15 container service specifically for tests. |
| **Duplicate Registration Endpoints** | `[INFERRED]` | We infer that `dj_rest_auth.registration` routes were left in `hvt/urls.py` during an incomplete migration to custom `HVTRegisterView` handlers. |
| **Argon2 Test Latency Cause** | `[INFERRED]` | We infer that the 44-minute test suite duration is driven by Argon2 key derivations because the test suite instantiates hundreds of user models while `MD5PasswordHasher` is only conditionally activated when `"test"` is in `sys.argv`. |
| **Estimated Code Coverage (~80-85%)** | `[INFERRED]` | We infer 80-85% backend coverage based on our endpoint catalog mapping 99 routes to 352 passing tests, though exact per-line coverage was not recorded in CI. |

---

## WHAT WE DON'T KNOW (could not verify, and why)

1.  **Production Infrastructure Architecture:** We could not inspect the live production server targeted by `.github/workflows/deploy.yml` (e.g. AWS EC2, DigitalOcean droplet) because SSH credentials (`DEPLOY_SSH_KEY`, `DEPLOY_HOST`) are stored as private GitHub repository secrets [UNKNOWN].
2.  **Hardware Passkey Biometrics:** We could not execute physical WebAuthn authentication ceremonies in an automated headless Windows console because WebAuthn requires hardware FIDO2 authenticators and interactive browser WebAuthn APIs [UNKNOWN].
3.  **Live Third-Party OAuth Exchanges:** We could not verify end-to-end OAuth callbacks for Google, GitHub, Apple, and Discord because active developer credentials and public redirect URIs are not configured in local development [UNKNOWN].
4.  **Third-Party Resend Deliverability:** We could not verify email delivery into real user inboxes because the local environment uses a test placeholder API key (`re_test_...`) [UNKNOWN].

---

## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with docs, unasked risks)

### 1. The "Zombie User" Registration Trap
In `hvt/apps/authentication/views.py:80-120`, user registration commits the `User` database record **before** dispatching the email verification message via Resend. If Resend experiences an outage, has an invalid API key, or rejects the recipient domain:
*   The view catches the email exception and returns `HTTP 400 Bad Request`.
*   **The transaction is NOT rolled back.** The user remains committed in the database with `is_active=False`.
*   When the user attempts to sign up again after the email provider recovers, the registration endpoint returns `HTTP 400: A user with that email already exists.`, permanently locking that email address out of self-service registration.

### 2. High-Severity SSRF with Response Exfiltration in Webhooks
`hvt/apps/organizations/webhooks.py:85-94` initiates outbound HTTP POST requests to customer-specified webhook URLs without filtering loopback (`127.0.0.1`), link-local (`169.254.169.254`), or private RFC 1918 subnets. Furthermore, line 94 captures the first 5,000 characters of the HTTP response body into `WebhookDelivery.response_body`, which is viewable by project administrators via `/api/v1/organizations/webhooks/{id}/deliveries/`. An attacker can use this feature to query cloud instance metadata and exfiltrate internal infrastructure data.

### 3. Account Takeover via Social Login Auto-Linking
`hvt/apps/authentication/adapters.py:20-45` automatically links incoming social accounts to existing user accounts whenever the email address matches, without requiring password verification or email confirmation. If an attacker creates an account on a social provider that does not verify emails, they can immediately seize full control of an existing victim's HVT account.

### 4. Symmetric Token Architecture
HVT signs all JWTs using symmetric `HS256` derived from Django's master `SECRET_KEY`. There is no asymmetric `RS256` key pair, no public JWKS endpoint (`/.well-known/jwks.json`), and no `iss` or `aud` claims. As a result, customer backend microservices cannot verify end-user tokens locally without possessing the master server secret key.
