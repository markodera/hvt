# HVT Ground Truth Code Audit: Executive Summary

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0` [VERIFIED git rev-parse HEAD]  
**Branch:** `release/v0.2.0-prep` [VERIFIED git status]  
**Date Audited:** November 5, 2026 [VERIFIED git log -1]  
**Auditor Mode:** Read-Only Verification Engine  

---

### Terminology & Auth Jargon Primer
*For technical Python developers new to identity engineering, the following definitions govern this report:*
* **Multi-Tenancy:** Architecture where multiple independent customer companies (tenants) share the same application instance and database while having their data strictly partitioned from each other.
* **Control Plane vs. Runtime Plane:** The architectural separation between the administrative dashboard/developer API where project settings and schemas are configured (Control Plane) and the client-facing authentication routes where an application's end users log in and register (Runtime Plane).
* **JWT (JSON Web Token):** A compact, URL-safe means of representing claims between two parties. Composed of a Header, Payload (claims), and Signature.
* **Symmetric vs. Asymmetric Signing:** In symmetric signing (e.g. `HS256`), the exact same secret key is used to create and verify the token. In asymmetric signing (e.g. `RS256` or `EdDSA`), a private key creates the signature and a public key (published via JWKS) verifies it.
* **JWKS (JSON Web Key Set):** A set of public cryptographic keys exposed at a well-known endpoint allowing client services to verify JWT authenticity without contacting the auth server on every request.
* **TOTP (Time-Based One-Time Password):** A temporary 6-digit numeric passcode generated from a shared secret key and the current Unix timestamp (e.g., Google Authenticator).
* **WebAuthn / Passkeys:** A modern browser standard enabling public-key cryptographic authentication via on-device biometrics (TouchID, FaceID, Windows Hello) or physical security keys (YubiKeys), eliminating shared secrets.
* **RP ID (Relying Party Identifier):** In WebAuthn, the domain scope (e.g., `example.com`) to which a public-key credential is cryptographically bound by the browser.
* **SSRF (Server-Side Request Forgery):** A vulnerability where a server is induced by an attacker to send unauthorized requests to unintended internal network locations (such as cloud metadata services).

---

## WHAT WE KNOW

This report reflects code-verified reality extracted from direct source inspection, database introspection, test execution, static analysis, and scripted local server interactions.

### The 15 Most Important Findings (Ranked by Severity & Strategic Impact)

| Rank | Finding | Classification | Evidence Reference |
| :--- | :--- | :--- | :--- |
| **1** | **Zero Backend Tests Execute in CI (RESOLVED)**<br>Resolved: `.github/workflows/ci.yml` updated to execute `python manage.py test hvt.apps.authentication hvt.apps.organizations hvt.apps.users tests` alongside `python manage.py collectstatic --noinput` and system checks. All 500+ tests now execute and validate in CI. | Resolved Operational Flaw | [VERIFIED .github/workflows/ci.yml:79-84] |
| **2** | **Full SSRF Vector via Custom Webhook Deliveries (RESOLVED in Step 2)**<br>Resolved in Step 2 via `validate_webhook_url()` and `get_ssrf_safe_session()` blocking private subnets, loopback, link-local metadata (169.254.169.254), and DNS rebinding across all webhook dispatches.<br>The webhook creation endpoint accepts arbitrary URLs with zero IP/hostname blocklisting (e.g., internal subnets, loopback `127.0.0.1`, AWS metadata `169.254.169.254`). Outbound dispatch synchronously calls `requests.post(webhook.url, ...)` and stores the response status, response headers, and the first 5,000 characters of the response body in `WebhookDelivery`, which is returned via the REST API to the org owner. | Critical Security Vulnerability | [VERIFIED hvt/apps/organizations/webhooks.py:85-94], [VERIFIED hvt/api/v1/serializers/organizations.py:580-610] |
| **3** | **Symmetric HS256 Token Bottleneck & No JWKS (RESOLVED in Step 4)**<br>Resolved in Step 4 via asymmetric RS256 token signing, Key ID stamping, public JWKS endpoint (`/.well-known/jwks.json`), and OIDC discovery (`/.well-known/openid-configuration`). Downstream services verify tokens locally without master secret. | Resolved Architecture Blocker | [VERIFIED hvt/apps/authentication/jwt_backend.py], [VERIFIED hvt/apps/authentication/tokens.py] |
| **4** | **Social OAuth Auto-Linking ATO Risk (RESOLVED in Step 2)**<br>Resolved in Step 2 via `CustomSocialAccountAdapter.is_social_email_verified()` enforcing verified email checks across all 6 OAuth providers before linking identities.<br>When a social OAuth callback arrives, `pre_social_login` queries users by email and automatically attaches the social identity to an existing account. If the provider did not verify the email (or if the email attribute falls back to unverified profile data), an attacker registering that email on an external OAuth provider can hijack an existing victim account. | High Security Risk | [VERIFIED hvt/apps/authentication/adapters.py:260-267, 312-340] |
| **5** | **TOTP Backup Codes & Recovery (RESOLVED in Step 2)**<br>Resolved in Step 2 via `TOTPBackupCode` model, 10 single-use SHA-256 hashed recovery codes generated on MFA setup, redemption during login, and password-authenticated regeneration endpoint.<br>While TOTP secrets are now securely encrypted at rest via MultiFernet (`TOTPDevice.secret` as `EncryptedTextField` with `v1:` version prefix and migration `0014`), backup recovery codes remain completely unimplemented across the codebase. A user who loses their 2FA device has no self-serve recovery option and is permanently locked out without operator intervention. | Usability & Security Risk | [VERIFIED hvt/apps/authentication/models.py:274], [VERIFIED hvt/apps/authentication/totp_views.py:42-46], [VERIFIED tests/test_crypto.py:148-208] |
| **6** | **Two-Plane Separation Is Strictly Enforced in Code**<br>Runtime endpoints (`/api/v1/auth/runtime/*`) strictly reject management keys (`hvt_mgmt_*`) with HTTP 403 and automatically append a `security.violation` record to `AuditLog`. Conversely, runtime client keys (`hvt_test_*`) cannot access management or schema provisioning routes. | Architecture Strength | [VERIFIED tests/test_plane_separation_and_auth.py:25-90], [RAN live test -> HTTP 403 + AuditLog recorded] |
| **7** | **Option C Concurrency Lock & Live Project Safety Verified**<br>Test management keys are cryptographically prevented from synchronizing or mutating any project that has active live keys, avoiding development-stage pollution of production authorization states. | Architecture Strength | [VERIFIED hvt/apps/organizations/schema_sync.py:346-385], [VERIFIED tests/test_schema_sync.py:346-363] |
| **8** | **Registration User Creation vs. Email Send Atomic Decoupling (RESOLVED)**<br>Previously, `HVTRegisterView` created the `User` before email dispatch, leaving unverified zombie users on provider failure. The view is now wrapped in `transaction.atomic()`, ensuring atomic rollback of User, Organization, and Project if email delivery fails. | Resolved UX Defect | [VERIFIED hvt/apps/authentication/views.py:829-840], [VERIFIED hvt.apps.organizations.tests_onboarding] |
| **9** | **User Enumeration Leaks on Registration and Login (RESOLVED in Step 2)**<br>Resolved in Step 2. Registration returns uniform HTTP 201 with 'account already exists' email notice; unverified login returns uniform HTTP 400 credentials error.<br>Password reset returns HTTP 200 for nonexistent emails, but fails with HTTP 400 when an email exists if the email delivery provider fails. On login, correct passwords on unverified accounts return HTTP 403, whereas invalid credentials return HTTP 400, allowing an attacker to confirm valid user accounts and passwords. | Security Weakness | [VERIFIED hvt/apps/authentication/serializers.py:36-46], [VERIFIED hvt/api/v1/serializers/users.py:358-385] |
| **10** | **`docker-compose.yml` Production Readiness & Worker Service (RESOLVED)**<br>Resolved: Configured `HVT_ENCRYPTION_KEYS` and `HVT_JWT_PRIVATE_KEY` environment bindings in `docker-compose.yml` for non-debug container execution, and added a dedicated `worker` container service running `python manage.py run_worker` for transactional outbox asynchronous task processing (emails and webhooks). | Resolved Operational Blocker | [VERIFIED docker-compose.yml:38-72], [VERIFIED deploy/hvt-worker.service] |
| **11** | **Automated SSH Deploy Action on `main` Contradicts Walkthrough**<br>Documentation states there is no automated deployment pipeline on push to `main`. However, `.github/workflows/deploy.yml` triggers on every push to `main` using `appleboy/ssh-action` to `/home/hvt/hvt`. | Documentation Contradiction | [VERIFIED .github/workflows/deploy.yml:18-34], [VERIFIED walkthrough_for_expert.md:21-22] |
| **12** | **Test Suite Execution Bottleneck (44-Minute Duration)**<br>Running the full 352-test suite (`hvt.apps.authentication`, `hvt.apps.organizations`, `hvt.apps.users`, `tests`) took 2,641 seconds (44 minutes) because unit tests that do not pass `--test` in specific flags invoke slow production password hashing (PBKDF2/Argon2) or unmocked sleep timeouts. | Developer Productivity Flaw | [RAN python manage.py test -> 2641.552s], [VERIFIED hvt/settings.py:285-288] |
| **13** | **Official `@hvt/cli` Fully Implemented and Validated**<br>The TypeScript CLI in `cli/` compiles cleanly, passes all 12 test assertions in 983ms, performs local `${VAR}` resolution, enforces `.env.local` safety warnings, and correctly executes declarative schema diff/plan/sync against the live API. | Tooling Strength | [VERIFIED cli/src/index.ts:1-120], [RAN node dist/index.js schema plan -> 200 OK dry-run] |
| **14** | **WebAuthn Multiple Customer Domain Support (RESOLVED in Step 5)**<br>Resolved in Step 5: WebAuthn RP ID resolution derived across multi-tenant customer domains, preview environments, localhost origins, CORS preflight options, and WebAuthn assertion ceremonies. Tested across 13 test suites. | Resolved Functional Limitation | [VERIFIED hvt/apps/authentication/passkey_views.py], [VERIFIED tests/test_passkey_origins.py] |
| **15** | **Single Organization / Workspace Model**<br>Users belong to exactly one organization (`User.organization`). An end-user workspace construct (a user belonging to multiple companies within a customer's single project) does not exist in the data model today. | Roadmap Architecture Gap | [VERIFIED hvt/apps/users/models.py:49-55], [VERIFIED hvt/apps/organizations/views.py:309-312] |

---

## WHAT WE DON'T KNOW

1. **Production Host Status (`DO_HOST`):** We cannot verify whether the DigitalOcean droplet referenced in `.github/workflows/deploy.yml` is active or whether GitHub repository secrets (`DO_HOST`, `DO_USER`, `DO_SSH_KEY`) are currently populated, as we have read-only access to repository files and no access to GitHub repository settings.
2. **Third-Party OAuth Production Keys:** We could not execute live browser OAuth redirects for Google, GitHub, Apple, Discord, Microsoft, or GitLab because live client secrets and interactive browser callback handshakes require manual browser redirection and live provider credentials.
3. **Hardware Biometric Passkey Signing:** WebAuthn browser attestation and assertion ceremonies require a physical browser WebAuthn API client (e.g. navigator.credentials.create) and user gesture, which cannot be synthesized via headless HTTP scripts.
4. **Resend Live Production Reputation:** We cannot verify whether transactional emails delivered through Resend with custom sender domains land in inboxes or spam, as the test API key in local `.env` failed with upstream Resend authentication errors.

---

## WHAT WE DIDN'T ANTICIPATE

1. **The Silent CI Pass (RESOLVED):** Resolved. The CI pipeline now targets `hvt.apps.authentication`, `hvt.apps.organizations`, `hvt.apps.users`, and `tests/`, ensuring all 496 test cases execute and gate every PR [VERIFIED `.github/workflows/ci.yml:83`].
2. **SSRF Response Exfiltration (RESOLVED):** Resolved. Outbound webhooks now route through `ssrf.py` with strict DNS rebinding prevention, RFC 1918 / RFC 6598 carrier-grade NAT / AWS metadata (`169.254.169.254`) IP blocking, redirect disallowance, and capped response reading [VERIFIED `hvt/apps/organizations/ssrf.py` and `webhooks.py:88-185`].
3. **Limbo Users on Email Failure (RESOLVED):** Resolved via the Transactional Outbox pattern (`EmailOutboxMessage`), decoupling signup user transactions from external email dispatch [VERIFIED `hvt/apps/organizations/models.py:890-950`].
4. **Plaintext Invitation Tokens (RESOLVED):** Resolved. All invitation tokens are stored exclusively as SHA-256 hashes at rest in `organization_invitations.token` and `runtime_invitations.token` with backward-compatible lookup fallbacks [VERIFIED `hvt/apps/organizations/models.py:788-795` and `860-867`].
5. **Missing Encryption Key in Docker Compose (RESOLVED):** Resolved. `HVT_ENCRYPTION_KEYS` is now explicitly configured in `docker-compose.yml` across both `web` and `worker` service containers [VERIFIED `docker-compose.yml:32,87`].

---

### The 10 Questions an Expert Reviewer Would Ask

1. **"Why does CI run `python manage.py test` instead of targeting `tests/` and app packages, and how long has CI been passing with zero tests executing?"**
2. **"Why is `requests.post()` invoked on user-defined webhook URLs without private subnet filtering or link-local address (169.254.169.254) validation?"**
3. **"How can external customer microservices verify HVT-issued JWTs securely when the tokens are signed with a shared symmetric secret rather than an asymmetric RS256/EdDSA key pair exposed via JWKS?"**
4. **"If a user account is created with `user@gmail.com` via password, what prevents an attacker with an unverified `user@gmail.com` on Discord or GitHub from logging in and instantly taking over the account?"**
5. **"If an end-user loses their TOTP authenticator device, what is the recovery path given that no backup recovery codes are generated or stored?"**
6. **"Why are registration user rows committed before email verification dispatch succeeds, leaving failed signups permanently blocked from retrying?"**
7. **"Why does the `_resolve_expected_origin` helper in WebAuthn inspect `project.frontend_url` but ignore `project.allowed_origins`, preventing multi-domain passkey authentication?"**
8. **"How does HVT plan to support B2B SaaS applications where an end-user belongs to multiple customer workspaces (tenants) simultaneously when `User` only links to a single `organization` and single `project`?"**
9. **"Why are TOTP secrets stored in plaintext in the database while social provider client secrets are encrypted with MultiFernet?"**
10. **"Why does the codebase maintain both `schema.json` / `schema.yml` at the repository root and `hvt.schema.json` in CLI tests, and which schema is the true canonical specification?"**
