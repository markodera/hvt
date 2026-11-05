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
| **1** | **Zero Backend Tests Execute in CI**<br>GitHub Actions runs `python manage.py test` without specifying app targets or test directories. Because tests reside in `tests/` and app subdirectories rather than standard discoverable roots, Django reports `Ran 0 tests in 0.000s` and exits with code 0. CI has been reporting green without testing a single line of backend logic. | Critical Operational Flaw | [VERIFIED .github/workflows/ci.yml:80], [RAN .\venv\Scripts\python manage.py test -> 0 tests ran] |
| **2** | **Full SSRF Vector via Custom Webhook Deliveries**<br>The webhook creation endpoint accepts arbitrary URLs with zero IP/hostname blocklisting (e.g., internal subnets, loopback `127.0.0.1`, AWS metadata `169.254.169.254`). Outbound dispatch synchronously calls `requests.post(webhook.url, ...)` and stores the response status, response headers, and the first 5,000 characters of the response body in `WebhookDelivery`, which is returned via the REST API to the org owner. | Critical Security Vulnerability | [VERIFIED hvt/apps/organizations/webhooks.py:85-94], [VERIFIED hvt/api/v1/serializers/organizations.py:580-610] |
| **3** | **Symmetric HS256 Token Bottleneck & No JWKS**<br>All JWTs are signed with symmetric `HS256` using Django's single root `SECRET_KEY`. No public-key endpoint (`/.well-known/jwks.json`) exists. Downstream customer backend services cannot verify tokens locally without possessing HVT's master secret, forcing all microservices to call HVT over the network. | Architectural Blocker | [VERIFIED hvt/settings.py:434-441], [VERIFIED hvt/apps/authentication/tokens.py:19-37] |
| **4** | **Social OAuth Auto-Linking Account Takeover (ATO) Risk**<br>When a social OAuth callback arrives, `pre_social_login` queries users by email and automatically attaches the social identity to an existing account. If the provider did not verify the email (or if the email attribute falls back to unverified profile data), an attacker registering that email on an external OAuth provider can hijack an existing victim account. | High Security Risk | [VERIFIED hvt/apps/authentication/adapters.py:260-267, 312-340] |
| **5** | **Plaintext TOTP Secrets & Missing Backup Codes**<br>TOTP secrets are stored in plaintext in the database (`auth_totp_devices.secret` as `VARCHAR(64)`), completely unencrypted and unhashed. Furthermore, backup recovery codes are completely unimplemented across the codebase; a user who loses their phone is permanently locked out. | Security & Usability Defect | [VERIFIED hvt/apps/authentication/models.py:273], [VERIFIED hvt/apps/authentication/totp_views.py:42-46] |
| **6** | **Two-Plane Separation Is Strictly Enforced in Code**<br>Runtime endpoints (`/api/v1/auth/runtime/*`) strictly reject management keys (`hvt_mgmt_*`) with HTTP 403 and automatically append a `security.violation` record to `AuditLog`. Conversely, runtime client keys (`hvt_test_*`) cannot access management or schema provisioning routes. | Architecture Strength | [VERIFIED tests/test_plane_separation_and_auth.py:25-90], [RAN live test -> HTTP 403 + AuditLog recorded] |
| **7** | **Option C Concurrency Lock & Live Project Safety Verified**<br>Test management keys are cryptographically prevented from synchronizing or mutating any project that has active live keys, avoiding development-stage pollution of production authorization states. | Architecture Strength | [VERIFIED hvt/apps/organizations/schema_sync.py:346-385], [VERIFIED tests/test_schema_sync.py:346-363] |
| **8** | **Registration User Creation vs. Email Send Atomic Decoupling**<br>During registration, `HVTRegisterView` creates the `User` record in the database before attempting to send the email via Resend. If Resend fails, an HTTP 400 error is returned, but the database transaction is not rolled back. The user is left in database limbo: cannot log in (unverified), cannot re-register (unique email collision), and cannot receive emails. | High Bug / UX Defect | [VERIFIED hvt/apps/authentication/views.py:834-858], [RAN live scripted session -> user left stranded] |
| **9** | **User Enumeration Leaks on Password Reset and Login**<br>Password reset returns HTTP 200 for nonexistent emails, but fails with HTTP 400 when an email exists if the email delivery provider fails. On login, correct passwords on unverified accounts return HTTP 403, whereas invalid credentials return HTTP 400, allowing an attacker to confirm valid user accounts and passwords. | Security Weakness | [VERIFIED hvt/apps/authentication/serializers.py:36-46], [VERIFIED hvt/api/v1/serializers/users.py:358-385] |
| **10** | **`docker-compose.yml` Fails Out-of-the-Box in Production Mode**<br>`docker-compose.yml` configures `DEBUG=0` for the `web` container but does not define `HVT_ENCRYPTION_KEYS`. When `DEBUG=0`, `hvt.crypto` raises `django.core.exceptions.ImproperlyConfigured` at boot, preventing container startup. | Operational Blocker | [VERIFIED docker-compose.yml:38-51], [VERIFIED hvt/crypto.py:48-50] |
| **11** | **Automated SSH Deploy Action on `main` Contradicts Walkthrough**<br>Documentation states there is no automated deployment pipeline on push to `main`. However, `.github/workflows/deploy.yml` triggers on every push to `main` using `appleboy/ssh-action` to `/home/hvt/hvt`. | Documentation Contradiction | [VERIFIED .github/workflows/deploy.yml:18-34], [VERIFIED walkthrough_for_expert.md:21-22] |
| **12** | **Test Suite Execution Bottleneck (44-Minute Duration)**<br>Running the full 352-test suite (`hvt.apps.authentication`, `hvt.apps.organizations`, `hvt.apps.users`, `tests`) took 2,641 seconds (44 minutes) because unit tests that do not pass `--test` in specific flags invoke slow production password hashing (PBKDF2/Argon2) or unmocked sleep timeouts. | Developer Productivity Flaw | [RAN python manage.py test -> 2641.552s], [VERIFIED hvt/settings.py:285-288] |
| **13** | **Official `@hvt/cli` Fully Implemented and Validated**<br>The TypeScript CLI in `cli/` compiles cleanly, passes all 12 test assertions in 983ms, performs local `${VAR}` resolution, enforces `.env.local` safety warnings, and correctly executes declarative schema diff/plan/sync against the live API. | Tooling Strength | [VERIFIED cli/src/index.ts:1-120], [RAN node dist/index.js schema plan -> 200 OK dry-run] |
| **14** | **WebAuthn Cannot Support Multiple Customer Domains**<br>WebAuthn Relying Party ID resolution derives `rp_id` from `project.frontend_url`. It cannot support customer apps that run across multiple subdomains or domains because `allowed_origins` is ignored during `_resolve_expected_origin`. | Functional Limitation | [VERIFIED hvt/apps/authentication/passkey_views.py:66-100] |
| **15** | **Single Organization / Workspace Model**<br>Users belong to exactly one organization (`User.organization`). An end-user workspace construct (a user belonging to multiple companies within a customer's single project) does not exist in the data model today. | Roadmap Architecture Gap | [VERIFIED hvt/apps/users/models.py:49-55], [VERIFIED hvt/apps/organizations/views.py:309-312] |

---

## WHAT WE DON'T KNOW

1. **Production Host Status (`DO_HOST`):** We cannot verify whether the DigitalOcean droplet referenced in `.github/workflows/deploy.yml` is active or whether GitHub repository secrets (`DO_HOST`, `DO_USER`, `DO_SSH_KEY`) are currently populated, as we have read-only access to repository files and no access to GitHub repository settings.
2. **Third-Party OAuth Production Keys:** We could not execute live browser OAuth redirects for Google, GitHub, Apple, Discord, Microsoft, or GitLab because live client secrets and interactive browser callback handshakes require manual browser redirection and live provider credentials.
3. **Hardware Biometric Passkey Signing:** WebAuthn browser attestation and assertion ceremonies require a physical browser WebAuthn API client (e.g. navigator.credentials.create) and user gesture, which cannot be synthesized via headless HTTP scripts.
4. **Resend Live Production Reputation:** We cannot verify whether transactional emails delivered through Resend with custom sender domains land in inboxes or spam, as the test API key in local `.env` failed with upstream Resend authentication errors.

---

## WHAT WE DIDN'T ANTICIPATE

1. **The Silent CI Pass:** We did not anticipate that the repository's GitHub Actions CI pipeline was completely inert with respect to backend testing, executing zero tests on every commit while displaying a green badge.
2. **SSRF Response Exfiltration:** We did not expect that webhook delivery attempts would capture and store the remote server's response headers and body in the database, allowing full data exfiltration from private internal microservices to the API.
3. **Limbo Users on Email Failure:** We did not anticipate that an email delivery failure during signup would leave an unverified user row committed to the database that prevents any future registration attempts with that email address.
4. **Plaintext Invitation Tokens:** While magic links hash tokens using SHA-256 (`auth_magic_link_tokens.token_hash`), organization and runtime invitations store their raw random tokens in plaintext in the database (`organization_invitations.token` and `runtime_invitations.token`).
5. **Missing Encryption Key in Docker Compose:** Despite `HVT_ENCRYPTION_KEYS` being a hard requirement enforced by Django system checks in non-debug mode, the official `docker-compose.yml` file completely omits this variable.

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
