# 02: Features & Endpoints Audit

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0` [VERIFIED git rev-parse HEAD]  
**Branch:** `release/v0.2.0-prep` [VERIFIED git status]  
**Date Audited:** November 5, 2026 [VERIFIED git log -1]  

---

### Terminology Primer
* **Authentication Class:** The component that inspects incoming HTTP request headers, cookies, or body tokens to identify the caller (e.g. `HVTJWTAuthentication`, `APIKeyAuthentication`).
* **Permission Class:** The authorization gate evaluated after authentication that decides if the identified caller has sufficient rights to perform the requested action (e.g. `IsAuthenticated`, `IsOrganizationOwner`).
* **Throttle Class:** Rate-limiting middleware that restricts the frequency of requests from a specific IP, email, or API key within a time window (e.g. `10/min`).
* **Dry-Run Mode:** An execution mode (`?dry_run=true`) where all schema validation, database queries, and diff calculations occur inside an uncommitted database transaction (`transaction.set_rollback(True)`), allowing clients to preview changes without mutating state.

---

## WHAT WE KNOW

### 1. URLconf Endpoint Inventory

HVT exposes 99 distinct API routes across three planes: Control Plane (developer dashboard), Runtime Plane (customer application auth), and Infrastructure / Ops [VERIFIED `scratch/endpoints_catalog.json`].

The following comprehensive table inventories the primary endpoint families across the system:

| HTTP Method | Route Path | Plane | Auth Class | Permission Class | Scopes Required | Throttling | Covering Test |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/healthz/` | Ops | None | `AllowAny` | None | None | `hvt.apps.authentication.test_health` |
| `GET` | `/readyz/` | Ops | None | `AllowAny` | None | None | `hvt.apps.authentication.test_health` |
| `GET` | `/.well-known/jwks.json` | Ops / Public | None | `AllowAny` | None | None | `tests.test_asymmetric_tokens` |
| `GET` | `/.well-known/openid-configuration` | Ops / Public | None | `AllowAny` | None | None | `tests.test_asymmetric_tokens` |
| `GET` | `/api/v1/auth/.well-known/jwks.json` | Ops / Public | None | `AllowAny` | None | None | `tests.test_asymmetric_tokens` |
| `GET` | `/api/v1/auth/.well-known/openid-configuration` | Ops / Public | None | `AllowAny` | None | None | `tests.test_asymmetric_tokens` |
| `GET` | `/api/schema/` | Ops | None | `AllowAny` | None | None | Django checks |
| `GET` | `/api/docs/` | Ops | None | `AllowAny` | None | None | Django checks |
| `POST` | `/api/v1/auth/register/` | Control | Session/JWT | `AllowAny` | None | `auth_register_ip`, `auth_register_email` | `test_plane_separation_and_auth` |
| `POST` | `/api/v1/auth/register/verify-email/` | Control | Session/JWT | `AllowAny` | None | `auth_email_verification_ip` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/register/resend-email/` | Control | Session/JWT | `AllowAny` | None | `auth_resend_verification_ip/email` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/login/` | Control | Session/JWT | `AllowAny` | None | `auth_login_ip`, `auth_login_email` | `test_plane_separation_and_auth` |
| `POST` | `/api/v1/auth/logout/` | Control | JWT/Cookie | `IsAuthenticated` | None | Default | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/token/refresh/` | Control | JWT/Cookie | `AllowAny` | None | `auth_token_refresh` | `hvt.apps.authentication.test_passkeys_and_tokens` |
| `GET` | `/api/v1/auth/sessions/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_session_revocation` |
| `DELETE` | `/api/v1/auth/sessions/<uuid:pk>/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_session_revocation` |
| `POST` | `/api/v1/auth/sessions/revoke-all/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_session_revocation` |
| `GET` | `/api/v1/auth/pats/` | Control | JWT/Cookie/PAT | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_personal_access_tokens` |
| `POST` | `/api/v1/auth/pats/` | Control | JWT/Cookie/PAT | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_personal_access_tokens` |
| `DELETE` | `/api/v1/auth/pats/<uuid:pk>/` | Control | JWT/Cookie/PAT | `IsAuthenticated`, `IsPlatformUser` | None | Default | `tests.test_personal_access_tokens` |
| `GET` | `/api/v1/auth/runtime/pats/` | Runtime | JWT/Cookie/PAT | `IsAuthenticated` | None | Default | `tests.test_personal_access_tokens` |
| `POST` | `/api/v1/auth/runtime/pats/` | Runtime | JWT/Cookie/PAT | `IsAuthenticated` | None | Default | `tests.test_personal_access_tokens` |
| `DELETE` | `/api/v1/auth/runtime/pats/<uuid:pk>/` | Runtime | JWT/Cookie/PAT | `IsAuthenticated` | None | Default | `tests.test_personal_access_tokens` |

| `GET, PUT, PATCH` | `/api/v1/auth/me/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `test_plane_separation_and_auth` |
| `POST` | `/api/v1/auth/password/reset/` | Control | Session/JWT | `AllowAny` | None | `auth_password_reset_ip/email` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/password/reset/confirm/<uid>/<token>/` | Control | Session/JWT | `AllowAny` | None | `auth_password_reset_confirm_ip` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/password/change/` | Control | JWT/Cookie | `IsAuthenticated` | None | `auth_password_change_user` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/mfa/totp/setup/` | Control | JWT/Cookie | `IsAuthenticated` | None | Default | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/mfa/totp/verify/` | Control | JWT/Cookie | `IsAuthenticated` | None | Default | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/mfa/totp/disable/` | Control | JWT/Cookie | `IsAuthenticated` | None | Default | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/mfa/totp/login/` | Control | None | `AllowAny` | None | `auth_login_ip`, `auth_login_email` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/passkey/register/options/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/passkey/register/verify/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/passkey/authenticate/options/` | Control | None | `AllowAny` | None | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/passkey/authenticate/verify/` | Control | None | `AllowAny` | None | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `GET` | `/api/v1/auth/passkey/credentials/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `test_passkeys_and_magic_links` |
| `DELETE` | `/api/v1/auth/passkey/credentials/<uuid:pk>/` | Control | JWT/Cookie | `IsAuthenticated`, `IsPlatformUser` | None | Default | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/magic-link/request/` | Control | None | `AllowAny` | None | `auth_login_ip`, `auth_login_email` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/magic-link/verify/` | Control | None | `AllowAny` | None | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/social/<provider>/` | Control | None | `AllowAny` | None | `auth_social_login_ip` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/runtime/register/` | Runtime | Runtime API Key | `IsRuntimeRegisterAllowed` | `auth:runtime` | `auth_runtime_register_api_key` | `test_plane_separation_and_auth` |
| `POST` | `/api/v1/auth/runtime/register/verify-email/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_email_verification_ip` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/runtime/register/resend-email/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_runtime_resend_verification_api_key` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/runtime/login/` | Runtime | Runtime API Key | `IsRuntimeLoginAllowed` | `auth:runtime` | `auth_runtime_login_api_key` | `test_plane_separation_and_auth` |
| `GET` | `/api/v1/auth/runtime/me/` | Runtime | JWT/Cookie | `IsAuthenticated`, `IsRuntimeUser` | None | Default | `test_plane_separation_and_auth` |
| `GET` | `/api/v1/auth/runtime/sessions/` | Runtime | JWT/Cookie | `IsAuthenticated` | None | Default | `tests.test_session_revocation` |
| `DELETE` | `/api/v1/auth/runtime/sessions/<uuid:pk>/` | Runtime | JWT/Cookie | `IsAuthenticated` | None | Default | `tests.test_session_revocation` |
| `POST` | `/api/v1/auth/runtime/sessions/revoke-all/` | Runtime | JWT/Cookie | `IsAuthenticated` | None | Default | `tests.test_session_revocation` |
| `POST` | `/api/v1/auth/runtime/password/reset/` | Runtime | Runtime API Key | `IsRuntimePasswordResetAllowed` | `auth:runtime` | `auth_runtime_password_reset_api_key` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/runtime/password/reset/confirm/<uid>/<token>/` | Runtime | Runtime API Key | `AllowAny` | None | `auth_password_reset_confirm_ip` | `hvt.apps.authentication.tests` |
| `POST` | `/api/v1/auth/runtime/passkey/register/options/` | Runtime | JWT/Cookie | `IsAuthenticated`, `IsRuntimeUser` | None | Default | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/passkey/register/verify/` | Runtime | JWT/Cookie | `IsAuthenticated`, `IsRuntimeUser` | None | Default | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/passkey/authenticate/options/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/passkey/authenticate/verify/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/magic-link/request/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_login_ip`, `auth_login_email` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/magic-link/verify/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_login_ip` | `test_passkeys_and_magic_links` |
| `POST` | `/api/v1/auth/runtime/social/<provider>/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | `auth_runtime_social_api_key` | `hvt.apps.authentication.tests` |
| `GET, POST` | `/api/v1/organizations/` | Control | JWT / Superuser | `IsAdminUser` (GET), `IsPlatformUser` (POST) | None | Default | `hvt.apps.organizations.tests` |
| `GET, PUT, PATCH` | `/api/v1/organizations/current/` | Control | JWT/API Key | `IsOrgMemberOrAPIKey` (GET), `IsOrganizationOwner` (PUT) | `organization:read/write` | Default | `hvt.apps.organizations.tests` |
| `GET, POST` | `/api/v1/organizations/current/projects/` | Control | JWT | `IsCurrentOrganizationOwner/Admin` | None | Default | `hvt.apps.organizations.tests` |
| `GET` | `/api/v1/organizations/current/projects/<id>/onboarding/` | Control | JWT / Mgmt Key | `IsOrgMemberOrAPIKey` | None | Default | `hvt.apps.organizations.tests_onboarding` |
| `POST` | `/api/v1/organizations/current/projects/<id>/setup-prompt/` | Control | JWT / Mgmt Key | `IsOrgOwnerOrAPIKey` | None | Default | `hvt.apps.organizations.tests_onboarding` |
| `POST` | `/api/v1/organizations/current/projects/<id>/sync/` | Control | Mgmt Key / JWT | `IsOrgOwnerOrAPIKey` | `schema:plan` (dry), `schema:sync` (apply) | Default | `tests/test_schema_sync.py` |
| `GET, POST` | `/api/v1/organizations/current/projects/<id>/permissions/` | Control | Mgmt Key / JWT | `IsOrgOwnerOrAPIKey` | `permissions:read/write` | Default | `hvt.apps.organizations.tests` |
| `GET, POST` | `/api/v1/organizations/current/projects/<id>/roles/` | Control | Mgmt Key / JWT | `IsOrgOwnerOrAPIKey` | `roles:read/write` | Default | `hvt.apps.organizations.tests` |
| `GET, POST` | `/api/v1/organizations/current/projects/<id>/social-providers/` | Control | Mgmt Key / JWT | `IsOrgOwnerOrAPIKey` | `providers:read/write` | Default | `hvt.apps.organizations.tests` |
| `GET, POST` | `/api/v1/organizations/current/keys/` | Control | JWT | `IsOrganizationOwner` | None | Default | `tests/test_api_key.py` |
| `POST` | `/api/v1/organizations/current/keys/<id>/revoke/` | Control | JWT | `IsOrganizationOwner` | None | Default | `tests/test_api_key.py` |
| `GET, POST` | `/api/v1/organizations/current/invitations/` | Control | JWT | `IsOrgAdminOrAPIKey` | None | Default | `hvt.apps.organizations.tests_invitations` |
| `POST` | `/api/v1/organizations/invitations/accept/` | Control | JWT | `IsAuthenticated`, `IsPlatformUser` | None | Default | `hvt.apps.organizations.tests_invitations` |
| `GET, POST` | `/api/v1/runtime/invitations/` | Runtime | Runtime API Key | `IsOrgAdminOrAPIKey` | `auth:runtime` | Default | `tests_runtime_invitations` |
| `POST` | `/api/v1/runtime/invitations/accept/` | Runtime | Runtime API Key | `AllowAny` | `auth:runtime` | Default | `tests_runtime_invitations` |
| `GET, POST` | `/api/v1/organizations/current/webhooks/` | Control | JWT / API Key | `IsOrgOwnerOrAPIKey` | `webhooks:read/write` | Default | `hvt.apps.organizations.tests_webhooks` |
| `GET` | `/api/v1/organizations/current/webhooks/<id>/deliveries/` | Control | JWT / API Key | `IsOrgOwnerOrAPIKey` | `webhooks:read` | Default | `hvt.apps.organizations.tests_webhooks` |
| `GET, PUT, PATCH, DELETE` | `/api/v1/organizations/current/projects/<id>/email-config/` | Control | JWT / Mgmt Key | `IsOrgOwnerOrAPIKey` | None | Default | `tests/test_byo_email_providers.py` |
| `POST` | `/api/v1/organizations/current/projects/<id>/email-config/test/` | Control | JWT / Mgmt Key | `IsOrgOwnerOrAPIKey` | None | Default | `tests/test_byo_email_providers.py` |
| `GET` | `/api/v1/organizations/current/audit-logs/` | Control | JWT / API Key | `IsOrgOwnerOrAPIKey` | `audit_logs:read` | Default | `tests/test_audit_logging.py` |

---

### 2. Feature-by-Feature Status & Mechanics

#### 1. User Registration (`register`)
* **Status:** `WORKING` (with atomic auto-provisioning and rollback protection).
* **Mechanics:**
  * Control Plane: Client POSTs `{email, password1, password2}` to `/api/v1/auth/register/`. User created with `project=NULL`. Under `transaction.atomic()`, new control-plane users with 0 organizations automatically receive an auto-provisioned organization (`<Name>'s Workspace` or `<email>'s Workspace`) with role `OWNER`, and an initial default test project (`slug="default"`, `is_default=True`). An email verification confirmation key is generated via `django-allauth` and dispatched via Resend. If email delivery fails, the entire transaction rolls back cleanly, leaving zero orphaned User, Organization, or Project rows.
  * Runtime Plane: Client POSTs `{email, password1, password2, role_slug?}` with header `X-API-Key: hvt_test_...` to `/api/v1/auth/runtime/register/`. User created bound to the key's `project` and `organization`. Assigned default signup role or requested self-assignable role.
* **Storage:** Rows in `users`, `account_emailaddress`, `account_emailconfirmation`, `organizations`, `projects`, and `user_project_roles`.

#### 2. User Authentication (`login`)
* **Status:** `WORKING`.
* **Mechanics:** Client POSTs `{email, password}`. Validates credentials and verifies that `EmailAddress.verified == True` (if mandatory). If MFA is active, returns HTTP 200 with `{mfa_required: true, mfa_token: "<signed_token>"}`. Otherwise issues access and refresh JWTs, and sets `auth-token` and `refresh-token` HttpOnly cookies.
* **Storage:** Creates `AuditLog` row (`user.login` or `login.failed`). If JWT token rotation is enabled, refresh token JTI is recorded in `token_blacklist_outstandingtoken`.

#### 3. Email Verification
* **Status:** `WORKING`.
* **Mechanics:** Client receives email containing link with verification key, then POSTs `{key: "<key>"}` to `/api/v1/auth/register/verify-email/` or `/api/v1/auth/runtime/register/verify-email/`. Marks `account_emailaddress.verified = True`.
* **Storage:** Updates `account_emailaddress` (`verified=True`), deletes `account_emailconfirmation`.

#### 4. Password Reset
* **Status:** `WORKING`.
* **Mechanics:** Client POSTs `{email}` to reset endpoint. Service renders reset URL (`/auth/password-reset/<uidb64>/<token>`) and sends via Resend. Client submits new password to confirm endpoint.
* **Storage:** Generates ephemeral HMAC token via Django's `default_token_generator`. Updates `users.password` (hashed with PBKDF2/Argon2). Records `AuditLog` (`password.reset.complete`).

#### 5. Passwordless Magic Links
* **Status:** `WORKING`.
* **Mechanics:** Client POSTs `{email}` to `/magic-link/request/`. Generates cryptographically secure 32-byte token (`secrets.token_urlsafe(32)`), hashes it with SHA-256, and saves hash to database with 15-minute expiry. Dispatches email via Resend. Client POSTs `{token}` to `/magic-link/verify/`. Verifies hash, marks `is_used=True`, and issues JWTs.
* **Storage:** `auth_magic_link_tokens` (`token_hash`, `expires_at`, `is_used`).

#### 6. Passkeys (WebAuthn / FIDO2)
* **Status:** `WORKING` (Control Plane & Runtime Plane).
* **Mechanics:**
  * Registration: Authenticated user requests options (`/passkey/register/options/`). Server returns WebAuthn challenge stored in cache for 300s. Browser prompts TouchID/FaceID and submits attestation. Server verifies signature counter and saves public key.
  * Authentication: Unauthenticated user requests options, signs challenge on device, submits assertion. Server verifies signature against stored COSE public key and issues JWTs.
* **Storage:** `auth_passkey_credentials` (`credential_id`, `public_key`, `sign_count`, `transports`, `aaguid`).

#### 7. TOTP & Backup Codes
* **Status:** `PARTIAL` (TOTP works cleanly; Backup Codes are completely missing).
* **Mechanics:** Authenticated user calls `/mfa/totp/setup/`. Generates base32 secret and otpauth URI. User submits 6-digit code to `/mfa/totp/verify/` to confirm. On subsequent logins, client passes `{mfa_token, code}` to `/mfa/totp/login/`.
* **Storage:** `auth_totp_devices` (`secret`, `is_confirmed`, `last_verified_at`). Backup codes have no model or database storage.

#### 8. Social Login (OAuth 2.0)
* **Status:** `WORKING` (Google, GitHub, Discord, Apple, Microsoft, GitLab).
* **Mechanics:** Frontend performs OAuth redirect with provider and receives authorization `code`. Frontend POSTs `{code, callback_url}` to `/api/v1/auth/runtime/social/<provider>/` with `X-API-Key`. Server verifies `callback_url` against `SocialProviderConfig.redirect_uris`, exchanges code for provider tokens, pulls profile, auto-links account by email, and issues HVT JWTs.
* **Storage:** `social_provider_configs` (encrypted client secret), `socialaccount_socialapp`, `socialaccount_socialaccount`, `socialaccount_socialtoken`.

#### 9. Invitations (Organization & Runtime)
* **Status:** `WORKING`.
* **Mechanics:**
  * Control Plane: Admin invites member via `/organizations/current/invitations/`. Generates plaintext hex token. Invitee visits frontend and accepts. User is linked to organization.
  * Runtime Plane: Developer/client issues invitation for an end user to join a project via runtime API key. Includes `role_slugs`.
* **Storage:** `organization_invitations` and `runtime_invitations` (both store raw tokens in plaintext).

#### 10. API Keys (Runtime vs Management)
* **Status:** `WORKING`.
* **Mechanics:** Org owner creates key in dashboard. Key generated as `hvt_{env}_{hex}` (runtime) or `hvt_mgmt_{env}_{hex}` (management). Plaintext prefix (8 chars) stored alongside SHA-256 hash. Runtime keys restricted to `auth:runtime`; management keys restricted to provisioning scopes.
* **Storage:** `api_keys` (`prefix`, `hashed_key`, `scopes`, `environment`, `key_type`, `is_active`, `expires_at`).

#### 11. Roles & Permissions (Declarative Schema Sync)
* **Status:** `WORKING`.
* **Mechanics:** Declarative schema in `hvt.schema.json` defines permissions and roles. Client invokes `POST /projects/<id>/sync/`. `SchemaSyncService` executes diff, creates new permissions/roles, links permissions, sets default signup roles, and reconciles manifest state. If `--prune` is passed, missing manifest-owned objects are safely deleted if not currently assigned to users.
* **Storage:** `project_permissions`, `project_roles`, `project_role_permissions`, `user_project_roles`.

#### 12. Audit Logging
* **Status:** `WORKING`.
* **Mechanics:** Centralized `AuditLog.log(...)` helper automatically logs security events (`user.login`, `security.violation`, `schema.sync`, `api_key.created`). Records client IP from `X-Forwarded-For`, user agent, actor user or API key, target entity, and structured JSON metadata.
* **Storage:** `audit_logs` table.

#### 13. Dashboard
* **Status:** `WORKING` (Separate Frontend Repository).
* **Mechanics:** The developer dashboard is built as a React/Vite SPA hosted separately (in `hvt-fr` workspace). Communicates with HVT backend exclusively via `/api/v1/organizations/*` and `/api/v1/auth/*` using JWT cookies.
* **Storage:** Stateless frontend client.

#### 14. SDK (`sdk/`)
* **Status:** `STUB` (in this repo) / `WORKING` (in external repo).
* **Mechanics:** The TypeScript SDK was factored out into standalone repository `markodera/hvt-sdk` (`c:\Users\odera\Documents\GitHub\hvt-sdk`). The `sdk/` directory in this repo contains only a `README.md` redirecting contributors to the external repo.
* **Storage:** N/A.

#### 15. CLI (`cli/`)
* **Status:** `WORKING`.
* **Mechanics:** Full TypeScript CLI (`@hvt/cli`) with commands:
  * `hvt init`: Scaffolds `hvt.schema.json` and `.env.local` starter files.
  * `hvt schema plan`: Sends `?dry_run=true` request to API to preview changes.
  * `hvt schema sync`: Sends live apply request, supports `--prune` with interactive confirmation, and auto-saves minted client key to `.env.local`.
  * `hvt whoami`: Inspects active management key and target project.
* **Storage:** Operates locally on disk, mutating `hvt.schema.json` and `.env.local`.

#### 16. Onboarding Quickstart & AI Setup Prompt
* **Status:** `WORKING` [VERIFIED `hvt.apps.organizations.tests_onboarding`].
* **Mechanics:**
  * Status Polling: `GET /api/v1/organizations/current/projects/<id>/onboarding/` tracks the 4 live milestone steps (`project_created`, `schema_synced`, `first_signup`, `first_login`), counting both standard and passwordless/social/invite logins (`USER_LOGIN`, `MAGIC_LINK_VERIFIED`, `PASSKEY_LOGIN`, `SOCIAL_LOGIN`, `RUNTIME_USER_INVITE_ACCEPTED`), and evaluates whether the project can issue an AI setup prompt (`can_use_setup_prompt`).
  * AI Setup Prompt: `POST /api/v1/organizations/current/projects/<id>/setup-prompt/` provisions an ephemeral 15-minute test management key (`hvt_mgmt_test_*`) with scopes `['schema:plan', 'schema:sync', 'roles:write', 'permissions:write', 'providers:write']` and returns a formatted prompt designed for AI coding agents (Claude Code, Cursor, Copilot, Antigravity).
  * Option C Lockout Safety: If a project has active `live` API keys, prompt generation is rejected with HTTP 400 (`Option C live project safety active`).
  * UI Integration: Rendered directly on the dashboard home (`OnboardingQuickstart.jsx`), polling every 3 seconds while active, with masked key preview, 15-minute countdown timer, zero persistent storage in localStorage or logs, and copyable CLI instructions.
* **Storage:** Temporary rows in `api_keys` (`expires_at = now + 15m`).

#### 17. Bring-Your-Own (BYO) Email & Background Task Engine (Step 6)

* **Management Endpoints:**
  * `GET /api/v1/organizations/current/projects/<id>/email-config/`: Retrieve per-project email provider configuration with masked credential statuses (`has_smtp_password`, `has_api_key`, `has_aws_secret_access_key`) [VERIFIED `hvt/apps/organizations/views.py:2672-2708`].
  * `PATCH /api/v1/organizations/current/projects/<id>/email-config/`: Update project provider (`smtp`, `resend`, `postmark`, `ses`), custom sender identity (`from_email`, `from_name`), and encrypted credentials [VERIFIED `hvt/apps/organizations/views.py:2710-2725`].
  * `POST /api/v1/organizations/current/projects/<id>/email-config/test/`: Send a test email to verify provider connectivity [VERIFIED `hvt/apps/organizations/views.py:2728-2775`].
* **Transactional Outbox Engine (`hvt.apps.organizations.tasks`):**
  * `enqueue_task(task_type, payload, project, organization, run_after_seconds, max_attempts)`: Enqueues tasks atomically with database records.
  * `process_outbox_tasks(max_tasks, worker_id)`: Concurrency-safe job claiming via `select_for_update(skip_locked=True)` with automatic stale lock reclamation.
  * `python manage.py run_worker`: Production CLI worker runner supporting `--once`, `--poll-interval`, `--batch-size`, and graceful SIGINT/SIGTERM shutdown [VERIFIED `hvt/apps/organizations/management/commands/run_worker.py`].
* **Asynchronous Webhook Dispatching:**
  * `trigger_webhook_event()`: Spawns transactional outbox tasks, constructs delivery envelope with cryptographic HMAC-SHA256 signature (`X-HVT-Signature`), executes requests with 10s timeout, schedules exponential backoff retries, and auto-disables endpoints after 10 consecutive failures [VERIFIED `hvt/apps/organizations/webhooks.py`].

---

## WHAT WE DON'T KNOW

1. **Apple Sign-In Private Key Processing:** Apple OAuth requires generating a client secret JWT signed with an Apple Developer private key (`.p8`). We cannot verify how HVT or allauth handles Apple `.p8` secret files in production, as `SocialProviderConfig.client_secret` expects a string.
2. **Discord and Microsoft Live Callback Quirks:** We could not verify provider-specific OAuth error handling for Discord and Microsoft when a user denies permissions on the consent screen.

---

## WHAT WE DIDN'T ANTICIPATE

1. **Complete Absence of TOTP Backup Codes:** The documentation states full MFA support, but there are zero models, fields, or endpoints for backup codes. A lost authenticator results in irreversible lockout.
2. **Missing SDK Code in Repository:** The `sdk/` directory has no code, only a 12-line markdown stub pointing to an external repo.
3. **Inconsistent Token Hashing Across Features:** Magic link tokens are cryptographically hashed using SHA-256, but both organization invitations and runtime invitations store their raw tokens in plaintext in the database.

#### 18. Multi-Page Architecture, Purple ASCII Hero Schematic & Anti-Zombie UI Redesign
* **Status:** `WORKING` [VERIFIED `hvt-fr/src/App.jsx`, `hvt-fr/src/pages/landing/Landing.jsx`].
* **Mechanics:**
  * **Anti-Zombie UI Hero Schematic:** Embedded an authentic, glowing purple monospace ASCII architectural schematic into the landing hero (`hvt-fr/src/pages/landing/Landing.jsx`), visually mapping the entire HVT cryptographic flow: Control Plane (`hvt_mgmt_...`) schema sync -> RS256 Private Key Sign -> Runtime Engine (`hvt_live_...`) -> 0.1ms In-Memory Verification at Edge without database lookups.
  * **Multi-Page Deep-Dive Architecture:** Disaggregated monolithic feature descriptions from the landing page into 5 dedicated, high-depth technical feature pages:
    1. `/features/engine`: Cryptographic In-Memory Engine, JWT claims anatomy, sub-millisecond benchmarks, and language SDK snippets (`hvt-fr/src/pages/features/FeatureEnginePage.jsx`).
    2. `/features/dual-plane`: Dual-Plane Architecture, isolation of administrative management keys (`hvt_mgmt_`) from public runtime keys (`hvt_live_`), and blast radius containment (`hvt-fr/src/pages/features/FeatureDualPlanePage.jsx`).
    3. `/features/passkeys`: Passkeys, FIDO2 WebAuthn biometric challenge-response ceremony, RFC 6238 TOTP fallback, and 10 single-use emergency backup recovery codes (`hvt-fr/src/pages/features/FeaturePasskeysPage.jsx`).
    4. `/features/sessions`: Active Device Registry, IP/user-agent profiling, single-session revocation, and global remote logout (`hvt-fr/src/pages/features/FeatureSessionsPage.jsx`).
    5. `/features/byo-email`: Bring-Your-Own Email Transports (Resend, AWS SES, Postmark, Custom SMTP), SPF/DKIM alignment, and delivery test sandbox (`hvt-fr/src/pages/features/FeatureByoEmailPage.jsx`).
  * **Rich Developer Sitemaps Footer:** Mounted `<Footer />` (`hvt-fr/src/components/layout/Footer.jsx`) across all public marketing and feature routes with Product, Developers, Standards & Legal, Apache 2.0 open-source badge, and live operational status pill.
  * **Collapsible Project Creation:** Refactored `ProjectsTab.jsx` to make project creation responsive and collapsible with an interactive `+ New project` / `Collapse` toggle and purple primary actions.
* **Verified Evidence:**
  * Clean lint and production build: `npm run lint` (0 errors), `npm run build` (built in 34.06s) [RAN `npm run build` -> exit code 0].
  * 10 high-resolution Playwright screenshots captured in `docs/audit/screens/anti_zombie/`: `01_landing_hero_ascii.png`, `01_landing_full.png`, `02_features_engine.png`, `03_features_dual_plane.png`, `04_features_passkeys.png`, `05_features_sessions.png`, `06_features_byo_email.png`, `07_settings_projects_collapsed.png`, `09_dashboard_overview.png`, `10_api_keys.png` [RAN Playwright -> all verified].
