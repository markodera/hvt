# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-11-06

### Security
- **Anti-User Enumeration Hardening:**
  - Standardized registration endpoints (`/api/v1/auth/register/` and `/api/v1/auth/runtime/register/`) to return identical HTTP 201 Created and verification detail payload regardless of whether an account already exists or is verified; dispatched an "account already exists" notification email on duplicate registration instead of an error.
  - Standardized login endpoints (`/api/v1/auth/login/` and `/api/v1/auth/runtime/login/`) to return identical HTTP 400 Bad Request responses for nonexistent accounts, invalid passwords, unverified accounts, and tenant mismatches.
  - Preserved anti-enumeration posture on password reset returning HTTP 200 OK across control and runtime planes.
  - Retained strict rate throttling across all registration, login, and password reset routes.
  - Added test suite `tests/test_user_enumeration.py` covering control and runtime planes.
- **Signup Limbo Prevention (Atomic Rollback on Email Failure):**
  - Wrapped user creation and verification email dispatch inside an atomic transaction (`transaction.atomic()`).
  - If sending the verification email fails (e.g. SMTP or Resend outage), the transaction rolls back cleanly, preventing abandoned unusable accounts.
  - Deferred registration webhook dispatch to `transaction.on_commit` to prevent spurious webhook events on signup failure.
  - Allowed subsequent registration attempts with the same email to proceed immediately without collision once service recovers.
  - Added test coverage in `tests/test_signup_limbo.py` covering control-plane and runtime registration flows with simulated email backend failures.
- **TOTP Encryption at Rest & Single-Use Backup Codes:**
  - Encrypted TOTP secrets at rest with `EncryptedTextField` and MultiFernet (`v1:` prefix) via migration `0013` and idempotent backfill migration `0014`.
  - Added 10 single-use cryptographically secure backup codes generated when TOTP is verified/enabled, displayed once to the user.
  - Stored only SHA-256 hashes of backup codes in `auth_totp_backup_codes`.
  - Accepted backup codes at the TOTP login step (`/api/v1/auth/mfa/totp/login/`) and standard login endpoint with atomic single-use invalidation (`used_at`).
  - Added backup code regeneration endpoint (`/api/v1/auth/mfa/totp/backup-codes/regenerate/`) requiring fresh password re-authentication.
  - Added structured audit-log events `totp.backup_code_used` and `totp.backup_codes_regenerated`.
- **Social OAuth Account Linking Verification:**
  - Enforced that social identities are linked to existing accounts only when the provider explicitly confirms the email is verified.
  - If unverified or if the provider does not state verification status, account linking is refused with a clear message: "Cannot link social identity: email is not verified by provider. Please log in to your existing account first."
  - Comprehensive test suite covering all 6 social providers (Google, GitHub, Discord, Apple, Microsoft, GitLab) with verified and unverified payloads across control and runtime planes.

- **Webhook SSRF & Exfiltration Hardening:**
  - Enforced HTTPS scheme in production (HTTP permitted only when DEBUG=True).
  - Prohibited embedded user credentials in webhook destination URLs.
  - Added strict IP validation refusing loopback (127.0.0.1, ::1), cloud metadata (169.254.169.254), private RFC 1918 networks, multicast, and reserved ranges.
  - Implemented connection-time socket IP verification (SSRFSafeHTTPAdapter) to prevent DNS rebinding attacks.
  - Strictly disabled redirect following (allow_redirects=False) with short timeouts (3.0s).
  - Stopped storing or returning response bodies through the API (response_body removed from WebhookDeliverySerializer; stored as empty with short error codes like SSRF_BLOCKED, REDIRECT_REFUSED).

- **Dependencies (pip-audit CI):**
  - Upgraded Python dependencies with known vulnerabilities (Django to 5.2.19, django-allauth to 65.21.1, djangorestframework to 3.18.3, python-dotenv to 1.2.2, oauthlib to 4.0.1, urllib3 to 2.8.0, pyjwt to 2.15.0).
  - Added automated dependency security auditing with pip-audit to CI pipeline (.github/workflows/ci.yml) and script scripts/audit_dependencies.py.
  - Added pip-audit-exceptions.txt to enforce failure on unaccepted vulnerabilities while tracking documented exceptions.

## [0.2.0] - 2026-11-05

### Relicensing & Governance
- **Transition from AGPL-3.0 to Apache-2.0:** All code in version `v0.2.0` and onwards is licensed under the Apache Software License, Version 2.0. Version `v0.1.0` was the final release under AGPL-3.0.
- **NOTICE & Contributor Licensing:** Added comprehensive `NOTICE` file crediting Mark Odera and HVT contributors. All dependency licenses reviewed and verified permissive (MIT, BSD, Apache, ISC).

### Added
- **Official CLI (`@hvt/cli`):**
  - Declarative schema provisioning, plan previews (`dry_run=true`), and schema application.
  - Interactive onboarding (`hvt init`) scaffolding all 6 major social providers (Google, GitHub, Discord, Apple, Microsoft, GitLab).
  - Safe environment variable interpolation (`${ENV_VAR}`) with redaction in logs and error outputs.
  - Automatic injection of generated runtime client keys into `.env.local` (`NEXT_PUBLIC_HVT_CLIENT_KEY`) with gitignore safety warnings.
  - Explicit safety guard: strictly refuses to write management keys into `NEXT_PUBLIC_*` variables.
- **Declarative Schema Sync Engine (`schema:sync` / `schema:plan`):**
  - Canonical `hvt.schema.json` specification with JSON schema validation.
  - Atomic synchronization of project permissions, RBAC roles, role-permission mappings, and OAuth provider credentials.
  - Two-way adoption: seamlessly adopts dashboard-created resources (`managed_by=dashboard` -> `managed_by=manifest`).
  - Pruning safety: `--prune` flag deletes only manifest-managed resources without active assigned users.
  - One-time runtime client key (`hvt_test_*` / `hvt_live_*`) minted upon initial successful schema application.
- **Envelope Encryption for Secrets:**
  - MultiFernet field-level encryption (`EncryptedTextField`) for sensitive provider secrets (`client_secret`), prefixed with `v1:`.
  - Seamless key rotation with primary/secondary keys configured via `HVT_ENCRYPTION_KEYS`.
  - Data migration backfill (`0024_encrypt_existing_social_provider_secrets`) upgrading legacy plaintext secrets.
  - Zero-leak guarantee: secrets are write-only and redacted from all API responses, validation errors, and audit logs.
- **Authentication & Plane Separation:**
  - Strict plane separation between the **Management Plane** (`hvt_mgmt_test_`, `hvt_mgmt_live_`) and the **Runtime Plane** (`hvt_test_`, `hvt_live_`, `hvt_client_*`).
  - Dedicated authenticators: `ManagementAPIKeyAuthentication` (allowed exclusively on schema provisioning endpoints) and `RuntimeAPIKeyAuthentication` (allowed exclusively on runtime endpoints).
  - Append-only security audit logging: every attempt to use a management key on a runtime route or invalid endpoint writes an audit event (`security.violation`).
  - Default-deny on write operations unless explicitly declared via `api_key_write_scopes`.

### Changed & Known Limitations
- **Option C Plane Isolation (Known Limitation):**
  - In HVT, projects are currently unified across test and live modes. Under Option C, test management keys (`hvt_mgmt_test_`) are strictly forbidden from modifying projects that contain active live API keys (`hvt_live_` or `hvt_mgmt_live_`).
  - Schema sync acquires a database row-level lock (`select_for_update()`) on the project and serializes concurrent sync operations.
  - **Known Limitation:** Once a project goes live and generates a live API key, AI developer setup prompts and test-environment CI jobs can no longer mutate the project schema. Schema changes for live projects must be executed with a live management key (`hvt_mgmt_live_`) in production CI/CD or managed via the HVT Dashboard.
- **Dashboard "Copy AI Setup Prompt" Visibility:**
  - The Project API now exposes `has_active_live_keys` and `can_use_setup_prompt` metadata. The dashboard hides or explains the "Copy AI Setup Prompt" button for projects that already have live keys.
