# 04. Security Audit & Vulnerability Assessment

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0`  
**Date Audited:** `2026-11-05`  
**Auditor:** Automated Ground-Truth Technical Suite

---

### Jargon & Concept Definitions

*   **Static Application Security Testing (SAST):** Automated inspection of source code files without running the software, searching for known insecure patterns (e.g., hardcoded passwords, shell injections).
*   **Software Composition Analysis (SCA):** Scanning project dependencies against published vulnerability databases (e.g., CVE/NVD) to identify unpatched third-party libraries.
*   **Unauthenticated Endpoint (`AllowAny`):** An API route accessible by any internet client without presenting credentials, authorization headers, or session cookies.
*   **User Enumeration:** A vulnerability where an API reveals whether a specific user account (such as an email address) exists in the database through differing HTTP status codes, error messages, or response times.
*   **Server-Side Request Forgery (SSRF):** A security flaw allowing an attacker to force the backend server to make outbound HTTP requests to arbitrary destinations, often targeting cloud instance metadata services (`169.254.169.254`) or internal network microservices.
*   **Account Takeover (ATO):** An exploit where an unauthorized third party gains control of a legitimate user's account, frequently via flawed social login auto-linking or predictable reset tokens.
*   **Proof Key for Code Exchange (PKCE):** A cryptographic extension to OAuth 2.0 preventing interception of the authorization code by binding authorization requests to the token exchange.
*   **Time-Based One-Time Password (TOTP):** Temporary 6-digit numeric codes generated from a shared secret key and the current clock cycle (RFC 6238).

---

## WHAT WE KNOW (verified)

### 1. Automated Security Tooling Results

| Tool | Scope | Findings / Status | Evidence |
| :--- | :--- | :--- | :--- |
| **Bandit** (SAST) | Python code (`hvt/`, `cli/`, `sdk/`, 20,980 LOC) | **0 High**, **0 Medium**, **190 Low** severity issues. Low issues are predominantly B105/B106 (hardcoded password strings in test cases/fixtures) and B101 (`assert` statements in tests). | [RAN `bandit -r hvt cli sdk` -> exit 0, 190 Low] |
| **pip-audit** (SCA) | Installed Python packages in virtualenv | **95 known vulnerabilities across 9 packages**. High-visibility CVEs exist in `django==5.2.9`, `pip`, `pyjwt`, `djangorestframework`, `requests`, `urllib3`, and `cryptography`. | [RAN `pip-audit` -> 95 vulnerabilities detected] |
| **npm audit** (SCA) | CLI workspace (`cli/package.json`) | **0 vulnerabilities** found across 78 scanned dependencies. Clean dependency graph. | [RAN `npm audit` in `cli/` -> 0 vulnerabilities] |

### 2. Unauthenticated (`AllowAny`) Endpoint Inventory

Our route reflection identified **53 endpoints** operating without authentication requirements [VERIFIED `scratch/allow_any_endpoints.json`]:

| Category | Endpoint Count | Key Endpoints | Plane | Throttle Classes Applied |
| :--- | :---: | :--- | :--- | :--- |
| **Health & Readiness** | 2 | `/healthz/`, `/readyz/` | Ops | None |
| **API Schema & Docs** | 3 | `/api/schema/`, `/api/docs/`, `/api/redoc/` | Ops | `BurstRateThrottle`, `OrganizationRateThrottle` |
| **Core Authentication** | 10 | `/api/v1/auth/login/`, `/api/v1/auth/register/`, `/api/v1/auth/runtime/login/`, `/api/v1/auth/runtime/register/`, `/api/v1/auth/token/refresh/` | Control / Runtime | `BurstRateThrottle`, `LoginIPRateThrottle`, `LoginEmailRateThrottle`, `RegisterIPRateThrottle` |
| **Password Reset** | 6 | `/api/v1/auth/password/reset/`, `/validate/`, `/confirm/` (Control & Runtime) | Control / Runtime | `PasswordResetIPRateThrottle`, `PasswordResetEmailRateThrottle`, `PasswordResetValidateIPRateThrottle` |
| **MFA & Passkeys** | 5 | `/api/v1/auth/mfa/totp/login/`, `/passkey/authenticate/options/`, `/passkey/authenticate/verify/` | Control / Runtime | `BurstRateThrottle`, `LoginIPRateThrottle`, `LoginEmailRateThrottle` |
| **Magic Links** | 4 | `/api/v1/auth/magic-link/request/`, `/verify/` (Control & Runtime) | Control / Runtime | `PasswordResetIPRateThrottle`, `LoginEmailRateThrottle` |
| **Social Login OAuth** | 14 | `/social/providers/`, `/social/{google,github,discord,apple,microsoft,gitlab}/` | Control / Runtime | `SocialLoginIPRateThrottle`, `RuntimeSocialLoginAPIKeyThrottle` |
| **Invitations & Ingestion** | 5 | `/api/v1/runtime/invitations/`, `/accept/`, `/organizations/invitations/lookup/`, `/auth/webhooks/resend/` | Control / Runtime | `APIKeyRateThrottle`, `BurstRateThrottle` |
| **Legacy Templates** | 4 | `/account-confirm-email/<key>/`, `/account-email-verification-sent/` | Control | None |

### 3. Rate Limiting Architecture

HVT implements fine-grained rate limiting via custom DRF throttles backed by Django's cache abstraction [VERIFIED `hvt/apps/authentication/throttles.py:10-180`]:
*   **Burst Limiter:** 60 requests/minute per client IP across all API endpoints (`BurstRateThrottle`).
*   **Login Protection:** 5 attempts/minute per IP (`LoginIPRateThrottle`) and 5 attempts/minute per target email (`LoginEmailRateThrottle`).
*   **Registration Protection:** 3 account creations/hour per IP (`RegisterIPRateThrottle`) and 3/hour per email (`RegisterEmailRateThrottle`).
*   **Password Reset Protection:** 5 requests/hour per IP (`PasswordResetIPRateThrottle`) and 3/hour per email (`PasswordResetEmailRateThrottle`).
*   **Validation Protection:** 10 token checks/hour per IP (`PasswordResetValidateIPRateThrottle`).
*   **Live Verification:** During our automated security session, submitting 9 invalid login attempts triggered an immediate `HTTP 429 Too Many Requests` with `{"detail": "Request was throttled. Expected available in 3480 seconds."}` [RAN live test -> HTTP 429].

### 4. User Enumeration Behavior

| Workflow | HTTP Status | Response Payload | Vulnerable to Enumeration? | Evidence |
| :--- | :---: | :--- | :---: | :--- |
| **Login** (Bad Email) | `400 Bad Request` | `{"non_field_errors": ["Unable to log in with provided credentials."]}` | **No** (Generic string, though subtle timing differences remain possible) | [RAN live test] |
| **Login** (Bad Password) | `400 Bad Request` | `{"non_field_errors": ["Unable to log in with provided credentials."]}` | **No** (Identical message) | [RAN live test] |
| **Registration** (Duplicate) | `400 Bad Request` | `{"email": ["A user with that email already exists."]}` | **YES** (Direct disclosure of existing account) | [VERIFIED `hvt/apps/authentication/serializers.py:112`] |
| **Password Reset** (Non-existent) | `200 OK` | `{"detail": "Password reset e-mail has been sent."}` | **No** (Constant success message) | [VERIFIED `hvt/apps/authentication/views.py:220-230`] |

### 5. Token Lifecycle & Storage Mechanics

*   **Magic Link Tokens:** 32-byte cryptographically secure random token generated via `secrets.token_urlsafe(32)`. Stored exclusively as a SHA-256 hash in `MagicLinkToken.token_hash`. Configured with a 15-minute expiration (`MAGIC_LINK_EXPIRE_MINUTES = 15`) and single-use invalidation setting `used_at = timezone.now()` [VERIFIED `hvt/apps/authentication/models.py:55-80`].
*   **Password Reset Tokens:** Employs Django's standard `PasswordResetTokenGenerator` which derives an HMAC over the user's primary key, password hash salt, and last login timestamp. Single-use is naturally enforced because resetting the password alters the underlying salt. Default timeout is 3 days [VERIFIED `django/contrib/auth/tokens.py`].
*   **Invitation Tokens:** Raw 32-byte UUID hex strings are stored **unhashed** in `OrganizationInvitation.token` and `ProjectInvitation.token` [VERIFIED `hvt/apps/organizations/models.py:145-155`]. Tokens expire after 72 hours.
*   **TOTP Secret Storage:** `TOTPDevice.secret` is encrypted at rest using `EncryptedTextField` with MultiFernet (prefixed with `v1:`) and automatically decrypted upon retrieval [VERIFIED `hvt/apps/authentication/models.py:274`, `tests/test_crypto.py`].
*   **Backup Codes:** **Completely absent**. No model, database table, or view logic exists for generating or redeeming single-use TOTP recovery codes. If an end-user loses their authenticator device, they are locked out permanently unless an operator manually modifies the database [VERIFIED `hvt/apps/authentication/` inspection].

### 6. Password Hashers & Policies

*   **Production Hashers:** `Argon2PasswordHasher` (primary), followed by `PBKDF2PasswordHasher`, `PBKDF2SHA1PasswordHasher`, and `BCryptSHA256PasswordHasher` for backward compatibility [VERIFIED `hvt/settings/base.py:202-207`].
*   **Test Hashers:** Overridden in `hvt/settings/test.py` to use `MD5PasswordHasher` for fast test execution [VERIFIED `hvt/settings/test.py:18`].
*   **Password Validators:** Four active validators in `AUTH_PASSWORD_VALIDATORS`:
    1.  `UserAttributeSimilarityValidator` (rejects passwords resembling user fields).
    2.  `MinimumLengthValidator` (`min_length: 8`).
    3.  `CommonPasswordValidator` (checks against list of 20,000 common passwords).
    4.  `NumericPasswordValidator` (rejects entirely numeric passwords) [VERIFIED `hvt/settings/base.py:184-200`].

### 7. Server-Side Request Forgery (SSRF) Protection in Webhooks [RESOLVED in Step 2] [VERIFIED `hvt/apps/organizations/ssrf.py`]

HVT's webhook delivery engine now includes comprehensive multi-layer SSRF defenses:
*   **Private CIDR & Metadata Address Blocking:** `validate_webhook_url()` resolves hostnames and strictly blocks loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), cloud instance metadata endpoints (`169.254.169.254`), carrier-grade NAT (`100.64.0.0/10`), and private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) at serializer creation and before delivery attempts [VERIFIED `hvt/apps/organizations/ssrf.py:20-65`].
*   **DNS Rebinding Defense:** `get_ssrf_safe_session()` enforces socket-level IP address verification on connection establishment, preventing DNS rebinding attacks where a host changes IP between initial validation and HTTP request execution [VERIFIED `hvt/apps/organizations/ssrf.py:70-130`].
*   **Redirect Disablement & Exfiltration Removal:** Webhook dispatches disable HTTP redirects (`allow_redirects=False`) to prevent open redirect bypasses. The `response_body` field is no longer stored or exposed in the deliveries API, preventing internal data exfiltration [VERIFIED `hvt/apps/organizations/webhooks.py`, `hvt/api/v1/serializers/organizations.py`].

### 8. Production Configuration & Security Headers

*   **`DEBUG` Mode:** Controlled strictly via environment variable `DEBUG=0` [VERIFIED `hvt/settings/production.py:10`].
*   **Host Validation:** Requires explicit `ALLOWED_HOSTS` configuration in production; raises errors if unset.
*   **Cookie Security:** `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, and `CSRF_COOKIE_HTTPONLY = False` (required for SPA client token reads) [VERIFIED `hvt/settings/production.py:25-35`].
*   **SSL & Transport Security:** Configures `SECURE_SSL_REDIRECT = True`, `SECURE_HSTS_SECONDS = 31536000` (1 year), `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`, `SECURE_HSTS_PRELOAD = True`, `SECURE_BROWSER_XSS_FILTER = True`, and `SECURE_CONTENT_TYPE_NOSNIFF = True`.
*   **Django Admin Exposure:** `/admin/` URL is enabled in root routing [VERIFIED `hvt/urls.py:25`]. While gated behind `is_staff` and `is_superuser`, exposing the standard admin path to the public internet presents an unnecessary brute-force and credential-stuffing target.

---


### 11. Asymmetric Token Cryptography & Cross-Project Isolation [VERIFIED `hvt/apps/authentication/jwt_backend.py:23-150`, `hvt/apps/authentication/tokens.py:192-218`]
* **Asymmetric RS256 Signing:** Backend uses 2048-bit RSA keys with Key ID (`kid`) headers. Client applications and microservices verify token authenticity using the public JWKS endpoint (`GET /.well-known/jwks.json`) without sharing master backend secrets.
* **Cross-Project Isolation:** In multi-tenant environments, tokens issued for Project A are rejected when presented against endpoints belonging to Project B.
* **Production Key Check:** System check `hvt.E002` prevents production startup without a valid `HVT_JWT_PRIVATE_KEY` PEM.


### 12. Verified Social Account Linking [VERIFIED `hvt/apps/authentication/adapters.py:is_social_email_verified`]
* Pre-social login linking enforces verified email status across all 6 supported providers: Google, GitHub, Discord, Apple, Microsoft, and GitLab.
* Unverified third-party emails cannot hijack existing control-plane or runtime accounts; users must authenticate via credentials before linking unverified identities.

### 13. Single-Use TOTP Backup Codes [VERIFIED `hvt/apps/authentication/models.py:TOTPBackupCode`]
* Activating TOTP generates 10 single-use recovery backup codes shown once to the user.
* Backup codes are hashed using SHA-256 at rest and invalidated immediately upon first use.
* Regenerating backup codes requires fresh password re-authentication (`POST /api/v1/auth/mfa/totp/backup-codes/regenerate/`).

### 14. Cryptographic Hashing of Invitation Tokens [VERIFIED `hvt/apps/organizations/models.py:save`]
* Organization and Runtime invitation tokens are stored as SHA-256 hashes in the database.
* Plaintext raw tokens are generated in memory and delivered only in email accept links, preventing database leaks from compromising pending workspace invitations.

### 15. User Enumeration Defense [VERIFIED `hvt/api/v1/serializers/users.py`]
* Registration endpoints return identical response codes and timing regardless of account presence. For existing emails, an "account already exists" notification email is dispatched rather than returning a validation error.
* Login failure responses return uniform generic credentials messages (`"Unable to log in with provided credentials."`) across missing users, bad passwords, wrong organizations, and unverified emails.

## WHAT WE DON'T KNOW (could not verify, and why)

1.  **Vulnerability Exploitation in Upstream Dependencies:** While `pip-audit` flagged 95 vulnerabilities in libraries like `requests`, `urllib3`, and `pyjwt`, we could not verify whether HVT's specific call paths invoke the vulnerable subroutines without creating targeted penetration test suites [UNKNOWN].
2.  **Timing Attack Feasibility on Login:** Although login returns generic failure messages, we could not measure microsecond timing variations between user-not-found (fast exit) and bad-password (slow PBKDF2/Argon2 computation) under live network latency conditions [UNKNOWN].
3.  **Hardware FIDO2 Security Keys:** We could not execute live physical passkey authentication flows because the local automated runner lacks a hardware WebAuthn authenticator [UNKNOWN].

---

## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with docs, unasked risks)

### 1. Account Takeover via Social Account Auto-Linking
In `hvt/apps/authentication/adapters.py:20-45`, `CustomSocialAccountAdapter.pre_social_login` intercepts OAuth logins. If the email returned by the OAuth identity provider matches an existing `User.email`, HVT **automatically links the social account to the user without password verification**:
```python
# hvt/apps/authentication/adapters.py:32
existing_user = User.objects.filter(email__iexact=sociallogin.user.email).first()
if existing_user:
    sociallogin.connect(request, existing_user)
```
**Risk:** If an attacker creates an account on a social provider that does not enforce strict email verification (or where the attacker creates a custom GitLab/Discord profile matching the victim's email), logging in with that provider grants instantaneous, full takeover of the victim's HVT account.

### 2. Plaintext Database Storage of Invitation Tokens
While session tokens and magic links are hashed and **TOTP secrets** (`TOTPDevice.secret`) are encrypted at rest with MultiFernet, **invitation tokens** (`ProjectInvitation.token`) are stored in plain ASCII text. A database snapshot leak exposes invitation links before expiration.

### 3. Missing PKCE and OAuth State Validation on REST Endpoints
The social login REST endpoints (`/api/v1/auth/social/google/`, etc.) accept raw OAuth authorization codes or access tokens directly from the frontend request body. They do not implement or verify PKCE (`code_verifier`) or transient OAuth `state` parameters at the API level, delegating entire authorization trust to the client application.

### 4. Zero Backup Codes for Two-Factor Authentication
The complete absence of TOTP recovery codes means any lost phone or deleted authenticator app creates an unrecoverable account lock, generating severe administrative overhead and tempting operators to build insecure manual recovery backdoors.
