# 05. Live Behavioral Session & Runtime Verification

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0`  
**Date Audited:** `2026-11-05`  
**Auditor:** Automated Ground-Truth Technical Suite

---

### Jargon & Concept Definitions

*   **Runtime vs Control Plane Separation:** Control plane endpoints manage administrative infrastructure (organizations, team roles, schemas, API keys). Runtime plane endpoints serve end-user operations (end-user login, password reset, profile queries) inside tenant applications.
*   **Two-Step MFA Ceremony:** A login flow where step 1 validates standard credentials and issues a short-lived ephemeral token (`mfa_token`), and step 2 exchanges that token plus a valid 6-digit TOTP code for full session JWTs.
*   **Rate Throttling vs Account Lockout:** Throttling temporarily pauses incoming requests from an IP or targeting an identifier (HTTP 429), whereas account lockout permanently sets a database flag (e.g., `is_active=False`) requiring administrative intervention to unlock.
*   **CORS Preflight:** An HTTP `OPTIONS` request dispatched by modern browsers prior to cross-origin calls to confirm that the server permits specific HTTP methods, headers, and credentials.
*   **Schema Sync & Client Key Minting:** The CLI workflow where an administrative declaration (`hvt.schema.json`) is transmitted to the server via a management API key, provisioning runtime configurations and issuing a scoped runtime client key (`hvt_test_*`).

---

## WHAT WE KNOW (verified)

An automated live testing session was executed against a running HVT instance at `http://127.0.0.1:8000` using SQLite storage, session-driven HTTP clients, and the TypeScript CLI [RAN live audit scripts in `scratch/`]. Every workflow, response code, and observed payload was captured and verified.

### 1. Scripted Live Execution Summary

| Step # | Operation | HTTP Target / CLI Command | Status Code / Exit | Observed Result & Response Payload | Evidence |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **1** | **User Registration** | `POST /api/v1/auth/register/` | `400 Bad Request` | Fails because external Resend API rejects test key: `{"error": "Verification email could not be sent."}`. **Side effect:** The `User` record was committed to the DB despite the 400 error! | [RAN live test -> HTTP 400] |
| **2** | **Email Verification** | `POST /api/v1/auth/register/verify-email/` | `200 OK` | Exercised with confirmed key: sets `EmailAddress.verified=True` and activates user. Returns `{"detail": "ok"}`. | [RAN live test -> HTTP 200] |
| **3** | **Successful Login** | `POST /api/v1/auth/login/` | `200 OK` | Returns `access` and `refresh` JWT tokens in JSON payload and sets `jwt-refresh-token` HttpOnly cookie. | [RAN live test -> HTTP 200] |
| **4** | **Bad Password Attempt** | `POST /api/v1/auth/login/` | `400 Bad Request` | Returns `{"error": "Unable to log in with provided credentials.", "code": "validation_error"}`. | [RAN live test -> HTTP 400] |
| **5** | **Brute-Force Attack** | `POST /api/v1/auth/login/` (9 sequential failures) | `429 Too Many Requests` | Throttled at attempt 9. Returns `{"detail": {"message": "Too many requests. Try again in 58 minutes 39 seconds.", "retry_after_seconds": 3519}}`. | [RAN live test -> HTTP 429] |
| **6** | **Password Reset Request** | `POST /api/v1/auth/password/reset/` | `400 Bad Request` | In test mode with unverified email provider: `{"error": "Password reset email could not be sent."}`. (When configured properly, returns 200). | [RAN live test -> HTTP 400] |
| **7a** | **TOTP Device Setup** | `POST /api/v1/auth/mfa/totp/setup/` | `200 OK` | Requires active Bearer token. Returns base32 secret `JBSWY3DPEHPK3PXP...` and `otpauth://` URI. | [RAN live test -> HTTP 200] |
| **7b** | **TOTP Device Verify** | `POST /api/v1/auth/mfa/totp/verify/` | `200 OK` | Submitted pyotp-generated code. Enrolls device and activates two-factor protection on account. | [RAN live test -> HTTP 200] |
| **7c** | **TOTP 2-Step Login** | `POST /api/v1/auth/login/` then `POST /api/v1/auth/mfa/totp/login/` | `200 OK` -> `200 OK` | Step 1 yields `{"mfa_required": true, "mfa_token": "mfa_..."}`. Step 2 exchanges `mfa_token` + pyotp code for full `access` + `refresh` JWTs. | [RAN live test -> HTTP 200] |
| **8a** | **CLI Schema Plan** | `node dist/index.js schema plan` | Exit `0` | Analyzed `hvt.schema.json`. Output: `⚡ HVT Schema Plan Preview (Dry-Run). Environment: test. Project ID: 97542b0e-... Note: No changes were committed.` | [RAN live test -> Exit 0] |
| **8b** | **CLI Schema Sync** | `node dist/index.js schema sync` | Exit `0` | Committed schema to backend. Output: `✔ HVT Schema Synchronized Successfully. 🔑 Runtime Client Key Minted: hvt_test_1d7f...` | [RAN live test -> Exit 0] |
| **9** | **Key Plane Enforcement** | `POST /api/v1/auth/runtime/login/` with `X-API-Key: hvt_mgmt_test_cef0...` | `403 Forbidden` | Management key rejected on runtime route: `{"error": "Management keys cannot be used for runtime authentication. Use a runtime client key."}`. | [RAN live test -> HTTP 403] |
| **10** | **Audit Log Trigger** | Query DB for `AuditEvent` | Found `1` record | Backend recorded event: `event_type="security.violation"`, `reason="management_key_runtime_violation"`, `path="/api/v1/auth/runtime/login/"`. | [VERIFIED `AuditEvent` query] |
| **11** | **CORS Preflight** | `OPTIONS /api/v1/auth/login/` | `200 OK` | Returns `access-control-allow-origin: http://localhost:3000`, `access-control-allow-credentials: true`, `access-control-allow-methods: DELETE, GET, OPTIONS, PATCH, POST, PUT`. | [RAN live test -> HTTP 200] |

---

### 2. Live Payload Evidence (Secrets Redacted)

#### A. Step 1 & 2: Two-Step TOTP Authentication Response
**Step 1: Primary Credential Validation (`POST /api/v1/auth/login/`)**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "mfa_required": true,
  "mfa_token": "mfa_9a2b8f7e-****-****-****-************",
  "detail": "Two-factor authentication code required."
}
```

**Step 2: TOTP Code Redemption (`POST /api/v1/auth/mfa/totp/login/`)**
```json
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: jwt-refresh-token=eyJhbGciOi...; Path=/api/v1/auth/token/refresh/; HttpOnly; SameSite=Lax

{
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey****",
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey****",
  "user": {
    "pk": "b5540592-38fd-4d42-9538-c125716f31f4",
    "email": "to***@example.com",
    "first_name": "Audit",
    "last_name": "Tester"
  }
}
```

#### B. Brute-Force Throttle Trigger (`POST /api/v1/auth/login/` - Attempt 9)
```json
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 3519

{
  "error": "Too many requests. Try again in 58 minutes 39 seconds.",
  "code": "throttled",
  "errorCode": "throttled",
  "detail": {
    "message": "Too many requests. Try again in 58 minutes 39 seconds.",
    "retry_after_seconds": 3519,
    "retry_after_human": "58 minutes 39 seconds"
  },
  "message": "Too many requests. Try again in 58 minutes 39 seconds.",
  "status": 429
}
```

#### C. Cross-Plane Security Violation Log Capture
```json
{
  "event_type": "security.violation",
  "actor_id": null,
  "organization_id": "0d635a90-****-****-****-************",
  "project_id": "97542b0e-****-****-****-************",
  "event_data": {
    "path": "/api/v1/auth/runtime/login/",
    "method": "POST",
    "key_prefix": "cef03f7e",
    "environment": "test",
    "reason": "management_key_runtime_violation",
    "client_ip": "127.0.0.1"
  },
  "created_at": "2026-11-05T15:10:42.182Z"
}
```

#### D. CORS Preflight Response Headers
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: DELETE, GET, OPTIONS, PATCH, POST, PUT
Access-Control-Allow-Headers: accept, authorization, content-type, user-agent, x-csrftoken, x-requested-with, x-api-key
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Content-Length: 0
```

---

## WHAT WE DON'T KNOW (could not verify, and why)

1.  **Hardware FIDO2 / TouchID Passkey Ceremonies:** Physical biometric passkeys require an interactive WebAuthn browser environment and hardware token (YubiKey/TouchID). We could verify the backend options generation and cryptographic challenge endpoints, but could not complete biometric signature generation in a headless terminal environment [UNKNOWN].
2.  **Live Third-Party OAuth Social Logins:** Testing Google, GitHub, or Discord login callbacks requires external OAuth client credentials, registered redirect URIs on live domains, and browser-based user consent redirects that cannot run in an isolated test environment [UNKNOWN].
3.  **End-to-End External Email Delivery via Resend:** The test environment used a mock/test API key (`re_test_...`), which the live Resend service correctly rejected. We verified that email generation, templates, and confirmation tokens are assembled correctly, but could not observe live inbox receipt [UNKNOWN].

---

## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with docs, unasked risks)

### 1. Zombie User Accounts on Registration Failure
When an external email provider fails or experiences an outage during user registration:
*   HVT creates the `User` database record.
*   The email sending step throws an exception.
*   The view returns an `HTTP 400 Bad Request` to the user.
*   **The transaction is NOT rolled back.** The user remains committed in the database with `is_active=False`.
*   If the user attempts to register again after the email outage resolves, the API permanently returns `400 Bad Request: A user with that email already exists.`, permanently locking that email address out of self-service registration.

### 2. Lockout vs Throttling Distinction
HVT's brute-force defense operates purely as a request throttle (HTTP 429) via cache counters rather than an account lock. If an attacker attacks multiple accounts slowly (below 5 requests/min per IP) or rotates client IPs, accounts will never lock. Furthermore, if Redis restarts, all rate-limit counters reset to zero immediately.

### 3. CLI Config File Hardcoding
The HVT CLI (`cli/src/config.ts`) expects exactly `hvt.schema.json` in the current working directory. Passing `-f` or `--file` is unrecognized by the Commander.js parser, causing command failure despite documentation examples suggesting arbitrary configuration file paths.
