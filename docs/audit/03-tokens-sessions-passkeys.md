# 03: Tokens, Sessions & Passkeys Audit

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0` [VERIFIED git rev-parse HEAD]  
**Branch:** `release/v0.2.0-prep` [VERIFIED git status]  
**Date Audited:** November 5, 2026 [VERIFIED git log -1]  

---

### Terminology Primer
* **Bearer Token:** A security token where the presenter (bearer) is granted access simply by presenting the token in the `Authorization: Bearer <token>` HTTP header, without proving possession of a private cryptographic key.
* **HttpOnly & Secure Cookies:** Browser cookie attributes that prevent client-side JavaScript from accessing the cookie (`HttpOnly`, mitigating XSS token theft) and ensure the cookie is only transmitted over encrypted HTTPS connections (`Secure`).
* **SameSite Cookie Policy:** Instructs the browser whether to send cookies with cross-site requests (`SameSite=Strict`, `SameSite=Lax`, or `SameSite=None`). Frontends running on different origins require `SameSite=None; Secure`.
* **Standard JWT Claims:**
  * `iss` (Issuer): Identifies the principal that issued the JWT.
  * `aud` (Audience): Identifies the recipients that the JWT is intended for.
  * `sub` (Subject): The principal that is the subject of the JWT (user ID).
  * `exp` (Expiration Time): Timestamp after which the token must not be accepted.
  * `iat` (Issued At): Timestamp when the token was created.
  * `jti` (JWT ID): Unique identifier providing a means to prevent token replay attacks.
* **COSE (CBOR Object Signing and Encryption):** A compact binary format used in WebAuthn to represent public cryptographic keys.

---

## WHAT WE KNOW

### 1. What Authentication & Login Endpoints Return

When a user logs in successfully via `/api/v1/auth/login/` or `/api/v1/auth/runtime/login/`, the response depends on the account's MFA state [VERIFIED `hvt/api/v1/serializers/users.py:345-420`, `hvt/apps/authentication/views.py:530-580`]:

1. **Standard Login (No MFA Active):**
   * **HTTP Status:** `200 OK`
   * **JSON Body Payload:**
     ```json
     {
       "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
       "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
       "user": {
         "id": "b5540592-38fd-4d42-9538-c125716f31f4",
         "email": "user@example.com",
         "first_name": "Jane",
         "last_name": "Doe",
         "role": "owner"
       }
     }
     ```
   * **HTTP Response Headers:** Sets two HttpOnly session cookies:
     * `Set-Cookie: auth-token=<access_jwt>; HttpOnly; Path=/; SameSite=None; Secure`
     * `Set-Cookie: refresh-token=<refresh_jwt>; HttpOnly; Path=/api/v1/auth/token/refresh/; SameSite=None; Secure`

2. **MFA-Gated Login (TOTP Enabled):**
   * **HTTP Status:** `200 OK`
   * **JSON Body Payload:**
     ```json
     {
       "mfa_required": true,
       "mfa_token": "eyJhbGciOi...",
       "detail": "Two-factor authentication code required."
     }
     ```
   * *Note:* No JWT or session cookies are issued until the client submits `{mfa_token, code}` to `/api/v1/auth/mfa/totp/login/`.

---

### 2. Token Cryptography, Key Storage & Claims Structure

* **Token Format:** Signed JSON Web Token (JWT) managed by `django-rest-framework-simplejwt` [VERIFIED `hvt/settings.py:121, 431-441`].
* **Signing Algorithm:** Symmetric `HS256` (HMAC with SHA-256) [VERIFIED decoded JWT header below].
* **Key Storage:** The HMAC signature is computed directly using Django's `settings.SECRET_KEY` [VERIFIED `hvt/settings.py:58-62`].
* **Public-Key (JWKS) Endpoint:** **DOES NOT EXIST.** Because `HS256` is a symmetric algorithm where verification requires the private signing key, there is no public key to publish. No `/.well-known/jwks.json` route exists in the URLconf [VERIFIED `hvt/urls.py:29-45`].
* **Lifetimes:**
  * Access Token: `15 minutes` (`timedelta(minutes=15)`) [VERIFIED `hvt/settings.py:435`].
  * Refresh Token: `7 days` (`timedelta(days=7)`) [VERIFIED `hvt/settings.py:436`].
* **Rotation & Blacklisting:**
  * `ROTATE_REFRESH_TOKENS = True` [VERIFIED `hvt/settings.py:437`]. Every call to `/token/refresh/` invalidates the old refresh token and issues a new one.
  * `BLACKLIST_AFTER_ROTATION = True` [VERIFIED `hvt/settings.py:438`]. Old refresh tokens are added to `token_blacklist_blacklistedtoken`.
  * **Stateless Access Token Caveat:** Access tokens are strictly stateless and cannot be revoked before their 15-minute expiration instant. There is no active session table or Redis revocation list checked during access token verification.

#### Decoded Real Login Token (Live Server Capture)

The following header and claims were decoded from a live login token issued during our verified audit session [RAN `scratch/run_cli_and_totp.py`]:

##### Decoded JWT Header [VERIFIED]
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

##### Decoded JWT Payload (Claims) [VERIFIED]
```json
{
  "token_type": "access",
  "exp": 1793892411,
  "iat": 1793891511,
  "jti": "ddcc8faa483e417aa1d5c8b4fc4798d8",
  "user_id": "b5540592-38fd-4d42-9538-c125716f31f4",
  "org_id": null,
  "org_slug": "",
  "project_id": null,
  "project_slug": "",
  "role": "member",
  "email": "to***@example.com",
  "app_roles": [],
  "app_permissions": []
}
```

#### Issuer (`iss`) & Audience (`aud`) Analysis
* **Status:** **UNBOUND.** Neither `iss` nor `aud` is stamped in `_stamp_org_claims` [VERIFIED `hvt/apps/authentication/tokens.py:19-37`].
* **Consequence:** Tokens are not cryptographically bound to a specific issuer URL or target audience. While HVT stamps custom `project_id` and `org_id` claims, any microservice verifying the token with `SECRET_KEY` cannot use standard OIDC/RFC-7519 validation rules to reject tokens intended for other applications.

---

### 3. Cookies vs. Bearer Tokens, CORS & CSRF Architecture

1. **Dual Transport Support:**
   * Both `HVTJWTCookieAuthentication` and `HVTJWTAuthentication` are enabled in `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]` [VERIFIED `hvt/settings.py:346-348`].
   * Browser SPAs can authenticate via `auth-token` cookies (credentialed requests) or by passing `Authorization: Bearer <token>`.
2. **CORS (Cross-Origin Resource Sharing):**
   * Configured via `django-cors-headers` middleware [VERIFIED `hvt/settings.py:143`].
   * In `DEBUG=True`: `CORS_ALLOW_ALL_ORIGINS = True` [VERIFIED `hvt/settings.py:209`].
   * In `DEBUG=False`: Origins must be explicitly listed in `CORS_ALLOWED_ORIGINS` [VERIFIED `hvt/settings.py:204-207`].
   * Allowed Headers: Includes standard headers plus `x-api-key` [VERIFIED `hvt/settings.py:214`].
   * Runtime Origin Preflight Signal: Connected via `check_request_enabled` to `_allow_localhost_runtime_cors`, dynamically granting CORS for localhost runtime endpoints during development [VERIFIED `hvt/settings.py:215-218`].
3. **CSRF Enforcement:**
   * `CsrfViewMiddleware` is enabled in `MIDDLEWARE` [VERIFIED `hvt/settings.py:148`].
   * DRF's JWT Bearer authentication bypasses CSRF checks because Bearer headers cannot be injected by malicious third-party cross-site forms.
   * Cookie-based authentication paths are protected by Django's `CSRF_TRUSTED_ORIGINS` setting [VERIFIED `hvt/settings.py:220-223`].

---

### 4. WebAuthn Passkeys: Relying Party (`rp_id`) & Origin Derivation

WebAuthn binds biometric credentials to an `rp_id` (domain) and `expected_origin` (full URL) to prevent phishing:

1. **RP ID Resolution (`_resolve_rp_id`) [VERIFIED `hvt/apps/authentication/passkey_views.py:37-64`]:**
   * Step 1: Checks `settings.WEBAUTHN_RP_ID`.
   * Step 2: If a `project` is present and has `frontend_url`, parses `urlparse(project.frontend_url).hostname`.
   * Step 3: Falls back to `request.headers.get("origin")` or `request.headers.get("referer")`.
   * Step 4: Falls back to `request.get_host()`.
2. **Expected Origin Resolution (`_resolve_expected_origin`) [VERIFIED `hvt/apps/authentication/passkey_views.py:66-100`]:**
   * Gathers permitted origins from `settings.FRONTEND_URL`, `settings.CORS_ALLOWED_ORIGINS`, and `project.frontend_url`.
   * Matches incoming `Origin` header against this set.

#### Can Passkeys Work on a Customer's Own Domain?

* **Single Domain Customer Apps (`app.customer.com`):** **YES.** If the customer configures `frontend_url = "https://app.customer.com"` in their HVT project settings, HVT sets `rp_id = "app.customer.com"` and accepts `expected_origin = "https://app.customer.com"`. Biometric passkeys created by the browser on `app.customer.com` will validate successfully.
* **Multi-Domain Customer Apps (`app.customer.com` + `admin.customer.com`):** **NO.** In `_resolve_expected_origin`, HVT checks `project.frontend_url` but **does not check `project.allowed_origins`** [VERIFIED `hvt/apps/authentication/passkey_views.py:78-80`]. Requests originating from secondary domains in `allowed_origins` are rejected during origin validation. Furthermore, WebAuthn specifications require `rp_id` to be a registrable suffix of the current page origin; HVT cannot dynamically negotiate different `rp_id` scopes across unrelated domains in a single project.

5. **Passwordless Magic Links: Token Consumption Atomicity [VERIFIED `hvt/apps/authentication/magic_link_views.py:125-140, 250-275`]:**
   * Tokens are 32-byte cryptographically random URL-safe strings hashed via SHA-256 before storage in `MagicLinkToken`.
   * Verification and consumption in `MagicLinkVerifyView` (control plane) and `RuntimeMagicLinkVerifyView` (runtime plane) are executed within `transaction.atomic()` using `MagicLinkToken.objects.select_for_update()`, guaranteeing atomic single-use redemption and preventing concurrent double-spend race conditions.

---

## WHAT WE DON'T KNOW

1. **Token Revocation in Distributed Clusters:** We do not know how token rotation behaves across multi-region database clusters where database write replication lag might allow a blacklisted refresh token to be reused within the replication window.
2. **Authenticator Backup Sync Tracking:** We cannot verify whether iOS iCloud Keychain or Google Password Manager credential syncing properly increments `sign_count`, as different platform authenticators handle passkey sync counters differently.

---

## WHAT WE DIDN'T ANTICIPATE

1. **Complete Lack of JWKS / Asymmetric Cryptography:** We did not anticipate that an authentication platform designed for multi-tenant microservices would rely exclusively on symmetric `HS256` signing, requiring customer backends to either make blocking HTTP roundtrips to HVT or share the root `SECRET_KEY`.
2. **Missing `iss` and `aud` Claims:** Despite the schema claiming OIDC compatibility, neither the access token nor the refresh token includes standard `iss` or `aud` claims, preventing standard token validation middleware in Go, Node.js, or Java from validating tokens off-the-shelf.
3. **Multi-Domain Passkey Origin Blindspot:** While `Project` includes an `allowed_origins` field specifically for CORS on multiple customer domains, the WebAuthn passkey origin resolver completely ignores it, creating an unexpected failure for multi-domain applications.
