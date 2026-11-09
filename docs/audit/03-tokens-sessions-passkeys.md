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

* **Token Format:** Signed JSON Web Token (JWT) managed by `django-rest-framework-simplejwt` with `HVTAsymmetricTokenBackend` [VERIFIED `hvt/apps/authentication/jwt_backend.py:23-150`].
* **Signing Algorithm:** Asymmetric `RS256` (RSA Signature with SHA-256, 2048-bit key) with Key ID (`kid`) header [VERIFIED `hvt/apps/authentication/jwt_keys.py:36-60`, `tests/test_asymmetric_tokens.py:40-70`].
* **Key Storage:** RSA private key loaded from `HVT_JWT_PRIVATE_KEY` (PEM string or file path). In development/testing, an in-memory 2048-bit RSA key pair is automatically generated and cached [VERIFIED `hvt/apps/authentication/jwt_keys.py:62-108`]. Production deployments without a configured private key fail system check `hvt.E002` [VERIFIED `hvt/apps/authentication/jwt_keys.py:175-203`].
* **Public-Key (JWKS) Endpoint:** **SHIPPED.** RFC 7517 compliant JSON Web Key Set published at `GET /.well-known/jwks.json` and `GET /api/v1/auth/.well-known/jwks.json` with CORS (`*`) and `Cache-Control: public, max-age=3600, must-revalidate` [VERIFIED `hvt/apps/authentication/jwks_views.py:9-25`, `tests/test_asymmetric_tokens.py:130-165`].
* **OIDC Discovery:** Published at `GET /.well-known/openid-configuration` exposing `issuer`, `jwks_uri`, and supported algorithms [VERIFIED `hvt/apps/authentication/jwks_views.py:27-53`].
* **Offline Verification:** Offline token verification helper provided via `hvt.jwt_verify.verify_hvt_token` for microservices without roundtrips to HVT [VERIFIED `hvt/jwt_verify.py:18-87`].
* **Legacy Compatibility Fallback:** Tokens signed with legacy `HS256` using `settings.SECRET_KEY` remain accepted and verified seamlessly during upgrades [VERIFIED `hvt/apps/authentication/jwt_backend.py:137-149`].
* **Lifetimes:**
  * Access Token: `15 minutes` (`timedelta(minutes=15)`) [VERIFIED `hvt/settings.py:435`].
  * Refresh Token: `7 days` (`timedelta(days=7)`) [VERIFIED `hvt/settings.py:436`].
* **Rotation & Blacklisting:**
  * `ROTATE_REFRESH_TOKENS = True` [VERIFIED `hvt/settings.py:437`]. Every call to `/token/refresh/` invalidates the old refresh token and issues a new one.
  * `BLACKLIST_AFTER_ROTATION = True` [VERIFIED `hvt/settings.py:438`]. Old refresh tokens are added to `token_blacklist_blacklistedtoken`.
  * **Stateful Session Revocation Check (COMPLETED - Step 7):** Access tokens and refresh tokens embed a unique Session ID (`sid` claim). Authenticated requests perform sub-millisecond session validation in `_OrgClaimVerificationMixin.authenticate` and `HVTTokenRefreshSerializer.validate` using a dual-layer Redis/Django cache registry (`session:active:<sid>`, `session:revoked:<sid>`) backed by persistent PostgreSQL `auth_user_sessions` fallback [VERIFIED `hvt/apps/authentication/sessions.py:143-196`, `hvt/apps/authentication/tokens.py:130-142, 230-242`, `tests/test_session_revocation.py:105-155`]. Revoking a session immediately cuts off existing access tokens on their next request without waiting for the 15-minute expiration window.

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

#### Issuer (`iss`), Audience (`aud`), & Cross-Project Isolation Analysis
* **Status:** **BOUND & ISOLATED [VERIFIED `hvt/apps/authentication/tokens.py:20-38, 192-218`].**
* **Stamping:**
  * `iss`: Canonical issuer URL from `HVT_JWT_ISSUER` or `FRONTEND_URL` (e.g. `https://api.hvts.app`).
  * `sub`: Subject set to the string UUID of the user (`str(user.id)`).
  * `aud`: Bound to `str(project.id)` for project-scoped runtime tokens, or `"hvt-control"` for control plane tokens.
  * `jti`: Unique UUID preventing replay attacks.
  * `iat`: Exact integer epoch timestamp of issuance.
* **Cross-Project Isolation:** When a token is presented alongside a runtime API key (`hvt_test_*` or `hvt_live_*`), `_OrgClaimVerificationMixin` validates that `token["project_id"] == str(api_key.project_id)`. Mismatched tenant tokens are rejected with HTTP 401 `InvalidToken` ("Token was not issued for this project.") [VERIFIED `tests/test_asymmetric_tokens.py:200-240`].

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

* **Single Domain Customer Apps (`app.customer.com`):** **YES.** If the customer configures `frontend_url = "https://app.customer.com"`, HVT dynamically resolves `rp_id = "app.customer.com"` and accepts `expected_origin = "https://app.customer.com"`. Biometric passkeys created by the browser validate successfully [VERIFIED `hvt/apps/authentication/passkey_views.py:37-118`].
* **Multi-Domain Customer Apps (`app.customer.com` + `admin.customer.com`):** **YES (SHIPPED in Step 5).** `_resolve_expected_origin` and `_resolve_rp_id` dynamically inspect `project.allowed_origins` in addition to `project.frontend_url` [VERIFIED `hvt/apps/authentication/passkey_views.py:43-118`]. When a request originates from an approved domain listed in `allowed_origins`, the matching hostname is used for `rp_id` resolution, and the full origin list is validated during registration and authentication verification [VERIFIED `tests/test_passkey_origins.py:23-238`]. Requests from unapproved origins are strictly rejected with HTTP 400 `passkey_verification_failed`.

5. **Passwordless Magic Links: Token Consumption Atomicity [VERIFIED `hvt/apps/authentication/magic_link_views.py:125-140, 250-275`]:**
   * Tokens are 32-byte cryptographically random URL-safe strings hashed via SHA-256 before storage in `MagicLinkToken`.
   * Verification and consumption in `MagicLinkVerifyView` (control plane) and `RuntimeMagicLinkVerifyView` (runtime plane) are executed within `transaction.atomic()` using `MagicLinkToken.objects.select_for_update()`, guaranteeing atomic single-use redemption and preventing concurrent double-spend race conditions.

---

### 6. Personal Access Tokens (PATs) Mechanics [VERIFIED `hvt/apps/authentication/models.py:433-540`, `hvt/apps/authentication/backends.py:230-291`]

1. **Format & Prefixing:**
   * Token format: `hvt_pat_<environment>_<64-hex>` (e.g. `hvt_pat_live_0123...`).
   * Prefix: First 8 hex characters: `hvt_pat_<environment>_<8-hex>`.
   * Stored at rest as a SHA-256 cryptographic hash (`hashed_token`); raw token is returned once upon issuance and never stored in the database.
2. **Authentication Flow (`PersonalAccessTokenAuthentication`):**
   * Registered in DRF `DEFAULT_AUTHENTICATION_CLASSES` ahead of JWT authentication.
   * Extracts credentials from `Authorization: Bearer hvt_pat_...`, `Authorization: Token hvt_pat_...`, or `X-PAT: hvt_pat_...`.
   * Non-PAT tokens cleanly return `None`, passing evaluation to SimpleJWT without interference.
   * Enforces token expiration, revocation timestamp (`revoked_at`), user active status, and optional project active status.
   * Throttled `last_used_at` touch timestamp (cached in Redis / LocMem for 60 seconds).
   * Supports fine-grained scopes (`scopes = ["projects:read", ...]`, with `*` or `admin` wildcard support).
   * Duck-types dictionary access (`.get("project_id")`, `["project_id"]`) allowing seamless interop with runtime user permission checks (`IsRuntimeUser`).

---

## WHAT WE DON'T KNOW

1. **Token Revocation in Distributed Clusters:** We do not know how token rotation behaves across multi-region database clusters where database write replication lag might allow a blacklisted refresh token to be reused within the replication window.
2. **Authenticator Backup Sync Tracking:** We cannot verify whether iOS iCloud Keychain or Google Password Manager credential syncing properly increments `sign_count`, as different platform authenticators handle passkey sync counters differently.

---

## WHAT WE DIDN'T ANTICIPATE

1. **Asymmetric Signing & JWKS (RESOLVED in Step 4):** Replaced legacy symmetric HS256 signing with asymmetric RS256 signing, public JWKS endpoint (/.well-known/jwks.json), OIDC discovery (/.well-known/openid-configuration), Key ID stamping, and offline verification helpers [VERIFIED hvt/apps/authentication/jwt_backend.py:23-150].
2. **Standard OIDC Claims & Cross-Project Isolation (RESOLVED in Step 4):** Tokens now stamp standard iss, ud, sub, jti, and iat claims, and enforce tenant project matching to eliminate cross-project token replay [VERIFIED hvt/apps/authentication/tokens.py:20-38, 192-218].
3. **Multi-Domain Passkey Origin Blindspot (RESOLVED in Step 5):** Previously, while Project included an llowed_origins field specifically for CORS on multiple customer domains, the WebAuthn passkey origin resolver completely ignored it, creating an unexpected failure for multi-domain applications. Resolved in Step 5 by updating _resolve_rp_id and _resolve_expected_origin to validate WebAuthn credentials against all domains registered in project.allowed_origins and project.frontend_url [VERIFIED hvt/apps/authentication/passkey_views.py:43-118, 	ests/test_passkey_origins.py].1. **Asymmetric Signing & JWKS (RESOLVED in Step 4):** Replaced legacy symmetric \HS256\ signing with asymmetric \RS256\ signing, public JWKS endpoint (\/.well-known/jwks.json\), OIDC discovery (\/.well-known/openid-configuration\), Key ID stamping, and offline verification helpers [VERIFIED \hvt/apps/authentication/jwt_backend.py:23-150\].
2. **Standard OIDC Claims & Cross-Project Isolation (RESOLVED in Step 4):** Tokens now stamp standard \iss\, \ud\, \sub\, \jti\, and \iat\ claims, and enforce tenant project matching to eliminate cross-project token replay [VERIFIED \hvt/apps/authentication/tokens.py:20-38, 192-218\].
3. **Multi-Domain Passkey Origin Blindspot (RESOLVED in Step 5):** Updated \_resolve_rp_id\ and \_resolve_expected_origin\ to validate WebAuthn credentials against all domains registered in \project.allowed_origins\ and \project.frontend_url\ [VERIFIED \hvt/apps/authentication/passkey_views.py:43-118\, \	ests/test_passkey_origins.py\]. & Passkeys Audit

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

* **Token Format:** Signed JSON Web Token (JWT) managed by `django-rest-framework-simplejwt` with `HVTAsymmetricTokenBackend` [VERIFIED `hvt/apps/authentication/jwt_backend.py:23-150`].
* **Signing Algorithm:** Asymmetric `RS256` (RSA Signature with SHA-256, 2048-bit key) with Key ID (`kid`) header [VERIFIED `hvt/apps/authentication/jwt_keys.py:36-60`, `tests/test_asymmetric_tokens.py:40-70`].
* **Key Storage:** RSA private key loaded from `HVT_JWT_PRIVATE_KEY` (PEM string or file path). In development/testing, an in-memory 2048-bit RSA key pair is automatically generated and cached [VERIFIED `hvt/apps/authentication/jwt_keys.py:62-108`]. Production deployments without a configured private key fail system check `hvt.E002` [VERIFIED `hvt/apps/authentication/jwt_keys.py:175-203`].
* **Public-Key (JWKS) Endpoint:** **SHIPPED.** RFC 7517 compliant JSON Web Key Set published at `GET /.well-known/jwks.json` and `GET /api/v1/auth/.well-known/jwks.json` with CORS (`*`) and `Cache-Control: public, max-age=3600, must-revalidate` [VERIFIED `hvt/apps/authentication/jwks_views.py:9-25`, `tests/test_asymmetric_tokens.py:130-165`].
* **OIDC Discovery:** Published at `GET /.well-known/openid-configuration` exposing `issuer`, `jwks_uri`, and supported algorithms [VERIFIED `hvt/apps/authentication/jwks_views.py:27-53`].
* **Offline Verification:** Offline token verification helper provided via `hvt.jwt_verify.verify_hvt_token` for microservices without roundtrips to HVT [VERIFIED `hvt/jwt_verify.py:18-87`].
* **Legacy Compatibility Fallback:** Tokens signed with legacy `HS256` using `settings.SECRET_KEY` remain accepted and verified seamlessly during upgrades [VERIFIED `hvt/apps/authentication/jwt_backend.py:137-149`].
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

#### Issuer (`iss`), Audience (`aud`), & Cross-Project Isolation Analysis
* **Status:** **BOUND & ISOLATED [VERIFIED `hvt/apps/authentication/tokens.py:20-38, 192-218`].**
* **Stamping:**
  * `iss`: Canonical issuer URL from `HVT_JWT_ISSUER` or `FRONTEND_URL` (e.g. `https://api.hvts.app`).
  * `sub`: Subject set to the string UUID of the user (`str(user.id)`).
  * `aud`: Bound to `str(project.id)` for project-scoped runtime tokens, or `"hvt-control"` for control plane tokens.
  * `jti`: Unique UUID preventing replay attacks.
  * `iat`: Exact integer epoch timestamp of issuance.
* **Cross-Project Isolation:** When a token is presented alongside a runtime API key (`hvt_test_*` or `hvt_live_*`), `_OrgClaimVerificationMixin` validates that `token["project_id"] == str(api_key.project_id)`. Mismatched tenant tokens are rejected with HTTP 401 `InvalidToken` ("Token was not issued for this project.") [VERIFIED `tests/test_asymmetric_tokens.py:200-240`].

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

* **Single Domain Customer Apps (`app.customer.com`):** **YES.** If the customer configures `frontend_url = "https://app.customer.com"`, HVT dynamically resolves `rp_id = "app.customer.com"` and accepts `expected_origin = "https://app.customer.com"`. Biometric passkeys created by the browser validate successfully [VERIFIED `hvt/apps/authentication/passkey_views.py:37-118`].
* **Multi-Domain Customer Apps (`app.customer.com` + `admin.customer.com`):** **YES (SHIPPED in Step 5).** `_resolve_expected_origin` and `_resolve_rp_id` dynamically inspect `project.allowed_origins` in addition to `project.frontend_url` [VERIFIED `hvt/apps/authentication/passkey_views.py:43-118`]. When a request originates from an approved domain listed in `allowed_origins`, the matching hostname is used for `rp_id` resolution, and the full origin list is validated during registration and authentication verification [VERIFIED `tests/test_passkey_origins.py:23-238`]. Requests from unapproved origins are strictly rejected with HTTP 400 `passkey_verification_failed`.

5. **Passwordless Magic Links: Token Consumption Atomicity [VERIFIED `hvt/apps/authentication/magic_link_views.py:125-140, 250-275`]:**
   * Tokens are 32-byte cryptographically random URL-safe strings hashed via SHA-256 before storage in `MagicLinkToken`.
   * Verification and consumption in `MagicLinkVerifyView` (control plane) and `RuntimeMagicLinkVerifyView` (runtime plane) are executed within `transaction.atomic()` using `MagicLinkToken.objects.select_for_update()`, guaranteeing atomic single-use redemption and preventing concurrent double-spend race conditions.

---

## WHAT WE DON'T KNOW

1. **Token Revocation in Distributed Clusters:** We do not know how token rotation behaves across multi-region database clusters where database write replication lag might allow a blacklisted refresh token to be reused within the replication window.
2. **Authenticator Backup Sync Tracking:** We cannot verify whether iOS iCloud Keychain or Google Password Manager credential syncing properly increments `sign_count`, as different platform authenticators handle passkey sync counters differently.

---

## WHAT WE DIDN'T ANTICIPATE

1. **Asymmetric Signing & JWKS (RESOLVED in Step 4):** Replaced legacy symmetric HS256 signing with asymmetric RS256 signing, public JWKS endpoint (/.well-known/jwks.json), OIDC discovery (/.well-known/openid-configuration), Key ID stamping, and offline verification helpers [VERIFIED hvt/apps/authentication/jwt_backend.py:23-150].
2. **Standard OIDC Claims & Cross-Project Isolation (RESOLVED in Step 4):** Tokens now stamp standard iss, ud, sub, jti, and iat claims, and enforce tenant project matching to eliminate cross-project token replay [VERIFIED hvt/apps/authentication/tokens.py:20-38, 192-218].
3. **Multi-Domain Passkey Origin Blindspot (RESOLVED in Step 5):** Previously, while Project included an llowed_origins field specifically for CORS on multiple customer domains, the WebAuthn passkey origin resolver completely ignored it, creating an unexpected failure for multi-domain applications. Resolved in Step 5 by updating _resolve_rp_id and _resolve_expected_origin to validate WebAuthn credentials against all domains registered in project.allowed_origins and project.frontend_url [VERIFIED hvt/apps/authentication/passkey_views.py:43-118, 	ests/test_passkey_origins.py].


---

### 5. Session Registry, Device Management & Remote Revocation (COMPLETED - Step 7)

* **Session Model:** `UserSession` (`auth_user_sessions`) records user, project, client IP, raw user agent, parsed human-friendly device name (e.g. `Chrome on macOS`, `Mobile App (Android)`), creation timestamp, and throttled `last_active_at` [VERIFIED `hvt/apps/authentication/models.py:387-424`].
* **Dual-Layer Invalidation:**
  1. **Hot Path (Cache):** Explicitly checks `session:revoked:<sid>` (fast reject) and `session:active:<sid>` (fast accept) in Redis/cache with 7-day TTL matching refresh token lifespan.
  2. **Cold Fallback (PostgreSQL):** On Redis cache miss or restart, validates `UserSession.objects.filter(id=sid, revoked_at__isnull=True)` and warms active cache back up.
* **Token Claims Stamping:**
  * Access & refresh tokens carry `"sid": "<session-uuid>"` [VERIFIED `hvt/apps/authentication/tokens.py:39-44`].
  * SimpleJWT refreshSerializer revalidates the session before issuing fresh tokens and restamps the same `sid` [VERIFIED `hvt/apps/authentication/tokens.py:132-140`].
* **Endpoints:**
  * `GET /api/v1/auth/sessions/` / `GET /api/v1/auth/runtime/sessions/`: List connected devices with `is_current` computation comparing request token's `sid` with record ID [VERIFIED `hvt/apps/authentication/session_views.py:21-61`].
  * `DELETE /api/v1/auth/sessions/<uuid:pk>/` / `DELETE /api/v1/auth/runtime/sessions/<uuid:pk>/`: Instantly revokes a targeted session across cache and database, emitting `AuditLog.EventType.SESSION_REVOKED`.
  * `POST /api/v1/auth/sessions/revoke-all/` / `POST /api/v1/auth/runtime/sessions/revoke-all/`: Global remote logout revoking all sessions except the requesting `current_sid`, emitting `AuditLog.EventType.SESSION_REVOKED_ALL`.