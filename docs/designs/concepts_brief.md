# Asymmetric JWT Token Issuance, Public JWKS, and Test-Mode Auto-Activation

* **Author:** Engineering Architecture Team / EGM Synthesizer
* **Date:** 2026-11-07
* **Status:** Synthesized Concept Brief (Step 2 Complete)

## Overview

HVT currently signs runtime JSON Web Tokens (JWTs) using a symmetric shared secret (`HS256` via Django's `SECRET_KEY`). This topology forces every downstream microservice or client to query HVT over HTTP (`GET /api/v1/auth/runtime/me/`) to validate a user session, capping throughput at approximately 500 requests per second under load.

This design introduces asymmetric key signing (`RS256`), a public JSON Web Key Set endpoint (`/.well-known/jwks.json`), and database-driven test-mode email auto-activation. These changes allow microservices and edge runtimes (Next.js middleware, Cloudflare Workers) to verify tokens locally with sub-millisecond cryptographic checks while removing SMTP delivery dependencies during automated testing.

## Analysis

### 1. Algorithm Selection: RS256 vs. Ed25519 (EdDSA)
- **RS256 (RSA 2048-bit):** Universal compatibility across standard runtime runtimes, browser WebCrypto APIs, edge workers, and authentication libraries (`jose`, `pyjwt`, `jsonwebtoken`) without requiring native cryptographic extensions.
- **Ed25519 (EdDSA):** More compact signatures and faster computation, but lacks universal support in older edge runtime environments.
- **Resolution:** Standardize on **RS256** as the default algorithm for Phase 1. Structure the JWKS schema to support dual-publishing of Ed25519 keys in future phases.

### 2. Revocation vs. Performance Invariant
- **Offline Trade-off:** When microservices verify signatures locally via public keys, immediate token revocation cannot be checked against HVT's database on each request.
- **Mitigation:** Enforce a strict access token lifetime bounded to **5 to 15 minutes** (`ACCESS_TOKEN_LIFETIME = 15m`). Revocations and privilege changes take effect upon token expiration. Real-time control plane actions (user ban, role revocation) operate on rotating refresh tokens through `token_blacklist`.

### 3. Key Rotation & Edge Cache Safety
- Edge runtimes cache public keys to avoid hammering the JWKS endpoint. If HVT rotates its private signing key without notice, cached edge services will reject newly signed tokens (`unknown kid`).
- **Mitigation:** Multi-key JWKS publishing. HVT will publish both active and retired public keys in `/.well-known/jwks.json` for a grace period (minimum 2 hours: `cache_max_age + access_token_lifetime`) before retiring an old key.
- The JWKS endpoint must emit `Cache-Control: public, max-age=3600, stale-while-revalidate=86400`.

### 4. Security Hardening
- **Algorithm Confusion Attack:** Strictly pin `algorithms=["RS256"]` in token decoding logic to prevent attackers from submitting tokens signed with the RSA public key using HMAC.
- **JWKS URL Injection:** Reject `jku` (JWK Set URL) headers in incoming tokens. Clients must only resolve keys from the trusted, configured HVT issuer URL.
- **Test-Mode Scope Gating:** Email auto-activation must be derived exclusively from verified server-side database records (`project.environment == Project.Environment.TEST` and test-scoped API keys). Client-supplied request parameters (such as `?test=true`) must never trigger auto-activation.

### 5. Test-Mode Auto-Activation Mechanics
- When `project.environment == "test"`, registration will immediately mark the email address verified (`EmailAddress(verified=True, primary=True)`), issue runtime tokens, and omit outbound email dispatch via Resend/SMTP.
- The API response payload will return `{"email_verified": true, "test_mode": true}` to make the sandbox behavior explicit to developers and integration test runners.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  - Expose `GET /.well-known/jwks.json` and `GET /.well-known/openid-configuration` with valid RSA public keys and key identifiers (`kid`).
  - Sign runtime access tokens with RS256 by default.
  - Support dual-acceptance of legacy HS256 and new RS256 tokens during rollout to eliminate customer downtime.
  - Implement test-mode email auto-activation for `environment: "test"` runtime signups.
  - Provide an official token verification utility in `@hvt/sdk` using standard public key resolution.
* **Out-of-Scope Non-Goals:**
  - Real-time instant revocation for sub-15-minute access tokens without an external revocation check.
  - Replacing Django session cookies or dashboard control-plane authentication.
  - Shipping full framework adapters (`@hvt/next`) in this specific cycle; adapters will be built as downstream consumers once the JWKS contract is stable.

## Key Decisions & Staging for Next Steps

1. **Step 1:** Add test-mode email auto-activation to `RuntimeRegisterSerializer` and `HVTRuntimeRegisterView` to unblock CI/CD test flows without SMTP credentials.
2. **Step 2:** Harden `hvt/apps/authentication/jwt_keys.py` and `jwks_views.py` with multi-key retention support and strict HTTP caching headers.
3. **Step 3:** Switch `HVTTokenObtainPairSerializer` to issue RS256 access tokens with `sub`, `iss`, `aud`, `kid`, and capability claims.
4. **Step 4:** Update `@hvt/sdk` with a local `verifyToken(jwt)` function backed by RemoteJWKSet caching via `jose`.
