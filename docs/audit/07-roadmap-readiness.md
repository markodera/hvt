# 07. Roadmap Readiness & Architectural Gap Analysis

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0`  
**Date Audited:** `2026-11-05`  
**Auditor:** Automated Ground-Truth Technical Suite

---

### Jargon & Concept Definitions

*   **JSON Web Key Set (JWKS):** A standardized format (RFC 7517) for publishing cryptographic public keys at a well-known URL (`/.well-known/jwks.json`), enabling external services to verify JWT signatures locally without sharing secret keys or making database calls.
*   **System for Cross-domain Identity Management (SCIM):** An open standard protocol (RFC 7644) that allows corporate identity providers (like Okta, Azure AD) to automatically create, update, and deactivate employee user accounts in downstream SaaS applications.
*   **Security Assertion Markup Language (SAML 2.0):** An XML-based federated authentication framework used by enterprise IT departments for single sign-on (SSO).
*   **Personal Access Token (PAT):** A long-lived, scoped API credential minted by an individual end-user to authenticate automated scripts or CLI tools against their own account.
*   **End-User Workspaces (Nested Multi-Tenancy):** A software architecture where end-users of a customer's application can create, join, and switch between multiple organizational workspaces (e.g., Slack teams, GitHub organizations, Linear workspaces) under a single identity.

---

## WHAT WE KNOW (verified)

### 1. Roadmap Feature Evaluation

We analyzed HVT's current codebase to determine the reusable foundation, necessary refactoring, security/operational risks, and estimated level of effort (**S:** < 1 week, **M:** 1–3 weeks, **L:** 4+ weeks) for 11 critical roadmap initiatives.

| Feature Initiative | Reusable Existing Code |
| **0. Immediate Hardening & Security (COMPLETED - Step 2)** | SSRF defense (`ssrf.py`), verified social login requirement across 6 providers, TOTP backup codes (`TOTPBackupCode`), SHA-256 hashed invitations at rest, anti-enumeration. | Deployed in Step 2. | Zero regressions across all 480 tests. | **DONE** |
 Required Changes | Key Risks & Complexities | Effort |
| :--- | :--- | :--- | :--- | :---: |
| **1. Token Groundwork & JWKS (COMPLETED - Step 4)** | Asymmetric RS256 tokens, deterministic Key ID, public JWKS (`/.well-known/jwks.json`), OIDC discovery (`/.well-known/openid-configuration`), cross-project isolation, offline verifier helper (`hvt.jwt_verify`). | Deployed in Step 4. | Backward compatibility maintained via automatic fallback decode. | **DONE** |
| **2. Copy AI Setup Prompt** | `llms.txt`, OpenAPI 3.0 schema generation (`drf-spectacular`), CLI configuration commands. | Add CLI command (`hvt ai setup-prompt`) or API endpoint that formats dynamic system prompts with active project ID, keys, and schema specs. | Minimal technical risk. | **S** |
| **3. Rate Limiting & Bot Defense** | DRF throttle framework (`throttles.py`), `BurstRateThrottle`, IP/email throttles. | Enforce production Redis (`USE_REDIS_CACHE=True`); integrate Cloudflare Turnstile or reCAPTCHA v3 challenge endpoints on registration/login; implement token bucket. | False positives blocking legitimate corporate NAT/VPN users. | **M** |
| **4. Session Management & Revocation (COMPLETED - Step 7)** | `UserSession` model, dual-layer Redis cache + DB session engine (`sessions.py`), `sid` claim in JWT access/refresh tokens, list/single/bulk revocation endpoints. | Deployed in Step 7. | Zero regressions across all 489 tests. Sub-millisecond cache checks with resilient Postgres fallback. | **DONE** |
| **5. Bring-Your-Own Email (COMPLETED - Step 6)** | Pluggable `EmailProvider` interface (`Resend`, `SMTP`, `Postmark`, `SES`, `Console`), per-project `ProjectEmailConfig` with MultiFernet encryption, test-send API, async dispatch. | Deployed in Step 6. | Zero timeout risk via background Outbox queuing. | **DONE** |
| **6. Webhook Hardening & Async Delivery (COMPLETED - Step 6)** | Transactional Outbox engine (`OutboxTask`), HMAC-SHA256 request signatures (`X-HVT-Signature`), automated exponential backoff retries, auto-disable on 10 failures, `run_worker` management command. | Deployed in Step 6. | Zero container overhead via Postgres/Django outbox queue. | **DONE** |
| **7. End-User Workspaces & Roles** | `Role`, `Permission`, `ProjectInvitation` models, tenant isolation logic. | Create `Workspace` model inside `Project`; build `WorkspaceMembership` and `WorkspaceRole`; update runtime JWTs to encode active workspace ID; add workspace switching endpoints. | High schema complexity; breaking changes to runtime token format; migration of existing single-tenant projects. | **L** |
| **8. Personal Access Tokens (PATs)** | `APIKey` hashing, verification logic, and prefix parsing. | Create `PersonalAccessToken` model bound to runtime users; build token generation and revocation views; add scope validation middleware. | End-user token leakage; requires fine-grained permission evaluation. | **S** |
| **9. Agent Tokens (AI Agents)** | `APIKey` infrastructure, granular permission scoping. | Create `AgentToken` model with strict TTLs, maximum action budgets, parent user binding, and audit trail annotations. | Rogue AI agents exhausting customer API budgets. | **S / M** |
| **10. Custom Branded Domains** | Runtime CORS origin resolution, WebAuthn RP ID resolution. | Add `CustomDomain` model; automate TLS certificate generation via Caddy or Cloudflare for Platforms; implement host header routing middleware. | DNS verification delays; SSL certificate renewal failures; WebAuthn domain-binding restrictions. | **L** |
| **11. Enterprise SSO & SCIM** | `CustomSocialAccountAdapter`, OAuth flow integration. | Integrate SAML 2.0 service provider (e.g. `pysaml2`); implement SCIM 2.0 endpoints (`/scim/v2/Users`, `/scim/v2/Groups`); add tenant SSO configuration models. | SAML XML signature vulnerabilities; IdP directory sync conflicts. | **L** |

---

### 2. Application Architecture Gap Matrix

We evaluated whether HVT in its current state (`v0.2.0-prep`) can support three representative SaaS application archetypes without architectural workarounds:

| Application Archetype | Feasibility Today | Architectural Analysis & Unmet Requirements | Critical Blockers |
| :--- | :---: | :--- | :--- |
| **(A) Invoicing SaaS** (Users, Invoices, Clients, Payments) | **PARTIAL** | Can handle individual user auth and basic team collaboration if the entire company is represented as a single HVT `Project`. However, customers cannot self-manage team workspaces without calling administrative APIs. | 1. (RESOLVED in Step 6) Webhooks dispatched asynchronously via Transactional Outbox.<br>2. (RESOLVED in Step 4) Asymmetric RS256 + public JWKS allow offline token verification. |
| **(B) Multi-Role Marketplace** (Buyers, Sellers, Admins) | **PARTIAL** | Custom `Role` and `Permission` models support distinct permission sets. However, marketplace users often operate as both a buyer and a seller under a single login. | 1. Account-linking vulnerability allows email-matching takeovers across buyer/seller profiles.<br>2. No native support for multi-profile switching under a single identity. |
| **(C) Multi-Company Workspace Platform** (Slack/Notion clone where 1 user belongs to N companies) | **UNSUPPORTED / BLOCKED** | **Completely blocked by the data model.** In HVT, a runtime `User` exists in a 1:1 relationship with a single `Project`. There is no intermediate `Workspace` or `Tenant` abstraction allowing an end-user to be a member of 10 different companies with different roles in each. | 1. Missing `Workspace` and `WorkspaceMembership` models.<br>2. Runtime JWT claims do not encode workspace scope.<br>3. No runtime endpoints exist for workspace creation, invitation, or switching. |

---

## WHAT WE DON'T KNOW (could not verify, and why)

1.  **Enterprise SCIM Scale Thresholds:** We could not verify how HVT's database indexes would perform under a bulk SCIM directory sync of 50,000 corporate employees in a single batch [UNKNOWN].
2.  **KMS Signing Latency for Asymmetric Keys:** Because HVT currently uses symmetric in-memory HS256 signing, we could not measure the latency impact of offloading token signing to AWS KMS or HashiCorp Vault [UNKNOWN].

---

## WHAT WE DIDN'T ANTICIPATE (surprises, contradictions with docs, unasked risks)

### 1. The Multi-Company Workspace Blindspot
Modern B2B SaaS applications almost universally require nested multi-tenancy: an application (`Project`) contains multiple customer companies (`Workspaces`), and end-users (`Users`) belong to multiple companies. HVT's data model stops at `Project`, meaning developers building B2B SaaS must implement their own entire workspace and membership system on top of HVT.

### 2. Lack of Asymmetric Public Key Infrastructure (JWKS) (RESOLVED in Step 4)
Resolved in Step 4 by implementing asymmetric RS256 token signing, Key ID stamping, a public JWKS endpoint (`/.well-known/jwks.json`), OIDC discovery (`/.well-known/openid-configuration`), cross-project isolation, and offline token verification helpers [VERIFIED `hvt/apps/authentication/jwt_backend.py:23-150`, `hvt/jwt_verify.py:18-87`].

### 3. The Celery Absence Reality (RESOLVED in Step 6)
Documentation and design proposals previously referred to asynchronous background operations that did not exist. In Step 6, this was resolved by deploying a zero-dependency Transactional Outbox engine (`OutboxTask`), asynchronous webhook dispatch with HMAC signatures and exponential backoff, pluggable Bring-Your-Own Email (`ProjectEmailConfig`), and the `python manage.py run_worker` / `process_outbox` daemon [VERIFIED `hvt/apps/organizations/tasks.py:30-244`, `hvt/apps/organizations/management/commands/run_worker.py:23-103`].
