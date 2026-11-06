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

| Feature Initiative | Reusable Existing Code | Required Changes | Key Risks & Complexities | Effort |
| :--- | :--- | :--- | :--- | :---: |
| **1. Token Groundwork & JWKS** | SimpleJWT integration, token claims structure (`hvt/apps/authentication/views.py`), blacklist tables. | Migrate signing from symmetric HS256 to asymmetric RS256/EdDSA; deploy public JWKS endpoint (`/.well-known/jwks.json`); stamp `iss` and `aud`; publish verification SDKs. | Key rotation ceremony complexity; breaking existing clients expecting HS256 tokens. | **M** |
| **2. Copy AI Setup Prompt** | `llms.txt`, OpenAPI 3.0 schema generation (`drf-spectacular`), CLI configuration commands. | Add CLI command (`hvt ai setup-prompt`) or API endpoint that formats dynamic system prompts with active project ID, keys, and schema specs. | Minimal technical risk. | **S** |
| **3. Rate Limiting & Bot Defense** | DRF throttle framework (`throttles.py`), `BurstRateThrottle`, IP/email throttles. | Enforce production Redis (`USE_REDIS_CACHE=True`); integrate Cloudflare Turnstile or reCAPTCHA v3 challenge endpoints on registration/login; implement token bucket. | False positives blocking legitimate corporate NAT/VPN users. | **M** |
| **4. Session Management & Revocation** | SimpleJWT token blacklist (`OutstandingToken`, `BlacklistedToken`), cookie handling. | Add unique Session ID (`sid`) to access/refresh JWTs; build Redis active session registry (`user:{id}:sessions`); add list/revoke endpoints; add sub-millisecond `sid` cache check to auth middleware. | Redis dependency in hot authentication path; cache failure fallback strategy. | **M** |
| **5. Bring-Your-Own Email (BYO)** | Email templates, verification/reset views (`views.py`). | Decouple hardcoded `ResendClient`; create `EmailProvider` interface (SMTP, SendGrid, Postmark, AWS SES); create `ProjectEmailSettings` model (encrypted credentials); wrap user signup in atomic transaction. | Customer SMTP credentials causing timeouts; deliverability degradation if customer DNS is misconfigured. | **M** |
| **6. Webhook Hardening & Async Delivery** | `WebhookEndpoint`, `WebhookDelivery` models, payload schemas. | **CRITICAL:** Fix SSRF by blocking private IP ranges (`127.0.0.1`, `169.254.169.254`, RFC 1918); decouple delivery to asynchronous Celery/worker queue; add exponential backoff retries and HMAC-SHA256 signing headers. | Operational overhead of running distributed worker queues (Celery/Redis). | **M** |
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
| **(A) Invoicing SaaS** (Users, Invoices, Clients, Payments) | **PARTIAL** | Can handle individual user auth and basic team collaboration if the entire company is represented as a single HVT `Project`. However, customers cannot self-manage team workspaces without calling administrative APIs. | 1. Synchronous webhooks block API threads on slow billing webhooks.<br>2. Symmetric HS256 tokens prevent third-party payment microservices from validating tokens offline. |
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

### 2. Lack of Asymmetric Public Key Infrastructure (JWKS)
Every modern identity platform (Auth0, Clerk, Supabase, Firebase) publishes a JWKS endpoint so customer microservices and edge workers can independently verify user tokens. HVT's reliance on symmetric HS256 requires customer backend services to possess the server's master `SECRET_KEY`, creating severe architectural coupling and key exposure risks.

### 3. The Celery Absence Reality
Documentation and design proposals refer to asynchronous background operations. In verified reality, **no asynchronous task worker exists**. Every email dispatch, webhook notification, and audit log write runs directly on the synchronous HTTP request thread, creating extreme fragility under production traffic spikes.
