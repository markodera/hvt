# HVT Backlog & Architectural Decisions

This document tracks pending architectural decisions, technical debt remediations, and developer experience enhancements from **`fe2proposal.md` v1.3**, alongside deferred enterprise capabilities.

---

## 1. Architectural Decisions Needed (`fe2proposal.md` v1.3)

* [ ] **Worker Choice:** Decide between a database outbox pattern with a lightweight worker management command (`python manage.py run_worker`) vs a traditional Celery + Redis worker cluster.
* [ ] **Signing Key Storage:** Decide whether asymmetric private signing keys are stored in environment variables, a Multi-Fernet encrypted database table, or an external cloud KMS (AWS KMS / HashiCorp Vault).
* [ ] **Signing Key Scope:** Decide between issuing per-project asymmetric key pairs (cryptographic tenant isolation) vs a global shared server key pair (operational simplicity).
* [ ] **Signing Key Algorithm:** Decide between RS256 (universal language and JWT library compatibility) vs EdDSA / Ed25519 (smaller token size and faster signature verification).
* [ ] **Signing Key Rotation:** Define the key ID (`kid`) header specification, overlapping key validity grace periods, and zero-downtime key rotation protocol.
* [ ] **Public JWKS URL Structure:** Decide whether to publish public keys at a central path (`/.well-known/jwks.json`) vs a project-partitioned path (`/api/v1/projects/<project_id>/.well-known/jwks.json`).
* [ ] **Redis Outage Policy:** Decide whether session revocation checks fail-open (allow valid unexpired JWTs during Redis downtime) vs fail-closed (reject authenticated requests if Redis is unreachable).
* [ ] **SDK Repository Home:** Decide whether `@hvt/node` and `hvt-py` verification helpers reside in the dedicated `hvt-sdk` repository, inside the core `hvt` repository as a monorepo, or in separate language-specific repositories.
* [ ] **Workspace Data Model:** Finalize the schema hierarchy for `Workspace` and `WorkspaceMembership` models, project-scoped slug uniqueness (`unique_together = ('project', 'slug')`), role inheritance, and the migration strategy for existing single-tenant runtime users.
* [ ] **MCP Authorization Architecture:** Audit the latest Model Context Protocol (MCP) specifications regarding client authentication and authorization before designing OAuth 2.1 Rich Authorization Requests (RAR) and token exchange endpoints.

---

## 2. Developer Experience & Schema Backlog

* [ ] **CLI Custom Schema File Option:** Add support for `--file` / `-f <path>` options in `@hvt/cli` commands (`schema plan`, `schema sync`, `schema validate`) instead of strictly requiring `hvt.schema.json` in the current working directory.
* [ ] **AI Context Linking in `llms.txt`:** Update `llms.txt` to explicitly reference and link to `/api/schema/` (the live OpenAPI 3.0 endpoint generated via `drf-spectacular`) so AI coding agents can discover and ingest API contracts automatically.

---

## 3. Deferred Enterprise & Out-of-Scope Items

This section captures features intentionally deferred or kept out of scope from the streamlined **Onboarding Journey Pass** (which is strictly bounded from **sign-up to first successful runtime login**):

* **Enterprise SSO & Identity Federation:**
  - SAML 2.0 (Okta, Azure AD / Entra ID, PingIdentity) identity provider connections.
  - SCIM 2.0 automated employee directory synchronization.
  - Custom domain enterprise identity broker endpoints.
* **Advanced Multi-Tenancy & Governance:**
  - Multi-organization switcher and tenant context selector.
  - Tenant deletion lifecycles, soft-delete cascades, and data purging.
  - Dynamic role permissions matrices and fine-grained ACL editors.
  - Team seat allocation, member invite policies, and expiration rules.
* **Custom Domains & Infrastructure Automation:**
  - Automated Let's Encrypt / Cloudflare SSL certificate provisioning for vanity domains (`auth.customer.com`).
  - Multi-region runtime data routing and geo-distributed read replicas.
* **Monetization & Billing:**
  - Stripe / LemonSqueezy subscription integration and invoice portal.
  - Usage-based billing (MAUs, active passkeys) and metered API rate limit tiers.
* **Security & Compliance Operations:**
  - External SIEM audit log streaming (AWS S3, Datadog, Splunk, Google Cloud Storage).
  - Automated cloud OAuth credential provisioning (auto-scraping or direct cloud API provisioning).
  - Webhook replay debugger and event delivery simulator.
