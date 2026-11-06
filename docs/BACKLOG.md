# HVT Backlog & Architectural Decisions

This document tracks pending architectural decisions, technical debt remediations, and developer experience enhancements from **`fe2proposal.md` v1.2**, alongside deferred enterprise capabilities.

---

## 1. Architectural Decisions Needed (`fe2proposal.md` v1.2)

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

* **Enterprise SSO & Identity Federation:** SAML 2.0 (Okta, Azure AD / Entra ID, PingIdentity) and SCIM 2.0 automated employee directory synchronization.
* **Advanced Multi-Tenancy & Governance:** Tenant deletion lifecycles, soft-delete cascades, and dynamic role permissions matrices.
* **Custom Domains & Infrastructure Automation:** Automated Let's Encrypt / Cloudflare SSL certificate provisioning for vanity domains (`auth.customer.com`).
* **Monetization & Billing:** Stripe / LemonSqueezy subscription integration, MAU quotas, and metered API limits.
* **Security & Compliance Operations:** SIEM audit log streaming (AWS S3, Datadog, Splunk) and webhook replay simulators.
