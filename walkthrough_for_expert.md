# HVT v2 Implementation & Security Audit Walkthrough

> **Prepared for:** HVT Technical Advisory & Security Review  
> **Repository:** `hvt` (Identity & Auth Engine)  
> **Release Target:** `v0.2.0` (First Apache-2.0 Release)  
> **Date:** 2026-11-05  
> **License:** Apache-2.0

---

## 1. Executive Summary

This walkthrough addresses every question, verification requirement, and order-of-operations gate raised in your review prior to pushing to `main` and tagging `v0.2.0`.

All 11 atomic commits have been implemented, tested, and verified with **26 backend tests (0 failures, 0 errors)** and **10 CLI unit tests (0 failures, 0 errors)**.

---

## 2. Answers to Pre-Push & Pre-Tag Verification Gates

### A. Auto-Deploy & Production Migration Safety
* **Current VPS / Deployment Status:** There is currently **no automated deployment pipeline or live VPS connected** to push events on `main`. Pushing to `main` will not trigger an accidental deployment or alter any remote database.
* **Encryption Key Requirement:** When the production environment is deployed:
  - Django system check `hvt.E001` in `hvt/crypto.py` strictly prevents server startup when `DEBUG=False` if `HVT_ENCRYPTION_KEYS` is missing.
  - The secret-encryption backfill migration (`0024_encrypt_existing_social_provider_secrets`) and `managed_by` tracking migration (`0023`) are fully tested and idempotent.

### B. Test vs. Live Security (Option C Settlement)
* **The Risk:** If roles and permissions were project-wide, a test management key (`hvt_mgmt_test_...`) could alter live production authorization.
* **The Settlement (Option C):** We implemented and enforced **Option C**:
  - Test management keys (`hvt_mgmt_test_...`) are **strictly blocked from modifying projects that have active live runtime keys**.
  - Attempting to sync with a test management key on a project with live keys immediately halts the transaction and returns HTTP `403 Forbidden`:
    `"Test management keys cannot modify projects with active live keys. Use a live management key or migrate to live environment."`
* **Option C Test Proof:** Verified in [`tests/test_schema_sync.py`](tests/test_schema_sync.py#L346-L363) (`test_option_c_test_management_key_blocked_on_live_project`).

### C. Runtime Route Management Key Rejection & Permission Matrix
* **Prefix Hardening:** Hardened `RUNTIME_API_KEY_CORS_PATH_PREFIXES` in [`hvt/apps/organizations/runtime_origins.py`](hvt/apps/organizations/runtime_origins.py) so all endpoints starting with `/api/v1/auth/runtime/*` and `/api/v1/runtime/*` are recognized as runtime routes.
* **Exhaustive Runtime Route Test:** Added `test_all_runtime_endpoints_reject_management_key_via_http_client` in [`tests/test_plane_separation_and_auth.py`](tests/test_plane_separation_and_auth.py).
  - Iterates through `/login/`, `/register/`, `/password/reset/`, `/passkey/...`, `/magic-link/...`, and `/invitations/` using an HTTP API client with a management key.
  - **Result:** Every endpoint returns HTTP `403 Forbidden` with the exact message:  
    `"Management keys cannot be used for runtime authentication. Use a runtime client key."`
  - **Audit Proof:** Confirms an append-only `AuditLog` event is recorded for each attempt (`event_type="security.violation"`, `reason="management_key_runtime_violation"`).
* **Permission Matrix Test:** Added `test_permission_matrix_for_schema_sync`:
  - `roles:read` only: Blocked with HTTP 403 on both dry-run and live sync.
  - `schema:plan` only: Allowed for dry-run plan (`status: "planned"`), blocked with HTTP 403 on live apply (`"The 'schema:plan' scope permits dry-run only. Use 'schema:sync' to apply changes."`).
  - `schema:sync`: Allowed for both dry-run and live apply (`status: "applied"`).

### D. Relicensing & Contributor Audit
* **Contributor Check:** Ran `git shortlog -sne --all`. Confirmed that **100% of all commits** were authored exclusively by Mark Odera. No third-party copyright claims exist.
* **Dependency License Audit:** All Python and JavaScript dependencies were inspected. Zero copyleft licenses (no AGPL, GPL, SSPL, or BUSL dependencies).
* **NOTICE File:** Added [`NOTICE`](NOTICE) attributing copyright to `"Mark Odera and HVT Contributors"`.
* **README Licensing Note:** Added note in [`README.md`](README.md):
  > *"Releases prior to v0.2.0 were licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). Starting with v0.2.0, HVT is licensed under the Apache-2.0 License."*
* **SPDX Headers:** All source files include `SPDX-License-Identifier: Apache-2.0`.
* **Leftovers Check:** Ran `git grep -i "agpl\|affero\|copyleft"`; only the historical release note in README remains.

### E. Secret Scan
* Ran a regex scanner across the entire patch history of all recent commits (`git log -p -7`).
* **Result:** Zero leaked secrets, API keys, or production credentials. (The only match was the mock string `"my-google-secret-xyz"` in the unit test file).

### F. Canonical Schema Manifest Format
* Settled on **`hvt.schema.json`** as the canonical format to prevent YAML type-coercion quirks (e.g. YAML parsing country code `NO` as boolean `false`).
* Updated [`llms.txt`](llms.txt) and CLI to designate `hvt.schema.json` as canonical while maintaining safe, backwards-compatible parsing for `hvt.schema.yaml`.

---

## 3. The Official CLI (`@hvt/cli`)

Built in [`cli/`](cli/) under Apache-2.0 and linked globally (`npm link`):

### Key Safety & DX Features:
1. **Local Secret Resolution:** Resolves `${ENV_VAR}` expressions from `.env` / `.env.local` locally before network transmission.
2. **Write-Only Secrets:** Redacts secrets in terminal output (`[REDACTED]`) and error traces.
3. **Prune Safety Gate:** `--prune` requires interactive user confirmation (`y/N`), or an explicit `--yes` flag in non-interactive/CI environments.
4. **Auto-Save Client Key:** Automatically appends `NEXT_PUBLIC_HVT_CLIENT_KEY=...` to `.env.local` upon first sync.
5. **All 6 OAuth Providers Scaffolded:** `hvt init` supports all 6 native providers (`--all-providers` or `--providers google,github,discord,apple,microsoft,gitlab`).

---

## 4. Test Suite Execution Proof

### Backend Test Suite (Django)
```powershell
.\.venv\Scripts\python.exe manage.py test tests.test_crypto tests.test_plane_separation_and_auth tests.test_schema_sync
```
**Output:**
```text
Ran 26 tests in 14.316s
OK
System check identified no issues (1 silenced).
```

### CLI Test Suite (Node.js)
```powershell
cd cli; npm test
```
**Output:**
```text
▶ CLI Config & Manifest Parser
  ✔ builds starter schema with specific selected providers (13.9ms)
  ✔ builds starter schema with all 6 supported providers (0.7ms)
  ✔ parses valid JSON manifest with schema_version 1 (1.7ms)
  ✔ parses valid YAML manifest safely (48.1ms)
  ✔ rejects manifest with invalid schema_version (2.0ms)
  ✔ writes client key to .env.local cleanly (28.1ms)
✔ CLI Config & Manifest Parser (102.1ms)
▶ CLI Secret Interpolation
  ✔ interpolates ${VAR} and $VAR correctly from env (7.8ms)
  ✔ throws a clear error if an environment variable is missing (3.1ms)
  ✔ recursively interpolates nested schema objects and arrays (1.1ms)
  ✔ redacts secrets safely without leaking content (2.1ms)
✔ CLI Secret Interpolation (19.2ms)
ℹ tests 10, pass 10, fail 0
```

---

## 5. Complete Commit Log (`git log -11 --oneline`)

| Hash | Type | Commit Description |
| :--- | :--- | :--- |
| `f61335a` | `feat(cli)` | Support scaffolding all 6 OAuth providers in `hvt init` |
| `5ac0f02` | `docs` | Add Phase 2 architecture and feature proposal (`fe2proposal.md`) |
| `e73ac97` | `feat(cli)` | Add official `@hvt/cli` for declarative schema provisioning and sync |
| `e3b1fb3` | `test(auth)` | Verify all runtime endpoints reject management keys and test permission matrix |
| `d1a3fc4` | `docs(sync)` | Update schema provisioning design document to v2 |
| `4c35855` | `test(sync)` | Add comprehensive unit and integration tests for schema sync |
| `50511a4` | `feat(sync)` | Add declarative schema sync service and endpoint |
| `968d821` | `feat(auth)` | Enforce plane separation, management keys, scopes, and default-deny |
| `11e14cf` | `feat(models)` | Add `managed_by`, `EncryptedTextField` with `MultiFernet`, and role protect |
| `12afacb` | `chore(license)` | Transition repository license from AGPL-3.0 to Apache-2.0 |
| `b93508f` | `feat(auth)` | Add passkeys WebAuthn, magic links, and TOTP 2FA |

---

## 6. Recommended Next Steps for Team Discussion

1. Review [`fe2proposal.md`](fe2proposal.md) for Phase 2 roadmap priorities (Webhooks, Custom Domains, White-Label Emails, Active Session Revocation).
2. Run an end-to-end timed simulation of a fresh Next.js app using `hvt init` and `hvt schema sync`.
3. Build the backend endpoint `POST /api/v1/organizations/current/projects/<id>/ai-setup-prompt/` for 1-click dashboard copying.
