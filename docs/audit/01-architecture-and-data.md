# 01: Architecture, Multi-Tenancy & Data Model Audit

**Commit Audited:** `1c05dcff9e9b9f723adfbce6ed02ed74d6358bb0` [VERIFIED git rev-parse HEAD]  
**Branch:** `release/v0.2.0-prep` [VERIFIED git status]  
**Date Audited:** November 5, 2026 [VERIFIED git log -1]  

---

### Terminology Primer
* **Composite Constraint:** A database constraint spanning two or more columns simultaneously (e.g. `(email, project_id)`) to enforce uniqueness within a specific scope while allowing duplicate values across different scopes.
* **Partial Index / Conditional Unique Constraint:** A database index or unique constraint that only applies to rows satisfying a specific SQL `WHERE` clause (e.g. uniqueness on `email` only where `project_id IS NULL`).
* **Foreign Key `on_delete` Rules:**
  * `CASCADE`: Deleting the parent object automatically deletes all referencing child records.
  * `PROTECT`: Prevents deletion of the parent if any referencing child records exist (raises `ProtectedError`).
  * `SET_NULL`: Sets the referencing foreign key column to `NULL` when the parent is deleted.

---

## WHAT WE KNOW

### 1. Repository Layout & Software Versions

* **Python Version:** Python `3.12.8` [VERIFIED `.\.venv\Scripts\python --version`]
* **Django Version:** Django `5.2.9` [VERIFIED `pip list`]
* **REST Framework:** `djangorestframework` `3.17.1`, `djangorestframework_simplejwt` `5.5.1`, `drf-spectacular` `0.29.0` [VERIFIED `pip list`]
* **Allauth Stack:** `django-allauth` `65.13.1`, `dj-rest-auth` `7.2.0` [VERIFIED `pip list`]
* **Database Engine:** 
  * Local Development default: SQLite 3 (`db.sqlite3`, 748 KB) [VERIFIED `hvt/settings.py:191`]
  * Production / CI target: PostgreSQL 16 (`psycopg2-binary` `2.9.11`, `dj-database-url` `3.1.2`) [VERIFIED `docker-compose.yml:3`, `ci.yml:28`]
* **Task Queues & Caching:**
  * Celery is **not installed or configured** in the project [VERIFIED `pip list`, `requirements.txt`]. Asynchronous email execution relies on ad-hoc background Python threads via `threading.Thread(target=_worker, daemon=True)` [VERIFIED `hvt/apps/authentication/email.py:250-266`].
  * Redis: `redis` `8.1.0` and `django-redis` `6.0.0` configured for caching (`USE_REDIS_CACHE=1`) [VERIFIED `hvt/settings.py:320-333`].
* **Directory Tree Structure:**
  * `hvt/`: Django root application containing `settings.py`, `urls.py`, `wsgi.py`, `crypto.py`, `health.py`, `exceptions.py`.
  * `hvt/api/v1/`: API routing and serializers for auth, users, and organizations.
  * `hvt/apps/authentication/`: Authentication backends, tokens, MFA/TOTP, passkeys, magic links, audit logging, and email adapters.
  * `hvt/apps/organizations/`: Multi-tenant organization models, projects, permissions, roles, API keys, social configs, invitations, webhooks.
  * `hvt/apps/users/`: Custom `User` model, role choices, user management views.
  * `cli/`: TypeScript CLI package (`@hvt/cli`) with commands `init`, `plan`, `sync`, `whoami`.
  * `sdk/`: Documentation stub pointing to external repository `markodera/hvt-sdk`.
  * `deploy/`: Gunicorn systemd service, Nginx configuration, shell deployment script.
  * `tests/`: End-to-end integration tests for API keys, audit logging, crypto, plane separation, and schema sync.

---

### 2. Complete Model Inventory & Schema Definitions

HVT declares 17 models across its three internal domain applications.

#### App: `hvt.apps.users`

##### 1. `User` (`db_table = "users"`) [VERIFIED `hvt/apps/users/models.py:30-101`]
* **Purpose:** Custom user identity model using email instead of username. Supports both Control Plane administrators and Runtime customer end users.
* **Fields:**
  * `id`: `UUIDField(primary_key=True, default=uuid.uuid4, editable=False)`
  * `email`: `EmailField(db_index=True)`
  * `first_name`: `CharField(max_length=150, blank=True)`
  * `last_name`: `CharField(max_length=150, blank=True)`
  * `organization`: `ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="users", null=True, blank=True)`
  * `project`: `ForeignKey("organizations.Project", on_delete=models.PROTECT, related_name="users", null=True, blank=True)`
  * `role`: `CharField(max_length=10, choices=["owner", "admin", "member"], default="member")`
  * `is_active`: `BooleanField(default=True)`
  * `is_staff`: `BooleanField(default=False)`
  * `is_test`: `BooleanField(default=False)`
  * `created_at`: `DateTimeField(auto_now_add=True)`
  * `updated_at`: `DateTimeField(auto_now=True)`
* **Unique Constraints:**
  * `uniq_user_email_per_project`: `UniqueConstraint(fields=["email", "project"])` (Enforces unique email within each customer project).
  * `uniq_user_email_when_project_null`: `UniqueConstraint(fields=["email"], condition=Q(project__isnull=True))` (Enforces unique email across all Control Plane dashboard accounts).
* **Indexes:** `email` (`db_index=True`), `ordering = ["-created_at"]`.

---

#### App: `hvt.apps.organizations`

##### 2. `Organization` (`db_table = "organizations"`) [VERIFIED `hvt/apps/organizations/models.py:32-65`]
* **Fields:** `id` (UUID PK), `name` (CharField 225), `slug` (SlugField 225, unique=True, indexed), `owner` (`ForeignKey("users.User", on_delete=PROTECT, null=True, blank=True, related_name="owned_organization")`), `is_active` (BooleanField, default=True), `allow_signup` (BooleanField, default=True), `created_at`, `updated_at`.
* **Relationships:** Has many `Project`, `User`, `APIKey`, `Webhook`, `OrganizationInvitation`.

##### 3. `Project` (`db_table = "projects"`) [VERIFIED `hvt/apps/organizations/models.py:95-144`]
* **Fields:** `id` (UUID PK), `organization` (`ForeignKey(Organization, on_delete=CASCADE, related_name="projects")`), `name` (CharField 225), `slug` (SlugField 225), `is_default` (BooleanField, default=False), `is_active` (BooleanField, default=True), `allow_signup` (BooleanField, default=True), `frontend_url` (URLField 500, default=""), `allowed_origins` (JSONField, default=list), `created_at`, `updated_at`.
* **Constraints:**
  * `uniq_project_slug_per_organization`: `UniqueConstraint(fields=["organization", "slug"])`
  * `uniq_default_project_per_organization`: `UniqueConstraint(fields=["organization"], condition=Q(is_default=True))`

##### 4. `ProjectPermission` (`db_table = "project_permissions"`) [VERIFIED `hvt/apps/organizations/models.py:154-183`]
* **Fields:** `id` (UUID PK), `project` (`ForeignKey(Project, on_delete=CASCADE, related_name="app_permissions")`), `slug` (CharField 100, validated by `APP_ACCESS_SLUG_VALIDATOR`), `name` (CharField 120), `description` (TextField), `managed_by` (CharField 16, choices=["dashboard", "manifest"], default="dashboard", indexed), `created_at`, `updated_at`.
* **Constraints:** `uniq_project_permission_slug`: `UniqueConstraint(fields=["project", "slug"])`.

##### 5. `ProjectRole` (`db_table = "project_roles"`) [VERIFIED `hvt/apps/organizations/models.py:194-237`]
* **Fields:** `id` (UUID PK), `project` (`ForeignKey(Project, on_delete=CASCADE, related_name="app_roles")`), `slug` (CharField 100), `name` (CharField 120), `description` (TextField), `is_default_signup` (BooleanField, default=False), `is_self_assignable` (BooleanField, default=False), `managed_by` (CharField 16, choices=["dashboard", "manifest"], default="dashboard", indexed), `permissions` (`ManyToManyField(ProjectPermission, through="ProjectRolePermission")`), `created_at`, `updated_at`.
* **Constraints:** `uniq_project_role_slug`: `UniqueConstraint(fields=["project", "slug"])`.

##### 6. `ProjectRolePermission` (`db_table = "project_role_permissions"`) [VERIFIED `hvt/apps/organizations/models.py:248-274`]
* **Fields:** `id` (UUID PK), `role` (`ForeignKey(ProjectRole, on_delete=CASCADE)`), `permission` (`ForeignKey(ProjectPermission, on_delete=CASCADE)`), `created_at`.
* **Constraints:** `uniq_project_role_permission`: `UniqueConstraint(fields=["role", "permission"])`. Cross-project link prevented via `clean()`.

##### 7. `UserProjectRole` (`db_table = "user_project_roles"`) [VERIFIED `hvt/apps/organizations/models.py:292-325`]
* **Fields:** `id` (UUID PK), `user` (`ForeignKey("users.User", on_delete=CASCADE, related_name="project_role_assignments")`), `role` (`ForeignKey(ProjectRole, on_delete=PROTECT)`), `assigned_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True, blank=True)`), `created_at`.
* **Constraints:** `uniq_user_project_role_assignment`: `UniqueConstraint(fields=["user", "role"])`. Org membership enforced via `clean()`.

##### 8. `SocialProviderConfig` (`db_table = "social_provider_configs"`) [VERIFIED `hvt/apps/organizations/models.py:349-395`]
* **Fields:** `id` (UUID PK), `project` (`ForeignKey(Project, on_delete=CASCADE, related_name="social_provider_configs")`), `provider` (CharField 32, choices=["google", "github", "discord", "apple", "microsoft", "gitlab"]), `client_id` (CharField 255), `client_secret` (`EncryptedTextField`, MultiFernet encrypted), `managed_by` (CharField 16), `redirect_uris` (JSONField, default=list), `is_active` (BooleanField, default=True), `created_at`, `updated_at`.
* **Constraints:** `uniq_social_provider_per_project`: `UniqueConstraint(fields=["project", "provider"])`.

##### 9. `APIKey` (`db_table = "api_keys"`) [VERIFIED `hvt/apps/organizations/models.py:404-565`]
* **Fields:** `id` (UUID PK), `organization` (`ForeignKey(Organization, on_delete=CASCADE)`), `project` (`ForeignKey(Project, on_delete=CASCADE, null=True, blank=True)`), `environment` (CharField 4, choices=["test", "live"], default="test"), `key_type` (CharField 16, choices=["runtime", "management"], default="runtime", indexed), `name` (CharField 225), `prefix` (CharField 8, unique=True, indexed), `hashed_key` (CharField 128, SHA-256), `scopes` (JSONField, default=list), `is_active` (BooleanField, default=True), `expires_at` (DateTimeField, nullable), `expired_webhook_sent_at` (DateTimeField, nullable), `last_used_at` (DateTimeField, nullable), `created_at`, `created_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`).

##### 10. `OrganizationInvitation` (`db_table = "organization_invitations"`) [VERIFIED `hvt/apps/organizations/models.py:684-747`]
* **Fields:** `id` (UUID PK), `organization` (`ForeignKey(Organization, on_delete=CASCADE)`), `project` (`ForeignKey(Project, on_delete=SET_NULL, null=True, blank=True)`), `email` (EmailField, indexed), `role` (CharField 10, choices=["admin", "member"]), `token` (CharField 64, unique=True, indexed, plaintext hex), `invited_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`), `accepted_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`), `expires_at`, `accepted_at`, `revoked_at`, `created_at`, `updated_at`, `app_roles` (`ManyToManyField(ProjectRole)`).
* **Indexes:** `[organization, email]`, `[organization, -created_at]`.

##### 11. `RuntimeInvitation` (`db_table = "runtime_invitations"`) [VERIFIED `hvt/apps/organizations/models.py:784-824`]
* **Fields:** `id` (UUID PK), `project` (`ForeignKey(Project, on_delete=CASCADE)`), `email` (EmailField, indexed), `role_slugs` (JSONField, default=list), `token` (CharField 64, unique=True, indexed, plaintext urlsafe), `invited_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`), `status` (CharField 10, choices=["pending", "accepted", "expired", "revoked"], default="pending", indexed), `expires_at`, `accepted_at`, `created_at`.
* **Indexes:** `[project, email]`, `[project, status, -created_at]`.

##### 12. `Webhook` (`db_table = "webhooks"`) [VERIFIED `hvt/apps/organizations/models.py:854-921`]
* **Fields:** `id` (UUID PK), `organization` (`ForeignKey(Organization, on_delete=CASCADE)`), `project` (`ForeignKey(Project, on_delete=CASCADE)`), `url` (URLField 500), `events` (JSONField, default=list), `secret` (CharField 64), `is_active` (BooleanField, default=True), `description` (TextField), `created_at`, `created_by` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`), `last_triggered_at`, `success_count` (int, default=0), `failure_count` (int, default=0), `consecutive_failures` (int, default=0).

##### 13. `WebhookDelivery` (`db_table = "webhook_deliveries"`) [VERIFIED `hvt/apps/organizations/models.py:932-981`]
* **Fields:** `id` (UUID PK), `webhook` (`ForeignKey(Webhook, on_delete=CASCADE)`), `event_type` (CharField 50), `payload` (JSONField), `request_headers` (JSONField), `request_body` (TextField), `status` (CharField 20, choices=["pending", "success", "failed", "retrying"]), `response_status_code` (int, nullable), `response_headers` (JSONField), `response_body` (TextField), `error_message` (TextField), `attempt_count` (int, default=0), `max_attempts` (int, default=3), `next_retry_at` (DateTimeField, nullable), `created_at`, `delivered_at`.
* **Indexes:** `[webhook, -created_at]`, `[status, next_retry_at]`.

---

#### App: `hvt.apps.authentication`

##### 14. `AuditLog` (`db_table = "audit_logs"`) [VERIFIED `hvt/apps/authentication/models.py:7-178`]
* **Fields:** `id` (UUID PK), `event_type` (CharField 50, indexed), `event_data` (JSONField), `actor_user` (`ForeignKey("users.User", on_delete=SET_NULL, null=True)`), `actor_api_key` (`ForeignKey("organizations.APIKey", on_delete=SET_NULL, null=True)`), `target_content_type` (`ForeignKey(ContentType, on_delete=SET_NULL, null=True)`), `target_object_id` (UUIDField, nullable), `target_object` (GenericForeignKey), `organization` (`ForeignKey(Organization, on_delete=CASCADE, null=True)`), `project` (`ForeignKey(Project, on_delete=SET_NULL, null=True)`), `ip_address` (GenericIPAddressField, nullable), `user_agent` (TextField), `success` (BooleanField, default=True), `error_message` (TextField), `created_at` (DateTimeField, auto_now_add=True, indexed).
* **Indexes:** `[-created_at, event_type]`, `[organization, -created_at]`, `[actor_user, -created_at]`.

##### 15. `TOTPDevice` (`db_table = "auth_totp_devices"`) [VERIFIED `hvt/apps/authentication/models.py:262-283`]
* **Fields:** `id` (UUID PK), `user` (`OneToOneField("users.User", on_delete=CASCADE, related_name="totp_device")`), `secret` (`EncryptedTextField`, MultiFernet encrypted at rest with `v1:` prefix), `is_confirmed` (BooleanField, default=False), `created_at`, `last_verified_at`.

##### 16. `UserPasskeyCredential` (`db_table = "auth_passkey_credentials"`) [VERIFIED `hvt/apps/authentication/models.py:285-313`]
* **Fields:** `id` (UUID PK), `user` (`ForeignKey("users.User", on_delete=CASCADE, related_name="passkey_credentials")`), `name` (CharField 120, default="Passkey"), `credential_id` (CharField 512, unique=True, indexed), `public_key` (TextField, Base64URL COSE), `sign_count` (BigIntegerField, default=0), `transports` (JSONField, default=list), `aaguid` (CharField 64, blank=True), `backed_up` (BooleanField, default=False), `created_at`, `last_used_at`.

##### 17. `MagicLinkToken` (`db_table = "auth_magic_link_tokens"`) [VERIFIED `hvt/apps/authentication/models.py:315-348`]
* **Fields:** `id` (UUID PK), `user` (`ForeignKey("users.User", on_delete=CASCADE)`), `project` (`ForeignKey(Project, on_delete=CASCADE, null=True)`), `token_hash` (CharField 64, SHA-256 hash, indexed), `expires_at`, `is_used` (BooleanField, default=False), `created_at`.

---

### 3. Multi-Tenancy Isolation & Queryset Scoping Analysis

Multi-tenancy isolation in HVT is enforced through a dual identity partition in `User` and request-level filtering:

1. **Identity Layer:**
   * **Control Plane Accounts:** Rows where `project IS NULL`. Email is globally unique across all Control Plane accounts [VERIFIED `hvt/apps/users/models.py:96-100`].
   * **Runtime Plane Accounts:** Rows where `project IS NOT NULL`. Email is unique per project [VERIFIED `hvt/apps/users/models.py:92-95`]. A single end user email (e.g. `customer@domain.com`) can exist independently in Project A and Project B without credential collision.

2. **Queryset Scoping Assessment:**
   * **Project-Scoped Views:**
     * `ProjectPermissionListCreateView`, `ProjectRoleListCreateView`, `SocialProviderConfigListCreateView` strictly scope their base querysets using `_get_current_project_or_404(request, project_pk)` which chains to `Project.objects.filter(organization=request.user.organization)` [VERIFIED `hvt/apps/organizations/views.py:104-112`].
     * `RuntimeInvitationListCreateView`: strictly filters `RuntimeInvitation.objects.filter(project=api_key.project)` [VERIFIED `hvt/apps/organizations/views.py:1801`].
     * `UserListView`: When accessed by API key, filters `project=request.auth.project`. When accessed by Control Plane user, filters `organization=org` [VERIFIED `hvt/apps/users/views.py:63-65`].
   * **Querysets That Are NOT Project-Scoped (Potential Drift / Intentional Org-Wide):**
     * `UserListView`: Control plane dashboard users view **all users across all projects** within their organization. There is no query parameter or default filter restricting dashboard listings to a specific project [VERIFIED `hvt/apps/users/views.py:47-65`].
     * `OrganizationListView` and `OrganizationDetailView`: Defined with `queryset = Organization.objects.all()`. Accessible only to Django superusers / staff (`IsAdminUser`), but returns all tenants globally across the database instance [VERIFIED `hvt/apps/organizations/views.py:289, 360`].
     * `AuditLogListView`: Control plane users can view all audit logs across all projects within the organization unless explicitly filtering by `project_id` [VERIFIED `hvt/apps/authentication/audit_views.py:50-80`].

---

### 4. Migration History & Lineage

The database schema has 46 custom local migrations applied in sequence [VERIFIED `manage.py showmigrations`]:
* **`hvt.apps.users` (6 migrations):** Initial user model (`0001`), remove legacy email verified field (`0002`), add `is_test` (`0003`), add `role` (`0004`), add `project` foreign key (`0005`), enforce composite unique constraint `uniq_user_email_per_project` and conditional `uniq_user_email_when_project_null` (`0006`).
* **`hvt.apps.organizations` (26 migrations):** Initial orgs (`0001`), API keys (`0002`), org owner (`0003`), key scopes (`0004`), environments (`0005-0010`), webhooks (`0007, 0008, 0011, 0015`), invitations (`0012`), projects and project-scoped keys (`0013`), social provider configs (`0014`), RBAC permissions and roles (`0016, 0017`), key expiry webhook tracking (`0018`), project frontend URL (`0019`), allowed origins (`0020`), runtime invitations (`0021`), social provider choices (`0022`), `managed_by` manifest tracking (`0023`), MultiFernet secret encryption backfill (`0024`), key types (`runtime` vs `management`) (`0025`), project passkey relying party ID (`passkey_rp_id`) (`0026`).
* **`hvt.apps.authentication` (14 migrations):** Initial audit logs (`0001-0005`), allauth verified email constraint drops (`0006-0007`), TOTP devices (`0010`), WebAuthn credentials and magic link tokens (`0011`), audit event expansion (`0012`), EncryptedTextField for TOTPDevice secret (`0013`), idempotent backfill of encrypted TOTP secrets (`0014`).

---

### 5. Environment Variables Catalog

The following environment variables are recognized across `hvt/settings.py` and deployment scripts [VERIFIED `hvt/settings.py`, `entrypoint.sh`]:

| Environment Variable | Source / Scope | Purpose |
| :--- | :--- | :--- |
| `DEBUG` | Django Settings | Enables debug mode and relaxed local CORS/CSRF defaults |
| `SECRET_KEY` | Django Settings | Symmetric cryptographic master secret for sessions and legacy token fallback |
| `HVT_JWT_PRIVATE_KEY` | Authentication App | RSA 2048-bit private key PEM (or path) for asymmetric RS256 JWT signing |
| `HVT_JWT_PUBLIC_KEY` | Authentication App | RSA 2048-bit public key PEM (optional; auto-derived from private key) |
| `HVT_JWT_KEY_ID` | Authentication App | Explicit Key ID (kid) stamped into token headers (default: sha256 fingerprint) |
| `HVT_JWT_ISSUER` | Authentication App | Canonical JWT issuer URL (iss claim; default: FRONTEND_URL or api.hvts.app) |
| `HVT_JWT_ROTATION_PUBLIC_KEYS` | Authentication App | List of previous RSA public keys for zero-downtime key rotation in JWKS |
| `HVT_ENCRYPTION_KEYS` | Django Crypto | Comma-separated Fernet keys for encrypting secrets at rest |
| `ALLOWED_HOSTS` | Django Settings | Permitted HTTP Host headers |
| `FRONTEND_URL` | Django Settings | Base URL for the Control Plane dashboard SPA |
| `CORS_ALLOWED_ORIGINS` | Django Settings | Allowed browser origins for cross-origin CORS requests |
| `CSRF_TRUSTED_ORIGINS` | Django Settings | Trusted origins for CSRF protection on unsafe HTTP methods |
| `DATABASE_URL` | Django Database | PostgreSQL connection URI |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | Django Database | Fallback individual database connection parameters |
| `DATABASE_SSL_REQUIRE` | Django Database | Enforces SSL mode `require` on Postgres connections |
| `REDIS_URL` | Django Cache | Redis cache connection string |
| `USE_REDIS_CACHE` | Django Cache | Toggles between Redis and LocMemCache |
| `RUN_MIGRATIONS` | `entrypoint.sh` | Automatically runs `manage.py migrate` on container startup |
| `COLLECTSTATIC_ON_START` | `entrypoint.sh` | Automatically runs `manage.py collectstatic` on boot |
| `WAIT_FOR_DB` | `entrypoint.sh` | Triggers `scripts/wait_for_db.py` retry loop |
| `DB_CONNECT_MAX_ATTEMPTS` | `scripts/wait_for_db.py` | Maximum retry attempts for Postgres readiness (default: 45) |
| `DB_CONNECT_RETRY_DELAY` | `scripts/wait_for_db.py` | Delay in seconds between connection retries (default: 2) |
| `DEFAULT_FROM_EMAIL` | Django / Resend | Default sender address for outgoing transactional emails |
| `RESEND_API_KEY` | Authentication App | API key for the Resend transactional email backend |
| `RESEND_WEBHOOK_SIGNING_KEY` | Authentication App | HMAC secret for verifying incoming Resend webhook events |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Social Auth | Control-plane OAuth credentials for Google |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | Social Auth | Control-plane OAuth credentials for GitHub |
| `USE_X_FORWARDED_HOST` | Django Security | Respects `X-Forwarded-Host` reverse proxy header |
| `SECURE_SSL_REDIRECT` | Django Security | Redirects all HTTP traffic to HTTPS |
| `SESSION_COOKIE_SECURE` | Django Security | Marks session cookies as `Secure` |
| `CSRF_COOKIE_SECURE` | Django Security | Marks CSRF cookies as `Secure` |
| `SECURE_HSTS_SECONDS` | Django Security | HTTP Strict Transport Security duration |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | Django Security | Extends HSTS to all subdomains |
| `SECURE_HSTS_PRELOAD` | Django Security | Requests browser HSTS preload list inclusion |
| `SECURE_REFERRER_POLICY` | Django Security | Configures HTTP `Referrer-Policy` header |
| `X_FRAME_OPTIONS` | Django Security | Clickjacking protection (default: `DENY`) |
| `EXPOSE_ADMIN` | Django Settings | Mounts the Django Admin interface |
| `EXPOSE_API_DOCS` | Django Settings | Mounts OpenAPI Swagger/Redoc endpoints |
| `ADMIN_URL` | Django Settings | Customizable URL path prefix for Django Admin (default: `admin/`) |
| `DOCS_URL` | Email Templates | Target link for documentation references |
| `API_KEY_MAX_PER_PROJECT` | Django Settings | Maximum allowable API keys per project (default: 25) |
| `PORT` | `entrypoint.sh` | TCP port for Gunicorn binding (default: 8000) |
| `WEB_CONCURRENCY` | `entrypoint.sh` | Number of Gunicorn worker processes (default: 3) |
| `GUNICORN_TIMEOUT` | `entrypoint.sh` | Gunicorn request timeout in seconds (default: 120) |
| `GUNICORN_GRACEFUL_TIMEOUT` | `entrypoint.sh` | Gunicorn graceful shutdown timeout (default: 30) |
| `GUNICORN_KEEPALIVE` | `entrypoint.sh` | HTTP keep-alive timeout in seconds (default: 5) |
| `GUNICORN_MAX_REQUESTS` | `entrypoint.sh` | Worker restart threshold to prevent memory leaks (default: 1000) |
| `GUNICORN_MAX_REQUESTS_JITTER` | `entrypoint.sh` | Randomized jitter added to restart threshold (default: 100) |

---

### 6. Docker, Deploy & CI Infrastructure

* **Containerization (`Dockerfile`):**
  * Multi-stage build based on `python:3.12-slim-bookworm` [VERIFIED `Dockerfile:2`].
  * Builds dependencies in `deps` stage with `build-essential` and `libpq-dev`, then copies clean Python packages to `production` stage containing only `libpq5` [VERIFIED `Dockerfile:14-49`].
  * Runs under dedicated unprivileged system user `hvt` (`useradd --create-home --shell /bin/bash hvt`) [VERIFIED `Dockerfile:52, 64`].
* **Compose Orchestration (`docker-compose.yml`):**
  * Declares three services: `db` (`postgres:16-alpine`), `redis` (`redis:7-alpine`), and `web` (HVT Gunicorn app).
  * Uses Docker healthchecks with `depends_on: { condition: service_healthy }` to ensure PostgreSQL and Redis are responsive before starting Gunicorn [VERIFIED `docker-compose.yml:52-56`].
* **CI Pipeline (`.github/workflows/ci.yml`):**
  * **Job 1: `gitleaks`:** Scans commit history for leaked credentials using `gitleaks/gitleaks-action@v2` [VERIFIED `ci.yml:10-21`].
  * **Job 2: `backend`:** Boots PostgreSQL 16 container, checks out code, installs `requirements.txt`, runs `manage.py check`, runs `manage.py makemigrations --check`, and executes `manage.py test` [VERIFIED `ci.yml:23-81`].
  * **Job 3: `cli`:** Sets up Node.js 20, installs dependencies via `npm ci`, builds TypeScript via `npm run build`, and executes `npm test` [VERIFIED `ci.yml:83-107`].
* **CD Pipeline (`.github/workflows/deploy.yml`):**
  * Automatically connects to a self-hosted Linux VPS via SSH (`appleboy/ssh-action@v1.0.3`) upon push to `main` [VERIFIED `deploy.yml:18-34`].
  * Executes zero-downtime reload via `kill -HUP $(cat /tmp/hvt-gunicorn.pid)` [VERIFIED `deploy.yml:56`].

---

## WHAT WE DON'T KNOW

1. **Redis Persistence Settings:** We do not know if customer deployments configure Redis RDB or AOF persistence; `docker-compose.yml` mounts `redis_data` volume but does not specify custom persistence flags [INFERRED default redis-cli defaults apply].
2. **Postgres Connection Pooling Outside Gunicorn:** We cannot determine whether production deployments utilize external connection poolers (PgBouncer) or rely strictly on Django's `conn_max_age=600` [VERIFIED `hvt/settings.py:196`].

---

## WHAT WE DIDN'T ANTICIPATE

1. **Docker Compose Missing Encryption Keys:** `docker-compose.yml` explicitly sets `DEBUG=0` for the `web` container, but omits `HVT_ENCRYPTION_KEYS`. In non-debug mode, Django raises `ImproperlyConfigured` at startup if `HVT_ENCRYPTION_KEYS` is not provided. Running `docker compose up` without manually editing the file causes container crashloops [VERIFIED `hvt/crypto.py:48-50`].
2. **Zero Async Background Workers (No Celery):** Documentation frequently mentions asynchronous email delivery and webhooks. However, Celery is completely absent; background tasks run inside detached Python daemon threads (`threading.Thread`) which are destroyed if the Gunicorn worker process recycles or restarts [VERIFIED `hvt/apps/authentication/email.py:265-266`].
3. **Absence of User Workspace Join Table:** While the system allows users to belong to an organization and assigned to projects, there is no many-to-many model allowing a single runtime user to belong to multiple sub-workspaces or teams within a single project [VERIFIED `hvt/apps/users/models.py:49-63`].
