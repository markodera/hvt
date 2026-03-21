# HVT Codebase Analysis

> Generated: March 4, 2026 — End of Phase 3

---

## 1. Project Overview

**HVT** is a **REST-first authentication service** — an identity provider and single source of truth for auth. It provides user lifecycle management, token-based authentication, social OAuth, per-organization API keys, role-based access control, webhooks, and audit logging. It's designed to sit in front of one or more application backends: those apps delegate all identity concerns to HVT.

**Think:** Auth0 for startups, but open-source and affordable.

**Current phase:** Phases 1–3 are complete (Core Auth, Platform Infrastructure, Developer Experience). Phase 4 (Docker/Production) is in progress. All **113 tests pass**.

---

## 2. Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Framework | Django | 5.2.9 |
| API Layer | Django REST Framework | 3.14.0 |
| JWT | djangorestframework-simplejwt | 5.5.1 |
| Auth Bridge | dj-rest-auth | 7.0.1 |
| Social OAuth | django-allauth | 65.13.1 |
| API Docs | drf-spectacular (OpenAPI 3) | 0.29.0 |
| Filtering | django-filter | 25.2 |
| Database | PostgreSQL (psycopg2) | 2.9.11 |
| Password Hashing | Django default (PBKDF2, Argon2 available) | — |
| CORS | django-cors-headers | 4.3.1 |
| Email (future) | Resend SDK | 2.19.0 |
| Env Config | python-dotenv | 1.2.1 |
| WSGI Server | Gunicorn | 23.0.0 |
| Runtime | Python 3.12+ | — |

**Notable libraries also in `requirements.txt`** (installed but not directly used by HVT core): Celery 5.3.6, Redis 7.1.0, Stripe 14.1.0, Twilio 9.9.0, whitenoise 6.11.0 — these are scaffolding for Phase 4+.

---

## 3. Architecture

### 3.1 Project Layout

```
hvt/                         ← Django project root (settings, urls, wsgi)
├── settings.py              ← Single settings file, env-var driven
├── urls.py                  ← Root URL conf → admin + api/v1 + schema docs
├── exceptions.py            ← Custom error envelope handler
├── pagination.py            ← 3 pagination classes
├── api/v1/
│   ├── urls.py              ← Router: auth/, users/, organizations/
│   └── serializers/         ← All DRF serializers (users, organizations, audit)
└── apps/
    ├── authentication/      ← Auth logic: signals, backends, permissions, views
    ├── organizations/       ← Org model, API keys, webhooks, webhook engine
    └── users/               ← Custom User model and user CRUD views
```

### 3.2 Request Flow

```
Client → CORS middleware → DRF Authentication (JWT or API Key)
       → Permission check (role-based) → Rate limiting (burst + org + key)
       → View logic → Serializer → Response
       ↓ (side effects)
       Signal handlers → AuditLog.log() + trigger_webhook_event()
```

### 3.3 Multi-Tenancy Model

Every authenticated request is scoped to an **Organization**. The org is resolved from:
- **JWT auth:** `request.user.organization`
- **API Key auth:** `request.auth.organization` (the `APIKeyAuthentication` backend returns `(None, api_key_obj)`)

All querysets filter by org. There is no cross-org read path except superuser admin views.

### 3.4 Authentication Dual-Path

Two authentication backends run in order (defined in `settings.py`):
1. **JWTAuthentication** — sets `request.user` to the User, `request.auth` to the token
2. **APIKeyAuthentication** — sets `request.user` to `None`, `request.auth` to the `APIKey` object

Every permission class checks `isinstance(request.auth, APIKey)` to branch accordingly. API keys are **read-only** for all endpoints.

---

## 4. Core Features

### 4.1 User Lifecycle
- **Registration** — email-only (no username), via `dj-rest-auth/registration`. Custom `CustomRegisterSerializer` strips username, fires audit log + webhook.
- **Email verification** — mandatory (`ACCOUNT_EMAIL_VERIFICATION = "mandatory"`). Console backend in dev.
- **Login** — email + password via `dj-rest-auth`. Custom `CustomLoginSerializer` removes username field.
- **Password reset** — request + confirm flow via `dj-rest-auth` explicit URL paths.
- **Password change** — authenticated endpoint for changing own password.
- **Social OAuth** — Google and GitHub via allauth. `CustomSocialAccountAdapter` handles email-only users (no username, auto-populates name fields).
- **Profile** — `GET/PATCH /api/v1/auth/me/` for current user.

### 4.2 Token Management
- **JWT** — 15-minute access tokens, 7-day refresh tokens
- **Token rotation** — enabled; old refresh token is blacklisted after each rotation
- **JWT cookies** — `auth-token` and `refresh-token` cookie names (for browser-based flows)
- **Token refresh** — `POST /api/v1/auth/token/refresh/`

### 4.3 API Key System
- **Key format:** `hvt_test_<64 hex chars>` or `hvt_live_<64 hex chars>`
- **Storage:** only an 8-char prefix and SHA-256 hash are stored
- **Lookup:** prefix-based O(1) lookup → hash verification
- **Environments:** test/live isolation at the key level
- **Lifecycle:** create, list, revoke (soft-disable), delete (hard)
- **Scopes:** JSON array field (schema only, not enforced in middleware yet)

### 4.4 Role-Based Access Control (RBAC)
Three roles: **owner**, **admin**, **member**

| Action | Owner | Admin | Member |
|---|---|---|---|
| Users CRUD | ✅ | ✅ | read-only |
| Change roles | ✅ | ✅ (not owner role) | ❌ |
| Organization update/delete | ✅ | ❌ | ❌ |
| API Keys CRUD | ✅ | ❌ | ❌ |
| Webhooks CRUD | ✅ | ✅ | ❌ |
| Audit logs (all org) | ✅ | ✅ | own only |

The full 22-entry permissions matrix is served at `GET /api/v1/organizations/current/permissions/` for frontend consumption.

### 4.5 Webhook System
- **CRUD** — create, list, update, delete webhook endpoints per org
- **Event subscriptions** — JSON array of event types (user.created, user.login, api_key.created, etc.)
- **Delivery** — `trigger_webhook_event()` fires daemon threads (never blocks the view)
- **Signing** — HMAC-SHA256 signature in `X-HVT-Signature` header, prefixed with `sha256=`
- **Retry** — 3 attempts with exponential backoff (1s, 4s, 9s)
- **Auto-disable** — after 10 consecutive failures, webhook is deactivated
- **Delivery logs** — full request/response stored in `WebhookDelivery` model
- **Headers sent:** `X-HVT-Signature`, `X-HVT-Event`, `X-HVT-Delivery`, `User-Agent: HVT-Webhook/1.0`

### 4.6 Audit Logging
- **21 event types** across 6 categories: auth, password, email, social, API key, org, user management
- **Signal-driven** — 9 Django/allauth signal receivers in `authentication/signals.py`
- **View-driven** — explicit `AuditLog.log()` calls in org/user views for CRUD events
- **Actor tracking** — records user or API key that performed the action
- **Target tracking** — GenericForeignKey to any model (User, Org, APIKey)
- **Request metadata** — IP address (X-Forwarded-For aware), user agent
- **Cursor-based pagination** on the list endpoint for efficient time-series queries
- **Role-scoped reads** — members can only see their own events; admins/owners see all org events

### 4.7 Rate Limiting
Four throttle classes (defined in `authentication/throttling.py`):
- **BurstRateThrottle** — 20 req/sec per org or IP
- **OrganizationRateThrottle** — 1000 req/hr per org
- **APIKeyRateThrottle** — 100 req/min per key
- **AnonRateThrottle** — 10 req/min per IP

### 4.8 Error Handling
Custom exception handler (`hvt/exceptions.py`) wraps all DRF errors into a consistent envelope:
```json
{
  "error": "Validation Error",
  "code": "validation_error",
  "detail": { "email": ["This field is required."] },
  "status": 400
}
```
Maps specific exception classes to semantic codes. Throttled responses include `retry_after_seconds`.

---

## 5. Data Models

### 5.1 User (`users/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | Auto-generated |
| `email` | EmailField | Unique, `USERNAME_FIELD` |
| `first_name`, `last_name` | CharField(150) | Optional |
| `organization` | FK → Organization | CASCADE, nullable |
| `role` | CharField (owner/admin/member) | Default: member |
| `is_active`, `is_staff`, `is_test` | Boolean | Test users only accessible via test API keys |
| `created_at`, `updated_at` | DateTime | Auto timestamps |

Helper methods: `is_org_owner()`, `is_org_admin()`, `can_manage_users()`, `can_manage_api_keys()`, `can_manage_organization()`, `full_name` property.

### 5.2 Organization (`organizations/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `name` | CharField(225) | |
| `slug` | SlugField | Unique, indexed |
| `owner` | FK → User | PROTECT, nullable |
| `is_active` | Boolean | |
| `allow_signup` | Boolean | |
| `created_at`, `updated_at` | DateTime | |

**Constraint:** Each user can own max 3 organizations (enforced in view).

### 5.3 APIKey (`organizations/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `organization` | FK → Organization | CASCADE |
| `environment` | CharField (test/live) | Default: test |
| `name` | CharField(225) | Friendly name |
| `prefix` | CharField(8) | Unique, indexed, for lookup |
| `hashed_key` | CharField(128) | SHA-256 of full key |
| `scopes` | JSONField | List of scope strings |
| `is_active` | Boolean | |
| `expires_at` | DateTime | Nullable |
| `last_used_at` | DateTime | Updated on each auth |
| `created_by` | FK → User | SET_NULL |
| `created_at` | DateTime | |

### 5.4 Webhook (`organizations/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `organization` | FK → Organization | CASCADE |
| `url` | URLField(500) | Target endpoint |
| `events` | JSONField | List of event types |
| `secret` | CharField(64) | `token_hex(32)` |
| `is_active` | Boolean | |
| `description` | TextField | |
| `created_by` | FK → User | SET_NULL |
| `last_triggered_at` | DateTime | |
| `success_count`, `failure_count`, `consecutive_failures` | Integer | Auto-disable at 10 consecutive |

### 5.5 WebhookDelivery (`organizations/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `webhook` | FK → Webhook | CASCADE |
| `event_type` | CharField(50) | |
| `payload` | JSONField | Full delivery envelope |
| `request_headers`, `request_body` | JSON/Text | What was sent |
| `status` | CharField (pending/success/failed/retrying) | |
| `response_status_code` | Integer | |
| `response_headers`, `response_body` | JSON/Text | What came back |
| `error_message` | TextField | |
| `attempt_count`, `max_attempts` | Integer | Default 3 |
| `next_retry_at` | DateTime | |
| `created_at`, `delivered_at` | DateTime | |

**Indexes:** `(webhook, -created_at)`, `(status, next_retry_at)`

### 5.6 AuditLog (`authentication/models.py`)
| Field | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `event_type` | CharField(50) | 21 choices |
| `event_data` | JSONField | Arbitrary context |
| `actor_user` | FK → User | SET_NULL |
| `actor_api_key` | FK → APIKey | SET_NULL |
| `target` | GenericForeignKey | Points to any model |
| `organization` | FK → Organization | CASCADE |
| `ip_address` | GenericIPAddressField | X-Forwarded-For aware |
| `user_agent` | TextField | Truncated to 500 chars |
| `success` | Boolean | |
| `error_message` | TextField | |
| `created_at` | DateTime | |

**Indexes:** `(-created_at, event_type)`, `(organization, -created_at)`, `(actor_user, -created_at)`

---

## 6. API Endpoints

### Auth (`/api/v1/auth/`)
| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/login/` | Email + password login → JWT | Public |
| POST | `/logout/` | Blacklist refresh token | JWT |
| GET | `/user/` | dj-rest-auth user detail | JWT |
| POST | `/password/reset/` | Request password reset email | Public |
| POST | `/password/change/` | Change own password | JWT |
| POST | `/password/reset/confirm/<uidb64>/<token>/` | Confirm reset | Public |
| POST | `/register/` | Register new user | Public |
| POST | `/token/refresh/` | Refresh JWT | Public (refresh token) |
| POST | `/social/google/` | Google OAuth login | Public (OAuth token) |
| POST | `/social/github/` | GitHub OAuth login | Public (OAuth token) |
| GET/PATCH | `/me/` | Current user profile | JWT |
| POST | `/webhooks/resend/` | Resend email delivery webhook | Signature |

### Users (`/api/v1/users/`)
| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/` | List org users | Member+ / API Key (read) |
| POST | `/` | Create user | Admin+ |
| GET | `/<id>/` | Get user detail | Member+ / API Key (read) |
| PUT/PATCH | `/<id>/` | Update user | Admin+ |
| DELETE | `/<id>/` | Delete user | Admin+ |
| PUT/PATCH | `/<id>/role/` | Change user role | Admin+ (CanChangeRole) |

### Organizations (`/api/v1/organizations/`)
| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/` | List all orgs | Superuser |
| POST | `/` | Create org (max 3) | JWT |
| GET/PUT/PATCH/DELETE | `/<id>/` | Org CRUD | Superuser |
| GET | `/current/` | Get current org | Member+ / API Key |
| PUT/PATCH | `/current/` | Update org | Owner only |
| GET | `/current/members/` | List org members | Member+ / API Key |
| GET | `/current/keys/` | List API keys | Owner / API Key (read) |
| POST | `/current/keys/` | Create API key | Owner |
| GET/DELETE | `/current/keys/<id>/` | Key detail/delete | Owner / API Key (read) |
| PATCH | `/current/keys/<id>/revoke/` | Soft-revoke key | Owner |
| GET | `/current/webhooks/` | List webhooks | Admin+ / API Key (read) |
| POST | `/current/webhooks/` | Create webhook | Admin+ |
| GET/PUT/PATCH/DELETE | `/current/webhooks/<id>/` | Webhook CRUD | Admin+ / API Key (read) |
| GET | `/current/webhooks/<id>/deliveries/` | Delivery logs | Admin+ / API Key (read) |
| GET | `/current/audit-logs/` | List audit events | Member+ (scoped) / API Key |
| GET | `/current/audit-logs/<id>/` | Audit detail | Member+ (scoped) / API Key |
| GET | `/current/permissions/` | RBAC matrix | Member+ / API Key |

### Schema/Docs
| Method | Path | Description |
|---|---|---|
| GET | `/api/schema/` | OpenAPI 3.0 YAML/JSON |
| GET | `/api/docs/` | Swagger UI |
| GET | `/api/redoc/` | ReDoc |

---

## 7. Current State

### What's Complete (Phases 1–3)
- ✅ Full user lifecycle (register, login, logout, verify, reset, social OAuth)
- ✅ JWT with rotation + blacklisting
- ✅ API Key system with test/live environments
- ✅ RBAC (3 roles × 22 permissions)
- ✅ Webhook system with HMAC signing, retry, auto-disable
- ✅ Comprehensive audit logging (21 event types, signal-driven)
- ✅ Consistent error envelope on all endpoints
- ✅ 3 pagination strategies (standard, large, cursor)
- ✅ Filtering, search, ordering on all list endpoints
- ✅ OpenAPI schema with Swagger UI and ReDoc
- ✅ Developer docs: QUICKSTART.md, WEBHOOKS.md, BROWSER_AUTHENTICATION.md, API_KEY_GUIDE.md
- ✅ Django admin configured for all models
- ✅ 113 tests passing

### What's Missing / In Progress (Phase 4+)
- ⬜ **Docker containerization** — Dockerfile created (empty), guidance provided
- ⬜ **Production settings** — no separate prod config yet (single settings.py, env-var driven)
- ⬜ **Static files** — no `STATIC_ROOT`, no WhiteNoise integration yet
- ⬜ **Celery/async** — Celery is installed but not configured; webhooks use daemon threads
- ⬜ **Scope enforcement** — API key scopes field exists but isn't enforced in middleware
- ⬜ **Email delivery** — console backend in dev; Resend adapter written but not active
- ⬜ **Test/live data isolation** — `is_test` flag on User exists but no middleware enforcing query isolation per key environment
- ⬜ **No CI/CD pipeline**
- ⬜ **No Kubernetes manifests**
- ⬜ **No billing/subscription system**
- ⬜ **No customer-facing dashboard** (only Django admin)

### Known Technical Debt
1. **Webhook delivery is synchronous-in-thread** — daemon threads work at low scale but don't survive process restarts. Celery migration is the roadmap plan.
2. **Single settings file** — works with env vars but a prod split would be cleaner.
3. **`requirements.txt` is `pip freeze` output** (119 packages) — includes dev tools, unrelated packages. Should be split into `requirements/base.txt` + `dev.txt`.
4. **API key scopes are stored but never checked** — the `scopes` JSONField on APIKey is populated but no middleware enforces them.
5. **Test/live isolation is incomplete** — the `is_test` flag on User and `environment` on APIKey exist, but views don't filter User querysets by key environment.

---

## 8. Dependencies

### Direct (core to HVT functionality)
| Package | Purpose |
|---|---|
| Django 5.2.9 | Web framework |
| djangorestframework 3.14.0 | REST API layer |
| djangorestframework-simplejwt 5.5.1 | JWT tokens |
| dj-rest-auth 7.0.1 | Auth endpoint scaffolding |
| django-allauth 65.13.1 | Social OAuth + email verification |
| drf-spectacular 0.29.0 | OpenAPI schema generation |
| django-filter 25.2 | Queryset filtering |
| django-cors-headers 4.3.1 | CORS handling |
| python-dotenv 1.2.1 | .env file loading |
| psycopg2-binary 2.9.11 | PostgreSQL driver |
| gunicorn 23.0.0 | WSGI server |
| requests 2.32.5 | Webhook HTTP delivery |

### Installed but not yet integrated
| Package | Intended Purpose |
|---|---|
| celery 5.3.6 | Async task queue (for webhooks, future) |
| redis 7.1.0 | Celery broker + cache backend |
| whitenoise 6.11.0 | Static file serving in production |
| resend 2.19.0 | Transactional email delivery |
| stripe 14.1.0 | Billing (to be replaced with Paystack) |
| twilio 9.9.0 | SMS notifications (future) |

---

## 9. Notable Design Decisions & Patterns

### 9.1 Email as Username
No `username` field anywhere. `email` is the `USERNAME_FIELD`. The `CustomRegisterSerializer` and `CustomLoginSerializer` strip the username field from DRF serializers entirely.

### 9.2 UUID Primary Keys Everywhere
All models use `UUIDField(default=uuid.uuid4)` as primary key. No auto-increment integers exposed in URLs.

### 9.3 Org Resolution via Helper
A `_get_org(request)` helper in `users/views.py` resolves the organization from either `request.user.organization` (JWT) or `request.auth.organization` (API key). This is used by every view that needs org scope.

### 9.4 Permission Class Composition
Views stack multiple permission classes: e.g., `[IsOrgAdminOrAPIKey, CanChangeRole]`. DRF ANDs them — all must pass.

### 9.5 AuditLog.log() Classmethod
A convenience classmethod that extracts IP, user agent, org, and actor from the request object:
```python
AuditLog.log(
    event_type=AuditLog.EventType.USER_CREATED,
    request=request,
    user=request.user,
    organization=org,
    target=new_user,
    event_data={'email': new_user.email},
)
```

### 9.6 Webhook Delivery in Daemon Threads
`trigger_webhook_event()` spawns `threading.Thread(daemon=True)` for each matching webhook. This is fast and non-blocking but doesn't survive worker restarts. The architecture is designed for easy migration to Celery tasks later.

### 9.7 API Key Prefix Lookup
Keys are stored as `(prefix[8], sha256_hash)`. On auth, the backend extracts the 8-char prefix from `hvt_{env}_<prefix><rest>`, finds the DB row by prefix (indexed, unique), then verifies `sha256(full_key) == hashed_key`. This avoids scanning all keys.

### 9.8 Consistent Error Envelope
The custom exception handler in `hvt/exceptions.py` catches all DRF exceptions and wraps them in `{error, code, detail, status}`. This means SDK/frontend consumers only need to handle one error shape.

### 9.9 Cursor Pagination for Audit Logs
Standard page-number pagination suffers from "page drift" when new rows are inserted. Audit logs use `CursorPagination(ordering="-created_at")` which is stable and efficient for append-only time-series data.

### 9.10 Signal-Driven Audit Logging
Django signals (`user_logged_in`, `user_logged_out`, `user_login_failed`) and allauth signals (`password_changed`, `password_reset`, `email_confirmed`, etc.) are connected in `authentication/signals.py`. This decouples audit logging from view logic entirely for auth events.

---

## 10. What a New Developer Needs to Know

### Getting Started
1. Clone the repo, install Python 3.12+, create a virtualenv
2. `pip install -r requirements.txt`
3. Set up PostgreSQL locally, configure env vars (or create a `.env` file — see `.env.example`)
4. `python manage.py migrate`
5. `python manage.py createsuperuser`
6. `python manage.py runserver`
7. Visit `/api/docs/` for Swagger UI

### Key Files to Read First
1. **`hvt/settings.py`** — all config in one place, env-var driven
2. **`hvt/api/v1/urls.py`** — see how routes are organized
3. **`hvt/apps/users/models.py`** — the User model and role system
4. **`hvt/apps/organizations/models.py`** — Organization, APIKey, Webhook, WebhookDelivery
5. **`hvt/apps/authentication/permissions.py`** — all 7+ permission classes
6. **`hvt/apps/authentication/signals.py`** — how audit logging hooks into auth events

### Conventions
- **All PKs are UUIDs** — never expose sequential IDs
- **No username** — email is the only identifier
- **Every view has `@extend_schema` annotations** — keep OpenAPI docs up to date
- **Every mutating action logs to AuditLog** — don't skip this in new views
- **API keys are read-only** — write operations require JWT
- **Tests live in each app's `tests.py`** (and `tests_webhooks.py` for webhook-specific tests)
- **Run `python manage.py spectacular --file schema.yml`** after changing endpoints

### Running Tests
```bash
python manage.py test hvt.apps.organizations.tests_webhooks hvt.apps.organizations.tests hvt.apps.users.tests hvt.apps.authentication.tests --noinput
```

### Roadmap
- **Phase 4:** Docker, production hardening, Kubernetes, Paystack billing
- **Phase 5:** Customer dashboard (React, separate repo)
- **Future:** Celery for async webhooks, scope enforcement, test/live data isolation
