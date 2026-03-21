# Developer Quickstart

Get your application integrated with HVT in 15 minutes.

---

## Base URL

```
http://localhost:8000/api/v1/
```

Interactive API docs (Swagger UI) are available at `/api/docs/`.

---

## Authentication Methods

HVT supports two authentication methods. Every request must use one (never both).

| Method | Header | Use Case |
|--------|--------|----------|
| **JWT** | `Authorization: Bearer <access_token>` | End-user sessions (login, profile, etc.) |
| **API Key** | `X-API-Key: hvt_live_xxx` | Server-to-server / B2B integrations |

> **Important:** If you send both headers, JWT takes priority and the API key is ignored.

---

## 1. Register & Log In

### Create an Account

```bash
curl -X POST http://localhost:8000/api/v1/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@example.com",
    "password1": "YourStr0ng!Pass",
    "password2": "YourStr0ng!Pass"
  }'
```

### Log In (Get Tokens)

```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@example.com",
    "password": "YourStr0ng!Pass"
  }'
```

Response:

```json
{
  "access": "eyJ0eXAiOiJKV1Q...",
  "refresh": "eyJ0eXAiOiJKV1Q..."
}
```

- **Access token** — expires in **15 minutes**, used for API requests
- **Refresh token** — expires in **7 days**, used to get new access tokens

### Refresh an Access Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "<refresh_token>"}'
```

---

## 2. Create an Organization

Every user belongs to one organization. Organizations own API keys, webhooks, and audit logs.

```bash
curl -X POST http://localhost:8000/api/v1/organizations/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Company",
    "slug": "my-company"
  }'
```

The creating user becomes the **owner** automatically.

---

## 3. Generate an API Key

API keys let your backend call HVT without user tokens.

```bash
curl -X POST http://localhost:8000/api/v1/organizations/current/keys/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Key",
    "scopes": ["read", "write"],
    "environment": "live"
  }'
```

Response:

```json
{
  "id": "a1b2c3d4-...",
  "key": "hvt_live_df7ec398...",
  "name": "Production Key",
  "environment": "live"
}
```

> **Save the `key` value immediately** — it is only shown once. HVT stores a hash, not the plaintext key.

### Key Environments

| Prefix | Environment | Purpose |
|--------|-------------|---------|
| `hvt_live_` | Production | Real user data |
| `hvt_test_` | Testing | Development & CI |

### Using an API Key

```bash
curl http://localhost:8000/api/v1/users/ \
  -H "X-API-Key: hvt_live_df7ec398..."
```

API keys grant **read-only** access. Write operations (POST, PATCH, DELETE) require JWT authentication.

---

## 4. Manage Users

### List Organization Users

```bash
GET /api/v1/users/
```

Supports filtering and ordering:

```bash
GET /api/v1/users/?role=admin&ordering=-created_at&is_active=true
```

### Create a User

```bash
POST /api/v1/users/
{
  "email": "newuser@example.com",
  "password": "Str0ng!Pass123",
  "role": "member"
}
```

### Update a User's Role

```bash
PATCH /api/v1/users/<user_id>/role/
{
  "role": "admin"
}
```

**Roles:** `owner` (one per org), `admin`, `member`

---

## 5. Response Formats

### Paginated Lists

All list endpoints return paginated responses:

```json
{
  "count": 42,
  "next": "http://localhost:8000/api/v1/users/?page=2",
  "previous": null,
  "results": [
    { "id": "...", "email": "user@example.com", "role": "member" }
  ]
}
```

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `page` | 1 | — | Page number |
| `page_size` | 25 | 100 | Items per page |

Audit logs use **cursor-based pagination** (50 items/page) for efficiency at scale:

```json
{
  "next": "http://localhost:8000/api/v1/organizations/current/audit-logs/?cursor=cD0yMDI2...",
  "previous": null,
  "results": [ ... ]
}
```

### Error Responses

Every error follows a consistent envelope:

```json
{
  "error": "Bad Request",
  "code": "validation_error",
  "detail": {
    "email": ["This field is required."]
  },
  "status": 400
}
```

| Field | Type | Description |
|-------|------|-------------|
| `error` | string | Human-readable label |
| `code` | string | Machine-readable code for switch statements |
| `detail` | string / object / array | Specific error info |
| `status` | integer | HTTP status code |

**Error codes:** `validation_error`, `authentication_failed`, `not_authenticated`, `permission_denied`, `not_found`, `method_not_allowed`, `throttled`

---

## 6. Rate Limits

| Scope | Limit |
|-------|-------|
| Burst (per IP) | 20 requests/second |
| Organization | 1,000 requests/hour |
| API Key | 100 requests/minute |
| Anonymous | 10 requests/minute |

When rate-limited, you receive a `429` response with a `Retry-After` header.

---

## 7. Webhooks (Event Notifications)

Subscribe to real-time auth events via HTTP POST callbacks.

### Create a Webhook

```bash
curl -X POST http://localhost:8000/api/v1/organizations/current/webhooks/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhooks/hvt",
    "events": ["user.created", "user.deleted", "user.login"]
  }'
```

### Supported Events

| Event | Trigger |
|-------|---------|
| `user.created` | New user added |
| `user.updated` | User profile changed |
| `user.deleted` | User removed |
| `user.login` | Successful login |
| `user.role.changed` | Role modified |
| `api_key.created` | API key generated |
| `api_key.revoked` | API key deactivated |

### Verify Signatures

Every webhook includes an `X-HVT-Signature` header (HMAC-SHA256). Always verify before processing:

```python
import hmac, hashlib

def verify(payload_body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

> Full webhook documentation: [docs/WEBHOOKS.md](WEBHOOKS.md)

---

## 8. Audit Logs

Query authentication events for your organization.

### List Audit Events

```bash
GET /api/v1/organizations/current/audit-logs/
```

Filter by event type or outcome:

```bash
GET /api/v1/organizations/current/audit-logs/?event_type=user.login&success=true
```

Response:

```json
{
  "next": "...?cursor=cD0yMDI2...",
  "previous": null,
  "results": [
    {
      "id": "e5f6a7b8-...",
      "event_type": "user.login",
      "actor_email": "dev@example.com",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "created_at": "2026-03-04T10:30:00Z",
      "event_data": {}
    }
  ]
}
```

### Access Rules

| Role | Can See |
|------|---------|
| Owner / Admin | All org events (filterable by `actor_user`) |
| Member | Only their own events |
| API Key | All org events (read-only) |

### Logged Event Types

Authentication: `user.login`, `user.logout`, `login.failed`, `password.changed`, `password.reset.complete`, `email.verified`, `email.verification.sent`

Social auth: `social.account.connected`, `social.account.disconnected`

User lifecycle: `user.created`, `user.updated`, `user.deleted`, `user.role.changed`

Organization: `org.created`, `org.updated`

API keys: `api_key.created`, `api_key.revoked`

---

## 9. Permissions Matrix

Check what each role can do:

```bash
GET /api/v1/organizations/current/permissions/
```

Response:

```json
{
  "role": "admin",
  "permissions": {
    "users.list": true,
    "users.create": true,
    "webhooks.create": true,
    "audit_logs.list": true,
    "organization.delete": false
  },
  "matrix": {
    "users.list": { "owner": true, "admin": true, "member": true },
    "webhooks.create": { "owner": true, "admin": true, "member": false },
    "audit_logs.list": { "owner": true, "admin": true, "member": true }
  }
}
```

---

## Full Endpoint Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register/` | Create account |
| POST | `/api/v1/auth/login/` | Get JWT tokens |
| POST | `/api/v1/auth/logout/` | Invalidate session |
| POST | `/api/v1/auth/token/refresh/` | Refresh access token |
| GET | `/api/v1/auth/me/` | Current user profile |
| PATCH | `/api/v1/auth/me/` | Update profile |
| POST | `/api/v1/auth/password/reset/` | Request password reset |
| POST | `/api/v1/auth/password/change/` | Change password (authenticated) |
| POST | `/api/v1/auth/social/google/` | Google OAuth login |
| POST | `/api/v1/auth/social/github/` | GitHub OAuth login |

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations/` | List organizations |
| POST | `/api/v1/organizations/` | Create organization |
| GET | `/api/v1/organizations/current/` | Current org details |
| PATCH | `/api/v1/organizations/current/` | Update current org |
| GET | `/api/v1/organizations/current/members/` | List org members |

### API Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations/current/keys/` | List API keys |
| POST | `/api/v1/organizations/current/keys/` | Create API key |
| GET | `/api/v1/organizations/current/keys/<id>/` | Key details |
| DELETE | `/api/v1/organizations/current/keys/<id>/` | Delete key |
| PATCH | `/api/v1/organizations/current/keys/<id>/revoke/` | Deactivate key |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/` | List org users |
| POST | `/api/v1/users/` | Create user |
| GET | `/api/v1/users/<id>/` | User details |
| PATCH | `/api/v1/users/<id>/` | Update user |
| DELETE | `/api/v1/users/<id>/` | Remove user |
| PATCH | `/api/v1/users/<id>/role/` | Change role |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations/current/webhooks/` | List webhooks |
| POST | `/api/v1/organizations/current/webhooks/` | Create webhook |
| GET | `/api/v1/organizations/current/webhooks/<id>/` | Webhook details |
| PATCH | `/api/v1/organizations/current/webhooks/<id>/` | Update webhook |
| DELETE | `/api/v1/organizations/current/webhooks/<id>/` | Delete webhook |
| GET | `/api/v1/organizations/current/webhooks/<id>/deliveries/` | Delivery history |

### Audit & Permissions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations/current/audit-logs/` | List audit events |
| GET | `/api/v1/organizations/current/audit-logs/<id>/` | Event details |
| GET | `/api/v1/organizations/current/permissions/` | Permission matrix |

---

## Further Reading

- [API Key Guide](../API_KEY_GUIDE.md) — Detailed API key setup and Postman configuration
- [Browser Authentication](BROWSER_AUTHENTICATION.md) — JWT flow for frontend apps
- [Webhooks Guide](WEBHOOKS.md) — Full webhook setup, signatures, retry behavior
- [OpenAPI Schema](/api/docs/) — Interactive Swagger UI
