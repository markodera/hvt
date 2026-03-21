# Webhooks Guide

## Overview

HVT sends real-time HTTP POST notifications to your endpoints when authentication events occur. Webhooks let your application react immediately to user lifecycle changes without polling.

---

## Supported Events

| Event | Trigger |
|-------|---------|
| `user.created` | New user added to organization |
| `user.updated` | User profile fields changed |
| `user.deleted` | User removed from organization |
| `user.login` | User authenticated successfully |
| `user.role.changed` | User's role was modified |
| `api_key.created` | New API key generated |
| `api_key.revoked` | API key deleted or deactivated |

---

## Managing Webhooks

All webhook endpoints require **organization owner or admin** access (JWT or API key).

### Create a Webhook

```bash
POST /api/v1/organizations/current/webhooks/
Authorization: Bearer <access_token>
# OR
X-API-Key: hvt_live_xxx

{
  "url": "https://your-app.com/webhooks/hvt",
  "events": ["user.created", "user.deleted", "api_key.created"],
  "description": "Production webhook"
}
```

Response:
```json
{
  "id": "a1b2c3d4-...",
  "url": "https://your-app.com/webhooks/hvt",
  "events": ["user.created", "user.deleted", "api_key.created"],
  "description": "Production webhook",
  "is_active": true,
  "created_at": "2026-02-28T12:00:00Z",
  "last_triggered_at": null,
  "success_count": 0,
  "failure_count": 0,
  "consecutive_failures": 0
}
```

### List Webhooks

```bash
GET /api/v1/organizations/current/webhooks/
```

### Get / Update / Delete a Webhook

```bash
GET    /api/v1/organizations/current/webhooks/<id>/
PATCH  /api/v1/organizations/current/webhooks/<id>/
DELETE /api/v1/organizations/current/webhooks/<id>/
```

Update example — subscribe to additional events:
```bash
PATCH /api/v1/organizations/current/webhooks/<id>/
{
  "events": ["user.created", "user.deleted", "user.login", "api_key.created"]
}
```

### View Delivery History

```bash
GET /api/v1/organizations/current/webhooks/<id>/deliveries/
```

Response:
```json
[
  {
    "id": "...",
    "event_type": "user.created",
    "payload": { ... },
    "status": "success",
    "response_status_code": 200,
    "response_body": "OK",
    "error_message": "",
    "attempt_count": 1,
    "max_attempts": 3,
    "next_retry_at": null,
    "created_at": "2026-02-28T12:01:00Z",
    "delivered_at": "2026-02-28T12:01:01Z"
  }
]
```

---

## Webhook Payload Format

Every webhook delivery sends a JSON POST with this structure:

```json
{
  "event": "user.created",
  "delivery_id": "d4e5f6a7-...",
  "timestamp": "2026-02-28T12:01:00.000000+00:00",
  "organization_id": "a1b2c3d4-...",
  "data": {
    "user_id": "e5f6a7b8-...",
    "email": "newuser@example.com",
    "role": "member"
  }
}
```

### Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-HVT-Signature` | HMAC-SHA256 signature for verification |
| `X-HVT-Event` | Event type (e.g., `user.created`) |
| `X-HVT-Delivery` | Unique delivery ID |
| `User-Agent` | `HVT-Webhook/1.0` |

---

## Verifying Webhook Signatures

Every webhook is signed with your webhook's secret using **HMAC-SHA256**. Always verify signatures before processing payloads.

### Signature Format

The `X-HVT-Signature` header contains: `sha256=<hex_digest>`

### Verification Examples

**Python:**
```python
import hmac
import hashlib

def verify_webhook(payload_body: bytes, signature_header: str, secret: str) -> bool:
    expected = hmac.new(
        key=secret.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    ).hexdigest()
    expected_signature = f"sha256={expected}"
    return hmac.compare_digest(expected_signature, signature_header)

# In your view:
signature = request.headers.get('X-HVT-Signature', '')
if not verify_webhook(request.body, signature, WEBHOOK_SECRET):
    return HttpResponse(status=401)
```

**Node.js:**
```javascript
const crypto = require('crypto');

function verifyWebhook(payloadBody, signatureHeader, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payloadBody)
    .digest('hex');
  const expectedSignature = `sha256=${expected}`;
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(signatureHeader)
  );
}

// In your route handler:
app.post('/webhooks/hvt', (req, res) => {
  const signature = req.headers['x-hvt-signature'] || '';
  if (!verifyWebhook(req.rawBody, signature, process.env.HVT_WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  // Process event...
  res.status(200).send('OK');
});
```

> **Security:** Always use constant-time comparison (`hmac.compare_digest` / `crypto.timingSafeEqual`) to prevent timing attacks.

---

## Retry Behavior

| Aspect | Detail |
|--------|--------|
| **Max retries** | 3 attempts per delivery |
| **Backoff** | Exponential: 1s, 4s, 9s |
| **Timeout** | 10 seconds per attempt |
| **Success** | Any 2xx HTTP response |
| **Failure** | Non-2xx response or network error |
| **Auto-disable** | Webhook deactivated after 10 consecutive failures |

### Delivery Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Queued, not yet attempted |
| `retrying` | Failed, waiting for next retry |
| `success` | Delivered successfully (2xx response) |
| `failed` | All retry attempts exhausted |

### Auto-Disable

If a webhook accumulates **10 consecutive failures**, HVT automatically sets `is_active = false`. To re-enable:

```bash
PATCH /api/v1/organizations/current/webhooks/<id>/
{ "is_active": true }
```

The `consecutive_failures` counter resets to 0 on any successful delivery.

---

## Best Practices

### 1. Respond Quickly
Return a `200 OK` immediately and process the event asynchronously. HVT times out after 10 seconds.

```python
# ✅ Good — acknowledge immediately, process later
@app.route('/webhooks/hvt', methods=['POST'])
def handle_webhook():
    event = request.json
    queue.enqueue(process_event, event)  # Background job
    return '', 200

# ❌ Bad — slow processing blocks the response
@app.route('/webhooks/hvt', methods=['POST'])
def handle_webhook():
    event = request.json
    sync_user_to_database(event)  # Takes 5+ seconds
    send_welcome_email(event)     # Takes 3+ seconds
    return '', 200
```

### 2. Handle Duplicates (Idempotency)
Use the `delivery_id` field to detect and skip duplicate deliveries:

```python
def handle_webhook(payload):
    delivery_id = payload['delivery_id']
    if DeliveryLog.objects.filter(delivery_id=delivery_id).exists():
        return  # Already processed
    DeliveryLog.objects.create(delivery_id=delivery_id)
    # Process event...
```

### 3. Verify Signatures
Always validate `X-HVT-Signature` before trusting payload data. See examples above.

### 4. Use HTTPS
Always use `https://` URLs for webhook endpoints in production. HVT will deliver to HTTP URLs but they are **not recommended** outside of local development.

### 5. Subscribe to Specific Events
Only subscribe to events you need. Fewer events = less noise and fewer unnecessary deliveries:

```json
{
  "events": ["user.created", "user.deleted"]
}
```

If `events` is empty (`[]`), the webhook receives **all** event types.

### 6. Monitor Delivery Health
Check `success_count`, `failure_count`, and `consecutive_failures` on your webhook to detect issues early:

```bash
GET /api/v1/organizations/current/webhooks/<id>/
```

---

## Debugging

### Check Delivery Logs

```bash
GET /api/v1/organizations/current/webhooks/<id>/deliveries/
```

Each delivery includes:
- `status` — current delivery state
- `response_status_code` — HTTP status your server returned
- `response_body` — first 5KB of your server's response
- `error_message` — network/timeout error details
- `attempt_count` — how many attempts were made

### Common Issues

**Webhook never fires:**
- Check `is_active` is `true`
- Check the webhook's `events` list includes the event type
- Check the organization matches (webhooks are per-org)

**Getting `failed` status:**
- Your endpoint returning non-2xx status
- Network timeout (> 10 seconds)
- DNS resolution failure
- TLS/SSL certificate errors

**Webhook auto-disabled:**
- 10+ consecutive failures disable the webhook
- Fix the underlying issue, then re-enable with `PATCH`

### Enable Server Logs

```python
# settings.py
LOGGING = {
    "loggers": {
        "hvt.apps.organizations.webhooks": {
            "level": "DEBUG",
        },
    },
}
```

---

## Local Development

For testing webhooks locally, use a tunnel service:

```bash
# Using ngrok
ngrok http 8000
# Copy the HTTPS URL → use as webhook URL

# Using localtunnel
npx localtunnel --port 8000
```

Or use a webhook testing service like [webhook.site](https://webhook.site) to inspect payloads.
