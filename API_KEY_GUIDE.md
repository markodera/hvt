# API Key Authentication Guide

## Overview
HVT supports API key authentication for B2B integrations. External applications can use API keys instead of JWT tokens to access protected endpoints.

## How It Works

### Authentication Order
DRF processes authentication classes in order (defined in `settings.py`):
1. **JWT Authentication** (checks `Authorization: Bearer <token>` header)
2. **API Key Authentication** (checks `X-API-Key: <key>` header)

**IMPORTANT**: The first authentication method that succeeds "wins". If you send both headers, JWT will be used and the API key will be ignored.

## Creating API Keys

### 1. Register & Login
```bash
POST /api/v1/auth/register/
{
  "email": "user@example.com",
  "password": "securepass123",
  "password2": "securepass123"
}

POST /api/v1/auth/login/
{
  "email": "user@example.com",
  "password": "securepass123"
}
```

### 2. Create Organization (if not exists)
```bash
POST /api/v1/organizations/
Authorization: Bearer <access_token>

{
  "name": "My Company",
  "slug": "my-company"
}
```

### 3. Generate API Key
```bash
POST /api/v1/organizations/<org_id>/api-keys/
Authorization: Bearer <access_token>

{
  "name": "Production Key",
  "scopes": ["read", "write"]
}
```

Response:
```json
{
  "id": "...",
  "key": "hvt_live_abc123...",  // ⚠️ SAVE THIS - shown only once!
  "name": "Production Key",
  "scopes": ["read", "write"],
  "created_at": "2026-01-06T15:30:00Z"
}
```

## Using API Keys

### ✅ Correct Usage
Send **ONLY** the `X-API-Key` header:

```bash
# cURL
curl -H "X-API-Key: hvt_live_abc123..." \
  http://localhost:8000/api/v1/users/

# Python requests
import requests
headers = {"X-API-Key": "hvt_live_abc123..."}
response = requests.get("http://localhost:8000/api/v1/users/", headers=headers)

# JavaScript fetch
fetch('http://localhost:8000/api/v1/users/', {
  headers: {
    'X-API-Key': 'hvt_live_abc123...'
  }
})
```

### ❌ Common Mistakes

**1. Sending both JWT and API key**
```bash
# DON'T DO THIS - JWT will be used, API key ignored
curl -H "Authorization: Bearer <jwt_token>" \
     -H "X-API-Key: hvt_live_abc123..." \
     http://localhost:8000/api/v1/users/
```

**2. Wrong header name**
```bash
# DON'T DO THIS - must be "X-API-Key" (case-insensitive)
curl -H "API-Key: hvt_live_abc123..." \
     http://localhost:8000/api/v1/users/
```

**3. Wrong key format**
```bash
# DON'T DO THIS - must include full key with prefix
curl -H "X-API-Key: abc123..." \
     http://localhost:8000/api/v1/users/
```

## Postman Configuration

### Setup
1. Create a new request in Postman
2. Set URL: `GET http://localhost:8000/api/v1/users/`
3. Go to **Headers** tab
4. Add header:
   - Key: `X-API-Key`
   - Value: `hvt_live_abc123...`
5. **IMPORTANT**: Make sure **Authorization** tab is set to "No Auth" or remove any Authorization headers

### Troubleshooting

**Problem**: Getting 403 Forbidden even though API key is valid

**Check**:
1. Open Postman **Console** (View → Show Postman Console)
2. Look at request headers sent
3. If you see **both** `Authorization` and `X-API-Key` headers:
   - Go to **Authorization** tab → Select "No Auth"
   - Go to **Headers** tab → Uncheck/delete any `Authorization` header
   - Remove any Collection-level or Environment-level auth settings

**Problem**: Getting 401 Unauthorized

**Possible causes**:
- API key is invalid or expired
- Wrong header name (must be `X-API-Key`)
- Key format is wrong (must start with `hvt_live_`)
- Key was not saved correctly during creation

## API Key Format

```
hvt_live_<64-character-hex-string>
         └── Random cryptographic token
└── Environment prefix (live/test)
```

Example: `hvt_live_df7ec39866f7880297574e7d81629853e2ee6c7028c30b40160110af24598ecd`

## Security Best Practices

1. **Store securely**: Treat API keys like passwords
2. **Use environment variables**: Never hardcode keys
3. **Rotate regularly**: Create new keys and revoke old ones
4. **Limit scopes**: Only grant necessary permissions
5. **Monitor usage**: Check `last_used_at` for suspicious activity
6. **Use HTTPS**: Always use encrypted connections in production

## Testing

Run the test script:
```bash
python test_api_key.py hvt_live_abc123...
```

Or run the test suite:
```bash
python manage.py test hvt.apps.authentication.tests.APIKeyAuthenticationTest
```

## Debugging

Enable debug logging in `settings.py`:
```python
LOGGING = {
    "loggers": {
        "hvt.apps.authentication": {
            "level": "DEBUG",
        },
        "hvt.apps.users": {
            "level": "DEBUG",
        },
    },
}
```

Check server logs for:
- `[APIKeyAuthentication]` - Authentication backend processing
- `[IsAdminOrAPIKey]` - Permission checks
- `request.auth` should be `APIKey` instance, not `AccessToken`
