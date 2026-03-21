# Browser Authentication Guide

## Overview
HVT supports two authentication modes for browser-based applications:

1. **JWT Tokens** (B2C) - For customer-facing apps where users log in with email/password
2. **API Keys** (B2B) - For embedded integrations where your app calls HVT on behalf of users

## JWT Authentication (Standard Browser Flow)

### Use Case
Your frontend app where **end users** directly interact with HVT.

### How It Works
```javascript
// 1. User logs in
const loginResponse = await fetch('http://localhost:8000/api/v1/auth/login/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',  // Important: sends/receives cookies
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123'
  })
});

const { access, refresh } = await loginResponse.json();

// 2. Store access token (choose one method)
localStorage.setItem('access_token', access);  // Option A
// OR use httpOnly cookies (more secure) - refresh token already in cookie

// 3. Make authenticated requests
const usersResponse = await fetch('http://localhost:8000/api/v1/users/', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
  }
});
```

### Security Notes
- ✅ Access token expires in 15 minutes
- ✅ Refresh token in httpOnly cookie (not accessible to JavaScript)
- ⚠️ XSS can steal access token from localStorage
- ✅ Use Content Security Policy (CSP) headers

---

## API Key Authentication (Embedded Integration)

### Use Case
Your **backend server** calls HVT on behalf of your users. Your frontend never sees the API key.

### Architecture

```
User's Browser → Your Frontend → Your Backend → HVT API
                                     ↑
                              API Key stored here
```

### Example: React + Express

**Frontend (React):**
```javascript
// frontend/src/services/auth.js
export async function createUser(userData) {
  // Call YOUR backend, not HVT directly
  const response = await fetch('https://your-api.com/api/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // Your own auth (e.g., session cookie, Firebase token)
      'Authorization': `Bearer ${yourOwnUserToken}`
    },
    body: JSON.stringify(userData)
  });
  
  return response.json();
}
```

**Backend (Express):**
```javascript
// backend/routes/users.js
const express = require('express');
const router = express.Router();

// API key stored in environment variable (NEVER in frontend)
const HVT_API_KEY = process.env.HVT_API_KEY;

router.post('/api/users', async (req, res) => {
  // Verify YOUR user is authenticated
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Call HVT with API key
  const hvtResponse = await fetch('http://hvt-server.com/api/v1/users/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': HVT_API_KEY  // API key stays on server
    },
    body: JSON.stringify(req.body)
  });
  
  const data = await hvtResponse.json();
  res.json(data);
});

module.exports = router;
```

**Why This Works:**
- ✅ API key never exposed to browser
- ✅ No XSS risk for HVT credentials
- ✅ You control rate limiting and access
- ✅ Can add business logic before calling HVT

---

## ⚠️ DANGER: API Keys Directly in Browser

### What NOT to Do

```javascript
// ❌ NEVER DO THIS - API key exposed in browser!
const response = await fetch('http://localhost:8000/api/v1/users/', {
  headers: {
    'X-API-Key': 'hvt_live_abc123...'  // VISIBLE IN BROWSER DEV TOOLS!
  }
});
```

### Why It's Dangerous
1. **Anyone can steal it**: Open DevTools → Network tab → See the key
2. **No rate limiting per user**: All users share the same quota
3. **Can't revoke per-user access**: Must revoke entire key
4. **Source code exposure**: If you bundle it in JS, it's in the source

### Exceptions (Rare Cases)
You might use API keys directly in browser if:
- **Demo/testing environment only**
- **Public read-only API** (like weather data)
- **Short-lived keys** that expire in minutes
- **Rate-limited by IP** on the server side

---

## Recommended Architectures

### Architecture 1: Pure JWT (B2C SaaS)
**Best for**: Customer-facing apps where users create accounts

```
┌─────────────┐
│   Browser   │
│             │
│ JWT stored  │
│ in memory/  │
│ localStorage│
└──────┬──────┘
       │ Authorization: Bearer <jwt>
       ↓
┌─────────────┐
│  HVT API    │
│             │
│ Validates   │
│ JWT         │
└─────────────┘
```

**Frontend Code:**
```javascript
// Store token after login
const { access } = await login(email, password);
sessionStorage.setItem('token', access);  // Or use Context API

// Protected component
function UsersList() {
  const [users, setUsers] = useState([]);
  
  useEffect(() => {
    fetch('http://localhost:8000/api/v1/users/', {
      headers: {
        'Authorization': `Bearer ${sessionStorage.getItem('token')}`
      }
    })
      .then(res => res.json())
      .then(setUsers);
  }, []);
  
  return <ul>{users.map(u => <li key={u.id}>{u.email}</li>)}</ul>;
}
```

---

### Architecture 2: Backend Proxy (B2B Integration)
**Best for**: Your app uses HVT as authentication service

```
┌─────────────┐
│   Browser   │
│             │
│ Your app's  │
│ session     │
└──────┬──────┘
       │ Your auth
       ↓
┌─────────────┐
│ Your Backend│
│             │
│ HVT API Key │ ──── X-API-Key: hvt_live_xxx ────┐
└─────────────┘                                   │
                                                  ↓
                                           ┌─────────────┐
                                           │  HVT API    │
                                           │             │
                                           │ Validates   │
                                           │ API Key     │
                                           └─────────────┘
```

**Frontend (Next.js):**
```javascript
// pages/api/auth/register.js (API Route)
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).end();
  }
  
  // Call HVT from server-side
  const hvtResponse = await fetch('http://localhost:8000/api/v1/auth/register/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': process.env.HVT_API_KEY  // Server-side env var
    },
    body: JSON.stringify(req.body)
  });
  
  const data = await hvtResponse.json();
  
  // Create your own session
  req.session.user = data.user;
  
  res.json(data);
}
```

```javascript
// pages/register.js (Client component)
export default function Register() {
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Call YOUR API route, not HVT directly
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: e.target.email.value,
        password: e.target.password.value
      })
    });
    
    if (response.ok) {
      router.push('/dashboard');
    }
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
}
```

---

### Architecture 3: Hybrid (Both)
**Best for**: Multi-tenant B2B SaaS with embedded auth

```
End Users ──JWT──> Your App ──API Key──> HVT
(B2C)             (B2B)                (Auth Service)

- End users authenticate with your app (JWT)
- Your app manages orgs/teams (API Key per org)
- Each API key represents one tenant/organization
```

---

## CORS Configuration

If calling HVT directly from browser (JWT mode), configure CORS:

**HVT settings.py:**
```python
# Install: pip install django-cors-headers

INSTALLED_APPS = [
    'corsheaders',
    # ...
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ...
]

# Development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8080",
]

# Production
CORS_ALLOWED_ORIGINS = [
    "https://your-app.com",
]

# Allow credentials (cookies)
CORS_ALLOW_CREDENTIALS = True
```

---

## Security Checklist

### For JWT in Browser
- [ ] Use `httpOnly` cookies for refresh tokens
- [ ] Store access tokens in memory or sessionStorage (not localStorage for sensitive apps)
- [ ] Implement token refresh before expiry
- [ ] Use HTTPS in production
- [ ] Set Content-Security-Policy headers
- [ ] Validate on both client and server

### For API Keys (Backend Only)
- [ ] **NEVER** expose API keys in frontend code
- [ ] Store in environment variables
- [ ] Use different keys for dev/staging/prod
- [ ] Rotate keys regularly
- [ ] Monitor usage via `last_used_at`
- [ ] Implement rate limiting per key
- [ ] Use HTTPS for all API calls

---

## Testing in Browser

### JWT Flow (DevTools)
1. Open browser DevTools (F12)
2. Go to **Network** tab
3. Login → See `Set-Cookie` header with refresh token
4. Make request → See `Authorization: Bearer xxx` header
5. Check **Application** tab → See token in Storage

### API Key Flow (Should NOT work from browser)
```javascript
// This will fail with CORS error (good!)
fetch('http://localhost:8000/api/v1/users/', {
  headers: { 'X-API-Key': 'hvt_live_xxx' }
})
.catch(err => console.log('Expected error:', err));
```

---

## Quick Reference

| Scenario | Auth Method | Where Token Lives | Security Level |
|----------|-------------|-------------------|----------------|
| User logs into your app | JWT | Browser (storage/memory) | ⭐⭐⭐ Medium |
| Your backend calls HVT | API Key | Server environment | ⭐⭐⭐⭐⭐ High |
| Public demo/testing | API Key | Browser (temporary) | ⭐ Low |
| Embedded iframe | JWT (cross-origin) | iframe storage | ⭐⭐ Medium-Low |

---

## Example: Full Stack App

**Tech Stack**: React + Django (your app) + HVT

**Flow:**
1. User registers on your frontend
2. Your Django backend receives request
3. Django calls HVT with API key to create user
4. Django creates session for user
5. Frontend stores session cookie
6. User is authenticated with YOUR app
7. Your backend handles all HVT calls

**Code:**
```python
# your_app/views.py
import requests
from django.conf import settings

def register_user(request):
    # Call HVT with API key
    response = requests.post(
        'http://localhost:8000/api/v1/auth/register/',
        headers={'X-API-Key': settings.HVT_API_KEY},
        json=request.data
    )
    
    if response.status_code == 201:
        # Create local user record
        user = User.objects.create(
            email=request.data['email'],
            hvt_user_id=response.json()['user']['id']
        )
        
        # Create Django session
        login(request, user)
        
        return JsonResponse({'success': True})
```

This way, your users never interact with HVT directly - they only interact with your app!
