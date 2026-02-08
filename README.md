# HVT – Open-Source Authentication Platform

> **"We remove authentication from your list of problems."**

## What Is HVT?

HVT is an **open-source, self-hostable authentication platform** for developers who want to ship fast without building auth from scratch.

**Think:** Auth0 for startups, but open-source and affordable.

---

## The Problem

Most developers waste **weeks** rebuilding the same authentication infrastructure:

* Email + password auth
* Social login (Google, GitHub, etc.)
* Token handling (JWT)
* Email verification
* Password resets
* User management

**Existing solutions:**
* **Firebase** → Closed-source, Google ecosystem lock-in, frontend-heavy
* **Auth0/Clerk** → Expensive ($25+/month), closed-source, pricing scales with users
* **DIY with Django/Passport** → Time-consuming, error-prone, hard to maintain

**We're building a better alternative:**
* ✅ Open-source (no vendor lock-in)
* ✅ Self-hostable (data stays with you)
* ✅ Affordable hosted option (predictable pricing)
* ✅ REST API-first (works with any stack)
* ✅ Simple & opinionated (just auth, done right)

---

## Who This Is For

We are **not** targeting:
* Complex enterprise RBAC systems
* Banks or government systems
* Massive multi-tenant IAM products

We **are** targeting:
* 🎯 Solo founders
* 🎯 Early-stage startups
* 🎯 Indie hackers
* 🎯 Small engineering teams
* 🎯 Products with simple onboarding needs

If you say:
> "I don't want to think about auth anymore"

You're our customer.

---

## How It Works (Data Model)

### We Store Your Users' Authentication Data

Unlike a library (Passport.js, NextAuth), HVT is a **hosted service**:

**What we store in our database:**
* User credentials (email, hashed passwords)
* Social login connections (Google, GitHub)
* Email verification status
* Basic profile data (first_name, last_name)

**What you store in your database:**
* App-specific user data (subscription plans, preferences, etc.)
* A reference to our user: `hvt_user_id`

**Example:**
```javascript
// Your app calls our API
const response = await fetch('https://hvt-api.com/v1/auth/register', {
  headers: { 'Authorization': 'Bearer hvt_live_abc123' },
  body: JSON.stringify({ email: 'user@example.com', password: '***' })
});

// We return: { user_id: 'usr_xyz789', token: 'jwt_token_here' }

// You store in YOUR database:
// { hvt_user_id: 'usr_xyz789', subscription: 'pro', tasks_count: 42 }
```

**Benefits:**
* No password management headaches
* No email delivery infrastructure
* No OAuth provider setup
* Just consume verified user identity

---

## How People Use HVT (3 Modes)

### Mode 1: Hosted (Recommended for Most)

Use our managed service:
1. Sign up and create an organization
2. Generate an API key from dashboard
3. Call our REST API from your backend
4. We handle auth, you get verified users

**Perfect for:**
* MVPs and early startups
* Teams without DevOps resources
* Apps needing fast time-to-market

---

### Mode 2: Self-Hosted (Open-Source)

Deploy HVT on your own infrastructure:
1. Clone this repository
2. Deploy via Docker/Kubernetes
3. Manage your own database and email delivery
4. Full control and customization

**Perfect for:**
* Privacy-conscious applications
* Data residency requirements (GDPR, HIPAA)
* Enterprises needing on-premise deployment
* Developers wanting full code ownership

---

### Mode 3: Hybrid (Best of Both)

Start hosted, migrate to self-hosted later:
* No lock-in (open-source code available)
* Export your data anytime
* Gradual transition as you scale

---

## Monetization Strategy (Open-Core Model)

We monetize **services**, not code.

### Free Tier (Self-Hosted)
* ✅ Full source code (MIT license)
* ✅ Unlimited users (on your infrastructure)
* ✅ DIY deployment
* ✅ Community support (Discord, GitHub Issues)

**Cost: $0** (you pay your cloud provider)

---

### Starter – $19/month (Hosted)
* ✅ Up to 2,500 users
* ✅ Email + password auth
* ✅ Social login (Google, GitHub)
* ✅ Email delivery infrastructure
* ✅ Dashboard & analytics
* ✅ Email support (48hr response)

**Value: We manage everything for you**

---

### Pro – $49/month (Hosted)
* ✅ Up to 10,000 users
* ✅ Everything in Starter
* ✅ Webhooks (user.created, user.login, etc.)
* ✅ Custom email templates
* ✅ Audit logs (90-day retention)
* ✅ Priority email support (24hr response)

**Value: Advanced features + better support**

---

### Enterprise – Custom Pricing (Hosted or On-Premise)
* ✅ Unlimited users
* ✅ Everything in Pro
* ✅ Custom domain (auth.yourcompany.com)
* ✅ Dedicated instance
* ✅ SSO/SAML support
* ✅ Audit logs (1-year+ retention)
* ✅ 99.9% SLA
* ✅ On-premise deployment support
* ✅ Compliance certifications (SOC2, ISO)
* ✅ Dedicated Slack channel

**Value: Enterprise-grade reliability + compliance**

---

**Why This Works:**

Companies **pay for convenience**, not code:
* Hosted infrastructure
* Email delivery (no SMTP headaches)
* 99.9% uptime guarantee
* Support when things break
* Time saved (weeks of development)

**Open-source builds trust. Hosting generates revenue.**

---

## API Reference (High-Level)

### Authentication Endpoints
```
POST   /api/v1/auth/register      → Create new user
POST   /api/v1/auth/login         → Authenticate user
POST   /api/v1/auth/logout        → Invalidate session
POST   /api/v1/auth/refresh       → Refresh access token
POST   /api/v1/auth/social/google → Google OAuth
POST   /api/v1/auth/social/github → GitHub OAuth
```

### User Management
```
GET    /api/v1/auth/me            → Get current user
PATCH  /api/v1/auth/me            → Update user profile
DELETE /api/v1/auth/me            → Delete user account
```

### Password & Email
```
POST   /api/v1/auth/password/reset-request  → Request password reset
POST   /api/v1/auth/password/reset-confirm  → Confirm new password
POST   /api/v1/auth/email/verify            → Verify email address
POST   /api/v1/auth/email/resend            → Resend verification
```

### Organization & API Keys (Platform)
```
POST   /api/v1/organizations               → Create organization
GET    /api/v1/organizations               → List organizations
GET    /api/v1/organizations/:id           → Get organization details
POST   /api/v1/organizations/:id/keys      → Generate API key
GET    /api/v1/organizations/:id/keys      → List API keys
DELETE /api/v1/organizations/:id/keys/:key → Revoke API key
```

All endpoints use **JWT token-based authentication** or **API key authentication**.

---

## Technical Stack

**Backend:**
* Django 5.x (rapid development, battle-tested)
* Django REST Framework (clean API design)
* PostgreSQL (reliable, scalable)
* django-allauth (social auth providers)
* SimpleJWT (stateless token management)

**Why Django?**
We use Django **internally**, but expose a **pure REST API**. Your app never depends on Django—just HTTP.

**Benefits:**
* Fast initial development
* Mature authentication libraries
* Excellent security track record
* Works with ANY frontend/backend stack

---

## Security Model

* ✅ Short-lived access tokens (15 minutes)
* ✅ Refresh tokens (7 days, rotated)
* ✅ Per-organization API keys
* ✅ Argon2 password hashing
* ✅ Rate limiting (by API key + IP)
* ✅ Email verification enforcement
* ✅ HTTPS-only in production
* ✅ CORS configuration per organization

**No shortcuts. Security is non-negotiable.**

---

## Roadmap

### Phase 1: Core Authentication ✅ (Current)
- [x] Email/password auth
- [x] JWT token management
- [x] User model + organizations
- [x] Social login (Google, GitHub)
- [x] Email verification flow
- [x] Password reset flow

### Phase 2: Platform Infrastructure
- [x] API key generation & management
- [x] Rate limiting per organization
- [x] Organization roles & permissions
- [ ] Webhooks system
- [ ] Audit logging

### Phase 3: Developer Experience
- [ ] API documentation (OpenAPI/Swagger)
- [ ] JavaScript SDK
- [ ] Python SDK
- [ ] Example integrations (Next.js, Express, Django)

### Phase 4: Production & Hosting
- [ ] Docker containerization
- [ ] Kubernetes deployment configs
- [ ] Managed hosting infrastructure
- [ ] Customer dashboard
- [ ] Billing integration

---

## What Differentiates Us from Competitors?

| Feature | HVT | Firebase Auth | Auth0 | Clerk |
|---------|-----|---------------|-------|-------|
| **Open-Source** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Self-Hostable** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **REST API-First** | ✅ Yes | ⚠️ SDK-heavy | ✅ Yes | ✅ Yes |
| **Pricing Model** | Flat rate | Pay-per-use | Per user | Per user |
| **Starter Price** | $19/mo | Free tier | $23/mo | $25/mo |
| **Data Ownership** | ✅ Full | ❌ Google-only | ❌ Auth0-only | ❌ Clerk-only |
| **Backend Focus** | ✅ Yes | ⚠️ Frontend-heavy | ✅ Yes | ⚠️ Frontend-heavy |

**Our Advantage:**
* Open-source → Trust & customization
* Self-hostable → Data sovereignty
* Affordable → Predictable costs for startups
* Simple → Just auth, done right

---

## Getting Started (Self-Hosted)

### Prerequisites
* Python 3.11+
* PostgreSQL 14+
* Docker (optional)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/hvt.git
cd hvt

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

Visit http://localhost:8000/admin to access the admin panel.

---

## Documentation

* **API Docs:** [Coming Soon]
* **Integration Guides:** [Coming Soon]
* **Self-Hosting Guide:** [Coming Soon]

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

**Open code. Paid hosting. Fair business.**

---

## Support

* **Community:** [Discord Server] (Coming Soon)
* **Issues:** [GitHub Issues](https://github.com/yourusername/hvt/issues)
* **Email:** support@hvt.dev (Paid customers only)

---

**Built with ❤️ for developers who just want to ship.**
