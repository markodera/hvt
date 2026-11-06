# HVT

HVT is an open-source authentication platform built with Django and Django REST Framework. It provides a control plane for organizations, projects, API keys, invites, webhooks, and audit logs, plus a runtime auth plane for customer-facing applications.

## Current Scope

- email and password authentication
- JWT access and refresh tokens
- registration, email verification, and password reset
- Google and GitHub social login
- organizations, projects, and API keys
- project-scoped runtime auth with shared identity across projects
- invitations, project roles, permissions, and audit logs
- webhook delivery for organization events

## Project Model

HVT separates two concerns:

- control plane: the dashboard and admin-facing APIs used to manage organizations, projects, API keys, social providers, invites, and webhooks
- runtime plane: project-scoped auth flows that your application uses for sign-up, sign-in, social login, verify-email, and password reset

**True Multi-Tenant Isolation:**
User accounts are strictly isolated at the project level. Unlike traditional Django apps where an email must be globally unique, HVT uses an Auth0-style composite identity model (`Project_ID + Email`). The same customer can sign up for multiple independent apps on your platform without user pools ever bleeding across boundaries.

## Repository Layout

- `hvt/`: Django project and application code
- `docs/`: setup, deployment, webhook, and frontend handoff guides
- `sdk/`: pointers to standalone SDK repositories
- `scripts/`: maintenance and build scripts
- `.github/`: CI and contribution templates

## Quick Start

### Local development

```bash
git clone https://github.com/markodera/hvt.git
cd hvt
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

The API will be available at `http://localhost:8000`.

### Production Self-Hosting with Docker Compose

HVT is designed to run securely in production with Docker Compose.

1. **Clone and create environment configuration:**
   ```bash
   git clone https://github.com/markodera/hvt.git
   cd hvt
   cp .env.example .env
   ```

2. **Generate required production secrets:**
   ```bash
   # Generate SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(50))"

   # Generate HVT_ENCRYPTION_KEYS (for MultiFernet encryption of TOTP and OAuth secrets)
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Add both generated keys and your production database password to `.env`:
   ```env
   SECRET_KEY=your_generated_secret_key_here
   HVT_ENCRYPTION_KEYS=your_generated_fernet_key_here
   DB_PASSWORD=your_secure_db_password
   ALLOWED_HOSTS=api.yourdomain.com
   FRONTEND_URL=https://app.yourdomain.com
   CORS_ALLOWED_ORIGINS=https://app.yourdomain.com
   CSRF_TRUSTED_ORIGINS=https://app.yourdomain.com
   ```

3. **Start the production stack:**
   ```bash
   docker compose up -d --build
   ```
   The container boots in production mode with Gunicorn, automatically waits for PostgreSQL health checks, runs database migrations, collects static assets, and exposes `http://0.0.0.0:8000`.

4. **Create initial administrator / owner:**
   ```bash
   docker compose exec web python manage.py createsuperuser
   ```

### Django Admin Interface (Opt-In)

For production security, the Django Admin interface is **disabled by default** (`EXPOSE_ADMIN=0`).
To enable it:
1. In `.env`, set `EXPOSE_ADMIN=1`.
2. Optionally configure a non-standard custom path for defense-in-depth:
   ```env
   DJANGO_ADMIN_PATH=secure-mgmt-portal/
   ```
3. Restart the service (`docker compose up -d`). Visiting `/secure-mgmt-portal/` will open the admin interface; the default `/admin/` endpoint remains inaccessible.

## Configuration

Start from [`.env.example`](.env.example). The checked-in defaults are intentionally local-development oriented. For hosted or production deployment to a VPS (e.g., DigitalOcean), see the setup scripts and `.github/workflows/deploy.yml` for the standard Nginx and Gunicorn configuration.

If you use runtime auth in a customer-facing app, set each project's `frontend_url` so email verification and password reset links land on the correct frontend.

## Public Endpoints

- Main app: [hvts.app](https://hvts.app)
- Direct API base URL: [api.hvts.app](https://api.hvts.app)
- Documentation: [docs.hvts.app](https://docs.hvts.app)

## Runtime API Notes

Runtime requests are authenticated with `X-API-Key` and require the `auth:runtime` scope.

Key runtime endpoints:

```text
POST /api/v1/auth/runtime/register/
POST /api/v1/auth/runtime/login/
GET  /api/v1/auth/runtime/social/providers/
POST /api/v1/auth/runtime/social/google/
POST /api/v1/auth/runtime/social/github/
POST /api/v1/auth/runtime/register/resend-email/
POST /api/v1/auth/runtime/register/verify-email/
POST /api/v1/auth/runtime/password/reset/
POST /api/v1/auth/runtime/password/reset/validate/
POST /api/v1/auth/runtime/password/reset/confirm/<uidb64>/<token>/
```

## Docs

- [Developer quickstart](docs/QUICKSTART.md)
- [Browser authentication guide](docs/BROWSER_AUTHENTICATION.md)
- [Webhook guide](docs/WEBHOOKS.md)
- [Runtime/frontend handoff](docs/RUNTIME_FRONTEND_HANDOFF.md)
- [SDK repo split guide](docs/SDK_REPO_SPLIT.md)
- [Open-source release checklist](docs/OPEN_SOURCE_RELEASE_CHECKLIST.md)

When running locally, OpenAPI docs are available at `/api/docs/` and `/api/redoc/` if `EXPOSE_API_DOCS=1`.

## Development

Run checks and tests before opening a pull request:

```bash
python manage.py check
python manage.py test
```

Contribution, conduct, and security reporting live here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

## TypeScript SDK

The TypeScript SDK now lives in its own repository so SDK contributors do not need the backend codebase.

- SDK repo: [markodera/hvt-sdk](https://github.com/markodera/hvt-sdk)
- NPM package: `@hvt/sdk`
- Hosted Cloud API: [api.hvts.app](https://api.hvts.app) (recommended default for AI agents and vibe coders)
- Direct API users can integrate against [api.hvts.app](https://api.hvts.app) without using an SDK or self-hosting

## License

HVT is licensed under the [Apache License, Version 2.0](LICENSE).
See the [NOTICE](NOTICE) file for copyright and attribution information.

> **Release Licensing Note:** Releases prior to v0.2.0 were licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). Starting with v0.2.0, HVT is licensed under the Apache-2.0 License.
