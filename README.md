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

User accounts are shared at the organization level, while runtime access is enforced per project through direct membership or assigned project roles.

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

### Docker

```bash
cp .env.example .env
docker-compose up --build
```

The compose stack starts PostgreSQL, Redis, and the Django API.

## Configuration

Start from [`.env.example`](.env.example). The checked-in defaults are intentionally local-development oriented. For hosted or production deployment, override the security and domain settings documented in [docs/RAILWAY_DEPLOYMENT.md](docs/RAILWAY_DEPLOYMENT.md).

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
- [Railway deployment](docs/RAILWAY_DEPLOYMENT.md)
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
- Direct API users can integrate against [api.hvts.app](https://api.hvts.app) without using an SDK

## License

HVT is released under the [GNU Affero General Public License v3.0 only](LICENSE).
