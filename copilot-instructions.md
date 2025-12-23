# HVT - Auth Service Platform

## Project Overview

Framework-agnostic authentication API platform built with Django 5.2. Exposes clean HTTP REST APIs—consumers never depend on Django internals.

**Full product context:** See [README](/Users/MARK\Documents/GitHub/hvt/README) for vision, API contracts, and monetization strategy.

## Architecture

### Directory Structure

```
hvt/
├── apps/                    # Django apps (domain modules)
│   ├── authentication/      # Login, logout, tokens, password reset
│   ├── organizations/       # Orgs, API keys, multi-tenancy
│   └── users/               # User profiles, account management
├── api/v1/                  # Versioned API layer
│   ├── serializers/         # DRF serializers
│   └── views/               # DRF viewsets/views
└── settings.py              # Django config
```

### Key Design Decisions

- **API-first**: All functionality exposed via `/v1/` REST endpoints, not Django views
- **JWT tokens**: Use short-lived access + refresh tokens, not Django sessions
- **Multi-tenant**: Organizations own users; API keys scoped per-org
- **Versioned API**: All routes under `/v1/` for future compatibility

## Development Commands

```bash
python manage.py runserver          # Start dev server
python manage.py makemigrations     # Create migrations after model changes
python manage.py migrate            # Apply migrations
python manage.py test               # Run all tests
python manage.py createsuperuser    # Create admin user
```

## Coding Conventions

### Models

- Define models in `hvt/apps/<app>/models.py`
- Use `UUIDField` for public-facing IDs (not auto-increment PKs)
- Add `created_at` and `updated_at` timestamps to all models

### API Endpoints

- Serializers go in `hvt/api/v1/serializers/`
- Views go in `hvt/api/v1/views/`
- Follow REST conventions: `POST` create, `GET` read, `PATCH` update, `DELETE` remove
- Return consistent JSON responses with `data`, `error`, `message` structure

### Planned API Routes (implement under `/v1/`)

```
POST   /v1/auth/register, /v1/auth/login, /v1/auth/logout, /v1/auth/refresh
GET    /v1/users/me          PATCH /v1/users/me
POST   /v1/auth/password/reset-request, /v1/auth/password/reset-confirm
POST   /v1/orgs              GET /v1/orgs/:id        POST /v1/orgs/:id/keys
```

## Dependencies (to be added)

- `djangorestframework` - API layer
- `djangorestframework-simplejwt` - JWT authentication
- `django-allauth` - Social login providers
- `dj-rest-auth` - Rest Endpoint

## Testing

- Write tests in `hvt/apps/<app>/tests.py`
- Test API endpoints with DRF's `APITestCase`
- Mock external services (email, social providers)
