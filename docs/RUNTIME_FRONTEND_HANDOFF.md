# Runtime Frontend Handoff

This is the backend-to-frontend contract for launch prep across runtime auth, project access, and project-scoped social login.

## Confirmed Backend Behavior

- Runtime signup exists at `POST /api/v1/auth/runtime/register/` and requires `X-API-Key` with `auth:runtime`.
- Runtime resend verification exists at `POST /api/v1/auth/runtime/register/resend-email/`.
- Runtime verify-email alias exists at `POST /api/v1/auth/runtime/register/verify-email/`.
- Runtime login exists at `POST /api/v1/auth/runtime/login/` and issues project-scoped JWT claims when the API key is project-scoped.
- Runtime session bootstrap/introspection exists at `GET /api/v1/auth/runtime/me/` and returns the authenticated runtime user plus effective app roles/permissions for the JWT project context.
- Runtime password reset exists at:
  - `POST /api/v1/auth/runtime/password/reset/`
  - `POST /api/v1/auth/runtime/password/reset/validate/`
  - `POST /api/v1/auth/runtime/password/reset/confirm/<uidb64>/<token>/`
- Runtime social provider discovery exists at `GET /api/v1/auth/runtime/social/providers/` and is filtered to the API key project.
- Runtime Google and GitHub login exist at:
  - `POST /api/v1/auth/runtime/social/google/`
  - `POST /api/v1/auth/runtime/social/github/`
- Projects can now store an optional `frontend_url`.
  - Runtime verification and password reset emails use `project.frontend_url` when the request is API-key scoped, and fall back to global `FRONTEND_URL` otherwise.
- Project-level social provider config CRUD exists for the dashboard at:
  - `GET/POST /api/v1/organizations/current/projects/<project_pk>/social-providers/`
  - `GET/PATCH/DELETE /api/v1/organizations/current/projects/<project_pk>/social-providers/<id>/`
- Existing org members can be granted access to another project through project role assignment at:
  - `GET/PUT/PATCH /api/v1/organizations/current/projects/<project_pk>/users/<user_pk>/roles/`
- Current project access introspection exists at:
  - `GET /api/v1/organizations/current/projects/<project_pk>/access/`
- Invitation lookup and accept flows exist at:
  - `GET /api/v1/organizations/invitations/lookup/?token=...`
  - `POST /api/v1/organizations/invitations/accept/`
- Auth throttling is standardized. `429` responses include:
  - `detail.message`
  - `detail.retry_after_seconds`
  - `detail.retry_after_human`

## Frontend Decision Table

- New runtime user for a project:
  - Use `POST /api/v1/auth/runtime/register/`
  - Expect verification email flow and project-scoped membership on success
- Runtime forgot-password:
  - Use `POST /api/v1/auth/runtime/password/reset/` with the app API key
  - Frontend should use the runtime reset confirm alias when submitting the new password
- Runtime resend verification:
  - Use `POST /api/v1/auth/runtime/register/resend-email/` with the app API key
- Existing org member who needs access to another project:
  - Do not use runtime signup
  - Use a project invitation with app roles or dashboard project-role assignment
- Invited user who does not yet belong to an organization:
  - Use invitation lookup plus invitation accept flow
- Existing same-org member invited into another project:
  - Use invitation lookup plus invitation accept flow
  - Keep the user in the same organization
  - Rotate auth tokens into the invited project immediately after acceptance
- Runtime social login:
  - Load enabled providers from `GET /api/v1/auth/runtime/social/providers/`
  - Start OAuth only for providers returned by that endpoint
  - Send the exact selected `callback_url` back to the backend when finishing social login
- Runtime session bootstrap:
  - Call `GET /api/v1/auth/runtime/me/`
  - If `401`, call `POST /api/v1/auth/token/refresh/`
  - Retry `GET /api/v1/auth/runtime/me/`
- Cookie auth refresh:
  - `POST /api/v1/auth/token/refresh/` rotates cookies and can be treated as the session refresh path

## Product Constraints To Surface In UI

- Launch is single-organization for now.
- Shared identity currently means one user can access multiple projects inside the same organization.
- Project access is the real isolation boundary, not just organization membership.
- Each runtime project can point at its own frontend base URL for verification/reset links.
- Runtime app API keys must include `auth:runtime`.
- Runtime social login is project-scoped. A provider configured on Project A is not available to Project B.

## Confirmed Gaps

- Runtime signup still rejects duplicate emails. There is no self-service "existing account, add me to this project" flow.
- The docs do not yet describe:
  - shared identity across projects
  - the `retry_after_human` throttling payload
  - the correct frontend branching between signup, runtime reset, invite accept, and project-access assignment

## Backend Work Needed Before Frontend Handoff Is Fully Safe

1. Decide whether project invitations for existing same-org users should require explicit app roles or may rely on project default signup roles.
2. Update public docs and schema examples for:
   - runtime password reset
   - runtime resend verification
   - project `frontend_url`
   - the throttling payload
   - the shared-identity model

## Recommended Frontend Handoff Scope

- Safe to hand off now:
  - project CRUD
  - project frontend URL configuration
  - API key creation with project selection and `auth:runtime`
  - project social provider config UI
  - runtime login
  - runtime session bootstrap via `runtime/me`
  - runtime password reset
  - runtime resend verification
  - runtime social provider discovery
  - runtime social callback handling
  - invite lookup and invite accept
  - rate-limit UI using `retry_after_human`
- Hold until backend hardening is complete:
  - any UX that implies self-service project joining for an already-existing account
