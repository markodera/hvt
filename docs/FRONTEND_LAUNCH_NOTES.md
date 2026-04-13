# Frontend Launch Notes

See [RUNTIME_FRONTEND_HANDOFF.md](/c:/Users/MARK/Documents/GitHub/hvt/docs/RUNTIME_FRONTEND_HANDOFF.md) for the current backend contract, frontend branching rules, and remaining launch blockers around runtime auth.

## Core Product Decisions

- Launch is single-organization for now.
- Users should not be offered a "switch organization" UX yet.
- Multi-organization can be added later as a paid/expanded feature.

## API Keys

- API keys are now scope-aware for read access.
- New frontend flows should only offer canonical scopes:
  - `organization:read`
  - `users:read`
  - `api_keys:read`
  - `webhooks:read`
  - `audit_logs:read`
  - `auth:runtime`
- Do not create keys with an empty scope list.
- Runtime app keys must include `auth:runtime`.

## Projects Are the Real Isolation Boundary

- API keys can be project-scoped.
- Webhooks are project-scoped.
- Audit-log visibility through API keys is project-scoped.
- Runtime auth is project-aware:
  - if an API key is project-scoped, runtime users must belong to that project
  - runtime social provider discovery is filtered to the API key project

## UX Implications

- API key creation UI should include project selection.
- Project creation/edit UI should expose an optional runtime frontend URL for project-scoped email links.
- Webhook creation UI should include project selection and show project metadata.
- Audit log screens should assume API-key views may be narrower than org-admin JWT views.
- Runtime auth setup UI should clearly label `auth:runtime` as required for runtime login and runtime social auth.
- Permissions screens for API keys should reflect scopes rather than showing blanket read access.

## Auth Notes

- Cookie refresh now re-sets auth cookies on `/api/v1/auth/token/refresh/`.
- Frontend using cookie auth can rely on refresh responses to rotate cookies correctly.
- Runtime password reset now exists at:
  - `POST /api/v1/auth/runtime/password/reset/`
  - `POST /api/v1/auth/runtime/password/reset/validate/`
  - `POST /api/v1/auth/runtime/password/reset/confirm/<uidb64>/<token>/`
- Runtime resend verification now exists at `POST /api/v1/auth/runtime/register/resend-email/`.
- Runtime verification/reset emails use the project-level frontend URL when configured.
- Public invite accept flows can use:
  - `GET /api/v1/organizations/invitations/lookup/?token=...`
  - `POST /api/v1/organizations/invitations/accept/`

## Local Development

- Debug/test mode now tolerates `testserver` in `ALLOWED_HOSTS`.
- Debug/local runs default to locmem cache unless `USE_REDIS_CACHE=1` is explicitly enabled.
