# Contributing to HVT

Thanks for contributing. Keep changes small, explicit, and test-backed.

This file covers the backend and platform repository. The TypeScript SDK is being prepared for its own repository. Until that split happens, SDK-specific notes live in [`sdk/typescript/CONTRIBUTING.md`](sdk/typescript/CONTRIBUTING.md).

## Ground Rules

- Open an issue before large changes, migrations, or behavior changes.
- Keep pull requests focused on one concern.
- Add or update tests for behavior changes.
- Do not commit secrets, production data, local logs, or scratch files.
- Prefer backward-compatible API changes unless a breaking change is intentional and documented.

## Development Setup

1. Clone the repository.
2. Copy `.env.example` to `.env`.
3. Start PostgreSQL and Redis locally, or use `docker-compose`.
4. Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

5. Run migrations:

```bash
python manage.py migrate
```

6. Start the API:

```bash
python manage.py runserver
```

## Running Tests

Run the full Django checks before opening a PR:

```bash
python manage.py check
python manage.py test
```

If you are changing runtime auth or project access behavior, also run the targeted runtime cases:

```bash
python manage.py test \
  hvt.apps.authentication.tests.RuntimePasswordResetFlowTest \
  hvt.apps.authentication.tests.RuntimeEmailVerificationFlowTest \
  hvt.apps.authentication.tests.RuntimeLoginFlowTest.test_runtime_login_allows_project_role_assignment_on_api_key_project \
  hvt.apps.organizations.tests.ProjectAndAPIKeyScopingTest.test_owner_can_create_project_with_frontend_url \
  hvt.apps.organizations.tests.ProjectAccessManagementTest.test_current_project_access_allows_cross_project_role_assignment \
  hvt.apps.organizations.tests_invitations.OrganizationInvitationAPITest.test_accept_same_org_project_invitation_preserves_org_and_grants_project_access
```

## Pull Requests

Include:

- the problem being solved
- the behavioral impact
- the validation you ran
- any migrations, rollout notes, or manual follow-up

If you add a migration, mention it explicitly in the PR description.

## Style

- Python: follow existing Django and DRF conventions.
- API responses: preserve the existing error envelope and authentication patterns.
- Docs: update the relevant guide when public API behavior changes.

## Security

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
