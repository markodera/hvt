# Open Source Release Checklist

Use this before flipping the repository public.

## Repository Content

- remove internal scratch files, logs, generated archives, and local temp directories
- confirm `.env` is ignored and not tracked
- verify `.env.example` contains placeholders only
- confirm public docs match the current API and deployment model

## Security and Governance

- choose and commit a license
- add a code of conduct, contributing guide, and security policy
- enable GitHub private vulnerability reporting
- enable Dependabot alerts and secret scanning
- rotate any credential that may have existed in local history, staging, or screenshots

## GitHub Configuration

- set the repository description, topics, and homepage
- enable branch protection on `main`
- require CI before merge
- add maintainers and review rules
- publish issue templates and a PR template

## Release Hygiene

- tag the first public release
- publish release notes with known limitations
- verify the README quickstart from a clean machine
- confirm Docker, local setup, and docs links all work end to end
