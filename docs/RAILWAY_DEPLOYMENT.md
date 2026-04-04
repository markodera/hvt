# Railway Deployment

## Why Your Deploy Failed

This error:

```text
django.db.utils.OperationalError: could not translate host name "postgres.railway.internal" to address
```

means the app tried to run migrations before Railway database networking was available, or the web service was not actually receiving the Postgres service `DATABASE_URL`.

This repo now waits for database connectivity before Railway runs `migrate`.

## Railway Variables

Set these on the Railway web service:

```env
DEBUG=0
SECRET_KEY=replace-with-a-long-random-secret
ALLOWED_HOSTS=api.hvts.app,healthcheck.railway.app
FRONTEND_URL=https://hvts.app
RAILWAY_PUBLIC_DOMAIN=
CORS_ALLOWED_ORIGINS=https://hvts.app,https://docs.hvts.app
CSRF_TRUSTED_ORIGINS=https://hvts.app,https://api.hvts.app,https://docs.hvts.app
DATABASE_URL=${{Postgres.DATABASE_URL}}
USE_REDIS_CACHE=0
WAIT_FOR_DB=1
DB_CONNECT_MAX_ATTEMPTS=45
DB_CONNECT_RETRY_DELAY=2
RUN_MIGRATIONS=0
COLLECTSTATIC_ON_START=1
EXPOSE_ADMIN=0
EXPOSE_API_DOCS=0
DEFAULT_FROM_EMAIL=noreply@hvts.app
```

## Important

- In Railway, `DATABASE_URL` should come from the Postgres service variable reference, not a manually copied host string.
- Keep `RUN_MIGRATIONS=0` because Railway already runs migrations through `railway.json`.
- When you attach custom domains, your backend should be `api.hvts.app`, your frontend `hvts.app`, and docs `docs.hvts.app`.
