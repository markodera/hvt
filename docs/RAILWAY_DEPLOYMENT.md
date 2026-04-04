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
USE_REDIS_CACHE=1
REDIS_URL=${{Redis.REDIS_URL}}
WAIT_FOR_DB=1
DB_CONNECT_MAX_ATTEMPTS=45
DB_CONNECT_RETRY_DELAY=2
RUN_MIGRATIONS=0
COLLECTSTATIC_ON_START=1
EXPOSE_ADMIN=0
EXPOSE_API_DOCS=0
DEFAULT_FROM_EMAIL=noreply@hvts.app
DJANGO_SUPERUSER_EMAIL=admin@hvts.app
DJANGO_SUPERUSER_PASSWORD=replace-with-a-strong-password
```

## Important

- In Railway, `DATABASE_URL` should come from the Postgres service variable reference, not a manually copied host string.
- For Redis, do not run a second Redis process inside the same web container on Railway. Add a Railway Redis service and set `REDIS_URL` from that service.
- Keep `RUN_MIGRATIONS=0` because Railway already runs migrations through `railway.json`.
- Railway deploys now run `python manage.py ensure_superuser` after migrations. If `DJANGO_SUPERUSER_EMAIL` and `DJANGO_SUPERUSER_PASSWORD` are set, the user is created or updated automatically.
- When you attach custom domains, your backend should be `api.hvts.app`, your frontend `hvts.app`, and docs `docs.hvts.app`.

## Docker vs Railway

- Local `docker-compose` already runs Redis as its own container and the web app connects to `redis://redis:6379/0`.
- Railway should mirror that architecture with a separate Redis service, not an in-container Redis daemon.
