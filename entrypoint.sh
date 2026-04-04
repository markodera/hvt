#!/bin/sh
set -eu

run_manage_command() {
    echo "Running: python manage.py $*"
    python manage.py "$@"
}

if [ "$#" -gt 0 ]; then
    echo "Starting custom command: $*"
    exec "$@"
fi

if [ "${WAIT_FOR_DB:-1}" = "1" ]; then
    echo "Waiting for database connectivity..."
    python scripts/wait_for_db.py
fi

if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    run_manage_command migrate --noinput
fi

if [ "${COLLECTSTATIC_ON_START:-1}" = "1" ]; then
    run_manage_command collectstatic --noinput
fi

echo "Starting Gunicorn..."
exec gunicorn hvt.wsgi:application \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers "${WEB_CONCURRENCY:-3}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
    --keep-alive "${GUNICORN_KEEPALIVE:-5}" \
    --max-requests "${GUNICORN_MAX_REQUESTS:-1000}" \
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-100}" \
    --access-logfile - \
    --error-logfile -
