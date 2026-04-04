"""Lightweight liveness and readiness probes for deployments."""

from django.core.cache import cache
from django.db import connections
from django.http import JsonResponse
from django.views.decorators.http import require_GET


def _check_database() -> None:
    with connections["default"].cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()


def _check_cache() -> None:
    probe_key = "healthcheck:readyz"
    probe_value = "ok"
    cache.set(probe_key, probe_value, timeout=5)
    if cache.get(probe_key) != probe_value:
        raise RuntimeError("cache readiness probe failed")
    cache.delete(probe_key)


@require_GET
def healthz(_request):
    return JsonResponse({"status": "ok"})


@require_GET
def readyz(_request):
    checks = {}
    status_code = 200

    for name, check in (("database", _check_database), ("cache", _check_cache)):
        try:
            check()
        except Exception:
            checks[name] = {"status": "error"}
            status_code = 503
        else:
            checks[name] = {"status": "ok"}

    return JsonResponse(
        {
            "status": "ok" if status_code == 200 else "error",
            "checks": checks,
        },
        status=status_code,
    )
