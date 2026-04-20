from urllib.parse import urlparse


LOCAL_DEVELOPMENT_ORIGIN_HOSTS = {"localhost", "127.0.0.1"}
RUNTIME_PUBLIC_CORS_PATH_PREFIXES = (
    "/api/v1/auth/runtime/register",
    "/api/v1/auth/runtime/login",
    "/api/v1/auth/runtime/verify-email",
    "/api/v1/auth/runtime/register/verify-email",
    "/api/v1/auth/runtime/register/resend-email",
    "/api/v1/auth/runtime/password/reset",
    "/api/v1/auth/runtime/password/reset/validate",
    "/api/v1/auth/runtime/password/reset/confirm",
    "/api/v1/auth/runtime/social",
)
RUNTIME_API_KEY_CORS_PATH_PREFIXES = (
    "/api/v1/auth/runtime/register",
    "/api/v1/auth/runtime/login",
    "/api/v1/auth/runtime/register/resend-email",
    "/api/v1/auth/runtime/password/reset",
    "/api/v1/auth/runtime/social",
)


def normalize_runtime_origin(value: str) -> str:
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""

    parsed = urlparse(raw_value)
    scheme = (parsed.scheme or "").strip().lower()
    hostname = (parsed.hostname or "").strip().lower()
    if scheme not in {"http", "https"} or not hostname:
        return ""

    try:
        port = parsed.port
    except ValueError:
        return ""

    default_port = 443 if scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    return f"{scheme}://{netloc}"


def normalize_runtime_origins(values) -> list[str]:
    normalized = []
    for value in values or []:
        origin = normalize_runtime_origin(value)
        if origin and origin not in normalized:
            normalized.append(origin)
    return normalized


def origin_is_local_development(value: str) -> bool:
    normalized = normalize_runtime_origin(value)
    if not normalized:
        return False

    parsed = urlparse(normalized)
    return (parsed.hostname or "").strip().lower() in LOCAL_DEVELOPMENT_ORIGIN_HOSTS


def get_project_runtime_allowed_origins(project) -> list[str]:
    if project is None:
        return []

    combined = []
    if getattr(project, "frontend_url", ""):
        combined.append(project.frontend_url)
    combined.extend(getattr(project, "allowed_origins", []) or [])
    return normalize_runtime_origins(combined)


def path_matches_runtime_prefixes(path: str, prefixes) -> bool:
    normalized_path = (path or "").rstrip("/")
    return any(
        normalized_path == prefix or normalized_path.startswith(f"{prefix}/")
        for prefix in prefixes
    )


def request_targets_runtime_public_endpoint(request) -> bool:
    return path_matches_runtime_prefixes(
        getattr(request, "path_info", ""),
        RUNTIME_PUBLIC_CORS_PATH_PREFIXES,
    )


def request_targets_runtime_api_key_endpoint(request) -> bool:
    return path_matches_runtime_prefixes(
        getattr(request, "path_info", ""),
        RUNTIME_API_KEY_CORS_PATH_PREFIXES,
    )


def origin_is_allowed_for_runtime_preflight(value: str) -> bool:
    normalized_origin = normalize_runtime_origin(value)
    if not normalized_origin:
        return False
    if origin_is_local_development(normalized_origin):
        return True

    from hvt.apps.organizations.models import Project

    for frontend_url, allowed_origins in Project.objects.filter(
        is_active=True
    ).values_list("frontend_url", "allowed_origins"):
        project_origins = normalize_runtime_origins([frontend_url, *(allowed_origins or [])])
        if normalized_origin in project_origins:
            return True
    return False


def origin_is_allowed_for_api_key(value: str, api_key, request_host_origin: str = "") -> bool:
    normalized_origin = normalize_runtime_origin(value)
    if not normalized_origin:
        return False

    normalized_request_host = normalize_runtime_origin(request_host_origin)
    if normalized_request_host and normalized_origin == normalized_request_host:
        return True

    if getattr(api_key, "is_test", False) and origin_is_local_development(normalized_origin):
        return True

    return normalized_origin in get_project_runtime_allowed_origins(
        getattr(api_key, "project", None)
    )
