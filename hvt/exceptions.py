"""
Standardized error response handler for HVT API.

Wraps all DRF exceptions into a consistent envelope:

    {
        "error": "Short error label",
        "code": "machine_readable_code",
        "detail": <str | dict | list>,
        "status": <int>
    }

This ensures SDK consumers and frontend clients can rely on a
single error shape regardless of which endpoint they call.
"""

from __future__ import annotations

import math

from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied,
    NotFound,
    MethodNotAllowed,
    Throttled,
    ValidationError,
)

from rest_framework.response import Response
from django.http import Http404
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied

class EmailNotVerifiedException(APIException):
    status_code = 403
    default_detail = "E-mail is not verified. Please verify your email before logging in."
    default_code = "EMAIL_NOT_VERIFIED"


class EmailInUseException(APIException):
    status_code = 400
    default_detail = "A user with this email address already exists in this project."
    default_code = "EMAIL_IN_USE"


# ---- human-readable labels keyed by status code ----
_STATUS_LABELS: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests",
    500: "Internal Server Error",
}

# ---- machine-readable codes keyed by exception class ----
_EXCEPTION_CODES: dict[type, str] = {
    ValidationError: "validation_error",
    AuthenticationFailed: "authentication_failed",
    NotAuthenticated: "not_authenticated",
    PermissionDenied: "permission_denied",
    NotFound: "not_found",
    MethodNotAllowed: "method_not_allowed",
    Throttled: "throttled",
    EmailInUseException: "EMAIL_IN_USE",
    EmailNotVerifiedException: "EMAIL_NOT_VERIFIED",
}


def hvt_exception_handler(exc: Exception, context: dict) -> Response | None:
    """
    Custom exception handler that normalises every error into
    the HVT standard envelope.

    Falls through to DRF's default handler first so that signal
    hooks (e.g. ``got_request_exception``) still fire.
    """
    # Let DRF do its thing (converts Django exceptions → DRF exceptions, etc.)
    response = drf_exception_handler(exc, context)

    if response is None:
        # DRF didn't handle it — unexpected server error
        return Response(
            {
                "error": "Internal Server Error",
                "code": "server_error",
                "detail": "An unexpected error occurred.",
                "status": 500,
            },
            status=500,
        )

    status_code: int = response.status_code
    error_label: str = _STATUS_LABELS.get(status_code, "Error")
    code: str = _EXCEPTION_CODES.get(type(exc), _default_code(status_code))
    detail = _normalise_detail(response.data)

    # For throttled responses, include retry-after info if available
    if isinstance(exc, Throttled) and exc.wait is not None:
        retry_after_seconds = max(1, int(math.ceil(exc.wait)))
        retry_after_human = _format_retry_after(retry_after_seconds)
        detail = {
            "message": f"Too many requests. Try again in {retry_after_human}.",
            "retry_after_seconds": retry_after_seconds,
            "retry_after_human": retry_after_human,
        }

    if isinstance(detail, str):
        if detail == "E-mail is not verified.":
            exc = EmailNotVerifiedException()
            code = exc.default_code
            status_code = exc.status_code
            response.status_code = status_code
            message = exc.default_detail
            error_label = _STATUS_LABELS.get(status_code, "Error")
            detail = message
        else:
            message = detail
    elif isinstance(detail, dict) and detail:
        first_val = list(detail.values())[0]
        message = first_val[0] if isinstance(first_val, list) and first_val else str(first_val)
        if message == "E-mail is not verified.":
            exc = EmailNotVerifiedException()
            code = exc.default_code
            status_code = exc.status_code
            response.status_code = status_code
            message = exc.default_detail
            error_label = _STATUS_LABELS.get(status_code, "Error")
            detail = message
    elif isinstance(detail, list) and detail:
        message = detail[0]
        if message == "E-mail is not verified.":
            exc = EmailNotVerifiedException()
            code = exc.default_code
            status_code = exc.status_code
            response.status_code = status_code
            message = exc.default_detail
            error_label = _STATUS_LABELS.get(status_code, "Error")
            detail = message
    else:
        message = str(detail)

    response.data = {
        "error": message,
        "code": code,
        "errorCode": code,
        "detail": detail,
        "message": message,
        "status": status_code,
    }

    return response


# ---- helpers ----


def _default_code(status_code: int) -> str:
    """Fallback machine-readable code derived from the HTTP status."""
    return _STATUS_LABELS.get(status_code, "error").lower().replace(" ", "_")


def _normalise_detail(data):
    """
    DRF stores error details in various shapes:
      - ``{"detail": "..."}`` for simple exceptions
      - ``{"field": ["err1", ...]}`` for validation errors
      - ``["err1", ...]`` for non-field errors
    Flatten where possible so the envelope is predictable.
    """
    if isinstance(data, dict):
        # Simple DRF exception — just a "detail" key
        if list(data.keys()) == ["detail"]:
            return data["detail"]
        return data

    if isinstance(data, list):
        # Single-string list → unwrap
        if len(data) == 1:
            return data[0]
        return data

    return data


def _format_retry_after(seconds: int) -> str:
    """Return a compact human-readable retry window for throttled responses."""
    remaining = max(1, int(seconds))
    units = [
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    ]

    parts = []
    for unit_seconds, unit_name in units:
        count, remaining = divmod(remaining, unit_seconds)
        if not count:
            continue
        label = unit_name if count == 1 else f"{unit_name}s"
        parts.append(f"{count} {label}")
        if len(parts) == 2:
            break

    return " ".join(parts) if parts else "1 second"
