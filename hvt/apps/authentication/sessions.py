# SPDX-License-Identifier: Apache-2.0
"""
Session Registry & Revocation Engine for HVT.

Features:
- Maintains dual-layer session verification:
  1. Sub-millisecond Redis / Django cache lookups for every HTTP request.
  2. Persistent PostgreSQL `auth_user_sessions` table for durability across restarts and outages.
- Provides immediate token invalidation for single device revocation and global remote logout.
- Tracks client IP, User-Agent, friendly device names, and throttled last_active timestamps.
"""

import logging
import re
import uuid
from typing import Any, Optional, Union
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings

from .models import UserSession, AuditLog

logger = logging.getLogger(__name__)

SESSION_CACHE_TTL = 7 * 24 * 60 * 60  # 7 days, matching refresh token lifetime
REVOCATION_CACHE_TTL = 7 * 24 * 60 * 60


def parse_device_name(user_agent: str) -> str:
    """
    Parse a clean, user-friendly device/browser name from a User-Agent string.
    e.g. 'Chrome on Windows', 'Safari on iPhone', 'Firefox on Linux', 'Mobile App (Android)'.
    """
    if not user_agent:
        return "Unknown Device"

    ua = user_agent.strip()

    # Mobile apps / native clients
    if "MobileApp" in ua or "okhttp" in ua or "CFNetwork" in ua:
        if "Android" in ua:
            return "Mobile App (Android)"
        elif "iPhone" in ua or "iPad" in ua:
            return "Mobile App (iOS)"
        return "Mobile App"

    # OS detection
    os_name = "Unknown OS"
    if "iPhone" in ua:
        os_name = "iPhone"
    elif "iPad" in ua:
        os_name = "iPad"
    elif "Android" in ua:
        os_name = "Android"
    elif "Windows NT 10.0" in ua or "Windows NT 11.0" in ua or "Windows" in ua:
        os_name = "Windows"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"

    # Browser detection
    browser_name = "Browser"
    if "Edg/" in ua or "Edge/" in ua:
        browser_name = "Edge"
    elif "Chrome/" in ua and "Chromium/" not in ua:
        browser_name = "Chrome"
    elif "Firefox/" in ua:
        browser_name = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser_name = "Safari"
    elif "Opera/" in ua or "OPR/" in ua:
        browser_name = "Opera"

    return f"{browser_name} on {os_name}" if os_name != "Unknown OS" else browser_name


def get_client_ip(request) -> Optional[str]:
    """Extract real client IP address from request META headers."""
    if not request:
        return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # First IP in comma-separated list is the original client
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def get_active_cache_key(session_id: Union[str, uuid.UUID]) -> str:
    return f"session:active:{str(session_id)}"


def get_revoked_cache_key(session_id: Union[str, uuid.UUID]) -> str:
    return f"session:revoked:{str(session_id)}"


def create_user_session(
    user,
    request=None,
    project=None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> UserSession:
    """
    Create a new UserSession record and register it in the cache.
    """
    if request:
        ip = ip_address or get_client_ip(request)
        ua = user_agent or request.META.get("HTTP_USER_AGENT", "")
    else:
        ip = ip_address
        ua = user_agent or ""

    device = parse_device_name(ua)

    session = UserSession.objects.create(
        user=user,
        project=project,
        ip_address=ip,
        user_agent=ua,
        device_name=device,
        last_active_at=timezone.now(),
    )

    try:
        cache.set(
            get_active_cache_key(session.id),
            {
                "user_id": str(user.id),
                "project_id": str(project.id) if project else None,
                "created_at": session.created_at.isoformat(),
            },
            timeout=SESSION_CACHE_TTL,
        )
    except Exception as exc:
        logger.warning("Failed to write session to cache: %s", exc)

    return session


def is_session_active(session_id: Union[str, uuid.UUID]) -> bool:
    """
    Determine whether a session is valid and active.
    
    Order of evaluation:
    1. Check revocation cache (`session:revoked:<sid>`). If present -> False.
    2. Check active cache (`session:active:<sid>`). If present -> True.
    3. Database fallback (Redis miss or cold restart): Check `UserSession` table.
       If active in DB, re-warm active cache and return True.
    """
    if not session_id:
        return False

    sid_str = str(session_id)

    try:
        # Fast path 1: explicitly revoked in cache
        if cache.get(get_revoked_cache_key(sid_str)):
            return False

        # Fast path 2: cached as active
        active_cached = cache.get(get_active_cache_key(sid_str))
        if active_cached:
            return True
    except Exception as exc:
        logger.warning("Cache access error during session check; falling back to database: %s", exc)

    # Database fallback (resilient across Redis outages and cold starts)
    try:
        session = UserSession.objects.filter(id=sid_str, revoked_at__isnull=True).first()
        if session:
            try:
                cache.set(
                    get_active_cache_key(sid_str),
                    {
                        "user_id": str(session.user_id),
                        "project_id": str(session.project_id) if session.project_id else None,
                        "created_at": session.created_at.isoformat(),
                    },
                    timeout=SESSION_CACHE_TTL,
                )
            except Exception:
                pass
            return True
        else:
            try:
                cache.set(get_revoked_cache_key(sid_str), True, timeout=REVOCATION_CACHE_TTL)
            except Exception:
                pass
            return False
    except Exception as exc:
        logger.exception("Database error checking session validity: %s", exc)
        return False


def revoke_session(
    session_id: Union[str, uuid.UUID],
    reason: str = "user_revoked",
) -> bool:
    """
    Revoke a session immediately across cache and database.
    """
    if not session_id:
        return False

    sid_str = str(session_id)

    # 1. Update database
    now = timezone.now()
    updated = UserSession.objects.filter(id=sid_str, revoked_at__isnull=True).update(
        revoked_at=now,
        revoked_reason=reason,
    )

    # 2. Update cache immediately
    try:
        cache.set(get_revoked_cache_key(sid_str), True, timeout=REVOCATION_CACHE_TTL)
        cache.delete(get_active_cache_key(sid_str))
    except Exception as exc:
        logger.warning("Failed to update cache on session revocation: %s", exc)

    return bool(updated)


def revoke_all_user_sessions(
    user,
    project=None,
    except_session_id: Optional[Union[str, uuid.UUID]] = None,
    reason: str = "logout_all",
) -> int:
    """
    Revoke all active sessions for a user, optionally exempting the current session.
    """
    now = timezone.now()
    qs = UserSession.objects.filter(user=user, revoked_at__isnull=True)
    if project is not None:
        proj_id = getattr(project, "id", project)
        qs = qs.filter(project_id=proj_id)
    else:
        qs = qs.filter(project__isnull=True)

    if except_session_id:
        qs = qs.exclude(id=str(except_session_id))

    session_ids = list(qs.values_list("id", flat=True))
    if not session_ids:
        return 0

    count = qs.update(revoked_at=now, revoked_reason=reason)

    try:
        for sid in session_ids:
            sid_str = str(sid)
            cache.set(get_revoked_cache_key(sid_str), True, timeout=REVOCATION_CACHE_TTL)
            cache.delete(get_active_cache_key(sid_str))
    except Exception as exc:
        logger.warning("Failed to invalidate sessions in cache during revoke_all: %s", exc)

    return count


def touch_session(session_id: Union[str, uuid.UUID], request=None) -> None:
    """
    Update the last_active timestamp of a session.
    Throttled to write to the database at most once every 60 seconds per session.
    """
    if not session_id:
        return

    sid_str = str(session_id)
    throttle_key = f"session:touch:{sid_str}"

    try:
        if cache.get(throttle_key):
            return
        cache.set(throttle_key, True, timeout=60)
    except Exception:
        pass

    now = timezone.now()
    try:
        UserSession.objects.filter(id=sid_str, revoked_at__isnull=True).update(last_active_at=now)
    except Exception as exc:
        logger.debug("Could not touch session %s: %s", sid_str, exc)
