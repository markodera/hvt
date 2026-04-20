from __future__ import annotations

from hvt.apps.organizations.models import APIKey
from hvt.apps.users.models import User


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def get_control_plane_users_by_email(email: str):
    normalized_email = normalize_email(email)
    return User.objects.select_related("organization", "project").filter(
        email__iexact=normalized_email,
        project__isnull=True,
    )


def get_runtime_project_users_by_email(email: str, api_key: APIKey):
    normalized_email = normalize_email(email)
    return User.objects.select_related("organization", "project").filter(
        email__iexact=normalized_email,
        organization_id=api_key.organization_id,
        project_id=api_key.project_id,
    )


def get_runtime_legacy_users_by_email(email: str, api_key: APIKey):
    normalized_email = normalize_email(email)
    return User.objects.select_related("organization", "project").filter(
        email__iexact=normalized_email,
        organization_id=api_key.organization_id,
        project__isnull=True,
        role=User.Role.MEMBER,
    )


def get_runtime_org_users_by_email(email: str, api_key: APIKey):
    normalized_email = normalize_email(email)
    return User.objects.select_related("organization", "project").filter(
        email__iexact=normalized_email,
        organization_id=api_key.organization_id,
        project__isnull=True,
    )


def user_matches_runtime_project(
    user: User,
    api_key: APIKey,
    *,
    allow_legacy_unassigned: bool = True,
) -> bool:
    if not user or not api_key:
        return False

    if getattr(user, "organization_id", None) != getattr(api_key, "organization_id", None):
        return False

    if getattr(user, "project_id", None) == getattr(api_key, "project_id", None):
        return True

    return bool(
        allow_legacy_unassigned
        and getattr(user, "project_id", None) is None
        and getattr(user, "role", None) == User.Role.MEMBER
    )


def get_runtime_user_for_api_key(
    email: str,
    api_key: APIKey,
    *,
    allow_legacy_unassigned: bool = True,
) -> User | None:
    exact_user = get_runtime_project_users_by_email(email, api_key).first()
    if exact_user:
        return exact_user

    if not allow_legacy_unassigned:
        return None

    return get_runtime_org_users_by_email(email, api_key).first()
