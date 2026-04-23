from rest_framework import serializers

from hvt.apps.organizations.access import (
    CONTROL_PLANE_ROLE_SLUGS,
    get_project_roles_by_slugs,
    normalize_role_slug,
    normalize_role_slugs,
    sync_user_project_roles,
)


def validate_no_control_plane_role_slugs(
    role_slugs,
    *,
    field_name: str,
    message: str,
) -> list[str]:
    normalized_role_slugs = normalize_role_slugs(role_slugs)
    if any(role_slug in CONTROL_PLANE_ROLE_SLUGS for role_slug in normalized_role_slugs):
        raise serializers.ValidationError({field_name: [message]})
    return normalized_role_slugs


def resolve_project_roles_or_error(
    project,
    role_slugs,
    *,
    field_name: str = "role_slugs",
    invalid_message_prefix: str = "These roles do not exist in this project: ",
):
    normalized_role_slugs = normalize_role_slugs(role_slugs)
    roles, invalid_role_slugs = get_project_roles_by_slugs(project, normalized_role_slugs)
    if invalid_role_slugs:
        raise serializers.ValidationError(
            {
                field_name: [
                    f"{invalid_message_prefix}{', '.join(invalid_role_slugs)}"
                ]
            }
        )
    return roles, normalized_role_slugs


def assign_requested_registration_role(
    *,
    user,
    project,
    role_slug,
    assigned_by=None,
):
    if role_slug is None:
        return None

    normalized_role_slug = normalize_role_slug(role_slug)
    if not normalized_role_slug:
        raise serializers.ValidationError(
            {"role_slug": ["This field may not be blank."]}
        )

    if normalized_role_slug in CONTROL_PLANE_ROLE_SLUGS:
        raise serializers.ValidationError(
            {
                "role_slug": [
                    "Control plane roles cannot be assigned at runtime registration"
                ]
            }
        )

    roles, invalid_role_slugs = get_project_roles_by_slugs(project, [normalized_role_slug])
    if invalid_role_slugs:
        raise serializers.ValidationError(
            {"role_slug": ["This role does not exist in this project"]}
        )

    role = roles[0]
    if not role.is_self_assignable:
        raise serializers.ValidationError(
            {"role_slug": ["This role cannot be self-assigned"]}
        )

    sync_user_project_roles(user, project, [role], assigned_by=assigned_by)
    return role
