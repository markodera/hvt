from django.db import transaction

from hvt.apps.organizations.models import ProjectRole, UserProjectRole


def get_user_project_roles(user, project):
    """Return the project's role objects assigned to the user."""
    if not user or not project:
        return ProjectRole.objects.none()
    return (
        ProjectRole.objects.filter(
            project=project,
            assignments__user=user,
        )
        .prefetch_related("permissions")
        .distinct()
        .order_by("name", "slug")
    )


def get_user_project_role_slugs(user, project) -> list[str]:
    return list(get_user_project_roles(user, project).values_list("slug", flat=True))


def get_user_project_permission_slugs(user, project) -> list[str]:
    if not user or not project:
        return []

    return list(
        project.app_permissions.filter(
            roles__assignments__user=user,
        )
        .distinct()
        .order_by("slug")
        .values_list("slug", flat=True)
    )


def get_user_project_access(user, project) -> dict:
    roles = get_user_project_roles(user, project)
    return {
        "roles": [
            {
                "id": str(role.id),
                "slug": role.slug,
                "name": role.name,
            }
            for role in roles
        ],
        "role_slugs": [role.slug for role in roles],
        "permissions": get_user_project_permission_slugs(user, project),
    }


def assign_default_signup_roles(user, project, assigned_by=None) -> list[str]:
    """Attach all default signup roles for the project to the user."""
    if not user or not project:
        return []

    default_roles = list(
        ProjectRole.objects.filter(
            project=project,
            is_default_signup=True,
        ).order_by("name", "slug")
    )
    if not default_roles:
        return []

    created = []
    for role in default_roles:
        _, was_created = UserProjectRole.objects.get_or_create(
            user=user,
            role=role,
            defaults={"assigned_by": assigned_by},
        )
        if was_created:
            created.append(role.slug)
    return created


@transaction.atomic
def sync_user_project_roles(user, project, roles, assigned_by=None):
    """Replace a user's assigned roles for a single project."""
    target_roles = list(roles)
    target_ids = {role.id for role in target_roles}

    existing = UserProjectRole.objects.select_related("role").filter(
        user=user,
        role__project=project,
    )
    existing_by_role_id = {assignment.role_id: assignment for assignment in existing}

    existing.exclude(role_id__in=target_ids).delete()

    for role in target_roles:
        if role.id in existing_by_role_id:
            assignment = existing_by_role_id[role.id]
            if assigned_by and assignment.assigned_by_id != getattr(assigned_by, "id", None):
                assignment.assigned_by = assigned_by
                assignment.save(update_fields=["assigned_by"])
            continue
        UserProjectRole.objects.create(
            user=user,
            role=role,
            assigned_by=assigned_by,
        )

    return get_user_project_access(user, project)
