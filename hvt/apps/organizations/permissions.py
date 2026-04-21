from rest_framework import permissions
from hvt.apps.authentication.identity import is_project_scoped_user


class IsOrganizationOwner(permissions.BasePermission):
    """
    Allow access only to the owner of the organization.
    """

    message = "You must be the organization owner to perform this action."

    def has_object_permission(self, request, view, obj):
        # Check if user is the owner of the organization
        return bool(
            request.user
            and getattr(request.user, "is_authenticated", False)
            and not is_project_scoped_user(request.user)
            and obj.owner == request.user
        )


class IsCurrentOrganizationOwner(permissions.BasePermission):
    """
    Allow access only to authenticated users who own their current organization.
    """

    message = "You must be the current organization owner to perform this action."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(
            user
            and getattr(user, "is_authenticated", False)
            and not is_project_scoped_user(user)
            and getattr(user, "organization_id", None)
            and user.is_org_owner()
        )


class IsCurrentOrganizationAdmin(permissions.BasePermission):
    """
    Allow access only to authenticated users who can manage organization users.
    """

    message = "You must be an organization owner or admin to perform this action."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(
            user
            and getattr(user, "is_authenticated", False)
            and not is_project_scoped_user(user)
            and getattr(user, "organization_id", None)
            and user.can_manage_users()
        )
