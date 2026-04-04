from rest_framework import permissions
from hvt.apps.organizations.models import APIKey


class IsOrganizationOwner(permissions.BasePermission):
    """
    Allow access only to the owner of the organization.
    """

    message = "You must be the organization owner to perform this action."

    def has_object_permission(self, request, view, obj):
        # Check if user is the owner of the organization
        return obj.owner == request.user


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
            and getattr(user, "organization_id", None)
            and user.is_org_owner()
        )
