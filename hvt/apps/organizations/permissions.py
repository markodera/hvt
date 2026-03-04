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
