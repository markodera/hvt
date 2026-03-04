import logging
from rest_framework import permissions
from hvt.apps.organizations.models import APIKey

logger = logging.getLogger(__name__)


def _allow_api_key_read_only(request, permission_name):
    """Allow API keys for read-only requests only."""
    if request.method in permissions.SAFE_METHODS:
        logger.info(f"[{permission_name}] API key detected for read-only request")
        return True

    logger.warning(
        f"[{permission_name}] API key denied for write request: {request.method}"
    )
    return False


class IsAuthenticatedOrAPIKey(permissions.BasePermission):
    """
    Allow access if authenticated via JWT or Valid API key.
    """

    def has_permission(self, request, view):
        logger.info(f"[IsAuthenticatedOrAPIKey] request.user: {request.user}")
        logger.info(f"[IsAuthenticatedOrAPIKey] request.auth: {request.auth}")
        logger.info(
            f"[IsAuthenticatedOrAPIKey] request.auth type: {type(request.auth)}"
        )

        # Check if user is authenticated
        if request.user and request.user.is_authenticated:
            logger.info("[IsAuthenticatedOrAPIKey] User is authenticated via JWT")
            return True

        # Check if API key is present in auth
        if isinstance(request.auth, APIKey):
            logger.info("[IsAuthenticatedOrAPIKey] API Key detected, granting access")
            return True

        logger.info("[IsAuthenticatedOrAPIKey] No valid auth found, denying access")
        return False


class IsAdminOrAPIKey(permissions.BasePermission):
    """
    Allow access if user is staff/Admin or API key is valid for read-only requests.
    """

    def has_permission(self, request, view):
        logger.info(f"[IsAdminOrAPIKey] request.user: {request.user}")
        logger.info(f"[IsAdminOrAPIKey] request.auth: {request.auth}")
        logger.info(f"[IsAdminOrAPIKey] request.auth type: {type(request.auth)}")

        # Check if user is admin
        if request.user and request.user.is_authenticated and request.user.is_staff:
            logger.info("[IsAdminOrAPIKey] User is admin, granting access")
            return True

        # Check if API key is present in and valid
        if isinstance(request.auth, APIKey):
            return _allow_api_key_read_only(request, "IsAdminOrAPIKey")

        logger.info("[IsAdminOrAPIKey] No valid auth found, denying access")
        return False


class IsOrgAdminOrAPIKey(permissions.BasePermission):
    """
    Allow access if user is org owner/admin or valid API key.
    Use for: User management endpoints
    """

    message = "You must be an organization owner or admin to perform this action."

    def has_permission(self, request, view):
        # API key is read-only only
        if isinstance(request.auth, APIKey):
            return _allow_api_key_read_only(request, "IsOrgAdminOrAPIKey")

        if request.user and request.user.is_authenticated:
            # Check if user belongs to an organization
            if not request.user.organization:
                logger.info(
                    f"[IsOrgAdminOrAPIKey] User {request.user.email} has no organization"
                )
                return False

            if request.user.can_manage_users():
                logger.info(
                    f"[IsOrgAdminOrAPIKey] User {request.user.email} is {request.user.role}, granting access"
                )
                return True
            logger.info(
                f"[IsOrgAdminOrAPIKey] User {request.user.email} is {request.user.role}, denying access"
            )

        return False


class IsOrgOwnerOrAPIKey(permissions.BasePermission):
    """
    Allow access if user is org owner OR valid API key for read-only requests.
    Use for: org settings reads and owner-only operations (user ownership still required for writes).
    """

    message = "You must be the organization owner to perform this action."

    def has_permission(self, request, view):
        # API key is read-only only
        if isinstance(request.auth, APIKey):
            return _allow_api_key_read_only(request, "IsOrgOwnerOrAPIKey")

        # Check user role
        if request.user and request.user.is_authenticated:
            # Check if user belongs to an organization
            if not request.user.organization:
                logger.info(
                    f"[IsOrgOwnerOrAPIKey] User {request.user.email} has no organization"
                )
                return False

            if request.user.is_org_owner():
                logger.info(
                    f"[IsOrgOwnerOrAPIKey] User {request.user.email} is owner, granting access"
                )
                return True
            logger.info(
                f"[IsOrgOwnerOrAPIKey] User {request.user.email} is {request.user.role}, denying access"
            )

        return False


class IsOrgMemberOrAPIKey(permissions.BasePermission):
    """
    Allow access if user belongs to organization OR valid API key.
    Use for: Read-only access to organization data.
    """

    message = "You must be a member of the organization to perform this action."

    def has_permission(self, request, view):
        # API key is read-only only
        if isinstance(request.auth, APIKey):
            return _allow_api_key_read_only(request, "IsOrgMemberOrAPIKey")

        # Check if user is authenticated and belongs to an org
        if request.user and request.user.is_authenticated:
            if request.user.organization:
                logger.info(
                    f"[IsOrgMemberOrAPIKey] User {request.user.email} is org member, granting access"
                )
                return True
            logger.info(
                f"[IsOrgMemberOrAPIKey] User {request.user.email} has no organization"
            )

        return False


class IsSelfOrOrgAdmin(permissions.BasePermission):
    """
    Allow access if user is editing themselves OR is org owner/admin.
    Use for: User profile updates where users can edit their own profile.
    """

    message = "You can only edit your own profile or must be an admin."

    def has_object_permission(self, request, view, obj):
        # API key is read-only only
        if isinstance(request.auth, APIKey):
            return _allow_api_key_read_only(request, "IsSelfOrOrgAdmin")

        if request.user and request.user.is_authenticated:
            # User can always edit themselves
            if obj == request.user:
                logger.info(
                    f"[IsSelfOrOrgAdmin] User {request.user.email} editing self"
                )
                return True

            # Org admins can edit other users in their org
            if (
                request.user.can_manage_users()
                and obj.organization == request.user.organization
            ):
                logger.info(
                    f"[IsSelfOrOrgAdmin] Admin {request.user.email} editing {obj.email}"
                )
                return True

        return False


class CanChangeRole(permissions.BasePermission):
    """
    Permission to change user roles.
    - Only owners can assign/remove owner role
    - Owners and admins can assign/remove admin and member roles
    """

    message = "You don't have permission to change this user's role."

    def has_object_permission(self, request, view, obj):
        # API key role changes are never allowed
        if isinstance(request.auth, APIKey):
            logger.warning("[CanChangeRole] API key denied for role change")
            return False

        if not request.user or not request.user.is_authenticated:
            return False

        # Must be in the same organization
        if obj.organization != request.user.organization:
            return False

        new_role = request.data.get("role")
        if not new_role:
            return True  # Not changing role

        # Prevent self-demotion from owner (must transfer ownership first)
        if obj == request.user and request.user.is_org_owner() and new_role != "owner":
            logger.warning(
                f"[CanChangeRole] Owner {request.user.email} cannot demote themselves"
            )
            return False

        # Only owners can assign/remove owner role
        if new_role == "owner" or obj.role == "owner":
            if not request.user.is_org_owner():
                logger.warning(f"[CanChangeRole] Only owners can change owner role")
                return False

        # Owners and admins can change admin/member roles
        if request.user.can_manage_users():
            return True

        return False
