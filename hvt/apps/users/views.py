import logging
from rest_framework import generics, permissions
from .models import User
from hvt.apps.organizations.models import APIKey
from rest_framework.exceptions import NotFound, PermissionDenied
from hvt.apps.authentication.permissions import( 
    IsAdminOrAPIKey, 
    IsAuthenticatedOrAPIKey,
    IsOrgAdminOrAPIKey,
    IsOrgMemberOrAPIKey,
    IsOrgOwnerOrAPIKey,
    IsSelfOrOrgAdmin,
    CanChangeRole
    )
from hvt.api.v1.serializers.users import (
    UserSerializer, 
    UserCreateSerializer,
    UserRoleUpdateSerializer,
    OrganizationMemberSerializer,
    )

logger = logging.getLogger(__name__)


class UserListView(generics.ListCreateAPIView):
    """
    GET /api/v1/users/ - List users in current organization (staff only or API key)
    POST /api/v1/users/ - Create user (staff only or API key)
    """

    permission_classes = [IsAdminOrAPIKey]

    def initial(self, request, *args, **kwargs):
        """Log authentication details before permission checks"""
        logger.info(f"[UserListView] === REQUEST START ===")
        logger.info(f"[UserListView] Headers: {dict(request.headers)}")
        logger.info(f"[UserListView] META X-API-KEY: {request.META.get('HTTP_X_API_KEY', 'NOT FOUND')}")
        
        # Call parent to trigger authentication
        super().initial(request, *args, **kwargs)
        
        logger.info(f"[UserListView] After authentication:")
        logger.info(f"[UserListView] request.user: {request.user}")
        logger.info(f"[UserListView] request.auth: {request.auth}")
        logger.info(f"[UserListView] request.auth type: {type(request.auth)}")

    def get_queryset(self):
        # Get organization form user or API Key
        from hvt.apps.organizations.models import APIKey

        if isinstance(self.request.auth, APIKey):
            # API key authentication
            org = self.request.auth.organization
            is_test = self.request.auth.is_test
        elif self.request.user.is_authenticated:
            org = self.request.user.organization
            is_test = None 
        else:
            return User.objects.none()
        
        if org:
            return User.objects.filter(organization=org)
        
        queryset = User.objects.filter(organization=org)

        if is_test is not None:
            queryset = queryset.filter(is_test=is_test)
            logger.info(f"[UserListView] filtering by is_test={is_test}")

        return queryset
    
    def get_serializer_class(self):
        if self.request.method == "POST":
            return UserCreateSerializer
        return UserSerializer
    
    def perform_create(self, serializer):
        # Determine if thid is a test user
        is_test = False
        org = None
        if isinstance(self.request.auth, APIKey):
            is_test = self.request.auth.is_test
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization

        serializer.save(organization=org, is_test=is_test)
    
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET /api/v1/users/<id>/ - Get user details
    PATCH /api/v1/users/<id>/ - Update user
    DELETE /api/v1/users/<id>/ - Update user
    """

    serializer_class = UserSerializer
    permission_classes = [IsOrgMemberOrAPIKey, IsSelfOrOrgAdmin]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
            is_test = self.request.auth.is_test
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
            is_test = None
        else:
            return User.objects.none()
        
        if not org:
            return User.objects.none()
        
        queryset = User.objects.filter(organization=org)
        
        if is_test is not None:
            queryset = queryset.filter(is_test=is_test)
        
        return queryset
    
    def destroy(self, request, *args, **kwargs):
        """Only admins can delete users, and owners cannot be deleted."""
        user = self.get_object()

        # Check if requester is admin
        if isinstance(request.auth, APIKey):
            pass # API key can delete
        elif not request.user.can_manage_users():
            raise PermissionDenied("Only admins can delete users")
        
        # Cannot delete owner
        if user.is_org_owner():
            raise PermissionDenied("Cannot delete  organization owner. Transfer ownership first ")
        
        # Cannot delete self
        if user == request.user:
            raise PermissionDenied("Cannot delete yourself.")
        
        return super().destroy(request, *args, **kwargs)
    
class UserRoleUpdateView(generics.UpdateAPIView):
    """
    PATCH /api/v1/users/<id>/role/ - Update user's role 
    Only owner can assign owner role
    Onwner ad admins can assign admin/member roles.
    """

    serializer_class = UserRoleUpdateSerializer
    permission_classes = [IsOrgOwnerOrAPIKey, CanChangeRole]
    
    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return User.objects.none()
        
        if not org:
            return User.objects.none()
    
        return User.objects.filter(organization=org)
    
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        old_role = user.role

        response = super().update(request, *args, **kwargs)

        if response.status_code == 200:
            new_role = user.role
            logger.info(f"[UserRoleUpdate] {user.email} role changed: {old_role} -> {new_role}")

            # If promoting to owner, demote current owner
            if new_role == "owner" and old_role != "owner":
                if request.user.is_org_owner():
                    request.user.role = "admin"
                    request.user.save(update_fields=["role"])
                    logger.info(f"[UserRoleUpdateView] Previous owner {request.user.email} demoted to admin")
                
        return response
    
class OrganizationMembersView(generics.ListAPIView):
    """
    GET /api/v1/organizations/current/members/ - List all members with role
    """
    serializer_class = OrganizationMemberSerializer
    permission_classes = [IsOrgMemberOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return User.objects.none()
        
        return User.objects.filter(organization=org).order_by("-role", "email")