from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from .models import Organization, APIKey, Webhook, WebhookDelivery
from hvt.api.v1.serializers.organizations import (
    OrganizationSerializer,
    APIKeyCreateSerializer,
    APIKeyListSerializer,
    WebhookSerializer,
)
from hvt.apps.organizations.permissions import IsOrganizationOwner
from hvt.apps.authentication.permissions import IsOrgOwnerOrAPIKey, IsOrgMemberOrAPIKey

class OrganizationListView(generics.ListCreateAPIView):
    """
    GET /api/v1/organizations/ - List all organization (superuser only)
    POST /api/v1/organizations/ - Create organizations (superuser only)
    """

    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [permissions.IsAuthenticated()]
        return [permissions.IsAdminUser()]
    
    def perform_create(self, serializer):
        user = self.request.user
        from rest_framework.serializers import ValidationError


        owned_org_count = user.owned_organization.count()
        if owned_org_count >= 3:
            raise ValidationError("You can only create upto 3 organizations.")
        
        # Create org and set user as owner
        org = serializer.save(owner=user)


        # Assign user to org if they don't have one
        if not user.organization:
            user.organization = org
            user.role = "owner"
            user.save(update_fields=["organization", "role"])

class OrganizationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET /api/v1/organizations/<id> -  Get organization     (superuser only)
    PATCH /api/v1/organizations/<id> -  Update organization  (superuser only)   
    DELETE /api/v1/organizations/<id> -  Delete organization  (superuser only)   
    """
   
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAdminUser]


class CurrentOrganizationView(generics.RetrieveUpdateAPIView):
    """
    GET /api/v1/organizations/currrent/ - Get current user's organization (any member)
    PATCH /api/v1/organizations/currrent/ - Update current organization (owner only)
    """

    serializer_class = OrganizationSerializer
    
    def get_permissions(self):
        if self.request.method in ["PATCH", "PUT"]:
            return [permissions.IsAuthenticated(), IsOrganizationOwner()]
        return [IsOrgOwnerOrAPIKey()]
    
    def get_object(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else: 
            raise NotFound("No organization found")
        
        if not org:
            raise NotFound("User is not part of any organization")

        # Check permission for updates
        if self.request.method in ["PATCH", "PUT"]:
            self.check_object_permissions(self.request, org)
        return org
    
        


# API Key mangment views

class APIKeyListCreateView(generics.ListCreateAPIView):
    """
    GET: List all API Keys for the current organization.
    POST: Create a new API Key.
    """

    permission_classes = [IsOrgOwnerOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else: 
            return APIKey.objects.none()
        
        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)
    
    def get_serializer_class(self):
        if self.request.method == "POST":
            return APIKeyCreateSerializer
        return APIKeyListSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        if isinstance(self.request.auth, APIKey):
            context["organization"] = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            context["organization"] = self.request.user.organization
        return context
        
class APIKeyDetailView(generics.RetrieveDestroyAPIView):
    """
    GET: Get API Key details.
    DELETE: Revoke (delete) an API key (owner only).
    """

    serializer_class = APIKeyListSerializer
    permission_classes = [IsOrgOwnerOrAPIKey]
    
    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else: 
            return APIKey.objects.none()
        
        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)
  
class APIKeyRevokeView(generics.UpdateAPIView):
    """
    PATCH: Deactivate an API key without deleting it (owner only).
    """

    serializer_class = APIKeyListSerializer

    permission_classes = [IsOrgOwnerOrAPIKey]

    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user and self.request.user.is_authenticated:
            org = self.request.user.organization
        else: 
            return APIKey.objects.none()
        
        if not org:
            return APIKey.objects.none()
        return APIKey.objects.filter(organization=org)
    
    def patch(self, request, *args, **kwargs):
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save(update_fields=["is_active"])
        return Response({"detail": "API key revoked"}, status=status.HTTP_200_OK)
    
class WebhookListCreateView(generics.ListCreateAPIView):
    """Manage webhooks for current organization"""
    
    permission_classes = [IsOrgOwnerOrAPIKey]
    serializer_class = WebhookSerializer
    
    def get_queryset(self):
        if isinstance(self.request.auth, APIKey):
            org = self.request.auth.organization
        elif self.request.user.is_authenticated:
            org = self.request.user.organization
        else:
            return Webhook.objects.none()
        
        return Webhook.objects.filter(organization=org)
    
    def perform_create(self, serializer):
        org = self.request.auth.organization if isinstance(self.request.auth, APIKey) else self.request.user.organization
        serializer.save(
            organization=org,
            created_by=self.request.user if self.request.user.is_authenticated else None,
            secret=Webhook.generate_secret()
        )