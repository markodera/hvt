import uuid
from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


class AuditLog(models.Model):
    """
    Audit trail for authentication and authorization events.
    Tracks security-relevant actions across the platform.
    """

    class EventType(models.TextChoices):
        # Authentication events
        USER_LOGIN = "user.login", "User Login"
        USER_LOGOUT = "user.logout", "User Logout"
        USER_REGISTER = "user.register", "User Registration"
        LOGIN_FAILED = "login.failed", "Login Failed"

        # Password events
        PASSWORD_RESET_REQUEST = "password.reset.request", "Password Reset Requested"
        PASSWORD_RESET_COMPLETE = "password.reset.complete", "Password Reset Completed"
        PASSWORD_CHANGED = "password.changed", "Password Changed"

        # Email events
        EMAIL_VERIFIED = "email.verified", "Email Verified"
        EMAIL_VERIFICATION_SENT = "email.verification.sent", "Verification Email Sent"
        EMAIL_VERIFICATION_FAILED = (
            "email.verification.failed",
            "Verification Email Failed",
        )

        # Social auth
        SOCIAL_LOGIN = "social.login", "Social Login"
        SOCIAL_CONNECTED = "social.connected", "Social Account Connected"
        SOCIAL_DISCONNECTED = "social.disconnected", "Social Account disconnected"

        # API key events
        API_KEY_CREATED = "api_key.created", "API Key Created"
        API_KEY_REVOKED = "api_key.revoked", "API Key Revoked"
        API_KEY_DELETED = "api_key.deleted", "API Key Deleted"
        API_KEY_USED = "api_key.used", "API Key Used"

        # User managment
        USER_CREATED = "user.created", "User Created"
        USER_UPDATED = "user.updated", "User Updated"
        USER_DELETED = "user.deleted", "User Deleted"
        USER_ROLE_CHANGED = "user.role.changed", "User Role Changed"

        # Organization events
        ORG_CREATED = "org.created", "Organization Created"
        ORG_UPDATED = "org.updated", "Organization Updated"
        ORG_MEMBER_ADDED = "org.member.added", "Member Added to Organization"
        ORG_MEMBER_REMOVED = "org.member.removed", "Member Removed from Organization"
        ORG_INVITATION_CREATED = "org.invitation.created", "Organization Invitation Created"
        ORG_INVITATION_ACCEPTED = "org.invitation.accepted", "Organization Invitation Accepted"
        ORG_INVITATION_REVOKED = "org.invitation.revoked", "Organization Invitation Revoked"
        ORG_INVITATION_RESENT = "org.invitation.resent", "Organization Invitation Resent"
        RUNTIME_USER_INVITED = "runtime_user.invited", "Runtime User Invited"
        RUNTIME_USER_INVITE_ACCEPTED = (
            "runtime_user.invite_accepted",
            "Runtime User Invite Accepted",
        )

        # Project events
        PROJECT_CREATED = "project.created", "Project Created"
        PROJECT_UPDATED = "project.updated", "Project Updated"
        PROJECT_DELETED = "project.deleted", "Project Deleted"
        PROJECT_SOCIAL_PROVIDER_CREATED = (
            "project.social_provider.created",
            "Project Social Provider Created",
        )
        PROJECT_SOCIAL_PROVIDER_UPDATED = (
            "project.social_provider.updated",
            "Project Social Provider Updated",
        )
        PROJECT_SOCIAL_PROVIDER_DELETED = (
            "project.social_provider.deleted",
            "Project Social Provider Deleted",
        )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Event details
    event_type = models.CharField(
        max_length=50, choices=EventType.choices, db_index=True
    )
    event_data = models.JSONField(
        default=dict, blank=True, help_text="Additional event context"
    )

    # Actor(who performed the action)
    actor_user = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs_as_actor",
        help_text="User who performed the action",
    )
    actor_api_key = models.ForeignKey(
        "organizations.APIKey",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text="API Key used for this action",
    )

    # Target (what as affected) - using generic relations for flexibility
    target_content_type = models.ForeignKey(
        ContentType, on_delete=models.SET_NULL, null=True, blank=True
    )
    target_object_id = models.UUIDField(null=True, blank=True)
    target_object = GenericForeignKey("target_content_type", "target_object_id")

    # Organization context
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    project = models.ForeignKey(
        "organizations.Project",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    # Request metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Status
    success = models.BooleanField(
        default=True, help_text="Whether the action succeeded"
    )
    error_message = models.TextField(
        blank=True, help_text="Error message if action failed"
    )

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "event_type"]),
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["actor_user", "-created_at"]),
        ]

    def __str__(self):
        actor = self.actor_user.email if self.actor_user else "API Key"
        return f"{self.event_type} by {actor} at {self.created_at}"

    @classmethod
    def log(
        cls,
        event_type,
        request=None,
        user=None,
        api_key=None,
        organization=None,
        project=None,
        target=None,
        event_data=None,
        success=True,
        error_message="",
    ):
        """
        Helper method for audit log entries.
        """
        # Extract request metadata
        ip_address = None
        user_agent = ""
        actor_user = user
        actor_api_key = api_key

        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]

            # Determine actor from request if not explicitly passed
            if hasattr(request, "auth"):
                from hvt.apps.organizations.models import APIKey

                if isinstance(request.auth, APIKey) and not api_key:
                    actor_api_key = request.auth
                elif (
                    hasattr(request, "user")
                    and request.user.is_authenticated
                    and not user
                ):
                    actor_user = request.user

        if actor_api_key and project is None:
            project = getattr(actor_api_key, "project", None)

        if project is not None and organization is None:
            organization = getattr(project, "organization", None)

        # Set target object generic relation
        target_content_type = None
        target_object_id = None
        if target:
            target_content_type = ContentType.objects.get_for_model(target)
            target_object_id = target.id

        return cls.objects.create(
            event_type=event_type,
            event_data=event_data or {},
            actor_user=actor_user,
            actor_api_key=actor_api_key,
            target_content_type=target_content_type,
            target_object_id=target_object_id,
            organization=organization,
            project=project,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message,
        )

    @staticmethod
    def _get_client_ip(request):
        """Extract client IP from request, handling proxies."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
