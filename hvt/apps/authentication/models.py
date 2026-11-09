from django.utils import timezone
import uuid
from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from hvt.crypto import EncryptedTextField


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

        # MFA events
        MFA_SETUP = "mfa.setup", "MFA Setup Initiated"
        MFA_ENABLED = "mfa.enabled", "MFA Enabled"
        MFA_DISABLED = "mfa.disabled", "MFA Disabled"
        MFA_VERIFIED = "mfa.verified", "MFA Verified"
        TOTP_BACKUP_CODE_USED = "totp.backup_code_used", "TOTP Backup Code Used"
        TOTP_BACKUP_CODES_REGENERATED = "totp.backup_codes_regenerated", "TOTP Backup Codes Regenerated"

        # Session events
        SESSION_CREATED = "session.created", "Session Created"
        SESSION_REVOKED = "session.revoked", "Session Revoked"
        SESSION_REVOKED_ALL = "session.revoked_all", "All Sessions Revoked"

        # Passkey events
        PASSKEY_REGISTER_INITIATED = (
            "passkey.register.initiated",
            "Passkey Registration Initiated",
        )
        PASSKEY_REGISTERED = "passkey.registered", "Passkey Registered"
        PASSKEY_LOGIN = "passkey.login", "Passkey Login"
        PASSKEY_LOGIN_FAILED = "passkey.login.failed", "Passkey Login Failed"
        PASSKEY_DELETED = "passkey.deleted", "Passkey Deleted"

        # Magic Link events
        MAGIC_LINK_REQUESTED = "magic_link.requested", "Magic Link Requested"
        MAGIC_LINK_VERIFIED = "magic_link.verified", "Magic Link Verified"
        MAGIC_LINK_FAILED = "magic_link.failed", "Magic Link Failed"
        SECURITY_VIOLATION = "security.violation", "Security Violation"

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

        if actor_user and project is None:
            project = getattr(actor_user, "project", None)

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


class TOTPDevice(models.Model):
    """
    TOTP Two-Factor Authentication device for a user.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        "users.User",
        on_delete=models.CASCADE,
        related_name="totp_device",
    )
    secret = EncryptedTextField(help_text="TOTP secret (encrypted at rest via MultiFernet).")
    is_confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "auth_totp_devices"

    def __str__(self):
        return f"TOTP for {self.user.email} (confirmed={self.is_confirmed})"


class TOTPBackupCode(models.Model):
    """
    Single-use hashed backup codes for account recovery when TOTP device is unavailable.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        TOTPDevice,
        on_delete=models.CASCADE,
        related_name="backup_codes",
    )
    hashed_code = models.CharField(max_length=64, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_totp_backup_codes"
        ordering = ["-created_at"]

    def __str__(self):
        status = "used" if self.used_at else "active"
        return f"BackupCode ({status}) for {self.device.user.email}"


class UserPasskeyCredential(models.Model):
    """
    FIDO2 / WebAuthn Passkey credential for biometric and hardware security key authentication.
    Stores public key and signature counter to detect authenticator cloning.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="passkey_credentials",
    )
    name = models.CharField(max_length=120, default="Passkey")
    credential_id = models.CharField(max_length=512, unique=True, db_index=True)
    public_key = models.TextField(help_text="Base64URL-encoded COSE public key")
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.CharField(max_length=64, blank=True)
    backed_up = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "auth_passkey_credentials"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} for {self.user.email}"


class MagicLinkToken(models.Model):
    """
    Cryptographically secure, single-use passwordless authentication token.
    Stores only the SHA-256 hash of the token to prevent database leakage exploits.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="magic_link_tokens",
    )
    project = models.ForeignKey(
        "organizations.Project",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="magic_link_tokens",
    )
    token_hash = models.CharField(max_length=64, db_index=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_magic_link_tokens"
        ordering = ["-created_at"]

    def is_valid(self):
        from django.utils import timezone

        return not self.is_used and self.expires_at > timezone.now()




class UserSession(models.Model):
    """
    Tracks an authenticated client session across devices.
    The primary key `id` corresponds directly to the `sid` claim in JWT access and refresh tokens.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="sessions",
    )
    project = models.ForeignKey(
        "organizations.Project",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="sessions",
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_name = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(default=timezone.now, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_reason = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "auth_user_sessions"
        ordering = ["-last_active_at"]

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def __str__(self):
        status_str = "revoked" if self.revoked_at else "active"
        return f"Session ({status_str}) for {self.user.email} on {self.device_name or 'Unknown Device'}"
