import uuid
import secrets
import hashlib
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.utils import timezone

from hvt.apps.organizations.runtime_origins import normalize_runtime_origins


APP_ACCESS_SLUG_VALIDATOR = RegexValidator(
    regex=r"^[a-z0-9]+(?:[._:-][a-z0-9]+)*$",
    message=(
        "Use lowercase letters, numbers, and separators like '.', '_', ':', or '-'."
    ),
)


class Organization(models.Model):
    """
    Multi-tenant organization. Each user belogs to one organization.
    Organization isolate data and have their own settings.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=225)
    slug = models.SlugField(max_length=225, unique=True, db_index=True)

    # Owner of org
    owner = models.ForeignKey(
        "users.User",
        on_delete=models.PROTECT,
        related_name="owned_organization",
        null=True,
        blank=True,
    )

    # Settings
    is_active = models.BooleanField(default=True)
    allow_signup = models.BooleanField(default=True)

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "organizations"
        ordering = ["-created_at"]

    def __str__(self):
        return self.name

    def ensure_default_project(self):
        """Return the org's default project, creating it when missing."""
        project, _ = self.projects.get_or_create(
            is_default=True,
            defaults={
                "name": "Default",
                "slug": "default",
                "allow_signup": self.allow_signup,
            },
        )
        return project


class Project(models.Model):
    """Application/environment boundary inside an organization."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="projects",
    )
    name = models.CharField(max_length=225)
    slug = models.SlugField(max_length=225, db_index=True)
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    allow_signup = models.BooleanField(default=True)
    frontend_url = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=(
            "Optional frontend base URL for this runtime app. "
            "Used for project-scoped verification and password reset links."
        ),
    )
    allowed_origins = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Additional browser origins allowed to call runtime auth endpoints for this project. "
            "Use full origins like https://app.example.com or http://localhost:3000."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "projects"
        ordering = ["created_at", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "slug"],
                name="uniq_project_slug_per_organization",
            ),
            models.UniqueConstraint(
                fields=["organization"],
                condition=Q(is_default=True),
                name="uniq_default_project_per_organization",
            ),
        ]

    def __str__(self):
        return f"{self.organization.name} / {self.name}"

    def save(self, *args, **kwargs):
        if isinstance(self.frontend_url, str):
            self.frontend_url = self.frontend_url.strip().rstrip("/")
        self.allowed_origins = normalize_runtime_origins(self.allowed_origins)
        return super().save(*args, **kwargs)


class ProjectPermission(models.Model):
    """Project-scoped permission defined by the customer app."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="app_permissions",
    )
    slug = models.CharField(
        max_length=100,
        validators=[APP_ACCESS_SLUG_VALIDATOR],
        help_text="Stable permission identifier such as orders.read.own.",
    )
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "project_permissions"
        ordering = ["slug"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "slug"],
                name="uniq_project_permission_slug",
            ),
        ]

    def __str__(self):
        return f"{self.project.slug}:{self.slug}"

    def save(self, *args, **kwargs):
        self.slug = (self.slug or "").strip().lower()
        self.name = (self.name or "").strip()
        self.full_clean()
        return super().save(*args, **kwargs)


class ProjectRole(models.Model):
    """Project-scoped role that bundles one or more permissions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="app_roles",
    )
    slug = models.CharField(
        max_length=100,
        validators=[APP_ACCESS_SLUG_VALIDATOR],
        help_text="Stable role identifier such as buyer or teacher.",
    )
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    is_default_signup = models.BooleanField(
        default=False,
        help_text="Assign this role automatically during public runtime signup.",
    )
    permissions = models.ManyToManyField(
        ProjectPermission,
        through="ProjectRolePermission",
        related_name="roles",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "project_roles"
        ordering = ["name", "slug"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "slug"],
                name="uniq_project_role_slug",
            ),
        ]

    def __str__(self):
        return f"{self.project.slug}:{self.slug}"

    def save(self, *args, **kwargs):
        self.slug = (self.slug or "").strip().lower()
        self.name = (self.name or "").strip()
        self.full_clean()
        return super().save(*args, **kwargs)


class ProjectRolePermission(models.Model):
    """Explicit join table between project roles and permissions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(
        ProjectRole,
        on_delete=models.CASCADE,
        related_name="permission_links",
    )
    permission = models.ForeignKey(
        ProjectPermission,
        on_delete=models.CASCADE,
        related_name="role_links",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "project_role_permissions"
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"],
                name="uniq_project_role_permission",
            ),
        ]

    def __str__(self):
        return f"{self.role.slug}->{self.permission.slug}"

    def clean(self):
        if (
            self.role_id
            and self.permission_id
            and self.role.project_id != self.permission.project_id
        ):
            raise ValidationError(
                "Roles can only be linked to permissions from the same project."
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class UserProjectRole(models.Model):
    """Project role assignment for a user inside an organization."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="project_role_assignments",
    )
    role = models.ForeignKey(
        ProjectRole,
        on_delete=models.CASCADE,
        related_name="assignments",
    )
    assigned_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_project_roles",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_project_roles"
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role"],
                name="uniq_user_project_role_assignment",
            ),
        ]

    def __str__(self):
        return f"{self.user.email}->{self.role.project.slug}:{self.role.slug}"

    def clean(self):
        if self.user_id and self.role_id:
            if self.user.organization_id != self.role.project.organization_id:
                raise ValidationError(
                    "Users can only be assigned project roles within their organization."
                )
        if (
            self.assigned_by_id
            and self.role_id
            and self.assigned_by.organization_id
            and self.assigned_by.organization_id != self.role.project.organization_id
        ):
            raise ValidationError(
                "Role assigners must belong to the same organization as the project."
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class SocialProviderConfig(models.Model):
    """Per-project OAuth provider credentials for runtime social auth."""

    class Provider(models.TextChoices):
        GOOGLE = "google", "Google"
        GITHUB = "github", "GitHub"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="social_provider_configs",
    )
    provider = models.CharField(max_length=32, choices=Provider.choices)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    redirect_uris = models.JSONField(
        default=list,
        blank=True,
        help_text="Allowed frontend callback URLs for this provider config.",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "social_provider_configs"
        ordering = ["provider", "created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "provider"],
                name="uniq_social_provider_per_project",
            ),
        ]

    def __str__(self):
        return f"{self.project} / {self.provider}"

    @property
    def organization(self):
        return self.project.organization


class APIKey(models.Model):
    """
    API Key for organization server-to-server authentication.
    Keys are hased - only the prefix is stored in plain text for identification.
    """

    class Environment(models.TextChoices):
        TEST = "test", "Test"
        LIVE = "live", "Live"

    CANONICAL_SCOPES = (
        "organization:read",
        "organization:write",
        "users:read",
        "users:write",
        "api_keys:read",
        "api_keys:write",
        "webhooks:read",
        "webhooks:write",
        "audit_logs:read",
        "auth:runtime",
    )
    SUPPORTED_SCOPES = (
        *CANONICAL_SCOPES,
        "*",
        "read",
        "write",
        "auth:*",
        "organization:*",
        "org:*",
        "org:read",
        "org:write",
        "read:org",
        "write:org",
        "users:*",
        "api_keys:*",
        "webhooks:*",
        "audit_logs:*",
    )
    SCOPE_ALIASES = {
        "organization:read": {
            "organization:read",
            "organization:*",
            "org:read",
            "org:*",
            "read:org",
            "read",
            "write",
            "*",
        },
        "organization:write": {
            "organization:write",
            "organization:*",
            "org:write",
            "org:*",
            "write:org",
            "write",
            "*",
        },
        "users:read": {"users:read", "users:*", "read", "write", "*"},
        "users:write": {"users:write", "users:*", "write", "*"},
        "api_keys:read": {"api_keys:read", "api_keys:*", "read", "write", "*"},
        "api_keys:write": {"api_keys:write", "api_keys:*", "write", "*"},
        "webhooks:read": {"webhooks:read", "webhooks:*", "read", "write", "*"},
        "webhooks:write": {"webhooks:write", "webhooks:*", "write", "*"},
        "audit_logs:read": {"audit_logs:read", "audit_logs:*", "read", "write", "*"},
        "auth:runtime": {"auth:runtime", "auth:*", "write", "*"},
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    project = models.ForeignKey(
        "organizations.Project",
        on_delete=models.CASCADE,
        related_name="api_keys",
        null=True,
        blank=True,
    )

    # Environment mode
    environment = models.CharField(
        max_length=4,
        choices=Environment.choices,
        default=Environment.TEST,
        help_text="Test keys only access test data, live keys access production data",
    )

    # Key identification
    name = models.CharField(max_length=225, help_text="Friendly name for this key")
    prefix = models.CharField(max_length=8, unique=True, db_index=True)
    hashed_key = models.CharField(max_length=128)

    # permission and scope
    scopes = models.JSONField(
        default=list,
        blank=True,
        help_text="list of allowed scopes: ['users:read', 'users:write', 'auth:*']",
    )

    # Status
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    expired_webhook_sent_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_api_key",
    )

    class Meta:
        db_table = "api_keys"
        ordering = ["-created_at"]
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"

    def __str__(self):
        return f"{self.name} ({self.prefix}...)"

    @classmethod
    def generate_key(cls, environment="test"):
        """
        Generate a new API key.
        Returns (prefix, full_key, hashed_key)
        Key format:
        Test: hvt_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        Live: hvt_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        """
        raw_key = secrets.token_hex(32)
        prefix = raw_key[:8]
        full_key = f"hvt_{environment}_{raw_key}"
        hashed_key = cls.hash_key(full_key)
        return prefix, full_key, hashed_key

    @staticmethod
    def hash_key(key: str) -> str:
        """Hash the API key using SHA-256."""
        return hashlib.sha256(key.encode()).hexdigest()

    def verify_key(self, key: str) -> bool:
        """Verify a key against this API key's hash"""
        return self.hashed_key == self.hash_key(key)

    @property
    def is_valid(self) -> bool:
        """Check if the key is active and not expired."""
        if not self.is_active:
            return False
        if self.is_expired:
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Return True once the expiry instant has been reached."""
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    @property
    def status(self) -> str:
        """Return the dashboard/API lifecycle state for this key."""
        if not self.is_active:
            return "revoked"
        if self.is_expired:
            return "expired"
        return "active"

    @property
    def is_test(self):
        """Check if this is a test key."""
        return self.environment == self.Environment.TEST

    @property
    def is_live(self):
        """Check if this is a live key."""
        return self.environment == self.Environment.LIVE

    def update_last_used(self):
        """Updated the last_used_at timestamp."""
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

    @classmethod
    def get_supported_scopes(cls):
        return tuple(dict.fromkeys(scope.lower() for scope in cls.SUPPORTED_SCOPES))

    def normalized_scopes(self):
        return {
            str(scope).strip().lower()
            for scope in (self.scopes or [])
            if str(scope).strip()
        }

    def has_scope(self, scope: str) -> bool:
        normalized_scope = (scope or "").strip().lower()
        if not normalized_scope:
            return False

        granted_scopes = self.normalized_scopes()
        if not granted_scopes:
            return False

        accepted_scopes = self.SCOPE_ALIASES.get(normalized_scope, {normalized_scope})
        return any(candidate in granted_scopes for candidate in accepted_scopes)

    def has_any_scope(self, *scopes: str) -> bool:
        normalized = [scope for scope in scopes if (scope or "").strip()]
        if not normalized:
            return False
        return any(self.has_scope(scope) for scope in normalized)


class OrganizationInvitation(models.Model):
    """
    Invitation to join an organization as an admin or member.

    Invitations are email-bound and accepted by an authenticated user whose
    email matches the invite address.
    """

    class Role(models.TextChoices):
        ADMIN = "admin", "Admin"
        MEMBER = "member", "Member"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="invitations",
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="organization_invitations",
    )
    email = models.EmailField(db_index=True)
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.MEMBER,
    )
    token = models.CharField(max_length=64, unique=True, db_index=True, editable=False)
    invited_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="sent_organization_invitations",
    )
    accepted_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="accepted_organization_invitations",
    )
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    app_roles = models.ManyToManyField(
        ProjectRole,
        related_name="organization_invitations",
        blank=True,
    )

    class Meta:
        db_table = "organization_invitations"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "email"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.email} -> {self.organization.name} ({self.role})"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @property
    def status(self) -> str:
        if self.accepted_at:
            return "accepted"
        if self.revoked_at:
            return "revoked"
        if self.is_expired:
            return "expired"
        return "pending"

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"

    def clean(self):
        if self.project_id and self.organization_id:
            if self.project.organization_id != self.organization_id:
                raise ValidationError(
                    {"project": "Selected project must belong to the current organization."}
                )

    def save(self, *args, **kwargs):
        self.email = (self.email or "").strip().lower()
        if not self.token:
            self.token = secrets.token_hex(32)
        self.full_clean()
        super().save(*args, **kwargs)


class Webhook(models.Model):
    """
    Webhook configuration for organizations.
    Send HTTP POST request on specific events.
    """

    class EventType(models.TextChoices):
        USER_CREATED = "user.created", "User Created"
        USER_UPDATED = "user.updated", "User Updated"
        USER_DELETED = "user.deleted", "User Deleted"
        USER_LOGIN = "user.login", "User Login"
        USER_ROLE_CHANGED = "user.role.changed", "User Role Changed"
        API_KEY_CREATED = "api_key.created", "API Key Created"
        API_KEY_EXPIRED = "api_key.expired", "API Key Expired"
        API_KEY_REVOKED = "api_key.revoked", "API Key Revoked"
        ORG_INVITATION_CREATED = "org.invitation.created", "Organization Invitation Created"
        ORG_INVITATION_ACCEPTED = "org.invitation.accepted", "Organization Invitation Accepted"
        ORG_INVITATION_REVOKED = "org.invitation.revoked", "Organization Invitation Revoked"
        ORG_INVITATION_RESENT = "org.invitation.resent", "Organization Invitation Resent"
        PROJECT_CREATED = "project.created", "Project Created"
        PROJECT_UPDATED = "project.updated", "Project Updated"
        PROJECT_DELETED = "project.deleted", "Project Deleted"
        PROJECT_SOCIAL_PROVIDER_CREATED = "project.social_provider.created", "Project Social Provider Created"
        PROJECT_SOCIAL_PROVIDER_UPDATED = "project.social_provider.updated", "Project Social Provider Updated"
        PROJECT_SOCIAL_PROVIDER_DELETED = "project.social_provider.deleted", "Project Social Provider Deleted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="webhooks"
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="webhooks",
    )

    # Configuration
    url = models.URLField(max_length=500, help_text="Endpoint to send webhook events")
    events = models.JSONField(
        default=list, help_text="List of event types to subscribe to"
    )
    secret = models.CharField(
        max_length=64, help_text="Signing secret for webhook verification"
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="created_webhooks"
    )

    # Stats
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    consecutive_failures = models.IntegerField(
        default=0,
        help_text="Consecutive failed deliveries. Webhook auto-disables at 10.",
    )

    class Meta:
        db_table = "webhooks"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.project.slug} - {self.url}"

    @classmethod
    def generate_secret(cls):
        """Generate a random signing secret."""
        return secrets.token_hex(32)


class WebhookDelivery(models.Model):
    """
    Log of webhook deliery attempts.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"
        RETRYING = "retrying", "Retrying"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    webhook = models.ForeignKey(
        Webhook, on_delete=models.CASCADE, related_name="deliveries"
    )

    # Event data
    event_type = models.CharField(max_length=50)
    payload = models.JSONField()

    # Request details (what we sent)
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True)

    # Delivery details
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    response_status_code = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)

    # Retry tracking
    attempt_count = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "webhook_deliveries"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["webhook", "-created_at"]),
            models.Index(fields=["status", "next_retry_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} to {self.webhook.url} - {self.status}"
