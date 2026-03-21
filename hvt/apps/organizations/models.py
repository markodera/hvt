import uuid
import secrets
import hashlib
from django.db import models
from django.utils import timezone


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


class APIKey(models.Model):
    """
    API Key for organization server-to-server authentication.
    Keys are hased - only the prefix is stored in plain text for identification.
    """

    class Environment(models.TextChoices):
        TEST = "test", "Test"
        LIVE = "live", "Live"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="api_keys",
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
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

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
        API_KEY_CREATED = "api_key.created", "API Key Created"
        API_KEY_REVOKED = "api_key.revoked", "API Key Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="webhooks"
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
        return f"{self.organization.name} - {self.url}"

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
