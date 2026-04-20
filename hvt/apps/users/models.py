import uuid
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.db.models import Q


class UserManager(BaseUserManager):
    """Custom manager for User models with email as primary identifier."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email).strip().lower()
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model using email instead of username.
    Linked to an organization for multi-tenancy.
    """

    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Admin"
        MEMBER = "member", "Member"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(db_index=True)

    # Profile
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)

    # Organization link
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="users",
        null=True,
        blank=True,
    )
    project = models.ForeignKey(
        "organizations.Project",
        on_delete=models.PROTECT,
        related_name="users",
        null=True,
        blank=True,
    )

    # Role
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.MEMBER,
    )
    # Stauts Flag
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    # Test Mode flag
    is_test = models.BooleanField(
        default=False, help_text="Test user are only access via test API keys"
    )

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "users"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["email", "project"],
                name="uniq_user_email_per_project",
            ),
            models.UniqueConstraint(
                fields=["email"],
                condition=Q(project__isnull=True),
                name="uniq_user_email_when_project_null",
            ),
        ]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if isinstance(self.email, str):
            self.email = self.email.strip().lower()
        return super().save(*args, **kwargs)

    @property
    def full_name(self) -> str:
        parts = [
            (self.first_name or "").strip(),
            (self.last_name or "").strip(),
        ]
        return " ".join(part for part in parts if part)

    def is_org_owner(self):
        return self.role == self.Role.OWNER

    def is_org_admin(self):
        return self.role in [self.Role.OWNER, self.Role.ADMIN]

    @property
    def is_project_scoped(self) -> bool:
        return self.project_id is not None

    def can_manage_users(self):
        """Owner and Admin can manage users"""
        return self.role in [self.Role.OWNER, self.Role.ADMIN]

    def can_manage_api_keys(self):
        """Only owner can manage API keys"""
        return self.role == self.Role.OWNER

    def can_manage_organization(self):
        """Only owner can manage org settings"""
        return self.role == self.Role.OWNER
