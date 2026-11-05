# SPDX-License-Identifier: Apache-2.0
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml
from allauth.socialaccount.models import SocialAccount
from django.core.exceptions import ValidationError
from django.db import transaction
from rest_framework.exceptions import PermissionDenied, ValidationError as DRFValidationError

from hvt.apps.organizations.models import (
    APIKey,
    ManagedBy,
    Project,
    ProjectPermission,
    ProjectRole,
    ProjectRolePermission,
    SocialProviderConfig,
    UserProjectRole,
)
from hvt.apps.authentication.models import AuditLog

logger = logging.getLogger(__name__)


@dataclass
class ManifestPermission:
    slug: str
    name: str = ""
    description: str = ""


@dataclass
class ManifestRole:
    slug: str
    name: str = ""
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    is_default_signup: bool = False
    is_self_assignable: bool = False


@dataclass
class ManifestSocialProvider:
    provider: str
    client_id: str
    client_secret: Optional[str] = None
    allowed_redirect_uris: List[str] = field(default_factory=list)
    is_active: bool = True


@dataclass
class SchemaManifest:
    schema_version: int = 1
    permissions: List[ManifestPermission] = field(default_factory=list)
    roles: List[ManifestRole] = field(default_factory=list)
    social_providers: List[ManifestSocialProvider] = field(default_factory=list)


@dataclass
class ObjectChange:
    action: str
    object_type: str
    slug: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "action": self.action,
            "object_type": self.object_type,
            "slug": self.slug,
        }
        if self.details:
            data["details"] = self.details
        return data


@dataclass
class SyncResult:
    dry_run: bool
    status: str
    client_key: Optional[str] = None
    client_key_prefix: Optional[str] = None
    summary: Dict[str, int] = field(default_factory=dict)
    changes: List[ObjectChange] = field(default_factory=list)
    link_removals: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "status": self.status,
            "client_key": self.client_key,
            "client_key_prefix": self.client_key_prefix,
            "summary": self.summary,
            "changes": [c.to_dict() for c in self.changes],
            "link_removals": self.link_removals,
            "errors": self.errors,
        }


def validate_redirect_uri(uri: str, environment: str = "test") -> None:
    """
    Validates redirect URIs according to security policy:
    - Exact match only; no wildcards (*)
    - No URL fragments (#)
    - No embedded userinfo (user:pass@host)
    - HTTPS required, except localhost / 127.0.0.1 in test environment
    """
    if not uri or not isinstance(uri, str):
        raise DRFValidationError("Redirect URI must be a non-empty string.")

    cleaned = uri.strip()
    if "*" in cleaned:
        raise DRFValidationError(f"Invalid redirect URI '{cleaned}': wildcards (*) are not allowed.")

    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise DRFValidationError(
            f"Invalid redirect URI '{cleaned}': scheme and hostname are required."
        )

    if parsed.fragment:
        raise DRFValidationError(
            f"Invalid redirect URI '{cleaned}': URL fragments (#) are not allowed."
        )

    if parsed.username or parsed.password:
        raise DRFValidationError(
            f"Invalid redirect URI '{cleaned}': userinfo is not allowed."
        )

    hostname = (parsed.hostname or "").lower()
    is_loopback = hostname in ("localhost", "127.0.0.1")

    scheme = parsed.scheme.lower()
    if scheme == "http":
        if not (environment == "test" and is_loopback):
            raise DRFValidationError(
                f"Invalid redirect URI '{cleaned}': HTTP is only permitted for localhost/127.0.0.1 in test environment. HTTPS is required."
            )
    elif scheme != "https":
        raise DRFValidationError(
            f"Invalid redirect URI '{cleaned}': scheme must be HTTPS (or HTTP for localhost in test)."
        )


def parse_manifest_payload(payload: Any) -> SchemaManifest:
    """Parses JSON or YAML payload into a typed SchemaManifest dataclass."""
    data = payload
    if isinstance(payload, (bytes, bytearray)):
        payload_str = payload.decode("utf-8")
        try:
            data = yaml.safe_load(payload_str)
        except Exception as exc:
            raise DRFValidationError(f"Invalid YAML payload: {exc}")
    elif isinstance(payload, str):
        try:
            data = yaml.safe_load(payload)
        except Exception as exc:
            raise DRFValidationError(f"Invalid YAML/JSON payload: {exc}")

    if not isinstance(data, dict):
        raise DRFValidationError("Manifest payload must be an object/mapping.")

    # Validate schema_version
    schema_version = data.get("schema_version", 1)
    if schema_version != 1:
        raise DRFValidationError(
            f"Unsupported schema_version: {schema_version}. Supported versions: [1]."
        )

    permissions_raw = data.get("permissions") or []
    roles_raw = data.get("roles") or []
    providers_raw = data.get("social_providers") or []

    manifest = SchemaManifest(schema_version=schema_version)

    for p in permissions_raw:
        if not isinstance(p, dict) or not p.get("slug"):
            raise DRFValidationError("Each permission must include a non-empty 'slug'.")
        manifest.permissions.append(
            ManifestPermission(
                slug=str(p["slug"]).strip().lower(),
                name=str(p.get("name", "")).strip() or str(p["slug"]).strip().lower(),
                description=str(p.get("description", "")).strip(),
            )
        )

    for r in roles_raw:
        if not isinstance(r, dict) or not r.get("slug"):
            raise DRFValidationError("Each role must include a non-empty 'slug'.")
        perms = [str(item).strip().lower() for item in r.get("permissions", []) if str(item).strip()]
        manifest.roles.append(
            ManifestRole(
                slug=str(r["slug"]).strip().lower(),
                name=str(r.get("name", "")).strip() or str(r["slug"]).strip().lower(),
                description=str(r.get("description", "")).strip(),
                permissions=perms,
                is_default_signup=bool(r.get("is_default_signup", False)),
                is_self_assignable=bool(r.get("is_self_assignable", False)),
            )
        )

    for sp in providers_raw:
        if not isinstance(sp, dict) or not sp.get("provider") or not sp.get("client_id"):
            raise DRFValidationError("Each social provider must include 'provider' and 'client_id'.")
        
        # Support allowed_redirect_uris (new) with fallback to redirect_uris (legacy)
        uris = sp.get("allowed_redirect_uris")
        if uris is None:
            uris = sp.get("redirect_uris", [])
        if isinstance(uris, str):
            uris = [uris]

        manifest.social_providers.append(
            ManifestSocialProvider(
                provider=str(sp["provider"]).strip().lower(),
                client_id=str(sp["client_id"]).strip(),
                client_secret=str(sp["client_secret"]).strip() if sp.get("client_secret") else None,
                allowed_redirect_uris=[str(u).strip() for u in uris if str(u).strip()],
                is_active=bool(sp.get("is_active", True)),
            )
        )

    return manifest


class SchemaSyncService:
    """
    Reconciles declarative schema manifests against project roles, permissions,
    and OAuth social provider configurations.
    """

    @classmethod
    def execute_sync(
        cls,
        project: Project,
        manifest: SchemaManifest,
        dry_run: bool = False,
        prune: bool = False,
        issue_client_key: bool = False,
        environment: str = "test",
        actor_api_key: Optional[APIKey] = None,
        request=None,
    ) -> SyncResult:
        changes: List[ObjectChange] = []
        link_removals: List[Dict[str, str]] = []
        summary: Dict[str, int] = {
            "created": 0,
            "updated": 0,
            "adopted": 0,
            "deleted": 0,
            "linked": 0,
            "unlinked": 0,
        }

        # Validate all redirect URIs upfront
        for sp in manifest.social_providers:
            for uri in sp.allowed_redirect_uris:
                validate_redirect_uri(uri, environment=environment)

        with transaction.atomic():
            # 1. Row-level lock on target Project row
            locked_project = Project.objects.select_for_update().get(id=project.id)

            # Option C environment restriction check:
            # Test keys/environments cannot mutate projects with active live keys
            if environment == "test":
                has_active_live_keys = APIKey.objects.select_for_update().filter(
                    project=locked_project,
                    environment=APIKey.Environment.LIVE,
                    is_active=True,
                ).exists()
                if has_active_live_keys:
                    raise PermissionDenied(
                        "Test management keys cannot modify projects with active live keys. (Option C limitation)"
                    )

            # 2. Permissions Reconciliation
            existing_perms = {
                p.slug: p
                for p in ProjectPermission.objects.select_for_update().filter(project=locked_project)
            }
            declared_perm_slugs = set()

            for perm_data in manifest.permissions:
                slug = perm_data.slug
                declared_perm_slugs.add(slug)
                if slug in existing_perms:
                    perm = existing_perms[slug]
                    was_adopted = False
                    if perm.managed_by == ManagedBy.DASHBOARD:
                        perm.managed_by = ManagedBy.MANIFEST
                        was_adopted = True
                        changes.append(ObjectChange(action="adopted", object_type="permission", slug=slug))
                        summary["adopted"] += 1

                    updated = False
                    if perm.name != perm_data.name:
                        perm.name = perm_data.name
                        updated = True
                    if perm.description != perm_data.description:
                        perm.description = perm_data.description
                        updated = True

                    if updated:
                        perm.save()
                        changes.append(ObjectChange(action="updated", object_type="permission", slug=slug))
                        summary["updated"] += 1
                    elif was_adopted:
                        perm.save()
                else:
                    new_perm = ProjectPermission.objects.create(
                        project=locked_project,
                        slug=slug,
                        name=perm_data.name,
                        description=perm_data.description,
                        managed_by=ManagedBy.MANIFEST,
                    )
                    existing_perms[slug] = new_perm
                    changes.append(ObjectChange(action="created", object_type="permission", slug=slug))
                    summary["created"] += 1

            if prune:
                for slug, perm in list(existing_perms.items()):
                    if slug not in declared_perm_slugs and perm.managed_by == ManagedBy.MANIFEST:
                        perm.delete()
                        changes.append(ObjectChange(action="deleted", object_type="permission", slug=slug))
                        summary["deleted"] += 1

            # Refresh perm lookup map
            all_perms = {
                p.slug: p
                for p in ProjectPermission.objects.filter(project=locked_project)
            }

            # 3. Roles and Permissions Reconciliation
            existing_roles = {
                r.slug: r
                for r in ProjectRole.objects.select_for_update().filter(project=locked_project)
            }
            declared_role_slugs = set()

            # Handle default signup role singularly (ASK 3b)
            # If any declared role is default signup, unset existing defaults first
            has_declared_default = any(r.is_default_signup for r in manifest.roles)
            if has_declared_default:
                declared_default_slugs = [r.slug for r in manifest.roles if r.is_default_signup]
                if len(declared_default_slugs) > 1:
                    raise DRFValidationError("Only one role may be designated as is_default_signup.")

                target_default_slug = declared_default_slugs[0]
                existing_defaults = ProjectRole.objects.filter(
                    project=locked_project, is_default_signup=True
                ).exclude(slug=target_default_slug)

                for old_default in existing_defaults:
                    old_default.is_default_signup = False
                    old_default.save(update_fields=["is_default_signup"])
                    changes.append(
                        ObjectChange(
                            action="updated",
                            object_type="role",
                            slug=old_default.slug,
                            details={"is_default_signup": False, "note": "Unset prior default signup role"},
                        )
                    )
                    summary["updated"] += 1

            for role_data in manifest.roles:
                slug = role_data.slug
                declared_role_slugs.add(slug)

                if slug in existing_roles:
                    role = existing_roles[slug]
                    was_adopted = False
                    if role.managed_by == ManagedBy.DASHBOARD:
                        role.managed_by = ManagedBy.MANIFEST
                        was_adopted = True
                        changes.append(ObjectChange(action="adopted", object_type="role", slug=slug))
                        summary["adopted"] += 1

                    updated = False
                    if role.name != role_data.name:
                        role.name = role_data.name
                        updated = True
                    if role.description != role_data.description:
                        role.description = role_data.description
                        updated = True
                    if role.is_default_signup != role_data.is_default_signup:
                        role.is_default_signup = role_data.is_default_signup
                        updated = True
                    if role.is_self_assignable != role_data.is_self_assignable:
                        role.is_self_assignable = role_data.is_self_assignable
                        updated = True

                    if updated:
                        role.save()
                        changes.append(ObjectChange(action="updated", object_type="role", slug=slug))
                        summary["updated"] += 1
                    elif was_adopted:
                        role.save()
                    role_obj = role
                else:
                    role_obj = ProjectRole.objects.create(
                        project=locked_project,
                        slug=slug,
                        name=role_data.name,
                        description=role_data.description,
                        is_default_signup=role_data.is_default_signup,
                        is_self_assignable=role_data.is_self_assignable,
                        managed_by=ManagedBy.MANIFEST,
                    )
                    existing_roles[slug] = role_obj
                    changes.append(ObjectChange(action="created", object_type="role", slug=slug))
                    summary["created"] += 1

                # Exact reconciliation of permissions for this role
                current_links = {
                    link.permission.slug: link
                    for link in ProjectRolePermission.objects.filter(role=role_obj).select_related("permission")
                }
                target_slugs = set(role_data.permissions)

                # Check if all referenced permissions exist
                for perm_slug in target_slugs:
                    if perm_slug not in all_perms:
                        raise DRFValidationError(
                            f"Role '{role_data.slug}' references undefined permission '{perm_slug}'."
                        )

                # Add missing links
                for perm_slug in target_slugs:
                    if perm_slug not in current_links:
                        ProjectRolePermission.objects.create(
                            role=role_obj,
                            permission=all_perms[perm_slug],
                        )
                        changes.append(
                            ObjectChange(
                                action="linked",
                                object_type="role_permission",
                                slug=f"{role_obj.slug}:{perm_slug}",
                            )
                        )
                        summary["linked"] += 1

                # Remove links not in manifest
                for perm_slug, link in current_links.items():
                    if perm_slug not in target_slugs:
                        link.delete()
                        changes.append(
                            ObjectChange(
                                action="unlinked",
                                object_type="role_permission",
                                slug=f"{role_obj.slug}:{perm_slug}",
                            )
                        )
                        link_removals.append({"role": role_obj.slug, "permission": perm_slug})
                        summary["unlinked"] += 1

            if prune:
                roles_to_prune = list(
                    ProjectRole.objects.select_for_update()
                    .filter(project=locked_project, managed_by=ManagedBy.MANIFEST)
                    .exclude(slug__in=declared_role_slugs)
                )
                for candidate in roles_to_prune:
                    # Safety check: block prune if users hold this role
                    if UserProjectRole.objects.filter(role=candidate).exists():
                        raise DRFValidationError(
                            f"Cannot prune role '{candidate.slug}': one or more users currently hold this role."
                        )
                    candidate.delete()
                    changes.append(ObjectChange(action="deleted", object_type="role", slug=candidate.slug))
                    summary["deleted"] += 1

            # 4. Social Providers Reconciliation
            existing_providers = {
                sp.provider: sp
                for sp in SocialProviderConfig.objects.select_for_update().filter(project=locked_project)
            }
            declared_providers = set()

            for sp_data in manifest.social_providers:
                prov_name = sp_data.provider
                declared_providers.add(prov_name)

                if prov_name in existing_providers:
                    config = existing_providers[prov_name]
                    was_adopted = False
                    if config.managed_by == ManagedBy.DASHBOARD:
                        config.managed_by = ManagedBy.MANIFEST
                        was_adopted = True
                        changes.append(ObjectChange(action="adopted", object_type="social_provider", slug=prov_name))
                        summary["adopted"] += 1

                    updated = False
                    if config.client_id != sp_data.client_id:
                        config.client_id = sp_data.client_id
                        updated = True
                    if config.redirect_uris != sp_data.allowed_redirect_uris:
                        config.redirect_uris = sp_data.allowed_redirect_uris
                        updated = True
                    if config.is_active != sp_data.is_active:
                        config.is_active = sp_data.is_active
                        updated = True

                    # Secret handling: update only if supplied, otherwise retain existing
                    if sp_data.client_secret:
                        config.client_secret = sp_data.client_secret
                        updated = True

                    if updated:
                        config.save()
                        changes.append(ObjectChange(action="updated", object_type="social_provider", slug=prov_name))
                        summary["updated"] += 1
                    elif was_adopted:
                        config.save()
                else:
                    # New provider requires client_secret
                    if not sp_data.client_secret:
                        raise DRFValidationError(
                            f"client_secret is required when creating social provider '{prov_name}'."
                        )

                    SocialProviderConfig.objects.create(
                        project=locked_project,
                        provider=prov_name,
                        client_id=sp_data.client_id,
                        client_secret=sp_data.client_secret,
                        redirect_uris=sp_data.allowed_redirect_uris,
                        is_active=sp_data.is_active,
                        managed_by=ManagedBy.MANIFEST,
                    )
                    changes.append(ObjectChange(action="created", object_type="social_provider", slug=prov_name))
                    summary["created"] += 1

            if prune:
                configs_to_prune = list(
                    SocialProviderConfig.objects.select_for_update()
                    .filter(project=locked_project, managed_by=ManagedBy.MANIFEST)
                    .exclude(provider__in=declared_providers)
                )
                for candidate in configs_to_prune:
                    # Safety check: block prune if end users are linked to this provider
                    if SocialAccount.objects.filter(
                        user__project_id=locked_project.id, provider=candidate.provider
                    ).exists():
                        raise DRFValidationError(
                            f"Cannot prune social provider '{candidate.provider}': active user social accounts are linked to it."
                        )
                    candidate.delete()
                    changes.append(
                        ObjectChange(action="deleted", object_type="social_provider", slug=candidate.provider)
                    )
                    summary["deleted"] += 1

            # 5. Client Key Handoff
            client_key = None
            client_key_prefix = None

            active_runtime_key = (
                APIKey.objects.filter(
                    project=locked_project,
                    environment=environment,
                    key_type=APIKey.KeyType.RUNTIME,
                    is_active=True,
                )
                .order_by("-created_at")
                .first()
            )

            if not dry_run:
                if active_runtime_key is None or issue_client_key:
                    prefix, raw_key, hashed_key = APIKey.generate_key(
                        environment=environment, key_type=APIKey.KeyType.RUNTIME
                    )
                    APIKey.objects.create(
                        organization=locked_project.organization,
                        project=locked_project,
                        name=f"Auto-generated Client Key ({environment})",
                        environment=environment,
                        key_type=APIKey.KeyType.RUNTIME,
                        prefix=prefix,
                        hashed_key=hashed_key,
                        scopes=["auth:runtime"],
                    )
                    client_key = raw_key
                    client_key_prefix = prefix
                    changes.append(
                        ObjectChange(
                            action="minted",
                            object_type="api_key",
                            slug=prefix,
                            details={"environment": environment},
                        )
                    )
                else:
                    client_key = None
                    client_key_prefix = active_runtime_key.prefix

                # Security AuditLog for non-dry-run sync
                try:
                    AuditLog.objects.create(
                        event_type=AuditLog.EventType.PROJECT_UPDATED,
                        actor_api_key=actor_api_key,
                        organization=locked_project.organization,
                        project=locked_project,
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500] if request else "",
                        success=True,
                        event_data={
                            "action": "schema_sync",
                            "prune": prune,
                            "summary": summary,
                            "changes_count": len(changes),
                            # Secrets are strictly excluded
                        },
                    )
                except Exception as exc:
                    logger.error(f"[SchemaSync] AuditLog creation failed: {exc}")

            else:
                # Dry run persists nothing
                client_key = None
                client_key_prefix = active_runtime_key.prefix if active_runtime_key else None
                transaction.set_rollback(True)

        return SyncResult(
            dry_run=dry_run,
            status="planned" if dry_run else "applied",
            client_key=client_key,
            client_key_prefix=client_key_prefix,
            summary=summary,
            changes=changes,
            link_removals=link_removals,
            errors=[],
        )
