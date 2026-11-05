// SPDX-License-Identifier: Apache-2.0

export interface HVTManifestPermission {
  slug: string;
  name?: string;
  description?: string;
}

export interface HVTManifestRole {
  slug: string;
  name?: string;
  description?: string;
  is_default_signup?: boolean;
  is_default?: boolean;
  permissions?: string[];
}

export interface HVTManifestSocialProvider {
  provider: "google" | "github" | "discord" | "apple" | "microsoft" | "gitlab" | string;
  client_id: string;
  client_secret?: string;
  allowed_redirect_uris?: string[];
  is_active?: boolean;
  is_enabled?: boolean;
}

export interface HVTManifest {
  schema_version: number;
  permissions?: HVTManifestPermission[];
  roles?: HVTManifestRole[];
  social_providers?: HVTManifestSocialProvider[];
}

export interface SchemaChangeItem {
  type: "permission" | "role" | "social_provider" | "auth_methods" | "runtime_key";
  action: "created" | "adopted" | "reconciled" | "pruned" | "minted" | "updated";
  slug: string;
  details?: Record<string, unknown>;
}

export interface LinkRemovalItem {
  role_slug: string;
  permission_slug: string;
}

export interface SchemaSyncResponse {
  status: "applied" | "planned";
  environment: "test" | "live";
  project_id: string;
  organization_id: string;
  client_key?: string | null;
  client_key_prefix?: string;
  changes: SchemaChangeItem[];
  link_removals: LinkRemovalItem[];
  prune_candidates?: string[];
}
