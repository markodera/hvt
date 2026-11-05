// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import path from "node:path";
import pc from "picocolors";
import { HVTManifest, HVTManifestSocialProvider } from "../types.js";

export const SUPPORTED_PROVIDERS = [
  "google",
  "github",
  "discord",
  "apple",
  "microsoft",
  "gitlab",
] as const;

export type SupportedProvider = typeof SUPPORTED_PROVIDERS[number];

export const SOCIAL_PROVIDER_TEMPLATES: Record<SupportedProvider, HVTManifestSocialProvider> = {
  google: {
    provider: "google",
    client_id: "${GOOGLE_CLIENT_ID}",
    client_secret: "${GOOGLE_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "http://localhost:3000/auth/callback",
      "http://127.0.0.1:3000/auth/callback"
    ],
    is_enabled: true,
  },
  github: {
    provider: "github",
    client_id: "${GITHUB_CLIENT_ID}",
    client_secret: "${GITHUB_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "http://localhost:3000/auth/callback",
      "http://127.0.0.1:3000/auth/callback"
    ],
    is_enabled: true,
  },
  discord: {
    provider: "discord",
    client_id: "${DISCORD_CLIENT_ID}",
    client_secret: "${DISCORD_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "http://localhost:3000/auth/callback"
    ],
    is_enabled: true,
  },
  apple: {
    provider: "apple",
    client_id: "${APPLE_CLIENT_ID}",
    client_secret: "${APPLE_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "https://example.com/auth/callback"
    ],
    is_enabled: true,
  },
  microsoft: {
    provider: "microsoft",
    client_id: "${MICROSOFT_CLIENT_ID}",
    client_secret: "${MICROSOFT_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "http://localhost:3000/auth/callback"
    ],
    is_enabled: true,
  },
  gitlab: {
    provider: "gitlab",
    client_id: "${GITLAB_CLIENT_ID}",
    client_secret: "${GITLAB_CLIENT_SECRET}",
    allowed_redirect_uris: [
      "http://localhost:3000/auth/callback"
    ],
    is_enabled: true,
  },
};

export interface InitCommandOptions {
  force?: boolean;
  providers?: string; // Comma-separated list e.g. "google,github,discord"
  allProviders?: boolean;
}

export function buildStarterSchema(providerKeys: SupportedProvider[]): HVTManifest & { $schema: string } {
  const selectedProviders = providerKeys.map((p) => SOCIAL_PROVIDER_TEMPLATES[p]);

  return {
    "$schema": "https://hvts.app/schemas/hvt.schema.v1.json",
    schema_version: 1,
    auth_methods: {
      password_enabled: true,
      passkeys_enabled: true,
      magic_links_enabled: true,
      social_oauth_enabled: true,
      totp_2fa_enabled: true,
    },
    permissions: [
      {
        slug: "documents:create",
        name: "Create Documents",
        description: "Allows creating new documents",
      },
      {
        slug: "documents:read",
        name: "Read Documents",
        description: "Allows viewing documents",
      },
      {
        slug: "documents:delete",
        name: "Delete Documents",
        description: "Allows deleting documents",
      },
      {
        slug: "team:invite",
        name: "Invite Team Members",
        description: "Allows inviting members to the organization",
      },
    ],
    roles: [
      {
        slug: "admin",
        name: "Administrator",
        description: "Full access to all project resources",
        is_default: false,
        permissions: [
          "documents:create",
          "documents:read",
          "documents:delete",
          "team:invite",
        ],
      },
      {
        slug: "member",
        name: "Member",
        description: "Standard team member with document authoring rights",
        is_default: true,
        permissions: [
          "documents:create",
          "documents:read",
        ],
      },
    ],
    social_providers: selectedProviders,
  };
}

export async function initCommand(options: InitCommandOptions): Promise<void> {
  const targetPath = path.join(process.cwd(), "hvt.schema.json");

  if (fs.existsSync(targetPath) && !options.force) {
    console.log(pc.yellow(`⚠ A schema file already exists at ${targetPath}. Use --force to overwrite.`));
    return;
  }

  let selectedKeys: SupportedProvider[];
  if (options.allProviders) {
    selectedKeys = [...SUPPORTED_PROVIDERS];
  } else if (options.providers) {
    const rawKeys = options.providers.split(",").map((s) => s.trim().toLowerCase());
    selectedKeys = rawKeys.filter((k): k is SupportedProvider => {
      const isSupported = (SUPPORTED_PROVIDERS as readonly string[]).includes(k);
      if (!isSupported) {
        console.log(pc.yellow(`⚠ Ignoring unknown provider: '${k}'. Supported: ${SUPPORTED_PROVIDERS.join(", ")}`));
      }
      return isSupported;
    });
    if (selectedKeys.length === 0) {
      selectedKeys = ["google", "github"];
    }
  } else {
    // Default to the two most common web providers: Google & GitHub
    selectedKeys = ["google", "github"];
  }

  const schema = buildStarterSchema(selectedKeys);
  fs.writeFileSync(targetPath, JSON.stringify(schema, null, 2) + "\n", "utf-8");

  console.log("");
  console.log(pc.bold(pc.green("✔ Created starter 'hvt.schema.json'")));
  console.log(pc.dim("  Location:  ") + pc.white(targetPath));
  console.log(pc.dim("  Providers: ") + pc.cyan(selectedKeys.join(", ")));
  console.log("");
  console.log(pc.bold("Supported HVT OAuth Providers:"));
  console.log(`  ${SUPPORTED_PROVIDERS.map((p) => selectedKeys.includes(p) ? pc.green(`✔ ${p}`) : pc.dim(`• ${p}`)).join("  ")}`);
  console.log("");
  console.log(pc.bold("Next steps:"));
  console.log(`  1. Define ${pc.cyan("HVT_PROJECT_ID")} and ${pc.cyan("HVT_MANAGEMENT_KEY")} in your .env or .env.local file.`);
  console.log(`  2. Add client secrets for chosen providers (${selectedKeys.map(k => pc.yellow(`${k.toUpperCase()}_CLIENT_SECRET`)).join(", ")}).`);
  console.log(`  3. Preview planned changes:  ${pc.cyan("npx @hvt/cli schema plan")}`);
  console.log(`  4. Apply changes to HVT:     ${pc.cyan("npx @hvt/cli schema sync")}`);
  console.log("");
}
