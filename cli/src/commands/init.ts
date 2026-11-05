// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import path from "node:path";
import pc from "picocolors";

const STARTER_SCHEMA_JSON = {
  "$schema": "https://hvts.app/schemas/hvt.schema.v1.json",
  "schema_version": 1,
  "auth_methods": {
    "password_enabled": true,
    "passkeys_enabled": true,
    "magic_links_enabled": true,
    "social_oauth_enabled": true,
    "totp_2fa_enabled": true
  },
  "permissions": [
    {
      "slug": "documents:create",
      "name": "Create Documents",
      "description": "Allows creating new documents"
    },
    {
      "slug": "documents:read",
      "name": "Read Documents",
      "description": "Allows viewing documents"
    },
    {
      "slug": "documents:delete",
      "name": "Delete Documents",
      "description": "Allows deleting documents"
    },
    {
      "slug": "team:invite",
      "name": "Invite Team Members",
      "description": "Allows inviting members to the organization"
    }
  ],
  "roles": [
    {
      "slug": "admin",
      "name": "Administrator",
      "description": "Full access to all project resources",
      "is_default": false,
      "permissions": [
        "documents:create",
        "documents:read",
        "documents:delete",
        "team:invite"
      ]
    },
    {
      "slug": "member",
      "name": "Member",
      "description": "Standard team member with document authoring rights",
      "is_default": true,
      "permissions": [
        "documents:create",
        "documents:read"
      ]
    }
  ],
  "social_providers": [
    {
      "provider": "google",
      "client_id": "${GOOGLE_CLIENT_ID}",
      "client_secret": "${GOOGLE_CLIENT_SECRET}",
      "allowed_redirect_uris": [
        "http://localhost:3000/auth/callback",
        "http://127.0.0.1:3000/auth/callback"
      ],
      "is_enabled": true
    }
  ]
};

export async function initCommand(options: { force?: boolean }): Promise<void> {
  const targetPath = path.join(process.cwd(), "hvt.schema.json");

  if (fs.existsSync(targetPath) && !options.force) {
    console.log(pc.yellow(`⚠ A schema file already exists at ${targetPath}. Use --force to overwrite.`));
    return;
  }

  fs.writeFileSync(targetPath, JSON.stringify(STARTER_SCHEMA_JSON, null, 2) + "\n", "utf-8");

  console.log("");
  console.log(pc.bold(pc.green("✔ Created starter 'hvt.schema.json'")));
  console.log(pc.dim("  Location: ") + pc.white(targetPath));
  console.log("");
  console.log(pc.bold("Next steps:"));
  console.log(`  1. Define ${pc.cyan("HVT_PROJECT_ID")} and ${pc.cyan("HVT_MANAGEMENT_KEY")} in your .env or .env.local file.`);
  console.log(`  2. Preview planned changes:  ${pc.cyan("npx @hvt/cli schema plan")}`);
  console.log(`  3. Apply changes to HVT:     ${pc.cyan("npx @hvt/cli schema sync")}`);
  console.log("");
}
