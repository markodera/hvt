// SPDX-License-Identifier: Apache-2.0
import pc from "picocolors";
import { SchemaSyncResponse, SchemaChangeItem } from "./types.js";

/**
 * Pretty-prints schema plan/sync results to the terminal.
 */
export function printDiff(response: SchemaSyncResponse, options: { isDryRun: boolean }): void {
  const { status, environment, project_id, changes, link_removals, client_key, client_key_prefix } = response;

  console.log("");
  if (status === "planned") {
    console.log(pc.bold(pc.cyan(`⚡ HVT Schema Plan Preview (Dry-Run)`)));
  } else {
    console.log(pc.bold(pc.green(`✔ HVT Schema Synchronized Successfully`)));
  }

  console.log(pc.dim(`  Environment: `) + pc.yellow(environment));
  console.log(pc.dim(`  Project ID:  `) + pc.white(project_id));
  console.log("");

  if (changes.length === 0 && link_removals.length === 0) {
    console.log(pc.dim("  No changes detected. Remote authorization topology matches local manifest.\n"));
    return;
  }

  // Group by change type
  const permissions = changes.filter((c) => c.type === "permission");
  const roles = changes.filter((c) => c.type === "role");
  const providers = changes.filter((c) => c.type === "social_provider");
  const authMethods = changes.filter((c) => c.type === "auth_methods");

  if (permissions.length > 0) {
    console.log(pc.bold("  Permissions:"));
    for (const item of permissions) {
      printChangeItem(item);
    }
    console.log("");
  }

  if (roles.length > 0) {
    console.log(pc.bold("  Roles:"));
    for (const item of roles) {
      printChangeItem(item);
    }
    console.log("");
  }

  if (link_removals.length > 0) {
    console.log(pc.bold("  Role-Permission Detachments:"));
    for (const removal of link_removals) {
      console.log(`    ${pc.red("-")} Detach permission ${pc.bold(removal.permission_slug)} from role ${pc.bold(removal.role_slug)}`);
    }
    console.log("");
  }

  if (providers.length > 0) {
    console.log(pc.bold("  Social Providers:"));
    for (const item of providers) {
      printChangeItem(item);
    }
    console.log("");
  }

  if (authMethods.length > 0) {
    console.log(pc.bold("  Auth Methods:"));
    for (const item of authMethods) {
      printChangeItem(item);
    }
    console.log("");
  }

  if (client_key) {
    console.log(pc.bold(pc.green("  🔑 Runtime Client Key Minted (Save this once):")));
    console.log(`    ${pc.green(client_key)}`);
    console.log(pc.dim("    Saved to .env.local as NEXT_PUBLIC_HVT_CLIENT_KEY\n"));
  } else if (client_key_prefix) {
    console.log(pc.dim(`  Active Runtime Key: ${client_key_prefix}_...\n`));
  }

  if (options.isDryRun) {
    console.log(pc.cyan("  Note: No changes were committed (dry-run). Run 'hvt schema sync' to apply.\n"));
  }
}

function printChangeItem(item: SchemaChangeItem): void {
  switch (item.action) {
    case "created":
      console.log(`    ${pc.green("+")} Create ${item.type} ${pc.bold(pc.green(item.slug))}`);
      break;
    case "adopted":
      console.log(`    ${pc.cyan("~")} Adopt existing dashboard ${item.type} ${pc.bold(pc.cyan(item.slug))}`);
      break;
    case "reconciled":
    case "updated":
      console.log(`    ${pc.yellow("~")} Reconcile ${item.type} ${pc.bold(pc.yellow(item.slug))}`);
      break;
    case "pruned":
      console.log(`    ${pc.red("-")} Prune manifest-owned ${item.type} ${pc.bold(pc.red(item.slug))}`);
      break;
    default:
      console.log(`    ${pc.dim("•")} ${item.action} ${item.type} ${item.slug}`);
      break;
  }
}
