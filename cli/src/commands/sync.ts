// SPDX-License-Identifier: Apache-2.0
import readline from "node:readline";
import pc from "picocolors";
import { resolveConfig, writeClientKeyToEnvLocal } from "../config.js";
import { HVTAPIClient } from "../client.js";
import { printDiff } from "../diff.js";

export interface SyncCommandOptions {
  apiUrl?: string;
  projectId?: string;
  key?: string;
  schema?: string;
  prune?: boolean;
  yes?: boolean;
  issueClientKey?: boolean;
  json?: boolean;
}

export async function syncCommand(options: SyncCommandOptions): Promise<void> {
  const config = resolveConfig({
    apiUrl: options.apiUrl,
    projectId: options.projectId,
    key: options.key,
    schema: options.schema,
  });

  // Prune confirmation safety gate
  if (options.prune && !options.yes) {
    const isCI = Boolean(process.env.CI || !process.stdout.isTTY);
    if (isCI) {
      throw new Error(
        "Pruning requested in a non-interactive or CI environment without explicit confirmation.\n" +
        "Pass '--prune --yes' to confirm deleting manifest-owned objects missing from the schema."
      );
    }

    const confirmed = await askConfirmation(
      pc.yellow("⚠ WARNING: You passed --prune. Any manifest-owned roles, permissions, or social providers missing from your schema will be permanently deleted.\nAre you sure you want to proceed? (y/N): ")
    );

    if (!confirmed) {
      console.log(pc.dim("Sync cancelled."));
      return;
    }
  }

  const client = new HVTAPIClient(config.apiUrl, config.managementKey);

  const res = await client.sync({
    projectId: config.projectId,
    manifest: config.interpolatedManifest,
    dryRun: false,
    prune: options.prune,
    issueClientKey: options.issueClientKey,
  });

  // If a new client key was minted, auto-save to .env.local
  if (res.client_key) {
    writeClientKeyToEnvLocal(res.client_key);
  }

  if (options.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  printDiff(res, { isDryRun: false });
}

function askConfirmation(promptText: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(promptText, (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      resolve(trimmed === "y" || trimmed === "yes");
    });
  });
}
