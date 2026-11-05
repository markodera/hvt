// SPDX-License-Identifier: Apache-2.0
import { Command } from "commander";
import pc from "picocolors";
import { initCommand } from "./commands/init.js";
import { planCommand } from "./commands/plan.js";
import { syncCommand } from "./commands/sync.js";
import { whoamiCommand } from "./commands/whoami.js";

const program = new Command();

program
  .name("hvt")
  .description("Official CLI for HVT — Declarative schema provisioning, plan previews, and auth synchronization.")
  .version("0.1.0");

// Global options
program
  .option("--api-url <url>", "HVT API base URL (defaults to https://api.hvts.app or HVT_API_URL)")
  .option("-k, --key <key>", "HVT Management Key (defaults to HVT_MANAGEMENT_KEY)")
  .option("-p, --project <id>", "HVT Project ID (defaults to HVT_PROJECT_ID)")
  .option("-s, --schema <path>", "Path to schema file (defaults to hvt.schema.json or hvt.schema.yaml)")
  .option("--verbose", "Show detailed error stack traces")
  .option("--json", "Output results as JSON");

// hvt init
program
  .command("init")
  .description("Create a starter 'hvt.schema.json' file in the current directory")
  .option("-f, --force", "Overwrite existing schema file if present")
  .action(async (opts) => {
    try {
      await initCommand(opts);
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

// Schema group
const schemaGroup = program.command("schema").description("Declarative schema operations");

schemaGroup
  .command("plan")
  .description("Preview proposed changes to the project's authorization schema (dry-run)")
  .action(async () => {
    try {
      const globalOpts = program.opts();
      await planCommand({
        apiUrl: globalOpts.apiUrl,
        projectId: globalOpts.project,
        key: globalOpts.key,
        schema: globalOpts.schema,
        json: globalOpts.json,
      });
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

schemaGroup
  .command("sync")
  .description("Synchronize and reconcile local schema with HVT Cloud")
  .option("--prune", "Delete manifest-owned roles, permissions, and providers missing from the schema")
  .option("-y, --yes", "Confirm prune deletion automatically (required in non-interactive/CI environments)")
  .option("--issue-client-key", "Mint an additional runtime client key even if one is already active")
  .action(async (cmdOpts) => {
    try {
      const globalOpts = program.opts();
      await syncCommand({
        apiUrl: globalOpts.apiUrl,
        projectId: globalOpts.project,
        key: globalOpts.key,
        schema: globalOpts.schema,
        prune: cmdOpts.prune,
        yes: cmdOpts.yes,
        issueClientKey: cmdOpts.issueClientKey,
        json: globalOpts.json,
      });
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

// Shortcuts: `hvt plan` and `hvt sync`
program
  .command("plan", { hidden: true })
  .action(async () => {
    try {
      const globalOpts = program.opts();
      await planCommand({
        apiUrl: globalOpts.apiUrl,
        projectId: globalOpts.project,
        key: globalOpts.key,
        schema: globalOpts.schema,
        json: globalOpts.json,
      });
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

program
  .command("sync", { hidden: true })
  .option("--prune", "Delete manifest-owned roles, permissions, and providers missing from the schema")
  .option("-y, --yes", "Confirm prune deletion automatically")
  .option("--issue-client-key", "Mint an additional runtime client key")
  .action(async (cmdOpts) => {
    try {
      const globalOpts = program.opts();
      await syncCommand({
        apiUrl: globalOpts.apiUrl,
        projectId: globalOpts.project,
        key: globalOpts.key,
        schema: globalOpts.schema,
        prune: cmdOpts.prune,
        yes: cmdOpts.yes,
        issueClientKey: cmdOpts.issueClientKey,
        json: globalOpts.json,
      });
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

// hvt whoami
program
  .command("whoami")
  .description("Verify connection and credentials against HVT Cloud")
  .action(async () => {
    try {
      const globalOpts = program.opts();
      await whoamiCommand({
        apiUrl: globalOpts.apiUrl,
        projectId: globalOpts.project,
        key: globalOpts.key,
        json: globalOpts.json,
      });
    } catch (err: unknown) {
      handleCliError(err, program.opts().verbose);
    }
  });

function handleCliError(err: unknown, verbose?: boolean): void {
  const msg = err instanceof Error ? err.message : String(err);
  console.error("");
  console.error(pc.bold(pc.red("✖ Error: ") + pc.white(msg)));
  if (verbose && err instanceof Error && err.stack) {
    console.error(pc.dim("\nStack trace:"));
    console.error(pc.dim(err.stack));
  }
  console.error("");
  process.exit(1);
}

program.parse(process.argv);
