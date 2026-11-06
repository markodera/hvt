// SPDX-License-Identifier: Apache-2.0
import { resolveConfig } from "../config.js";
import { HVTAPIClient } from "../client.js";
import { printDiff } from "../diff.js";

export interface PlanCommandOptions {
  apiUrl?: string;
  projectId?: string;
  key?: string;
  schema?: string;
  json?: boolean;
}

export async function planCommand(options: PlanCommandOptions): Promise<void> {
  const config = resolveConfig({
    apiUrl: options.apiUrl,
    projectId: options.projectId,
    key: options.key,
    schema: options.schema,
  });

  const client = new HVTAPIClient(config.apiUrl, config.managementKey);

  const res = await client.sync({
    projectId: config.projectId,
    manifest: config.interpolatedManifest,
    dryRun: true,
  });

  if (options.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  printDiff(res, { isDryRun: true });
}
