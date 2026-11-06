// SPDX-License-Identifier: Apache-2.0
import pc from "picocolors";
import { resolveConfig } from "../config.js";
import { HVTAPIClient } from "../client.js";
import { redactKey } from "../interpolate.js";

export interface WhoamiCommandOptions {
  apiUrl?: string;
  projectId?: string;
  key?: string;
  json?: boolean;
}

export async function whoamiCommand(options: WhoamiCommandOptions): Promise<void> {
  const config = resolveConfig({
    apiUrl: options.apiUrl,
    projectId: options.projectId,
    key: options.key,
    requireSchema: false,
  });

  const client = new HVTAPIClient(config.apiUrl, config.managementKey);
  const status = await client.verifyConnection(config.projectId);

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          status: "connected",
          apiUrl: config.apiUrl,
          projectId: config.projectId,
          environment: status.environment,
          keyPrefix: redactKey(config.managementKey),
        },
        null,
        2
      )
    );
    return;
  }

  console.log("");
  console.log(pc.bold(pc.green("✔ Connected to HVT")));
  console.log(pc.dim("  API Endpoint:   ") + pc.white(config.apiUrl));
  console.log(pc.dim("  Project ID:     ") + pc.white(config.projectId));
  console.log(pc.dim("  Environment:    ") + pc.yellow(status.environment));
  console.log(pc.dim("  Management Key: ") + pc.cyan(redactKey(config.managementKey)));
  console.log("");
}
