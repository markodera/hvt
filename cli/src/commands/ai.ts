// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import pc from "picocolors";
import { resolveConfig } from "../config.js";
import { HVTAPIClient } from "../client.js";

export interface AISetupPromptOptions {
  apiUrl?: string;
  projectId?: string;
  key?: string;
  json?: boolean;
  copy?: boolean;
  file?: string;
}

export function formatFallbackPrompt(options: {
  apiUrl: string;
  projectId: string;
  managementKey: string;
}): string {
  const host = options.apiUrl.replace(/\/+$/, "");
  return `You are setting up HVT Authentication for this project.

CRITICAL DIRECTIVE:
HVT is NOT an OpenID Connect (OIDC), NextAuth, or Auth.js provider.
HVT is a direct REST authentication API. Do NOT guess endpoints or use OAuth redirect flows.

## Project Information
- Project ID: ${options.projectId}
- Environment: test (safe sandbox mode)
- HVT Host: ${host}
- Temporary Management Key: ${options.managementKey}

## Integration Instructions
1. Install the HVT SDK and CLI:
   npm install @hvt/sdk
   npm install -D @hvt/cli

2. Configure environment variables in \`.env.local\`:
   HVT_API_URL="${host}"
   HVT_PROJECT_ID="${options.projectId}"
   HVT_MANAGEMENT_KEY="${options.managementKey}"
   NEXT_PUBLIC_HVT_HOST="${host}"
   NEXT_PUBLIC_HVT_PROJECT_ID="${options.projectId}"

3. Preview authentication schema:
   npx @hvt/cli schema plan --project ${options.projectId}

4. Apply declarative schema to initialize auth methods, roles, and mint runtime client key:
   npx @hvt/cli schema sync --project ${options.projectId}

5. Save the returned client key as \`NEXT_PUBLIC_HVT_CLIENT_KEY\` in \`.env.local\`.
   Initialize \`@hvt/sdk\` or send \`X-API-Key: <key>\` on \`/api/v1/auth/runtime/*\` requests.
   Never put management keys (\`hvt_mgmt_*\`) in the browser or in NEXT_PUBLIC_ variables.

Full Machine-Readable Spec: ${host}/api/v1/auth/.well-known/openid-configuration
Live OpenAPI Schema: ${host}/api/schema/
`;
}

export function copyToClipboard(text: string): boolean {
  try {
    if (process.platform === "win32") {
      const proc = spawnSync("clip", { input: text, stdio: ["pipe", "ignore", "ignore"] });
      return proc.status === 0;
    } else if (process.platform === "darwin") {
      const proc = spawnSync("pbcopy", { input: text, stdio: ["pipe", "ignore", "ignore"] });
      return proc.status === 0;
    } else {
      const proc = spawnSync("xclip", ["-selection", "clipboard"], { input: text, stdio: ["pipe", "ignore", "ignore"] });
      if (proc.status === 0) return true;
      const wl = spawnSync("wl-copy", { input: text, stdio: ["pipe", "ignore", "ignore"] });
      return wl.status === 0;
    }
  } catch {
    return false;
  }
}

export async function aiSetupPromptCommand(options: AISetupPromptOptions): Promise<void> {
  const config = resolveConfig({
    apiUrl: options.apiUrl,
    projectId: options.projectId,
    key: options.key,
    requireSchema: false,
  });

  let promptText = "";
  let key = config.managementKey;
  let maskedKey: string | undefined;
  let expiresAt: string | undefined;

  try {
    const client = new HVTAPIClient(config.apiUrl, config.managementKey);
    const serverResult = await client.getSetupPrompt(config.projectId);
    promptText = serverResult.prompt;
    if (serverResult.key) key = serverResult.key;
    maskedKey = serverResult.maskedKey;
    expiresAt = serverResult.expiresAt;
  } catch {
    promptText = formatFallbackPrompt({
      apiUrl: config.apiUrl,
      projectId: config.projectId,
      managementKey: config.managementKey,
    });
  }

  if (options.file) {
    fs.writeFileSync(options.file, promptText, "utf-8");
  }

  let copied = false;
  if (options.copy) {
    copied = copyToClipboard(promptText);
  }

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          prompt: promptText,
          projectId: config.projectId,
          apiUrl: config.apiUrl,
          key,
          maskedKey,
          expiresAt,
          copied,
          savedToFile: options.file || null,
        },
        null,
        2
      )
    );
    return;
  }

  console.log("");
  console.log(pc.bold(pc.green("✔ HVT AI Agent Setup Prompt Generated")));
  console.log(pc.dim("  Project ID: ") + pc.white(config.projectId));
  console.log(pc.dim("  API Host:   ") + pc.white(config.apiUrl));
  if (options.file) {
    console.log(pc.dim("  Saved File: ") + pc.cyan(options.file));
  }
  if (options.copy) {
    if (copied) {
      console.log(pc.dim("  Clipboard:  ") + pc.green("Copied to system clipboard!"));
    } else {
      console.log(pc.dim("  Clipboard:  ") + pc.yellow("Failed to access system clipboard"));
    }
  }
  console.log("");
  console.log(pc.cyan("--- Prompt Begin ---"));
  console.log(promptText);
  console.log(pc.cyan("--- Prompt End ---"));
  console.log("");
  console.log(pc.dim("Tip: Paste this prompt into Claude Code, Cursor, or ChatGPT to scaffold your authentication integration."));
  console.log("");
}
