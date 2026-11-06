// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import path from "node:path";
import dotenv from "dotenv";
import YAML from "yaml";
import { HVTManifest } from "./types.js";
import { interpolateSchema } from "./interpolate.js";

export const DEFAULT_API_URL = "https://api.hvts.app";

export interface ResolvedConfig {
  apiUrl: string;
  projectId: string;
  managementKey: string;
  schemaPath: string;
  schemaFormat: "json" | "yaml";
  rawManifest: HVTManifest;
  interpolatedManifest: HVTManifest;
}

/**
 * Loads .env and .env.local from the current working directory.
 */
export function loadEnvFiles(cwd: string = process.cwd()): void {
  const envLocal = path.join(cwd, ".env.local");
  const envStandard = path.join(cwd, ".env");

  if (fs.existsSync(envStandard)) {
    dotenv.config({ path: envStandard });
  }
  if (fs.existsSync(envLocal)) {
    // .env.local overrides .env
    dotenv.config({ path: envLocal, override: true });
  }
}

/**
 * Finds the schema manifest file (preferring hvt.schema.json, then hvt.schema.yaml, then hvt.schema.yml).
 */
export function findSchemaFile(cwd: string = process.cwd(), explicitPath?: string): { path: string; format: "json" | "yaml" } {
  if (explicitPath) {
    const fullPath = path.isAbsolute(explicitPath) ? explicitPath : path.join(cwd, explicitPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Schema file not found at explicitly specified path: ${explicitPath}`);
    }
    const ext = path.extname(fullPath).toLowerCase();
    const format = ext === ".yaml" || ext === ".yml" ? "yaml" : "json";
    return { path: fullPath, format };
  }

  const candidates = [
    { name: "hvt.schema.json", format: "json" as const },
    { name: "hvt.schema.yaml", format: "yaml" as const },
    { name: "hvt.schema.yml", format: "yaml" as const },
  ];

  for (const candidate of candidates) {
    const candidatePath = path.join(cwd, candidate.name);
    if (fs.existsSync(candidatePath)) {
      return { path: candidatePath, format: candidate.format };
    }
  }

  throw new Error(
    "No schema file found in current directory.\n" +
    "Expected 'hvt.schema.json' (canonical) or 'hvt.schema.yaml'.\n" +
    "Run 'npx @hvt/cli init' to create a starter schema."
  );
}

/**
 * Parses and validates the raw manifest content.
 */
export function parseManifestContent(rawContent: string, format: "json" | "yaml"): HVTManifest {
  try {
    let parsed: unknown;
    if (format === "yaml") {
      parsed = YAML.parse(rawContent);
    } else {
      parsed = JSON.parse(rawContent);
    }

    if (!parsed || typeof parsed !== "object") {
      throw new Error("Schema root must be an object.");
    }
    const manifest = parsed as HVTManifest;
    if (manifest.schema_version !== 1) {
      throw new Error(
        `Invalid or missing 'schema_version'. Expected 1, received: ${manifest.schema_version}`
      );
    }
    return manifest;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse ${format.toUpperCase()} schema file: ${msg}`);
  }
}

/**
 * Resolves full CLI configuration from options, environment, and files.
 */
export function resolveConfig(options: {
  apiUrl?: string;
  projectId?: string;
  key?: string;
  schema?: string;
  cwd?: string;
}): ResolvedConfig {
  const cwd = options.cwd || process.cwd();
  loadEnvFiles(cwd);

  const apiUrl = (
    options.apiUrl ||
    process.env.HVT_API_URL ||
    process.env.NEXT_PUBLIC_HVT_HOST ||
    DEFAULT_API_URL
  ).replace(/\/+$/, "");
  const projectId =
    options.projectId ||
    process.env.HVT_PROJECT_ID ||
    process.env.NEXT_PUBLIC_HVT_PROJECT_ID;
  const managementKey = options.key || process.env.HVT_MANAGEMENT_KEY;

  if (!projectId) {
    throw new Error(
      "Missing Project ID.\n" +
      "Provide it via --project <id>, HVT_PROJECT_ID environment variable, or in .env."
    );
  }
  if (!managementKey) {
    throw new Error(
      "Missing Management Key.\n" +
      "Provide it via --key <key>, HVT_MANAGEMENT_KEY environment variable, or in .env.\n" +
      "Expected format: hvt_mgmt_test_... or hvt_mgmt_live_..."
    );
  }

  const { path: schemaPath, format: schemaFormat } = findSchemaFile(cwd, options.schema);
  const rawContent = fs.readFileSync(schemaPath, "utf-8");
  const rawManifest = parseManifestContent(rawContent, schemaFormat);
  const interpolatedManifest = interpolateSchema(rawManifest, process.env);

  return {
    apiUrl,
    projectId,
    managementKey,
    schemaPath,
    schemaFormat,
    rawManifest,
    interpolatedManifest,
  };
}

/**
 * Warns if a sensitive file like .env.local is not excluded by .gitignore.
 */
export function warnIfNotGitignored(filename: string = ".env.local", cwd: string = process.cwd()): boolean {
  const gitignorePath = path.join(cwd, ".gitignore");
  if (!fs.existsSync(gitignorePath)) {
    console.warn(`[WARNING] No .gitignore file found in ${cwd}. Ensure '${filename}' is never committed to version control!`);
    return false;
  }
  const content = fs.readFileSync(gitignorePath, "utf-8");
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  const isIgnored = lines.some((line) => {
    if (!line || line.startsWith("#")) return false;
    return (
      line === filename ||
      line === `/${filename}` ||
      line === ".env*" ||
      line === "*.local" ||
      line === ".env.local"
    );
  });
  if (!isIgnored) {
    console.warn(`[WARNING] '${filename}' does not appear to be ignored in .gitignore! Add '${filename}' or '.env*' to prevent leaking secrets.`);
    return false;
  }
  return true;
}

/**
 * Updates or creates .env.local with NEXT_PUBLIC_HVT_CLIENT_KEY.
 * Strictly refuses to write management keys into NEXT_PUBLIC_* variables.
 */
export function writeClientKeyToEnvLocal(clientKey: string, cwd: string = process.cwd()): string {
  if (clientKey.startsWith("hvt_mgmt_")) {
    throw new Error(
      "SECURITY ERROR: Management keys must never be written to NEXT_PUBLIC_* variables. " +
      "Only runtime client keys (hvt_test_*, hvt_live_*) can be exposed to frontend environments."
    );
  }

  warnIfNotGitignored(".env.local", cwd);

  const envLocalPath = path.join(cwd, ".env.local");
  let content = "";
  if (fs.existsSync(envLocalPath)) {
    content = fs.readFileSync(envLocalPath, "utf-8");
  }

  const keyVariable = "NEXT_PUBLIC_HVT_CLIENT_KEY";
  const regex = new RegExp(`^${keyVariable}=.*$`, "m");

  if (regex.test(content)) {
    content = content.replace(regex, `${keyVariable}=${clientKey}`);
  } else {
    content = content.trimEnd();
    content += (content.length > 0 ? "\n\n" : "") + `# Added by HVT CLI\n${keyVariable}=${clientKey}\n`;
  }

  fs.writeFileSync(envLocalPath, content, "utf-8");
  return envLocalPath;
}
