// SPDX-License-Identifier: Apache-2.0

const ENV_VAR_REGEX = /\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)/g;

/**
 * Resolves `${ENV_VAR}` or `$ENV_VAR` references in any string using values from process.env.
 * Throws a descriptive error if a referenced environment variable is not set.
 */
export function interpolateString(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(ENV_VAR_REGEX, (match, p1, p2) => {
    const varName = p1 || p2;
    const resolved = env[varName];
    if (resolved === undefined || resolved === "") {
      throw new Error(
        `Missing required environment variable '${varName}' referenced in schema as ${match}.\n` +
        `Define '${varName}' in your .env or .env.local file, or pass it in your shell environment.`
      );
    }
    return resolved;
  });
}

/**
 * Recursively traverses an object/array and interpolates all string values.
 */
export function interpolateSchema<T>(obj: T, env: NodeJS.ProcessEnv = process.env): T {
  if (typeof obj === "string") {
    return interpolateString(obj, env) as unknown as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => interpolateSchema(item, env)) as unknown as T;
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = interpolateSchema(value, env);
    }
    return result as T;
  }
  return obj;
}

/**
 * Safely masks a sensitive secret for terminal output.
 */
export function redactSecret(secret: string | null | undefined): string {
  if (!secret) return "[NONE]";
  if (secret.length <= 8) return "[REDACTED]";
  return `${secret.slice(0, 4)}...[REDACTED]...${secret.slice(-4)}`;
}

/**
 * Safely masks an API key, showing only the prefix.
 */
export function redactKey(key: string | null | undefined): string {
  if (!key) return "[NONE]";
  const parts = key.split("_");
  if (parts.length >= 3) {
    const prefix = parts.slice(0, 3).join("_");
    return `${prefix}_...`;
  }
  return `${key.slice(0, 8)}...`;
}
