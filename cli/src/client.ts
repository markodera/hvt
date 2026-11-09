// SPDX-License-Identifier: Apache-2.0
import { HVTManifest, SchemaSyncResponse } from "./types.js";

export interface SyncRequestOptions {
  apiUrl: string;
  projectId: string;
  managementKey: string;
  manifest: HVTManifest;
  dryRun?: boolean;
  prune?: boolean;
  issueClientKey?: boolean;
}

export interface ClientErrorResponse {
  status: number;
  message: string;
  detail?: unknown;
  code?: string;
}

export class HVTAPIClient {
  private apiUrl: string;
  private managementKey: string;

  constructor(apiUrl: string, managementKey: string) {
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.managementKey = managementKey;
  }

  /**
   * Calls the declarative schema synchronization endpoint.
   */
  async sync(options: {
    projectId: string;
    manifest: HVTManifest;
    dryRun?: boolean;
    prune?: boolean;
    issueClientKey?: boolean;
  }): Promise<SchemaSyncResponse> {
    const url = new URL(
      `${this.apiUrl}/api/v1/organizations/current/projects/${options.projectId}/sync/`
    );

    if (options.dryRun) {
      url.searchParams.set("dry_run", "true");
    }
    if (options.prune) {
      url.searchParams.set("prune", "true");
    }
    if (options.issueClientKey) {
      url.searchParams.set("issue_client_key", "true");
    }

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.managementKey,
          "User-Agent": "@hvt/cli/0.1.0",
        },
        body: JSON.stringify(options.manifest),
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to connect to HVT API at ${this.apiUrl}: ${msg}`);
    }

    const rawText = await response.text();
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(rawText);
    } catch {
      throw new Error(
        `Unexpected non-JSON response from server (HTTP ${response.status}):\n${rawText.slice(0, 300)}`
      );
    }

    if (!response.ok) {
      this.handleErrorResponse(response.status, data);
    }

    return data as unknown as SchemaSyncResponse;
  }

  /**
   * Helper that checks credentials against the sync plan endpoint.
   */
  async verifyConnection(projectId: string): Promise<{
    status: string;
    projectId: string;
    environment: string;
  }> {
    const emptyManifest: HVTManifest = { schema_version: 1 };
    const res = await this.sync({
      projectId,
      manifest: emptyManifest,
      dryRun: true,
    });
    return {
      status: "connected",
      projectId: res.project_id,
      environment: res.environment,
    };
  }

  /**
   * Fetches an AI setup prompt and temporary test management key from HVT Cloud.
   */
  async getSetupPrompt(projectId: string): Promise<{
    prompt: string;
    key?: string;
    maskedKey?: string;
    expiresAt?: string;
    expiresInSeconds?: number;
  }> {
    const url = `${this.apiUrl}/api/v1/organizations/current/projects/${projectId}/setup-prompt/`;
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.managementKey,
          "User-Agent": "@hvt/cli/0.1.0",
        },
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to connect to HVT API at ${this.apiUrl}: ${msg}`);
    }

    const rawText = await response.text();
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(rawText);
    } catch {
      throw new Error(
        `Unexpected non-JSON response from server (HTTP ${response.status}):\n${rawText.slice(0, 300)}`
      );
    }

    if (!response.ok) {
      this.handleErrorResponse(response.status, data);
    }

    return {
      prompt: data.prompt as string,
      key: data.key as string,
      maskedKey: data.masked_key as string,
      expiresAt: data.expires_at as string,
      expiresInSeconds: data.expires_in_seconds as number,
    };
  }

  private handleErrorResponse(status: number, data: Record<string, unknown>): never {
    const detail = (data.detail || data.error || data.message || JSON.stringify(data)) as string;

    if (status === 403) {
      if (typeof detail === "string" && detail.includes("Management keys cannot be used")) {
        throw new Error(
          `Security Plane Error (HTTP 403):\n${detail}\n` +
          `Make sure you are supplying a Management Key (hvt_mgmt_*), not a runtime client key.`
        );
      }
      if (typeof detail === "string" && detail.includes("schema:plan")) {
        throw new Error(
          `Scope Error (HTTP 403):\n${detail}\n` +
          `This key holds 'schema:plan' which only permits dry-run previews. Use a key with 'schema:sync' to apply changes.`
        );
      }
      throw new Error(`Permission Denied (HTTP 403):\n${detail}`);
    }

    if (status === 404) {
      throw new Error(
        `Not Found (HTTP 404):\n` +
        `The project was not found, or the provided management key does not belong to this project.`
      );
    }

    if (status === 400) {
      throw new Error(`Validation Error (HTTP 400):\n${typeof detail === "string" ? detail : JSON.stringify(data, null, 2)}`);
    }

    throw new Error(`HVT API Error (HTTP ${status}):\n${typeof detail === "string" ? detail : JSON.stringify(data, null, 2)}`);
  }
}
