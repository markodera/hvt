// SPDX-License-Identifier: Apache-2.0
import { describe, it } from "node:test";
import assert from "node:assert";
import { printDiff } from "./diff.js";
import { SchemaSyncResponse } from "./types.js";

describe("CLI Diff & Sync Reporting", () => {
  it("processes server response with object_type and link removals without error", () => {
    const logs: string[] = [];
    const originalLog = console.log;
    console.log = (msg?: unknown) => {
      logs.push(String(msg ?? ""));
    };

    try {
      const response: SchemaSyncResponse = {
        status: "applied",
        environment: "test",
        project_id: "test-proj-uuid",
        organization_id: "test-org-uuid",
        client_key: "hvt_test_1234567890abcdef",
        changes: [
          {
            object_type: "permission",
            action: "created",
            slug: "docs:write",
          },
          {
            object_type: "role",
            action: "adopted",
            slug: "editor",
          },
          {
            object_type: "social_provider",
            action: "created",
            slug: "google",
          },
        ],
        link_removals: [
          {
            role: "editor",
            permission: "admin:all",
          },
        ],
      };

      printDiff(response, { isDryRun: false });

      const combined = logs.join("\n");
      assert.ok(combined.includes("Permissions:"));
      assert.ok(combined.includes("docs:write"));
      assert.ok(combined.includes("Roles:"));
      assert.ok(combined.includes("editor"));
      assert.ok(combined.includes("Social Providers:"));
      assert.ok(combined.includes("google"));
      assert.ok(combined.includes("Role-Permission Detachments:"));
      assert.ok(combined.includes("admin:all"));
      assert.ok(combined.includes("hvt_test_1234567890abcdef"));
    } finally {
      console.log = originalLog;
    }
  });
});
