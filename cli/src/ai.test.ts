// SPDX-License-Identifier: Apache-2.0
import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { formatFallbackPrompt, aiSetupPromptCommand } from "./commands/ai.js";

describe("CLI AI Setup Prompt Command", () => {
  it("formats dynamic setup prompt containing project details and CLI directives", () => {
    const prompt = formatFallbackPrompt({
      apiUrl: "https://api.hvts.app",
      projectId: "proj-1234-uuid",
      managementKey: "hvt_mgmt_test_1234567890abcdef",
    });

    assert.ok(prompt.includes("proj-1234-uuid"));
    assert.ok(prompt.includes("hvt_mgmt_test_1234567890abcdef"));
    assert.ok(prompt.includes("https://api.hvts.app"));
    assert.ok(prompt.includes("@hvt/sdk"));
    assert.ok(prompt.includes("@hvt/cli"));
    assert.ok(prompt.includes("npx @hvt/cli schema plan --project proj-1234-uuid"));
    assert.ok(prompt.includes("npx @hvt/cli schema sync --project proj-1234-uuid"));
    assert.ok(prompt.includes("NEXT_PUBLIC_HVT_CLIENT_KEY"));
  });

  it("writes setup prompt to file when --file option is provided", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hvt-ai-test-"));
    const filePath = path.join(tmpDir, "SETUP_PROMPT.md");

    try {
      await aiSetupPromptCommand({
        apiUrl: "http://127.0.0.1:8000",
        projectId: "test-project-uuid",
        key: "hvt_mgmt_test_mockkey",
        file: filePath,
        json: true,
      });

      assert.ok(fs.existsSync(filePath));
      const content = fs.readFileSync(filePath, "utf-8");
      assert.ok(content.includes("test-project-uuid"));
      assert.ok(content.includes("hvt_mgmt_test_mockkey"));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("outputs structured JSON when --json option is provided", async () => {
    const logs: string[] = [];
    const originalLog = console.log;
    console.log = (msg?: unknown) => {
      logs.push(String(msg ?? ""));
    };

    try {
      await aiSetupPromptCommand({
        apiUrl: "http://127.0.0.1:8000",
        projectId: "test-json-uuid",
        key: "hvt_mgmt_test_mockkey",
        json: true,
      });

      const parsed = JSON.parse(logs[0]);
      assert.strictEqual(parsed.projectId, "test-json-uuid");
      assert.strictEqual(parsed.apiUrl, "http://127.0.0.1:8000");
      assert.strictEqual(parsed.key, "hvt_mgmt_test_mockkey");
      assert.ok(typeof parsed.prompt === "string");
      assert.ok(parsed.prompt.includes("test-json-uuid"));
    } finally {
      console.log = originalLog;
    }
  });
});
