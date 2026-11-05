// SPDX-License-Identifier: Apache-2.0
import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parseManifestContent, writeClientKeyToEnvLocal } from "./config.js";

describe("CLI Config & Manifest Parser", () => {
  it("parses valid JSON manifest with schema_version 1", () => {
    const raw = JSON.stringify({
      schema_version: 1,
      roles: [{ slug: "admin", name: "Admin" }],
    });
    const parsed = parseManifestContent(raw, "json");
    assert.strictEqual(parsed.schema_version, 1);
    assert.strictEqual(parsed.roles?.[0].slug, "admin");
  });

  it("parses valid YAML manifest safely", () => {
    const raw = `
schema_version: 1
roles:
  - slug: member
    is_default: true
`;
    const parsed = parseManifestContent(raw, "yaml");
    assert.strictEqual(parsed.schema_version, 1);
    assert.strictEqual(parsed.roles?.[0].slug, "member");
    assert.strictEqual(parsed.roles?.[0].is_default, true);
  });

  it("rejects manifest with invalid schema_version", () => {
    const raw = JSON.stringify({ schema_version: 2 });
    assert.throws(() => {
      parseManifestContent(raw, "json");
    }, /Invalid or missing 'schema_version'/);
  });

  it("writes client key to .env.local cleanly", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hvt-cli-test-"));
    const envLocalPath = writeClientKeyToEnvLocal("hvt_test_samplekey123", tmpDir);

    const content = fs.readFileSync(envLocalPath, "utf-8");
    assert.ok(content.includes("NEXT_PUBLIC_HVT_CLIENT_KEY=hvt_test_samplekey123"));

    // Overwrite with a new key
    writeClientKeyToEnvLocal("hvt_test_updatedkey456", tmpDir);
    const updatedContent = fs.readFileSync(envLocalPath, "utf-8");
    assert.ok(updatedContent.includes("NEXT_PUBLIC_HVT_CLIENT_KEY=hvt_test_updatedkey456"));
    assert.ok(!updatedContent.includes("samplekey123"));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
