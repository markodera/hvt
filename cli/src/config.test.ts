// SPDX-License-Identifier: Apache-2.0
import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parseManifestContent, writeClientKeyToEnvLocal, resolveConfig } from "./config.js";
import { buildStarterSchema, SUPPORTED_PROVIDERS } from "./commands/init.js";

describe("CLI Config & Manifest Parser", () => {
  it("builds starter schema with specific selected providers", () => {
    const schema = buildStarterSchema(["google", "github", "discord"]);
    assert.strictEqual(schema.social_providers?.length, 3);
    const providers = schema.social_providers?.map((p) => p.provider);
    assert.deepStrictEqual(providers, ["google", "github", "discord"]);
  });

  it("builds starter schema with all 6 supported providers", () => {
    const schema = buildStarterSchema([...SUPPORTED_PROVIDERS]);
    assert.strictEqual(schema.social_providers?.length, 6);
    const providers = schema.social_providers?.map((p) => p.provider);
    assert.deepStrictEqual(providers, [
      "google",
      "github",
      "discord",
      "apple",
      "microsoft",
      "gitlab",
    ]);
  });
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

  it("refuses to write management keys into NEXT_PUBLIC_HVT_CLIENT_KEY", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hvt-cli-test-mgmt-"));
    assert.throws(
      () => {
        writeClientKeyToEnvLocal("hvt_mgmt_test_forbidden1234567890", tmpDir);
      },
      /SECURITY ERROR: Management keys must never be written to NEXT_PUBLIC_\* variables/
    );
    const envLocalPath = path.join(tmpDir, ".env.local");
    assert.strictEqual(fs.existsSync(envLocalPath), false);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("warns if .env.local is not gitignored", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hvt-cli-test-warn-"));
    let warningLogged = false;
    const origWarn = console.warn;
    console.warn = (msg: string) => {
      if (typeof msg === "string" && msg.includes("not appear to be ignored in .gitignore")) {
        warningLogged = true;
      }
    };

    try {
      fs.writeFileSync(path.join(tmpDir, ".gitignore"), "node_modules/\ndist/\n", "utf-8");
      writeClientKeyToEnvLocal("hvt_test_samplekey123", tmpDir);
      assert.strictEqual(warningLogged, true);
    } finally {
      console.warn = origWarn;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("allows resolveConfig without schema when requireSchema is false", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hvt-cli-whoami-"));
    try {
      const cfg = resolveConfig({
        cwd: tmpDir,
        apiUrl: "http://localhost:8000",
        projectId: "proj_test_123",
        key: "hvt_mgmt_test_validkey",
        requireSchema: false,
      });
      assert.strictEqual(cfg.projectId, "proj_test_123");
      assert.strictEqual(cfg.managementKey, "hvt_mgmt_test_validkey");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
