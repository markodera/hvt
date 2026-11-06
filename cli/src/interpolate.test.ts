// SPDX-License-Identifier: Apache-2.0
import { describe, it } from "node:test";
import assert from "node:assert";
import { interpolateString, interpolateSchema, redactSecret, redactKey } from "./interpolate.js";

describe("CLI Secret Interpolation", () => {
  it("interpolates ${VAR} and $VAR correctly from env", () => {
    const env = { GOOGLE_SECRET: "super-secret-123", API_PORT: "8080" };
    const template = "Secret is ${GOOGLE_SECRET} on port $API_PORT";
    const resolved = interpolateString(template, env);
    assert.strictEqual(resolved, "Secret is super-secret-123 on port 8080");
  });

  it("throws a clear error if an environment variable is missing", () => {
    const env = {};
    assert.throws(() => {
      interpolateString("Secret is ${MISSING_VAR}", env);
    }, /Missing required environment variable 'MISSING_VAR'/);
  });

  it("recursively interpolates nested schema objects and arrays", () => {
    const env = { CLIENT_ID: "client-id-xyz", CLIENT_SECRET: "secret-abc" };
    const schema = {
      social_providers: [
        {
          provider: "google",
          client_id: "${CLIENT_ID}",
          client_secret: "${CLIENT_SECRET}",
          allowed_redirect_uris: ["http://localhost:3000/callback"],
        },
      ],
    };

    const resolved = interpolateSchema(schema, env);
    assert.strictEqual(resolved.social_providers[0].client_id, "client-id-xyz");
    assert.strictEqual(resolved.social_providers[0].client_secret, "secret-abc");
    assert.strictEqual(resolved.social_providers[0].allowed_redirect_uris[0], "http://localhost:3000/callback");
  });

  it("redacts secrets safely without leaking content", () => {
    const secret = "very-long-oauth-secret-key-that-must-be-hidden";
    const redacted = redactSecret(secret);
    assert.ok(redacted.includes("[REDACTED]"));
    assert.ok(!redacted.includes("oauth"));

    const key = "hvt_mgmt_test_0123456789abcdef";
    const redactedKey = redactKey(key);
    assert.ok(redactedKey.startsWith("hvt_mgmt_test_..."));
  });
});
