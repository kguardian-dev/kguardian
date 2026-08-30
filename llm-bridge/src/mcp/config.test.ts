import { test } from "node:test";
import assert from "node:assert/strict";

import { mcpConfigFromEnv } from "./config.js";

// The endpoint's on/off switch and its shared secret are read from env once at
// startup; getting the parsing wrong is a security-relevant bug (an endpoint
// believed disabled that is live, or a token believed set that is not), so the
// pure parser is pinned here rather than only exercised end-to-end.

test("MCP_ENABLED accepts true/1, case-insensitively, with whitespace", () => {
  for (const raw of ["true", "TRUE", "True", "1", " true ", "true\n"]) {
    assert.equal(mcpConfigFromEnv({ MCP_ENABLED: raw }).enabled, true, `expected ${JSON.stringify(raw)} to enable`);
  }
});

test("anything else leaves the endpoint off", () => {
  for (const raw of [undefined, "", "  ", "false", "0", "yes", "on", "enabled"]) {
    assert.equal(mcpConfigFromEnv({ MCP_ENABLED: raw }).enabled, false, `expected ${JSON.stringify(raw)} to stay off`);
  }
});

test("a whitespace-only auth token counts as unset", () => {
  // Same rule as the broker's AuthConfig::from_env. Treating "   " as a real
  // secret would reject every request with no way to satisfy the check.
  assert.equal(mcpConfigFromEnv({ MCP_AUTH_TOKEN: "   " }).authToken, null);
  assert.equal(mcpConfigFromEnv({ MCP_AUTH_TOKEN: "" }).authToken, null);
  assert.equal(mcpConfigFromEnv({}).authToken, null);
  assert.equal(mcpConfigFromEnv({ MCP_AUTH_TOKEN: " s3cret \n" }).authToken, "s3cret");
});

test("the rate limit defaults to 300/min and rejects nonsense overrides", () => {
  assert.equal(mcpConfigFromEnv({}).rateLimitPerMin, 300);
  assert.equal(mcpConfigFromEnv({ MCP_RATE_LIMIT_PER_MIN: " 50 " }).rateLimitPerMin, 50);
  // 0 would exhaust the bucket on the first request and "abc" would produce a
  // NaN limit (effectively unlimited) — both fall back to the default.
  assert.equal(mcpConfigFromEnv({ MCP_RATE_LIMIT_PER_MIN: "0" }).rateLimitPerMin, 300);
  assert.equal(mcpConfigFromEnv({ MCP_RATE_LIMIT_PER_MIN: "-5" }).rateLimitPerMin, 300);
  assert.equal(mcpConfigFromEnv({ MCP_RATE_LIMIT_PER_MIN: "abc" }).rateLimitPerMin, 300);
  assert.equal(mcpConfigFromEnv({ MCP_RATE_LIMIT_PER_MIN: "" }).rateLimitPerMin, 300);
});
