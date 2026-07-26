import { test } from "node:test";
import { strict as assert } from "node:assert";
import { availableProvidersFromEnv } from "./index.js";
import { LLMProvider } from "./types/index.js";

// availableProvidersFromEnv decides which LLM providers are usable
// based on the live env. The pre-fix `if (process.env.X)` check
// treated whitespace-only values as truthy — operators setting
// ANTHROPIC_API_KEY="  " expecting to disable Anthropic instead got
// /health reporting it as available, requests routing to Anthropic,
// and a 401 deep in the call chain rather than a clear "not
// configured" message at request entry. Trimming before truthy
// check makes disable-by-whitespace Just Work.

test("availableProvidersFromEnv: empty env returns empty list", () => {
  const got = availableProvidersFromEnv({});
  assert.deepEqual(got, []);
});

test("availableProvidersFromEnv: each provider keyed correctly", () => {
  // Pin the env-var → provider mapping. A typo in the wiring (e.g.
  // OPENAI_API_KEY accidentally added under the Gemini branch) would
  // silently route OpenAI users to Gemini.
  assert.deepEqual(
    availableProvidersFromEnv({ OPENAI_API_KEY: "sk-test" }),
    [LLMProvider.OPENAI],
  );
  assert.deepEqual(
    availableProvidersFromEnv({ ANTHROPIC_API_KEY: "sk-ant-test" }),
    [LLMProvider.ANTHROPIC],
  );
  assert.deepEqual(
    availableProvidersFromEnv({ GOOGLE_API_KEY: "AIza-test" }),
    [LLMProvider.GEMINI],
  );
  assert.deepEqual(
    availableProvidersFromEnv({ GITHUB_TOKEN: "ghp_test" }),
    [LLMProvider.COPILOT],
  );
});

test("availableProvidersFromEnv: all four configured returns all four", () => {
  const got = availableProvidersFromEnv({
    OPENAI_API_KEY: "a",
    ANTHROPIC_API_KEY: "b",
    GOOGLE_API_KEY: "c",
    GITHUB_TOKEN: "d",
  });
  assert.equal(got.length, 4);
});

test("availableProvidersFromEnv: empty string is NOT configured", () => {
  // JavaScript truthy-check already excludes "" — pin the contract
  // so a future refactor that does `env.X !== undefined` doesn't
  // silently start treating empty as configured.
  const got = availableProvidersFromEnv({
    OPENAI_API_KEY: "",
    ANTHROPIC_API_KEY: "",
  });
  assert.deepEqual(got, []);
});

test("availableProvidersFromEnv: whitespace-only is NOT configured (the bug case)", () => {
  // Operator sets ANTHROPIC_API_KEY="  " intending to disable.
  // Pre-fix this was treated as configured — the API call would 401
  // at runtime instead of /health reporting honestly.
  const got = availableProvidersFromEnv({
    OPENAI_API_KEY: "  ",
    ANTHROPIC_API_KEY: "\t",
    GOOGLE_API_KEY: "\n\n",
    GITHUB_TOKEN: " ",
  });
  assert.deepEqual(got, [], "whitespace-only env vars must NOT count as configured");
});

test("availableProvidersFromEnv: mixed configured + whitespace-disabled", () => {
  // Realistic scenario: operator wants OpenAI only, has the others
  // set to whitespace from a prior config they meant to clear.
  const got = availableProvidersFromEnv({
    OPENAI_API_KEY: "sk-real-key",
    ANTHROPIC_API_KEY: "  ",
    GOOGLE_API_KEY: "",
    GITHUB_TOKEN: undefined,
  });
  assert.deepEqual(got, [LLMProvider.OPENAI]);
});

test("availableProvidersFromEnv: ignores unrelated env vars", () => {
  const got = availableProvidersFromEnv({
    PATH: "/usr/bin",
    HOME: "/home/foo",
    BROKER_URL: "http://x:9090",
  });
  assert.deepEqual(got, []);
});
