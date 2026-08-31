import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { resolveBaseUrl, endpointHint } from "./baseUrl.js";

// Pure resolution tests — no provider, no HTTP. The provider-level tests
// (openai.test.ts, gemini.test.ts) prove the resolved base is actually the URL
// requested; these prove the resolution rules themselves, including the
// unset-var case that would otherwise mean calling the real vendor API.

const ENV = "TEST_BASE_URL";
const FALLBACK = "https://api.example.com/v1";

afterEach(() => {
  delete process.env[ENV];
});

test("unset env var falls back to the vendor default", () => {
  assert.equal(resolveBaseUrl(ENV, FALLBACK), FALLBACK);
});

test("set env var overrides the vendor default", () => {
  process.env[ENV] = "http://litellm.litellm.svc.cluster.local:4000/v1";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm.litellm.svc.cluster.local:4000/v1");
});

test("trailing slashes are stripped so base and base/ append identically", () => {
  process.env[ENV] = "http://litellm:4000/v1/";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm:4000/v1");

  process.env[ENV] = "http://litellm:4000///";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm:4000");
});

test("surrounding whitespace is trimmed rather than sent verbatim", () => {
  process.env[ENV] = "  http://litellm:4000/v1  ";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm:4000/v1");
});

test("whitespace-only counts as unset, not as an empty base", () => {
  process.env[ENV] = "   ";
  assert.equal(
    resolveBaseUrl(ENV, FALLBACK),
    FALLBACK,
    'a stray "  " must not build the endpoint "  /chat/completions"',
  );
});

test("the /v1 segment is never inserted or stripped", () => {
  // Both forms are legal against LiteLLM and the operator's choice is honoured
  // exactly; guessing here would break gateways that serve only one of them.
  process.env[ENV] = "http://litellm:4000";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm:4000");

  process.env[ENV] = "http://litellm:4000/v1";
  assert.equal(resolveBaseUrl(ENV, FALLBACK), "http://litellm:4000/v1");
});

test("malformed URL throws naming the env var", () => {
  process.env[ENV] = "not a url";
  assert.throws(
    () => resolveBaseUrl(ENV, FALLBACK),
    (error: Error) => {
      assert.match(error.message, /TEST_BASE_URL is not a valid URL/);
      assert.match(error.message, /"not a url"/);
      return true;
    },
  );
});

test("scheme-less host is rejected instead of failing later inside axios", () => {
  // `new URL("localhost:4000")` parses (protocol "localhost:"), so this case
  // only fails at request time without an explicit scheme check.
  process.env[ENV] = "localhost:4000";
  assert.throws(() => resolveBaseUrl(ENV, FALLBACK), /TEST_BASE_URL is not a valid URL/);
});

test("non-http scheme is rejected", () => {
  process.env[ENV] = "ftp://litellm:4000/v1";
  assert.throws(() => resolveBaseUrl(ENV, FALLBACK), /TEST_BASE_URL is not a valid URL/);
});

test("endpointHint fires on 404/405 with the URL and env var, and stays silent otherwise", () => {
  const hint = endpointHint("OPENAI_BASE_URL", "http://litellm:4000/chat/completions", 404);
  assert.match(hint, /http:\/\/litellm:4000\/chat\/completions/);
  assert.match(hint, /OPENAI_BASE_URL/);
  assert.match(hint, /\/v1/, "points at the /v1 mistake specifically");

  assert.match(endpointHint("OPENAI_BASE_URL", "http://litellm:4000/chat/completions", 405), /405/);
  // Real API failures keep their upstream message unadorned.
  assert.equal(endpointHint("OPENAI_BASE_URL", "http://x/chat/completions", 401), "");
  assert.equal(endpointHint("OPENAI_BASE_URL", "http://x/chat/completions", 429), "");
  assert.equal(endpointHint("OPENAI_BASE_URL", "http://x/chat/completions", undefined), "");
});
