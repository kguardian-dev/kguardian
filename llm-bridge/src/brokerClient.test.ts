import test from "node:test";
import assert from "node:assert/strict";
import { BrokerClient, resolveMcpUrl } from "./brokerClient.js";

const DEFAULT_URL = "http://kguardian-mcp-server.kguardian.svc.cluster.local:8081";

test("resolveMcpUrl prefers explicit arg over env over default", () => {
  assert.equal(resolveMcpUrl("http://from-arg:8081", "http://from-env:8081"), "http://from-arg:8081");
  assert.equal(resolveMcpUrl(undefined, "http://from-env:8081"), "http://from-env:8081");
  assert.equal(resolveMcpUrl(undefined, undefined), DEFAULT_URL);
});

test("resolveMcpUrl trims whitespace from arg and env", () => {
  // Surrounding whitespace must not slip through. Pre-fix, a
  // MCP_SERVER_URL=" http://x:8081 " env var (typical Helm YAML
  // literal artefact) would store the spaced value and produce a
  // cryptic `TypeError: Invalid URL` from `new URL(this.mcpUrl)`
  // inside the StreamableHTTPClientTransport — far from the
  // env-var read site.
  assert.equal(resolveMcpUrl("  http://from-arg:8081  "), "http://from-arg:8081");
  assert.equal(resolveMcpUrl(undefined, "\thttp://from-env:8081\n"), "http://from-env:8081");
});

test("resolveMcpUrl treats whitespace-only as empty (falls through)", () => {
  // A whitespace-only arg/env must NOT pass the truthy check;
  // resolution should fall through to the next candidate.
  assert.equal(resolveMcpUrl("   ", "http://from-env:8081"), "http://from-env:8081");
  assert.equal(resolveMcpUrl(undefined, "   "), DEFAULT_URL);
  assert.equal(resolveMcpUrl("  ", "  "), DEFAULT_URL);
  assert.equal(resolveMcpUrl("", ""), DEFAULT_URL);
});

// BrokerClient.parseContext is the gate that turns the LLM's free-form
// context blob into a structured filter. A regression here either:
//   - drops a valid namespace filter (LLM gets cluster-wide data when
//     the user asked for a single ns), or
//   - keeps malformed input and propagates it downstream.
//
// Use Node 22's built-in test runner (no vitest dep).

test("parseContext returns undefined for empty/missing input", () => {
  assert.equal(BrokerClient.parseContext(undefined), undefined);
  assert.equal(BrokerClient.parseContext(""), undefined);
});

test("parseContext returns undefined for invalid JSON (no throw)", () => {
  assert.equal(BrokerClient.parseContext("not-json"), undefined);
  assert.equal(BrokerClient.parseContext("{open"), undefined);
});

test("parseContext extracts namespace string", () => {
  const got = BrokerClient.parseContext('{"namespace":"prod"}');
  assert.deepEqual(got, { namespace: "prod", podNames: undefined });
});

test("parseContext extracts podNames array", () => {
  const got = BrokerClient.parseContext('{"podNames":["a","b"]}');
  assert.deepEqual(got, { namespace: undefined, podNames: ["a", "b"] });
});

test("parseContext extracts both fields when present", () => {
  const got = BrokerClient.parseContext('{"namespace":"prod","podNames":["web-1"]}');
  assert.deepEqual(got, { namespace: "prod", podNames: ["web-1"] });
});

test("parseContext rejects non-string namespace", () => {
  // If the LLM hallucinates {"namespace": 42} we must reject the
  // numeric — passing it downstream would either crash a string
  // comparison or be coerced into a misleading match.
  const got = BrokerClient.parseContext('{"namespace":42}');
  assert.equal(got?.namespace, undefined);
});

test("parseContext rejects non-array podNames", () => {
  const got = BrokerClient.parseContext('{"podNames":"web-1"}');
  assert.equal(got?.podNames, undefined);
});

test("parseContext ignores unrelated extra fields", () => {
  const got = BrokerClient.parseContext('{"namespace":"prod","unknown":"value"}');
  assert.deepEqual(got, { namespace: "prod", podNames: undefined });
});

test("parseContext handles pre-empty arrays", () => {
  const got = BrokerClient.parseContext('{"podNames":[]}');
  assert.deepEqual(got, { namespace: undefined, podNames: [] });
});
