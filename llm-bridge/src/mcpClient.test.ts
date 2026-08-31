import test from "node:test";
import assert from "node:assert/strict";
import { McpClient } from "./mcpClient.js";
import { TOOL_DEFS } from "./tools/registry.js";

// McpClient.parseContext is the gate that turns the LLM's free-form
// context blob into a structured filter. A regression here either:
//   - drops a valid namespace filter (LLM gets cluster-wide data when
//     the user asked for a single ns), or
//   - keeps malformed input and propagates it downstream.
//
// Use Node 22's built-in test runner (no vitest dep).

test("parseContext returns undefined for empty/missing input", () => {
  assert.equal(McpClient.parseContext(undefined), undefined);
  assert.equal(McpClient.parseContext(""), undefined);
});

test("parseContext returns undefined for invalid JSON (no throw)", () => {
  assert.equal(McpClient.parseContext("not-json"), undefined);
  assert.equal(McpClient.parseContext("{open"), undefined);
});

test("parseContext extracts namespace string", () => {
  const got = McpClient.parseContext('{"namespace":"prod"}');
  assert.deepEqual(got, { namespace: "prod", podNames: undefined });
});

test("parseContext extracts podNames array", () => {
  const got = McpClient.parseContext('{"podNames":["a","b"]}');
  assert.deepEqual(got, { namespace: undefined, podNames: ["a", "b"] });
});

test("parseContext extracts both fields when present", () => {
  const got = McpClient.parseContext('{"namespace":"prod","podNames":["web-1"]}');
  assert.deepEqual(got, { namespace: "prod", podNames: ["web-1"] });
});

test("parseContext rejects non-string namespace", () => {
  // If the LLM hallucinates {"namespace": 42} we must reject the
  // numeric — passing it downstream would either crash a string
  // comparison or be coerced into a misleading match.
  const got = McpClient.parseContext('{"namespace":42}');
  assert.equal(got?.namespace, undefined);
});

test("parseContext rejects non-array podNames", () => {
  const got = McpClient.parseContext('{"podNames":"web-1"}');
  assert.equal(got?.podNames, undefined);
});

test("parseContext ignores unrelated extra fields", () => {
  const got = McpClient.parseContext('{"namespace":"prod","unknown":"value"}');
  assert.deepEqual(got, { namespace: "prod", podNames: undefined });
});

test("parseContext handles pre-empty arrays", () => {
  const got = McpClient.parseContext('{"podNames":[]}');
  assert.deepEqual(got, { namespace: undefined, podNames: [] });
});

// tools are sourced from the in-repo registry (no MCP discovery hop).
// getToolsCached must surface every registered tool in provider format.

test("getToolsCached returns every registered tool in provider format", async () => {
  const tools = await McpClient.getToolsCached();
  assert.equal(tools.length, TOOL_DEFS.length);
  assert.equal(tools.length, 12);
  for (const t of tools) {
    assert.equal(typeof t.name, "string");
    assert.equal(typeof t.description, "string");
    assert.ok(t.parameters, `tool ${t.name} must carry a parameter schema`);
  }
});
