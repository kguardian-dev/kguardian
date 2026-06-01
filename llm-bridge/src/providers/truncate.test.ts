import test from "node:test";
import assert from "node:assert/strict";
import { serializeToolResult } from "./truncate.js";

// Wire-format contract tests for serializeToolResult, the helper that
// shapes broker tool results before they hit an LLM provider's TPM
// limits. A regression here either:
//   - blows the token budget (no truncation when needed) and the
//     provider returns 4xx, or
//   - hides relevant data (over-truncates) and the LLM gives a wrong
//     answer.
//
// Uses Node 22's built-in test runner — no vitest/jest dep required.
// Run via `node --import tsx --test src/**/*.test.ts`.

test("serializeToolResult forwards an error message verbatim", () => {
  const out = serializeToolResult({ error: "broker unreachable" } as any);
  assert.equal(out, "Error: broker unreachable");
});

test("serializeToolResult handles missing data", () => {
  const out = serializeToolResult({} as any);
  assert.equal(out, "No data returned");
});

test("serializeToolResult passes a small string through unchanged", () => {
  const small = "hello world";
  const out = serializeToolResult({ data: small } as any);
  assert.equal(out, small);
});

test("serializeToolResult JSON-encodes a small object", () => {
  const out = serializeToolResult({ data: { a: 1, b: "x" } } as any);
  assert.equal(out, JSON.stringify({ a: 1, b: "x" }));
});

test("serializeToolResult truncates an oversized non-array string", () => {
  const big = "x".repeat(60_000); // > MAX_TOOL_RESULT_CHARS = 50_000
  const out = serializeToolResult({ data: big } as any);
  assert.ok(out.length < big.length, "must shrink");
  assert.ok(out.includes("[TRUNCATED"), "must include the truncation marker");
});

test("serializeToolResult summarises an oversized array WITHOUT namespace", () => {
  // 5000 items × ~30 chars each = ~150 KB, well over the 50 KB cap.
  const items = Array.from({ length: 5000 }, (_, i) => ({
    pod_name: `p-${i}`,
    other: "data".repeat(20),
  }));
  const out = serializeToolResult({ data: items } as any);
  const parsed = JSON.parse(out);
  assert.equal(parsed._truncated, true);
  assert.equal(parsed._total, 5000);
  assert.equal(parsed._showing, 50);
  assert.equal(parsed._sample.length, 50);
  // Without pod_namespace/svc_namespace, breakdown must be absent.
  assert.equal(parsed._namespace_breakdown, undefined);
});

test("serializeToolResult produces a per-namespace breakdown when items have pod_namespace", () => {
  // Heavy enough to trip the truncation threshold + has pod_namespace
  // → namespace breakdown path.
  const items: any[] = [];
  for (let i = 0; i < 2000; i++) {
    items.push({ pod_name: `web-${i}`, pod_namespace: "prod", payload: "x".repeat(80) });
  }
  for (let i = 0; i < 1500; i++) {
    items.push({ pod_name: `db-${i}`, pod_namespace: "data", payload: "x".repeat(80) });
  }
  const out = serializeToolResult({ data: items } as any);
  const parsed = JSON.parse(out);

  assert.equal(parsed._truncated, true);
  assert.equal(parsed._total, 3500);
  assert.deepEqual(parsed._namespace_breakdown, {
    prod: 2000,
    data: 1500,
  });
});

test("serializeToolResult uses svc_namespace when pod_namespace is absent", () => {
  const items: any[] = [];
  for (let i = 0; i < 4000; i++) {
    items.push({ svc_name: `s-${i}`, svc_namespace: "system", junk: "x".repeat(50) });
  }
  const out = serializeToolResult({ data: items } as any);
  const parsed = JSON.parse(out);
  assert.equal(parsed._namespace_breakdown.system, 4000);
});

test("serializeToolResult marks unknown-namespace items in breakdown", () => {
  // Items that have a namespace key but it's missing/empty fall back
  // to "unknown" — keeps the breakdown safe to render in the LLM.
  const items: any[] = [];
  for (let i = 0; i < 2500; i++) {
    items.push({ pod_name: `p-${i}`, pod_namespace: "" });
  }
  const out = serializeToolResult({ data: items } as any);
  const parsed = JSON.parse(out);
  assert.ok(
    parsed._namespace_breakdown && Object.keys(parsed._namespace_breakdown).length > 0,
    "expected at least one namespace bucket",
  );
});
