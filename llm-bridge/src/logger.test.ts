import test from "node:test";
import assert from "node:assert/strict";
import { resolveLevel, shouldEmit, type Level } from "./logger.js";

test("resolveLevel defaults to info when unset", () => {
  assert.equal(resolveLevel(undefined), "info");
});

test("resolveLevel accepts each valid level case-insensitively", () => {
  for (const v of ["trace", "Debug", "INFO", "Warn", "ERROR"]) {
    const got = resolveLevel(v);
    assert.equal(got, v.toLowerCase());
  }
});

test("resolveLevel trims surrounding whitespace", () => {
  // Same operator-paste defense as the broker / mcp-server env reads —
  // a trailing newline ("info\n") shouldn't silently fall back to the
  // default. Without trim, the lower-case compare against the literal
  // levels would miss.
  assert.equal(resolveLevel("  debug\n"), "debug");
  assert.equal(resolveLevel("\tINFO"), "info");
});

test("resolveLevel falls back to info on unknown values", () => {
  // Typo or unrecognised value → info (safer than panicking on
  // startup; operator can still spot the typo from the steady-state
  // log output).
  assert.equal(resolveLevel("verbose"), "info");
  assert.equal(resolveLevel("DBG"), "info");
  assert.equal(resolveLevel(""), "info");
  assert.equal(resolveLevel("   "), "info");
});

test("shouldEmit allows same-rank messages through", () => {
  // A message at the active level is at the boundary — must emit
  // (this is the >= check, not >).
  for (const lvl of ["trace", "debug", "info", "warn", "error"] as Level[]) {
    assert.ok(shouldEmit(lvl, lvl), `${lvl}@${lvl} must emit`);
  }
});

test("shouldEmit allows higher-severity messages through", () => {
  // Active=info → info/warn/error pass; trace/debug drop.
  assert.ok(shouldEmit("info", "info"));
  assert.ok(shouldEmit("warn", "info"));
  assert.ok(shouldEmit("error", "info"));
  assert.ok(!shouldEmit("debug", "info"));
  assert.ok(!shouldEmit("trace", "info"));
});

test("shouldEmit at trace lets everything through", () => {
  // LOG_LEVEL=trace is the most verbose setting. Nothing should drop.
  for (const lvl of ["trace", "debug", "info", "warn", "error"] as Level[]) {
    assert.ok(shouldEmit(lvl, "trace"), `${lvl}@trace must emit`);
  }
});

test("shouldEmit at error suppresses everything below", () => {
  // LOG_LEVEL=error silences all but error — the quietest sane
  // production setting.
  assert.ok(shouldEmit("error", "error"));
  assert.ok(!shouldEmit("warn", "error"));
  assert.ok(!shouldEmit("info", "error"));
  assert.ok(!shouldEmit("debug", "error"));
  assert.ok(!shouldEmit("trace", "error"));
});

test("shouldEmit at debug keeps info+ but drops trace", () => {
  // LOG_LEVEL=debug is the typical "I'm debugging" setting —
  // unlocks the per-tool-call hot-path traces from brokerClient.ts
  // (commit 3528d437) but still drops the trace level (currently
  // unused but reserved for future ultra-verbose hooks).
  assert.ok(!shouldEmit("trace", "debug"));
  assert.ok(shouldEmit("debug", "debug"));
  assert.ok(shouldEmit("info", "debug"));
  assert.ok(shouldEmit("warn", "debug"));
  assert.ok(shouldEmit("error", "debug"));
});
