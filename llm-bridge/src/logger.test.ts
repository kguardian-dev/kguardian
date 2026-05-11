import test from "node:test";
import assert from "node:assert/strict";
import { resolveLevel } from "./logger.js";

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
