import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildSeccompProfile } from "./seccomp.js";

// G2 generator parity — seccomp, assistant side.
// The assistant's in-process seccomp generator asserts the SAME shared
// fixtures the frontend TS and advisor Go generators do, so the three cannot
// diverge. Compared as parsed objects.

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../test/fixtures/generators/seccomp",
);

interface Fixture {
  name: string;
  input: { syscalls: string[]; arch: string };
  expected: unknown;
}

const files = fs.readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));

test("assistant seccomp generator matches every shared fixture", () => {
  assert.ok(files.length > 0, "no seccomp fixtures found");
  for (const f of files) {
    const fx = JSON.parse(fs.readFileSync(path.join(fixturesDir, f), "utf8")) as Fixture;
    const got = buildSeccompProfile(fx.input.syscalls, fx.input.arch);
    assert.deepEqual(JSON.parse(JSON.stringify(got)), fx.expected, `${f} (${fx.name})`);
  }
});
