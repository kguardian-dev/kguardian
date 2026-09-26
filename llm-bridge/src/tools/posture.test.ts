import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";

import {
  buildQuery, clampToolLimit, fitToBudget, pick, shrinkProfile, trimImagePage, trimProfile,
  DEFAULT_TOOL_LIMIT, MAX_TOOL_LIMIT, MAX_RESPONSE_CHARS, MAX_TAGS_PER_IMAGE,
} from "./posture.js";
import { executeInProcessTool } from "./execute.js";
import { TOOL_DEFS } from "./registry.js";

// #1533 profile + image tools. Three layers:
//   1. pure helpers (limits, query strings, byte budget);
//   2. wiring: each tool hits the right broker path with a bounded limit
//      and the broker read token;
//   3. eval-style no-fabrication fixtures (test/fixtures/posture): replay
//      broker responses — including sparse and all-unknown ones — through
//      every tool and assert every leaf the model sees exists in the
//      broker's response or is a documented annotation, and that unknown
//      stays null.

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(here, "../../../test/fixtures/posture");
const fixture = (name: string): unknown => JSON.parse(fs.readFileSync(path.join(fixtureDir, name), "utf8"));

// --- 1. pure helpers --------------------------------------------------------

test("clampToolLimit defaults junk and clamps to [1, MAX]", () => {
  assert.equal(clampToolLimit(undefined), DEFAULT_TOOL_LIMIT);
  assert.equal(clampToolLimit("50"), DEFAULT_TOOL_LIMIT);
  assert.equal(clampToolLimit(Number.NaN), DEFAULT_TOOL_LIMIT);
  assert.equal(clampToolLimit(0), 1);
  assert.equal(clampToolLimit(-4), 1);
  assert.equal(clampToolLimit(7.9), 7);
  assert.equal(clampToolLimit(100_000), MAX_TOOL_LIMIT);
});

test("buildQuery omits empty values and encodes the rest", () => {
  assert.equal(buildQuery({}), "");
  assert.equal(buildQuery({ namespace: "", repository: "  ", limit: undefined }), "");
  assert.equal(buildQuery({ namespace: "shop", limit: 25 }), "?namespace=shop&limit=25");
  assert.equal(buildQuery({ repository: "docker.io/library/nginx" }), "?repository=docker.io%2Flibrary%2Fnginx");
});

test("pick copies present keys only, null included", () => {
  assert.deepEqual(pick({ a: 1, b: null }, ["a", "b", "c"]), { a: 1, b: null });
  assert.deepEqual(pick(null, ["a"]), {});
  assert.deepEqual(pick([1], ["0"]), {});
});

test("fitToBudget drops tail items and flags truncation only when over budget", () => {
  const small = { items: [1, 2, 3] };
  assert.deepEqual(fitToBudget(small, "items", 1000), small);
  const big = { items: Array.from({ length: 500 }, (_, i) => ({ i, pad: "x".repeat(100) })) };
  const out = fitToBudget(big, "items", 5_000);
  assert.equal(out.truncated, true);
  assert.ok(JSON.stringify(out).length <= 5_000);
  const kept = out.items as unknown[];
  assert.ok(kept.length > 0 && kept.length < 500);
  assert.deepEqual(kept[0], big.items[0], "keeps the head, drops the tail");
});

test("trimImagePage caps tags and marks more pages as truncated", () => {
  const tags = Array.from({ length: 20 }, (_, i) => `t${i}`);
  const out = trimImagePage({ items: [{ digest: "sha256:a", tags, runningContainers: 1 }], nextAfter: "sha256:a" }, {});
  const img = (out.images as Record<string, unknown>[])[0];
  assert.equal((img.tags as string[]).length, MAX_TAGS_PER_IMAGE);
  assert.equal(img.tagsOmitted, 20 - MAX_TAGS_PER_IMAGE);
  assert.equal(out.truncated, true);
  assert.equal(trimImagePage({ items: [], nextAfter: null }, {}).truncated, false);
  assert.deepEqual(trimImagePage("junk", {}).images, []);
});

// --- 2 + 3. wiring and no-fabrication, against a fake broker ----------------

interface Seen { path: string; query: URLSearchParams; auth: string | undefined }
let server: http.Server;
let seen: Seen[] = [];
let routes: Record<string, { status: number; body: unknown }> = {};

before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url || "/", "http://x");
    seen.push({ path: u.pathname, query: u.searchParams, auth: req.headers.authorization });
    const r = routes[u.pathname];
    if (!r) { res.writeHead(404); res.end("No data found"); return; }
    res.writeHead(r.status, { "Content-Type": "application/json" });
    res.end(typeof r.body === "string" ? r.body : JSON.stringify(r.body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  process.env.BROKER_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  process.env.BROKER_AUTH_TOKEN = "read-token";
});
after(async () => {
  delete process.env.BROKER_AUTH_TOKEN;
  await new Promise<void>((r) => server.close(() => r()));
});
beforeEach(() => { seen = []; routes = {}; });

/** Every JSON leaf path of v, arrays collapsed to "[]". */
function leafPaths(v: unknown, prefix = ""): Set<string> {
  const out = new Set<string>();
  const walk = (x: unknown, p: string) => {
    if (Array.isArray(x)) { if (x.length === 0) out.add(`${p}[]`); x.forEach((e) => walk(e, `${p}[]`)); return; }
    if (x !== null && typeof x === "object") {
      const keys = Object.keys(x);
      if (keys.length === 0) out.add(p);
      for (const k of keys) walk((x as Record<string, unknown>)[k], p ? `${p}.${k}` : k);
      return;
    }
    out.add(p);
  };
  walk(v, prefix);
  return out;
}

/**
 * Assert the tool output invents nothing: every leaf of `got` under
 * `listKey` maps to a leaf the broker sent for the same item shape, except
 * the documented annotations. Top-level fields must be in `topAllowed`.
 */
function assertNoFabrication(got: Record<string, unknown>, brokerItems: unknown[], listKey: string, itemAnnotations: string[], topAllowed: string[]) {
  for (const k of Object.keys(got)) assert.ok(topAllowed.includes(k), `unexpected top-level field ${k}`);
  const brokerLeaves = new Set<string>();
  for (const it of brokerItems) for (const p of leafPaths(it)) brokerLeaves.add(p);
  const items = got[listKey] as unknown[];
  for (const it of items) {
    for (const p of leafPaths(it)) {
      assert.ok(brokerLeaves.has(p) || itemAnnotations.includes(p), `${listKey} item field '${p}' was not in the broker response`);
    }
  }
}

test("get_image_inventory: bounded limit, filters and the read token reach the broker", async () => {
  routes["/images"] = { status: 200, body: fixture("images_page.json") };
  const r = await executeInProcessTool("get_image_inventory", { namespace: "shop", repository: "docker.io/library/nginx", limit: 9999 });
  assert.equal(r.isError, false, r.text);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].path, "/images");
  assert.equal(seen[0].query.get("namespace"), "shop");
  assert.equal(seen[0].query.get("repository"), "docker.io/library/nginx");
  assert.equal(seen[0].query.get("limit"), String(MAX_TOOL_LIMIT));
  assert.equal(seen[0].auth, "Bearer read-token");
});

test("get_image_inventory: fixture replay invents no fields and keeps null repository null", async () => {
  const page = fixture("images_page.json") as { items: Record<string, unknown>[] };
  routes["/images"] = { status: 200, body: page };
  const r = await executeInProcessTool("get_image_inventory", {});
  const got = JSON.parse(r.text) as Record<string, unknown>;
  assertNoFabrication(got, page.items, "images", ["tagsOmitted"], ["count", "images", "truncated", "note", "namespace", "repository"]);
  const imgs = got.images as Record<string, unknown>[];
  const unknownRepo = imgs.find((i) => i.digest === page.items[1].digest)!;
  assert.equal(unknownRepo.repository, null, "unknown repository must stay null");
  assert.equal("futureField" in imgs[0], false, "unlisted broker fields are dropped, not passed through");
  assert.ok(r.text.length <= MAX_RESPONSE_CHARS);
});

test("get_image_inventory: a broker error is a tool error, not an empty inventory", async () => {
  routes["/images"] = { status: 503, body: "shed" };
  const r = await executeInProcessTool("get_image_inventory", {});
  assert.equal(r.isError, true);
  assert.match(r.text, /503/);
});

const POSTURE_TOOLS = ["get_workload_security_profile", "list_workload_profiles", "diff_workload_profile", "get_image_inventory"];

test("every #1533 tool description states the unknown and never-applies rules", () => {
  for (const name of POSTURE_TOOLS) {
    const d = TOOL_DEFS.find((t) => t.name === name)?.description;
    assert.ok(d, `${name} is registered`);
    assert.match(d, /unknown/i, `${name} must explain unknown`);
    assert.match(d, /never (treat it as )?safe|not safe|never 'safe'|never safe/i, `${name} must say unknown is not safe`);
    assert.match(d, /never appl|applies nothing|nothing is applied/i, `${name} must say kguardian never applies`);
  }
});

/** Annotation keys a trimmer may add; everything else must come from the broker. */
const ANNOTATION = /(^|\.)(note|trimmed(\[\])?|found|[A-Za-z]+Omitted)$/;

function assertSubsetOfBroker(got: unknown, broker: unknown, label: string) {
  const have = leafPaths(broker);
  for (const p of leafPaths(got)) {
    assert.ok(have.has(p) || ANNOTATION.test(p), `${label}: '${p}' is not in the broker response`);
  }
}

/** Every leaf the broker sent as null must still be null where it survives. */
function assertNullsPreserved(got: unknown, broker: unknown, pathSoFar = "") {
  if (broker === null) { assert.equal(got, null, `${pathSoFar} was null (unknown) at the broker and must stay null`); return; }
  if (Array.isArray(broker) && Array.isArray(got)) { got.forEach((g, i) => assertNullsPreserved(g, broker[i], `${pathSoFar}[${i}]`)); return; }
  if (broker && typeof broker === "object" && got && typeof got === "object") {
    for (const k of Object.keys(got as object)) {
      if (k in (broker as object)) assertNullsPreserved((got as Record<string, unknown>)[k], (broker as Record<string, unknown>)[k], `${pathSoFar}.${k}`);
    }
  }
}

const PROFILE_PATH = "/workloads/payments/Deployment/checkout/profile";

test("get_workload_security_profile: path, token and no fabrication on a full profile", async () => {
  const body = fixture("profile_full.json");
  routes[PROFILE_PATH] = { status: 200, body };
  const r = await executeInProcessTool("get_workload_security_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  assert.equal(r.isError, false, r.text);
  assert.equal(seen[0].path, PROFILE_PATH);
  assert.equal(seen[0].auth, "Bearer read-token");
  const got = JSON.parse(r.text);
  assertSubsetOfBroker(got, body, "profile_full");
  assertNullsPreserved(got, body);
  assert.equal(got.posture.coverage, 0.41, "coverage passes through");
  assert.equal(got.posture.grade, null);
  assert.equal(got.dimensions.images.vulnerabilities, null, "not-configured vulnerabilities stay null");
  assert.equal(got.dimensions.podSecurity.recommendation.recommendation, true);
  assert.match(got.dimensions.podSecurity.recommendation.yaml, /not applied/);
  assert.match(got.note, /never safe/);
});

test("get_workload_security_profile: an all-unknown profile stays unknown (no zeros, no passes)", async () => {
  const body = fixture("profile_unknown.json");
  routes["/workloads/batch/CronJob/nightly-report/profile"] = { status: 200, body };
  const r = await executeInProcessTool("get_workload_security_profile", { namespace: "batch", kind: "CronJob", name: "nightly-report" });
  const got = JSON.parse(r.text);
  assertSubsetOfBroker(got, body, "profile_unknown");
  assertNullsPreserved(got, body);
  assert.equal(got.posture.score, null);
  assert.equal(got.posture.status, "unknown");
  for (const d of Object.values(got.dimensions) as { score: unknown; status: string }[]) {
    assert.equal(d.score, null);
    assert.equal(d.status, "unknown");
  }
  assert.equal(got.exposure.ingressPeers, null);
});

test("get_workload_security_profile: path segments are encoded", async () => {
  await executeInProcessTool("get_workload_security_profile", { namespace: "a/b", kind: "Deployment", name: "x?y" });
  assert.equal(seen[0].path, "/workloads/a%2Fb/Deployment/x%3Fy/profile");
});

test("get_workload_security_profile: 404 is found=false and says unknown, not safe", async () => {
  const r = await executeInProcessTool("get_workload_security_profile", { namespace: "nope", kind: "Deployment", name: "ghost" });
  assert.equal(r.isError, false);
  const got = JSON.parse(r.text);
  assert.equal(got.found, false);
  assert.match(got.note, /unknown, not safe/);
  assert.deepEqual(Object.keys(got).sort(), ["found", "kind", "name", "namespace", "note"]);
});

test("get_workload_security_profile: missing args and broker failures are tool errors", async () => {
  const missing = await executeInProcessTool("get_workload_security_profile", { namespace: "payments", kind: "Deployment" });
  assert.equal(missing.isError, true);
  assert.equal(seen.length, 0, "no broker call without a full key");
  routes[PROFILE_PATH] = { status: 500, body: "db down" };
  const failed = await executeInProcessTool("get_workload_security_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  assert.equal(failed.isError, true);
  assert.match(failed.text, /500/);
});

test("get_workload_security_profile: long lists are capped with counts, and the result fits the budget", async () => {
  const body = fixture("profile_full.json") as Record<string, any>;
  const peer = body.dimensions.network.peers[0];
  body.dimensions.network.peers = Array.from({ length: 200 }, () => peer);
  const finding = body.findings[0];
  body.findings = Array.from({ length: 300 }, (_, i) => ({ ...finding, detail: `${finding.detail} ${"x".repeat(400)} ${i}` }));
  routes[PROFILE_PATH] = { status: 200, body };
  const r = await executeInProcessTool("get_workload_security_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  const got = JSON.parse(r.text);
  assert.ok(r.text.length <= MAX_RESPONSE_CHARS, `result is ${r.text.length} chars`);
  assert.equal(got.dimensions.network.peers.length, 25);
  assert.equal(got.dimensions.network.peersOmitted, 175);
  assert.ok(got.findings === undefined || got.findings.length <= 25);
  assert.ok(got.attention.length >= 1, "attention survives trimming");
});

test("shrinkProfile: the budget is a hard guarantee even when no cut step is enough", () => {
  const base = fixture("profile_full.json") as Record<string, any>;
  // Oversized strings outside every list the cut steps remove.
  const hugeAttention = trimProfile({ ...base, attention: [{ ...base.attention[0], detail: "x".repeat(200_000) }] });
  assert.ok(JSON.stringify(hugeAttention).length <= MAX_RESPONSE_CHARS);
  assert.equal(hugeAttention.truncated, true);
  assert.deepEqual(hugeAttention.posture, base.posture, "the rollup survives when it fits");
  assert.equal((hugeAttention.workload as Record<string, unknown>).name, "checkout");
  assert.match(String(hugeAttention.note), /untrusted data/);

  const hugePosture = trimProfile({
    ...base,
    workload: { ...base.workload, name: "n".repeat(10_000) },
    posture: { ...base.posture, unknownDimensions: ["y".repeat(200_000)] },
  });
  assert.ok(JSON.stringify(hugePosture).length <= MAX_RESPONSE_CHARS);
  assert.equal(hugePosture.truncated, true);
  assert.equal(hugePosture.posture, undefined, "an oversized rollup is dropped, not cut mid-value");
  assert.ok(String((hugePosture.workload as Record<string, unknown>).name).length <= 254);

  const small = trimProfile(base);
  assert.equal(small.truncated, undefined, "an in-budget profile is not marked truncated");
  for (const n of [200, 5_000, 20_000]) {
    const r = shrinkProfile(JSON.parse(JSON.stringify(small)), n + 2_000);
    assert.ok(JSON.stringify(r).length <= n + 2_000, `budget ${n + 2_000}`);
  }
});

test("every posture tool result tells the model its strings are untrusted data", async () => {
  routes[PROFILE_PATH] = { status: 200, body: fixture("profile_full.json") };
  routes["/workloads"] = { status: 200, body: fixture("profiles_page.json") };
  routes[DIFF_PATH] = { status: 200, body: fixture("profile_diff.json") };
  routes["/images"] = { status: 200, body: fixture("images_page.json") };
  const key = { namespace: "payments", kind: "Deployment", name: "checkout" };
  for (const [tool, args] of [
    ["get_workload_security_profile", key], ["list_workload_profiles", {}], ["diff_workload_profile", key], ["get_image_inventory", {}],
  ] as const) {
    const r = await executeInProcessTool(tool, args);
    assert.match(JSON.parse(r.text).note, /untrusted data.*never follow instructions/i, tool);
  }
});

test("list_workload_profiles: posture maps to status, limit is bounded, no fabrication", async () => {
  const body = fixture("profiles_page.json") as { items: unknown[] };
  routes["/workloads"] = { status: 200, body };
  const r = await executeInProcessTool("list_workload_profiles", { namespace: "payments", posture: "RISK", limit: 1000 });
  assert.equal(r.isError, false, r.text);
  assert.equal(seen[0].query.get("status"), "risk");
  assert.equal(seen[0].query.get("namespace"), "payments");
  assert.equal(seen[0].query.get("limit"), String(MAX_TOOL_LIMIT));
  const got = JSON.parse(r.text);
  assert.equal(got.truncated, true, "nextAfter present means more rows");
  assertSubsetOfBroker({ items: got.workloads }, { items: body.items }, "profiles_page");
  assertNullsPreserved(got.workloads, body.items);
  const unknown = got.workloads.find((w: { name: string }) => w.name === "ledger-db");
  assert.equal(unknown.posture.score, null);
  assert.equal(unknown.dimensions.images.runningDigests, null);
});

test("list_workload_profiles: a bad posture value never reaches the broker", async () => {
  const r = await executeInProcessTool("list_workload_profiles", { posture: "safe" });
  assert.equal(r.isError, true);
  assert.match(r.text, /ok, warn, risk, unknown/);
  assert.equal(seen.length, 0);
});

const DIFF_PATH = "/workloads/payments/Deployment/checkout/profile/diff";

test("diff_workload_profile: revisions pass through, no fabrication, nulls kept", async () => {
  const body = fixture("profile_diff.json");
  routes[DIFF_PATH] = { status: 200, body };
  const r = await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout", from: 2, to: 3 });
  assert.equal(r.isError, false, r.text);
  assert.equal(seen[0].query.get("from"), "2");
  assert.equal(seen[0].query.get("to"), "3");
  const got = JSON.parse(r.text);
  assertSubsetOfBroker(got, body, "profile_diff");
  assertNullsPreserved(got, body);
  assert.equal(got.dimensions.syscalls.captureLevel, null, "unchanged scalar stays null");
});

test("diff_workload_profile: defaults omit from/to; bad revisions are rejected locally", async () => {
  routes[DIFF_PATH] = { status: 200, body: fixture("profile_diff.json") };
  await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  assert.equal(seen[0].query.has("from"), false);
  assert.equal(seen[0].query.has("to"), false);
  seen = [];
  for (const args of [{ from: 3, to: 2 }, { from: 0 }, { to: 1.5 }, { from: "2" }]) {
    const r = await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout", ...args });
    assert.equal(r.isError, true, JSON.stringify(args));
  }
  assert.equal(seen.length, 0);
});

test("get_workload_security_profile: the broker's own sample (contract v1.1) keeps every dimension field and invents nothing", async () => {
  const body = fixture("profile_broker_sample.json") as Record<string, any>;
  routes[PROFILE_PATH] = { status: 200, body };
  const r = await executeInProcessTool("get_workload_security_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  assert.equal(r.isError, false, r.text);
  const got = JSON.parse(r.text);
  assertSubsetOfBroker(got, body, "profile_broker_sample");
  assertNullsPreserved(got, body);
  for (const [dim, v] of Object.entries(body.dimensions as Record<string, Record<string, unknown>>)) {
    assert.deepEqual(Object.keys(got.dimensions[dim]).filter((k) => !k.endsWith("Omitted")).sort(), Object.keys(v).sort(), `${dim} lost a field`);
  }
  assert.deepEqual(got.dimensions.podSecurity.pod, body.dimensions.podSecurity.pod, "pod-level failing checks pass through");
  assert.equal(got.dimensions.podSecurity.recommendation.yaml, body.dimensions.podSecurity.recommendation.yaml);
});

test("diff_workload_profile: revision 1 with from=null passes through as null", async () => {
  const body = fixture("profile_diff_rev1.json");
  routes[DIFF_PATH] = { status: 200, body };
  const r = await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout", to: 1 });
  const got = JSON.parse(r.text);
  assert.equal(got.from, null);
  assertSubsetOfBroker(got, body, "profile_diff_rev1");
  assertNullsPreserved(got, body);
});

test("diff_workload_profile: capped lists and 404 as found=false", async () => {
  const body = fixture("profile_diff.json") as Record<string, any>;
  body.dimensions.syscalls.added = Array.from({ length: 120 }, (_, i) => `sys_${i}`);
  routes[DIFF_PATH] = { status: 200, body };
  const r = await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout" });
  const got = JSON.parse(r.text);
  assert.equal(got.dimensions.syscalls.added.length, 50);
  assert.equal(got.dimensions.syscalls.addedOmitted, 70);
  delete routes[DIFF_PATH];
  const nf = await executeInProcessTool("diff_workload_profile", { namespace: "payments", kind: "Deployment", name: "checkout", to: 9 });
  assert.equal(nf.isError, false);
  assert.equal(JSON.parse(nf.text).found, false);
});
