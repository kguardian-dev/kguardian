import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";

import { executeInProcessTool } from "./execute.js";
import { TOOL_DEFS } from "./registry.js";
import { MAX_RESPONSE_CHARS, MAX_TOOL_LIMIT } from "./posture.js";
import { IN_USE_NOTE, TIER_NOTE, hardFit, parseDigest, parseEpssMin, parseInUse, parseSeverity, parseTier, parseVulnId } from "./vulns.js";

// #1533 P1-7 vulnerability tools, replayed against real broker output:
// test/fixtures/vulns holds {request, status, body} captures from a local
// broker built from the vulnerability API PR (#1671), seeded through its
// ingest routes with neutral names and fake CVE-2099-* ids.
//
// The rules under test:
//   - every vulnerability id in a tool result exists in the broker
//     response (the tools never invent one), and every tool description
//     forbids the model from inventing ids;
//   - unknown stays unknown: no report = no data (not clean), exposed null
//     stays null, inUse null stays null;
//   - bounded: limits clamped, lists capped, results <= MAX_RESPONSE_CHARS.

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(here, "../../../test/fixtures/vulns");
interface Capture { request: string; status: number; body: any }
const capture = (name: string): Capture => JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), "utf8"));

const STOREFRONT = "sha256:00000000000000000000000000000000000000000000000000000000000000a2";
const LEDGER = "sha256:00000000000000000000000000000000000000000000000000000000000000b1";
const UNSCANNED = "sha256:00000000000000000000000000000000000000000000000000000000000000c1";

interface Seen { path: string; query: URLSearchParams; auth: string | undefined }
let server: http.Server;
let seen: Seen[] = [];
let routes: Record<string, { status: number; body: unknown }> = {};

/** Serve a capture at its own request path. */
function serve(name: string) {
  const c = capture(name);
  const p = c.request.replace(/^GET /, "").split("?")[0];
  routes[p] = { status: c.status, body: c.body };
  return c;
}

before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url || "/", "http://x");
    seen.push({ path: u.pathname, query: u.searchParams, auth: req.headers.authorization });
    const r = routes[decodeURIComponent(u.pathname)];
    if (!r) { res.writeHead(404); res.end("No data found"); return; }
    res.writeHead(r.status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(r.body));
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

const VULN_TOOLS = ["get_image_vulnerabilities", "list_vulnerabilities", "explain_cve_exposure", "get_image_sbom"];

/** Every vulnerability-id-looking token in a string. */
const ID_RE = /\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b/gi;
const ids = (s: string) => new Set((s.match(ID_RE) ?? []).map((x) => x.toUpperCase()));

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

/** Each list item's fields must exist on the broker's items (renamed lists allowed). */
function assertItemsFromBroker(got: unknown[], broker: unknown[], label: string) {
  const have = new Set<string>();
  for (const b of broker) for (const p of leafPaths(b)) have.add(p);
  for (const g of got) for (const p of leafPaths(g)) {
    assert.ok(have.has(p) || /Omitted$/.test(p), `${label}: '${p}' is not in the broker response`);
  }
}

// --- descriptions -------------------------------------------------------------

test("every vulnerability tool forbids inventing ids and says unknown is not safe", () => {
  for (const name of VULN_TOOLS) {
    const d = TOOL_DEFS.find((t) => t.name === name)?.description;
    assert.ok(d, `${name} registered`);
    assert.match(d, /NEVER invent vulnerability ids/, `${name}: must forbid invented ids`);
    assert.match(d, /UNKNOWN/, `${name}: must explain unknown`);
    assert.match(d, /never[^.]*applies anything/, `${name}: must say kguardian never applies`);
  }
  const exposure = TOOL_DEFS.find((t) => t.name === "explain_cve_exposure")!.description;
  assert.match(exposure, /unknown is potentially reachable/);
  assert.match(exposure, /never describe the package as unreachable/);
  for (const name of ["get_image_vulnerabilities", "list_vulnerabilities"]) {
    const d = TOOL_DEFS.find((t) => t.name === name)!.description;
    assert.match(d, /unknown is potentially reachable, never unused/, `${name}: unknown in-use is never unused`);
    assert.match(d, /P0, P1, P2, Background/, `${name}: names the tiers`);
  }
  assert.match(TOOL_DEFS.find((t) => t.name === "get_image_sbom")!.description, /ONLY 'verified' may be called signed/);
});

// --- argument validation (no broker call on bad input) --------------------------

test("arguments are validated before any broker call", async () => {
  assert.equal(parseDigest(` ${STOREFRONT.toUpperCase().replace("SHA256", "sha256")} `), STOREFRONT);
  assert.throws(() => parseDigest("nginx:latest"));
  assert.equal(parseSeverity("high, critical,HIGH"), "HIGH,CRITICAL");
  assert.throws(() => parseSeverity("SEVERE"));
  assert.equal(parseVulnId(" cve-2099-10001 "), "CVE-2099-10001");
  assert.throws(() => parseVulnId("../../pod/info"));
  assert.equal(parseTier("p0, background,P0"), "P0,Background");
  assert.equal(parseInUse("Loaded,unknown"), "loaded,unknown");
  assert.equal(parseEpssMin("0.1"), 0.1);
  assert.equal(parseEpssMin(undefined), undefined);
  assert.throws(() => parseEpssMin("-1"));
  for (const [tool, args] of [
    ["get_image_vulnerabilities", { digest: "latest" }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, severity: "SEVERE" }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, fixable: "maybe" }],
    ["list_vulnerabilities", { kev: "yes" }],
    ["list_vulnerabilities", { tier: "P9" }],
    ["list_vulnerabilities", { in_use: "maybe" }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, epss_min: 2 }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, tier: "urgent" }],
    ["explain_cve_exposure", { id: "a/b" }],
    ["get_image_sbom", { digest: STOREFRONT, source: "somewhere" }],
  ] as const) {
    const r = await executeInProcessTool(tool, args);
    assert.equal(r.isError, true, `${tool} ${JSON.stringify(args)}`);
  }
  assert.equal(seen.length, 0);
});

// --- get_image_vulnerabilities ------------------------------------------------------

test("get_image_vulnerabilities: path, query, token; findings deduped across sources pass through", async () => {
  const c = serve("image-vulns-storefront");
  const r = await executeInProcessTool("get_image_vulnerabilities", { digest: STOREFRONT, severity: "critical,high", fixable: true, limit: 5000 });
  assert.equal(r.isError, false, r.text);
  assert.equal(seen[0].path, `/images/${STOREFRONT}/vulnerabilities`);
  assert.equal(seen[0].query.get("severity"), "CRITICAL,HIGH");
  assert.equal(seen[0].query.get("fixable"), "true");
  assert.equal(seen[0].query.get("limit"), String(MAX_TOOL_LIMIT));
  assert.equal(seen[0].auth, "Bearer read-token");
  const got = JSON.parse(r.text);
  assertItemsFromBroker(got.findings, c.body.items, "findings");
  assertItemsFromBroker(got.reports, c.body.reports, "reports");
  const crit = got.findings.find((f: any) => f.id === "CVE-2099-10001");
  assert.deepEqual(crit.sources, ["grype", "trivy-operator"], "one finding, two sources");
  assert.deepEqual(crit.fixedVersions, ["2.1.10", "2.1.4"], "every source's fix, as the broker listed them; none picked");
  assert.equal(crit.kev, true);
  const unfixed = got.findings.find((f: any) => f.id === "CVE-2099-10003");
  assert.deepEqual(unfixed.fixedVersions, []);
  assert.equal(unfixed.fixable, false);
  assert.match(got.note, /not version order/);
  const other = got.findings.find((f: any) => f.id === "CVE-2099-10002");
  assert.equal(other.kev, null, "kev null stays null (unknown)");
  for (const f of got.findings) { assert.equal(f.inUse, null); assert.equal(f.inUseState, "unknown"); }
  assert.equal(got.noVulnerabilityData, false);
  assert.match(got.note, /potentially reachable/);
});

test("get_image_vulnerabilities: an unscanned image is unknown, never clean", async () => {
  serve("image-vulns-unscanned");
  const got = JSON.parse((await executeInProcessTool("get_image_vulnerabilities", { digest: UNSCANNED })).text);
  assert.equal(got.noVulnerabilityData, true);
  assert.deepEqual(got.findings, []);
  assert.match(got.note, /UNKNOWN, not zero/);
});

test("get_image_vulnerabilities: a broker 400 and 401 are tool errors", async () => {
  serve("image-vulns-noauth");
  const r = await executeInProcessTool("get_image_vulnerabilities", { digest: LEDGER });
  assert.equal(r.isError, true);
  assert.match(r.text, /401/);
});

// --- list_vulnerabilities -----------------------------------------------------------

test("list_vulnerabilities: filters reach the broker; rows pass through; freshness kept", async () => {
  const c = serve("vulns-list");
  const r = await executeInProcessTool("list_vulnerabilities", { namespace: "billing", severity: "HIGH", limit: 3 });
  assert.equal(seen[0].query.get("namespace"), "billing");
  assert.equal(seen[0].query.get("severity"), "HIGH");
  assert.equal(seen[0].query.get("limit"), "3");
  const got = JSON.parse(r.text);
  assertItemsFromBroker(got.vulnerabilities, c.body.items, "vulnerabilities");
  assert.equal(got.computedAt, c.body.computedAt);
  assert.equal(got.count, 3);
  assert.equal(got.truncated, true, "cut locally at limit");
});

test("list_vulnerabilities: kev is the broker's filter; the strict guard still excludes unknown rows", async () => {
  serve("vulns-list");
  const got = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: true, limit: 10 })).text);
  assert.equal(seen[0].query.get("kev"), "true", "kev reaches the broker");
  assert.equal(seen[0].query.get("limit"), "10", "no oversized page: the broker filters");
  // This capture predates the broker's kev filter (it returns every row),
  // so the local guard does the filtering: still strict.
  assert.deepEqual(got.vulnerabilities.map((v: any) => v.id), ["CVE-2099-10001"]);
  assert.match(got.kevFilter, /kev is null \(unknown/);
  assert.equal(got.kevScan, "complete", "4 rows < the 10 asked for, no cursor: every CVE was checked");
  assert.equal(got.truncated, false);
  const none = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: false })).text);
  assert.equal(none.count, 0, "no source said kev=false; null rows are not 'false'");
});

test("list_vulnerabilities: a broker that applied kev is complete even on a full page", async () => {
  const row = { ...capture("vulns-list").body.items[0], kev: true };
  const full = Array.from({ length: 5 }, (_, i) => ({ ...row, id: `CVE-2099-${String(60000 + i)}` }));
  routes["/vulnerabilities"] = { status: 200, body: { items: full, nextAfter: null, computedAt: "2026-09-26T03:00:00", staleSeconds: 5 } };
  const got = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: true, limit: 5 })).text);
  assert.equal(got.count, 5);
  assert.equal(got.kevScan, "complete", "nothing was dropped locally: the broker filtered");
});

// Rows as the in-use broker (#1678) serialises them: supplychain_read.rs
// Finding / CveSummary + CveItem. Not captures: the ids are fake.
const TIERED_FINDING = {
  id: "CVE-2099-30001", package: { name: "libfoo1", type: "debian", purl: "pkg:deb/debian/libfoo1@1.2.3-1" },
  installedVersion: "1.2.3-1", fixedVersions: ["1.2.4"], fixable: true, severity: "HIGH", score: 7.5,
  kev: true, kevDateAdded: "2026-01-02", epss: 0.31, epssPercentile: 0.97, sources: ["trivy-operator"],
  reportDigests: ["sha256:9f"], inUse: true, inUseState: "loaded",
  inUseDetail: { state: "loaded", reason: null, observedSince: null, windowHours: 24, containers: 1, coverage: "file" },
  tier: "P0", tierFactors: ["in_use:loaded", "kev", "epss>=0.1", "severity:high", "exposure:unknown"],
};
const TIERED_CVE = {
  id: "CVE-2099-30001", severity: "HIGH", maxScore: 7.5, fixable: true, kev: true, maxEpss: 0.31,
  packages: ["libfoo1"], sources: ["trivy-operator"], images: 1, workloads: 2, runningWorkloads: 2, namespaces: 1,
  weakestJoin: "image_id", tier: "P0", executedWorkloads: 0, loadedWorkloads: 1, unknownWorkloads: 1,
  notObservedWorkloads: 0, exposedWorkloads: 0, inUse: true, inUseState: "loaded",
};

test("an old broker that ignores tier/in_use/epss_min: filtered here, and says so", async () => {
  // The pre-tier capture: no tier or inUseState fields' values match, and
  // the broker returned every finding despite the filters.
  const c = serve("image-vulns-storefront");
  const got = JSON.parse((await executeInProcessTool("get_image_vulnerabilities", {
    digest: STOREFRONT, tier: "P0", in_use: "installed_not_observed", epss_min: 0.1,
  })).text);
  assert.ok(c.body.items.length > 0);
  assert.equal(got.count, 0, "no unfiltered rows labelled as filtered");
  assert.deepEqual(got.findings, []);
  assert.deepEqual(got.filtersAppliedLocally, ["epss_min", "in_use", "tier"]);
  assert.match(got.note, /The broker did not apply epss_min, in_use, tier/);
  assert.equal(got.tier, "P0", "the filter is still echoed");

  // Cluster list: a tierless summary row never matches tier=P0.
  routes["/vulnerabilities"] = { status: 200, body: capture("vulns-list").body };
  const list = JSON.parse((await executeInProcessTool("list_vulnerabilities", { tier: "P0" })).text);
  assert.equal(list.count, 0);
  assert.deepEqual(list.filtersAppliedLocally, ["tier"]);
  assert.match(list.note, /did not apply tier/);

  // A broker that applied the filters: nothing dropped, nothing said.
  routes[`/images/${STOREFRONT}/vulnerabilities`] = { status: 200, body: { digest: STOREFRONT, reports: [{ source: "trivy-operator" }], items: [TIERED_FINDING], nextAfter: null } };
  const ok = JSON.parse((await executeInProcessTool("get_image_vulnerabilities", { digest: STOREFRONT, tier: "P0", in_use: "loaded", epss_min: 0.1 })).text);
  assert.equal(ok.count, 1);
  assert.equal("filtersAppliedLocally" in ok, false);
  assert.doesNotMatch(ok.note, /did not apply/);
});

test("tier and in-use filters reach the broker and tier fields pass through", async () => {
  routes[`/images/${STOREFRONT}/vulnerabilities`] = { status: 200, body: { digest: STOREFRONT, reports: [{ source: "trivy-operator" }], items: [TIERED_FINDING], nextAfter: null } };
  const img = JSON.parse((await executeInProcessTool("get_image_vulnerabilities", {
    digest: STOREFRONT, kev: true, epss_min: 0.1, in_use: "loaded,unknown", tier: "p0,p1",
  })).text);
  const q = seen[0].query;
  assert.deepEqual([q.get("kev"), q.get("epss_min"), q.get("in_use"), q.get("tier")], ["true", "0.1", "loaded,unknown", "P0,P1"]);
  const f = img.findings[0];
  assert.equal(f.tier, "P0");
  assert.deepEqual(f.tierFactors, TIERED_FINDING.tierFactors);
  assert.deepEqual(f.inUseDetail, TIERED_FINDING.inUseDetail);
  assert.equal(img.tier, "P0,P1", "filters are echoed");
  assert.match(img.note, /a KEV finding there is P0/);

  seen = [];
  routes["/vulnerabilities"] = { status: 200, body: { items: [TIERED_CVE], nextAfter: null, computedAt: "2026-09-26T03:00:00", staleSeconds: 5 } };
  const list = JSON.parse((await executeInProcessTool("list_vulnerabilities", { tier: "P0", in_use: "loaded", epss_min: "0.2" })).text);
  assert.deepEqual([seen[0].query.get("tier"), seen[0].query.get("in_use"), seen[0].query.get("epss_min")], ["P0", "loaded", "0.2"]);
  const c = list.vulnerabilities[0];
  for (const k of ["tier", "executedWorkloads", "loadedWorkloads", "unknownWorkloads", "notObservedWorkloads", "exposedWorkloads", "inUseState"]) {
    assert.deepEqual(c[k], (TIERED_CVE as any)[k], k);
  }
  assert.ok(list.note.includes(TIER_NOTE) && list.note.includes(IN_USE_NOTE));
});

test("list_vulnerabilities: a full broker page makes the KEV scan partial, never complete", async () => {
  // A broker page exactly as full as the limit asked for, with no cursor:
  // more CVEs may exist, so the KEV result must not read as complete.
  const row = capture("vulns-list").body.items[1]; // kev null
  const full = Array.from({ length: MAX_TOOL_LIMIT }, (_, i) => ({ ...row, id: `CVE-2099-${String(50000 + i)}` }));
  routes["/vulnerabilities"] = { status: 200, body: { items: full, nextAfter: null, computedAt: "2026-09-26T03:00:00", staleSeconds: 5 } };
  const got = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: true })).text);
  assert.equal(got.count, 0);
  assert.equal(got.kevScan, "partial");
  assert.equal(got.truncated, true, "an empty KEV result from a full page is not complete");
  assert.match(got.kevFilter, new RegExp(`partial scan: only the first ${MAX_TOOL_LIMIT} CVEs by severity were checked`));

  // A next-page cursor also means partial, even on a short page.
  routes["/vulnerabilities"] = { status: 200, body: { ...capture("vulns-list").body, nextAfter: "3.CVE-2099-20001" } };
  const cursor = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: true })).text);
  assert.equal(cursor.kevScan, "partial");
  assert.equal(cursor.truncated, true);

  // Without a KEV filter nothing is said about KEV scanning.
  routes["/vulnerabilities"] = { status: 200, body: capture("vulns-list").body };
  const plain = JSON.parse((await executeInProcessTool("list_vulnerabilities", {})).text);
  assert.equal("kevScan" in plain, false);
});

test("list_vulnerabilities: a summary not built yet is unknown", async () => {
  routes["/vulnerabilities"] = { status: 200, body: { items: [], nextAfter: null, computedAt: null, staleSeconds: null } };
  const got = JSON.parse((await executeInProcessTool("list_vulnerabilities", {})).text);
  assert.match(got.note, /has not been built yet/);
});

// --- explain_cve_exposure -----------------------------------------------------------

test("explain_cve_exposure: images -> workloads -> exposure, with true/false/null kept exactly", async () => {
  const c = serve("exposure-shared");
  const r = await executeInProcessTool("explain_cve_exposure", { id: "cve-2099-10003", window_hours: 99999 });
  assert.equal(seen[0].path, "/vulnerabilities/CVE-2099-10003/exposure");
  assert.equal(seen[0].query.get("window_hours"), "720");
  const got = JSON.parse(r.text);
  assertItemsFromBroker(got.workloads, c.body.workloads, "workloads");
  assertItemsFromBroker(got.images, c.body.images, "images");
  const byName = Object.fromEntries(got.workloads.map((w: any) => [w.name, w.network]));
  assert.equal(byName.storefront.exposed, true);
  assert.deepEqual(byName.storefront.exposedVia, ["other_namespace", "unattributed", "public_ip"]);
  assert.equal(byName.ledger.exposed, false);
  assert.ok(byName.ledger.ingressFlowsObserved > 0, "false only with observed ingress");
  assert.equal(byName["catalog-sync"].exposed, null, "egress but no ingress observed stays unknown");
  assert.ok(byName["catalog-sync"].flowsObserved > 0 && byName["catalog-sync"].ingressFlowsObserved === 0);
  assert.match(got.note, /even if the workload had egress/);
  assert.equal(got.inUse, null);
  assert.match(got.note, /UNKNOWN, never 'not exposed'/);
  assert.match(got.note, /never as unreachable or unused/);
});

test("explain_cve_exposure: 404 is found=false and not proof of absence", async () => {
  serve("exposure-not-found");
  const r = await executeInProcessTool("explain_cve_exposure", { id: "CVE-2099-99999" });
  assert.equal(r.isError, false);
  const got = JSON.parse(r.text);
  assert.equal(got.found, false);
  assert.match(got.note, /not proof the cluster is unaffected/);
});

test("explain_cve_exposure: long lists are capped with counts and truncated set", async () => {
  const c = capture("exposure-shared");
  const w = c.body.workloads[0];
  routes["/vulnerabilities/CVE-2099-10003/exposure"] = {
    status: 200, body: { ...c.body, workloads: Array.from({ length: 200 }, (_, i) => ({ ...w, name: `wl-${i}` })) },
  };
  const got = JSON.parse((await executeInProcessTool("explain_cve_exposure", { id: "CVE-2099-10003" })).text);
  assert.equal(got.workloads.length, 25);
  assert.equal(got.workloadsOmitted, 175);
  assert.equal(got.truncated, true);
});

// --- get_image_sbom ---------------------------------------------------------------

test("get_image_sbom: every source with its trust; components from one; attestation kept", async () => {
  const c = serve("sbom-storefront");
  const r = await executeInProcessTool("get_image_sbom", { digest: STOREFRONT, source: "Registry", limit: 2 });
  assert.equal(seen[0].query.get("source"), "registry");
  assert.equal(seen[0].query.get("limit"), "2");
  const got = JSON.parse(r.text);
  assert.deepEqual(got.reports.map((x: any) => [x.source, x.sbomTrust]), c.body.reports.map((x: any) => [x.source, x.sbomTrust]));
  const reg = got.reports.find((x: any) => x.source === "registry");
  assert.equal(reg.attestation.verified, false);
  assert.equal(reg.attestation.predicate_type, "https://spdx.dev/Document");
  assertItemsFromBroker(got.components, c.body.items, "components");
  assert.match(got.note, /Only 'verified' may be described as signed/);
});

test("get_image_sbom: no SBOM is unknown", async () => {
  serve("sbom-unscanned");
  const got = JSON.parse((await executeInProcessTool("get_image_sbom", { digest: UNSCANNED })).text);
  assert.equal(got.report, null);
  assert.match(got.note, /contents are unknown/);
});

// --- no invented ids (replay over every capture) ----------------------------------------

const REPLAYS: [string, string, Record<string, unknown>][] = [
  ["image-vulns-storefront", "get_image_vulnerabilities", { digest: STOREFRONT }],
  ["image-vulns-storefront-critical", "get_image_vulnerabilities", { digest: STOREFRONT, severity: "CRITICAL,HIGH", fixable: true }],
  ["image-vulns-ledger", "get_image_vulnerabilities", { digest: LEDGER }],
  ["image-vulns-unscanned", "get_image_vulnerabilities", { digest: UNSCANNED }],
  ["vulns-list", "list_vulnerabilities", {}],
  ["vulns-list-billing", "list_vulnerabilities", { namespace: "billing" }],
  ["vulns-list-high", "list_vulnerabilities", { severity: "CRITICAL,HIGH", limit: 2 }],
  ["exposure-shared", "explain_cve_exposure", { id: "CVE-2099-10003" }],
  ["exposure-critical", "explain_cve_exposure", { id: "CVE-2099-10001" }],
  ["sbom-storefront", "get_image_sbom", { digest: STOREFRONT }],
  ["sbom-storefront-registry", "get_image_sbom", { digest: STOREFRONT, source: "registry" }],
];

for (const [name, tool, args] of REPLAYS) {
  test(`no invented ids: ${tool} over ${name}`, async () => {
    const c = serve(name);
    const r = await executeInProcessTool(tool, args);
    assert.equal(r.isError, false, r.text);
    assert.ok(r.text.length <= MAX_RESPONSE_CHARS);
    const allowed = ids(JSON.stringify(c.body));
    for (const a of Object.values(args)) if (typeof a === "string") for (const x of ids(a)) allowed.add(x);
    for (const id of ids(r.text)) assert.ok(allowed.has(id), `${id} is not in the broker response or the arguments`);
  });
}

// A model answer can be checked the same way: this is the grounding rule the
// descriptions state, applied to an answer against the tool text it saw.
function unsupportedIds(answer: string, toolTexts: string[], question = ""): string[] {
  const allowed = new Set<string>();
  for (const t of [...toolTexts, question]) for (const x of ids(t)) allowed.add(x);
  return [...ids(answer)].filter((x) => !allowed.has(x));
}

test("an answer citing an id no tool returned is caught; a grounded one passes", async () => {
  serve("exposure-critical");
  const r = await executeInProcessTool("explain_cve_exposure", { id: "CVE-2099-10001" });
  const grounded = "CVE-2099-10001 (critical, fixed in fastparse 2.1.4) runs in storefront, which saw ingress from a public IP.";
  const invented = "CVE-2099-10001 is exposed, and it is often chained with CVE-2021-44228.";
  assert.deepEqual(unsupportedIds(grounded, [r.text]), []);
  assert.deepEqual(unsupportedIds(invented, [r.text]), ["CVE-2021-44228"]);
});

test("hardFit: the size budget is a hard guarantee", () => {
  const huge = { id: "CVE-2099-1", severity: "HIGH", workloads: [{ name: "x".repeat(200_000) }], images: [] as unknown[] };
  const out = hardFit(huge, ["workloads", "images"], ["id", "severity"], 5_000);
  assert.ok(JSON.stringify(out).length <= 5_000);
  assert.equal(out.truncated, true);
  const giant = { id: "y".repeat(100_000), workloads: [] as unknown[] };
  const out2 = hardFit(giant, ["workloads"], ["id"], 5_000);
  assert.ok(JSON.stringify(out2).length <= 5_000);
});
