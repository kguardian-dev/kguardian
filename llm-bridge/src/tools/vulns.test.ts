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
import { hardFit, parseDigest, parseSeverity, parseVulnId } from "./vulns.js";

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
  assert.match(TOOL_DEFS.find((t) => t.name === "explain_cve_exposure")!.description, /never describe the vulnerable package as unused, unloaded or unreachable/);
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
  for (const [tool, args] of [
    ["get_image_vulnerabilities", { digest: "latest" }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, severity: "SEVERE" }],
    ["get_image_vulnerabilities", { digest: STOREFRONT, fixable: "maybe" }],
    ["list_vulnerabilities", { kev: "yes" }],
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

test("list_vulnerabilities: kev filter is strict and says unknown rows are excluded", async () => {
  serve("vulns-list");
  const got = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: true, limit: 10 })).text);
  assert.equal(seen[0].query.get("limit"), String(MAX_TOOL_LIMIT), "kev filtering asks for the largest page");
  assert.deepEqual(got.vulnerabilities.map((v: any) => v.id), ["CVE-2099-10001"]);
  assert.match(got.kevFilter, /kev is null \(unknown/);
  const none = JSON.parse((await executeInProcessTool("list_vulnerabilities", { kev: false })).text);
  assert.equal(none.count, 0, "no source said kev=false; null rows are not 'false'");
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
