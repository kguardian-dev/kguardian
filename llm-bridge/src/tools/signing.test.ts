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
import { SIGNING_CAPS, parseTrustVerdict, trimImageTrust, trimSigners } from "./signing.js";

// #1533 signature tools, replayed against real broker output:
// test/fixtures/signing holds {request, status, body} captures from a
// local broker (TELEMETRY_ENABLED=false) built from this branch. The
// signature results are real sigstore-go verifications of the supplychain
// test fixtures (chainguard-static keyless with SLSA provenance, a
// key-signed image with and without its key, the unsigned kguardian
// controller, a tampered pause signature, a registry answering 401), so
// repositories name the fixture registry's local host. The workload rows
// were seeded with SQL and the payments/recs digests are synthetic. The
// /image-trust captures come from the real evaluator binary against an
// envtest kube-apiserver holding two demo policies. See
// test/fixtures/signing/README.md.
//
// The rules under test:
//   - "verified" is never presented as trusted, and a signer is shown only
//     for a signature that verified;
//   - unknown stays unknown: a digest with no result, verdict unknown, an
//     unavailable or not-yet-evaluated image trust answer;
//   - bounded: limits clamped, lists capped, truncated flagged,
//     results <= MAX_RESPONSE_CHARS.

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(here, "../../../test/fixtures/signing");
interface Capture { request: string; status: number; body: any }
const capture = (name: string): Capture => JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), "utf8"));

const D = {
  storefront: "sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f",
  checkout: "sha256:94be8ca1be31f007a2a31fd67a3830ee9dbde9cc971a699f35d419b5f51b242b",
  search: "sha256:3de3b7e5f8062f772ceab50833cbd54cb09688ca0e7a0f70bd79895ab54cd95d",
  cart: "sha256:f6ab986a3a713f127b0f03c6f5319756883249bbf58cebbee9911d80eb7fa1f8",
  ledger: "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a",
  payments: `sha256:${"a".repeat(64)}`,
  recs: `sha256:${"d".repeat(64)}`,
};

interface Seen { path: string; query: URLSearchParams; auth: string | undefined }
let server: http.Server;
let seen: Seen[] = [];
let routes: Record<string, { status: number; body: unknown }> = {};

/** Serve a capture at its own request path (query ignored). */
function serve(name: string, at?: string) {
  const c = capture(name);
  const p = at ?? c.request.replace(/^GET /, "").split("?")[0];
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

async function run(tool: string, args: Record<string, unknown>): Promise<any> {
  const r = await executeInProcessTool(tool, args);
  assert.equal(r.isError, false, r.text);
  assert.ok(r.text.length <= MAX_RESPONSE_CHARS);
  return JSON.parse(r.text);
}

// --- descriptions ---------------------------------------------------------------

test("both tools are registered and their descriptions carry the rules", () => {
  const signers = TOOL_DEFS.find((t) => t.name === "get_image_signers")!.description;
  assert.match(signers, /NOT that the signer is trusted/);
  assert.match(signers, /unrecognised_reason/);
  assert.match(signers, /never signed, unsigned or a pass/);
  const trust = TOOL_DEFS.find((t) => t.name === "explain_image_trust")!.description;
  assert.match(trust, /never an all-clear/);
  assert.match(trust, /Unknown results are never a pass/);
  assert.match(trust, /Report-only/);
});

// --- get_image_signers --------------------------------------------------------------

test("get_image_signers: keyless verified shows signers and provenance, never 'trusted'", async () => {
  serve("attestation-storefront");
  const got = await run("get_image_signers", { digest: D.storefront.toUpperCase().replace("SHA256", "sha256") });
  assert.equal(seen[0].path, `/images/${D.storefront}/attestation`);
  assert.equal(seen[0].auth, "Bearer read-token");
  assert.equal(got.verdict, "verified");
  assert.deepEqual(got.signers, [{
    signerKind: "keyless",
    issuer: "https://token.actions.githubusercontent.com",
    san: "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
  }]);
  const slsa = got.attestations.find((a: any) => a.predicateType === "https://slsa.dev/provenance/v1");
  assert.equal(slsa.verified, true);
  assert.equal(slsa.provenance.builderId, "https://github.com/chainguard-dev/terraform-provider-apko");
  assert.match(got.verdictMeaning, /Valid, not trusted/);
  assert.match(got.note, /NOT trusted/);
  assert.equal(got.truncated, false);
  // Nothing says the image is trusted.
  assert.doesNotMatch(JSON.stringify({ ...got, note: "", verdictMeaning: "" }), /trusted/i);
});

test("get_image_signers: key verified names the key; key_signed shows no signer", async () => {
  serve("attestation-checkout");
  const key = await run("get_image_signers", { digest: D.checkout });
  assert.deepEqual(key.signers, [{ signerKind: "key", keyName: "fixture", keyFingerprint: "e2312c28209f4778ffc6c0ca2786638bb86d6027ee8092aba67c5d94d268ee30" }]);
  assert.ok(!JSON.stringify(key).includes("BEGIN PUBLIC KEY"), "the PEM is not needed");

  serve("attestation-search");
  const ks = await run("get_image_signers", { digest: D.search });
  assert.equal(ks.verdict, "key_signed");
  assert.deepEqual(ks.signers, []);
  assert.deepEqual(Object.keys(ks.signatures[0]).sort(), ["detail", "error", "format", "source", "verified"]);
  assert.equal(ks.signatures[0].error, "untrusted_key");
  assert.match(ks.verdictMeaning, /NOT checked/);
});

test("get_image_signers: unsigned, invalid and unknown are never a pass", async () => {
  serve("attestation-cart");
  const u = await run("get_image_signers", { digest: D.cart });
  assert.equal(u.verdict, "unsigned");
  assert.deepEqual(u.signers, []);

  serve("attestation-ledger");
  const inv = await run("get_image_signers", { digest: D.ledger });
  assert.equal(inv.verdict, "invalid");
  assert.deepEqual(inv.signers, []);
  assert.equal(inv.signatures[0].verified, false);
  assert.equal(inv.signatures[0].issuer, undefined);
  assert.match(inv.verdictMeaning, /never as signed/);

  serve("attestation-payments");
  const unk = await run("get_image_signers", { digest: D.payments });
  assert.equal(unk.verdict, "unknown");
  assert.equal(unk.reason, "registry_auth");
  assert.match(unk.verdictMeaning, /never a pass/);
  assert.match(unk.reasonMeaning, /private image/);
});

test("get_image_signers: no result is unknown (not checked), never unsigned", async () => {
  const c = serve("attestation-recs");
  assert.equal(c.status, 404);
  const got = await run("get_image_signers", { digest: D.recs });
  assert.equal(got.found, false);
  assert.equal(got.verdict, "unknown");
  assert.match(got.note, /never unsigned and never signed/);
});

test("get_image_signers: unrecognised_reason and unknown verdicts stay unknown", () => {
  const body = { ...capture("attestation-payments").body, reason: "unrecognised_reason" };
  const got = trimSigners(body);
  assert.match(String(got.reasonMeaning), /never good/);
  const odd = trimSigners({ ...body, verdict: "definitely_fine" });
  assert.match(String(odd.verdictMeaning), /treat as unknown, never as a pass/);
});

test("get_image_signers: signatures are capped with a count and truncated flag", () => {
  const base = capture("attestation-storefront").body;
  const many = Array.from({ length: SIGNING_CAPS.signatures + 5 }, (_, i) => ({
    ...base.signatures[0], san: `https://github.com/example/repo/.github/workflows/r.yaml@refs/tags/v${i}`,
  }));
  const got = trimSigners({ ...base, signatures: [{ verified: false, error: "bad_signature", format: "cosign-legacy", source: "sig-tag" }, ...many] });
  assert.equal((got.signatures as unknown[]).length, SIGNING_CAPS.signatures);
  assert.equal(got.signaturesOmitted, 6);
  assert.equal(got.truncated, true);
  // Verified first, even when the broker listed an unverified one first.
  assert.equal((got.signatures as any[])[0].verified, true);
  // Every distinct verified signer is kept for "who signed".
  assert.equal((got.signers as unknown[]).length, SIGNING_CAPS.signatures + 5);
});

test("get_image_signers: a malformed digest is refused before any broker call", async () => {
  const r = await executeInProcessTool("get_image_signers", { digest: "nginx:latest" });
  assert.equal(r.isError, true);
  assert.equal(seen.length, 0);
});

// --- explain_image_trust ---------------------------------------------------------------

test("explain_image_trust: WouldDeny first with reasons; counts from the broker", async () => {
  serve("image-trust-all");
  const got = await run("explain_image_trust", {});
  assert.equal(seen[0].path, "/image-trust");
  assert.equal(seen[0].query.get("limit"), "25");
  assert.equal(got.available, true);
  assert.deepEqual([got.total, got.wouldDeny, got.unknown, got.trusted], [10, 5, 2, 3]);
  const v = got.results.map((r: any) => r.verdict);
  assert.deepEqual(v, [...v].sort((a: string, b: string) => ["WouldDeny", "Unknown", "Trusted"].indexOf(a) - ["WouldDeny", "Unknown", "Trusted"].indexOf(b)));
  const search = got.results.find((r: any) => r.reason === "key-not-verified");
  assert.match(search.reasonMeaning, /give supplychain the key/);
  const payments = got.results.find((r: any) => r.workload === "Deployment/payments");
  assert.equal(payments.verdict, "Unknown");
  assert.equal(payments.reason, "registry_auth");
  assert.match(got.note, /never a pass/);
  assert.match(got.note, /never admits or blocks/);
  assert.equal(got.truncated, false);
});

test("explain_image_trust: filters are passed to the broker and echoed", async () => {
  serve("image-trust-storefront");
  const got = await run("explain_image_trust", { namespace: "shop", workload_kind: "Deployment", workload_name: "storefront", verdict: "trusted", limit: 500 });
  const q = seen[0].query;
  assert.deepEqual([q.get("namespace"), q.get("workload_kind"), q.get("workload_name"), q.get("verdict"), q.get("limit")],
    ["shop", "Deployment", "storefront", "Trusted", String(MAX_TOOL_LIMIT)]);
  assert.deepEqual(got.filters, { namespace: "shop", workloadKind: "Deployment", workloadName: "storefront", verdict: "Trusted" });
  assert.ok(got.results.every((r: any) => r.workload === "Deployment/storefront"));
});

test("explain_image_trust: a cut list is flagged truncated with the omitted count", async () => {
  serve("image-trust-woulddeny-limit2");
  const got = await run("explain_image_trust", { verdict: "WouldDeny", limit: 2 });
  assert.equal(got.results.length, 2);
  assert.equal(got.total, 5);
  assert.equal(got.resultsOmitted, 3);
  assert.equal(got.truncated, true);
});

test("explain_image_trust: unavailable or not evaluated is UNKNOWN, never an all-clear", () => {
  const off = trimImageTrust({
    available: false, reason: "image trust evaluation is off in the evaluator", evaluatedAt: null,
    total: 0, wouldDeny: 0, unknown: 0, trusted: 0, policies: [], results: [], truncated: false,
  }, {});
  assert.equal(off.available, false);
  assert.equal(off.results, undefined, "no empty result list that reads as 'nothing denied'");
  assert.equal(off.wouldDeny, undefined);
  assert.match(String(off.note), /UNKNOWN/);
  const fresh = trimImageTrust({ ...capture("image-trust-all").body, evaluatedAt: null, total: 0, wouldDeny: 0, unknown: 0, trusted: 0, results: [] }, {});
  assert.match(String(fresh.note), /^The evaluator has not finished a pass yet: results are UNKNOWN/);
  assert.equal(trimImageTrust("garbage", {}).available, false);
});

test("explain_image_trust: a bad verdict is refused before any broker call", async () => {
  assert.equal(parseTrustVerdict("would-deny"), "WouldDeny");
  const r = await executeInProcessTool("explain_image_trust", { verdict: "Denied" });
  assert.equal(r.isError, true);
  assert.equal(seen.length, 0);
});

test("explain_image_trust: a huge answer is cut to the budget and flagged", () => {
  const one = capture("image-trust-all").body.results[0];
  const results = Array.from({ length: MAX_TOOL_LIMIT }, (_, i) => ({ ...one, workload: `Deployment/${"w".repeat(600)}${i}` }));
  const got = trimImageTrust({ ...capture("image-trust-all").body, total: 5000, results }, {});
  assert.ok(JSON.stringify(got).length <= MAX_RESPONSE_CHARS);
  assert.equal(got.truncated, true);
});

test("explain_image_trust: the broker's answer with the evaluator down is UNKNOWN", async () => {
  serve("image-trust-evaluator-down");
  const got = await run("explain_image_trust", { namespace: "shop" });
  assert.equal(got.available, false);
  assert.match(got.reason, /the evaluator could not be reached/);
  assert.equal(got.results, undefined);
  assert.match(got.note, /UNKNOWN, never an all-clear/);
});

test("explain_image_trust: an unrecognised verdict is Unknown, never Trusted", () => {
  const base = capture("image-trust-all").body;
  const results = [
    { ...base.results[0], verdict: "Maybe", reason: undefined, workload: "Deployment/b" },
    { ...base.results[8], verdict: "Trusted" },
  ];
  // An older broker counted only the three known verdicts.
  const got = trimImageTrust({ ...base, total: 2, wouldDeny: 0, unknown: 0, trusted: 1, results }, {}) as any;
  assert.equal(got.unknown, 1);
  assert.equal(got.unrecognisedVerdicts, 1);
  assert.match(got.results[0].verdictMeaning, /never as Trusted/);
  assert.equal(got.results[1].verdictMeaning, undefined);
  // A consistent answer has no extra fields.
  const ok = trimImageTrust(base, {}) as any;
  assert.equal(ok.unrecognisedVerdicts, undefined);
  assert.equal(ok.unknown, base.unknown);
});

test("get_image_signers: verified without a signer identity is unknown, never signed", () => {
  const base = capture("attestation-storefront").body;
  for (const sig of [
    { format: "cosign-bundle", source: "referrers", verified: true },
    { format: "cosign-bundle", source: "referrers", verified: true, signerKind: "keyless" },
    { format: "cosign-bundle", source: "referrers", verified: true, signerKind: "keyless", issuer: "https://token.actions.githubusercontent.com" },
    { format: "cosign-legacy", source: "sig-tag", verified: true, signerKind: "key", keyName: "release" },
    // Whitespace-only identity fields are missing.
    { format: "cosign-bundle", source: "referrers", verified: true, signerKind: "keyless", issuer: "https://token.actions.githubusercontent.com", san: "   " },
    { format: "cosign-bundle", source: "referrers", verified: true, signerKind: "keyless", issuer: " ", san: "https://github.com/example/app" },
    { format: "cosign-legacy", source: "sig-tag", verified: true, signerKind: "key", keyName: "release", keyFingerprint: "  " },
  ]) {
    const got = trimSigners({ ...base, signatures: [sig], attestations: [{ predicateType: "https://slsa.dev/provenance/v1", verified: true }] }) as any;
    assert.equal(got.verdict, "unknown", JSON.stringify(sig));
    assert.equal(got.reason, "no_signer_identity");
    assert.equal(got.brokerVerdict, "verified");
    assert.deepEqual(got.signers, []);
    assert.equal(got.signatures[0].verified, false);
    assert.equal(got.signatures[0].error, "no_signer_identity");
    assert.equal(got.attestations[0].verified, false);
    assert.match(got.verdictMeaning, /never a pass/);
    assert.match(got.reasonMeaning, /not counted as signed/);
  }
  // One named signer keeps the verdict; the anonymous one is shown unverified.
  const mixed = trimSigners({ ...base, signatures: [{ format: "x", source: "y", verified: true }, ...base.signatures] }) as any;
  assert.equal(mixed.verdict, "verified");
  assert.equal(mixed.signers.length, 1);
  assert.equal(mixed.brokerVerdict, undefined);
  assert.ok(mixed.signatures.some((s: any) => s.error === "no_signer_identity" && s.verified === false));
});
