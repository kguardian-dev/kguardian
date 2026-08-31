import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { generateNetworkPolicy, generateCiliumPolicy, policyToYAML, type PeerResolver, type PodInfo, type TrafficRow } from "./networkpolicy.js";

// G2 generator parity — network policy, assistant side.
// Runs the assistant's in-process generators against the same scenarios the
// advisor Go golden tests use and asserts the produced policy — parsed from
// YAML — deep-equals the advisor golden (parsed). YAML serialization differs
// harmlessly between the Go and TS emitters; the POLICY is what must match.

const goldensDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../test/fixtures/generators/networkpolicy",
);
const golden = (f: string) => parse(fs.readFileSync(path.join(goldensDir, f), "utf8"));

const web: PodInfo = { name: "web", namespace: "prod", ip: "10.0.0.1", labels: { app: "web" } };
const idle: PodInfo = { name: "idle", namespace: "prod", ip: "10.0.0.2", labels: { app: "idle" } };
const traffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.7", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP" },
];
const noResolve: PeerResolver = async () => null;
const resolveEndpoints: PeerResolver = async (ip) =>
  ip === "10.96.0.10" ? { selector: { app: "db" }, namespace: "prod" }
  : ip === "10.0.0.7" ? { selector: { app: "frontend" }, namespace: "prod" }
  : null;

async function roundtrip(policy: Record<string, unknown>): Promise<unknown> {
  return parse(policyToYAML(policy));
}

test("standard policy — CIDR peers matches advisor golden", async () => {
  const got = await roundtrip(await generateNetworkPolicy(web, traffic, noResolve));
  assert.deepEqual(got, golden("standard_with_traffic.golden.yaml"));
});

test("standard policy — default-deny matches advisor golden", async () => {
  const got = await roundtrip(await generateNetworkPolicy(idle, [], noResolve));
  assert.deepEqual(got, golden("standard_default_deny.golden.yaml"));
});

test("cilium policy — CIDR peers matches advisor golden", async () => {
  const got = await roundtrip(await generateCiliumPolicy(web, traffic, noResolve));
  assert.deepEqual(got, golden("cilium_with_traffic.golden.yaml"));
});

test("cilium policy — endpoint-resolved peers matches advisor golden", async () => {
  const got = await roundtrip(await generateCiliumPolicy(web, traffic, resolveEndpoints));
  assert.deepEqual(got, golden("cilium_endpoint_resolved.golden.yaml"));
});

test("cilium policy — default-deny matches advisor golden", async () => {
  const got = await roundtrip(await generateCiliumPolicy(idle, [], noResolve));
  assert.deepEqual(got, golden("cilium_default_deny.golden.yaml"));
});
