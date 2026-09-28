import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import {
  generateCiliumPolicyWithComments, policyToYAML,
  type PeerResolver, type PodInfo, type TrafficRow,
} from "./networkpolicy.js";

// The cilium.io/v2 CiliumNetworkPolicy CRD (Cilium 1.17; datree CRDs-catalog
// cilium.io/ciliumnetworkpolicy_v2.json) constrains spec with anyOf over these
// keys; a spec carrying none of them is rejected by the API server.
const CILIUM_SPEC_ANY_OF = ["ingress", "ingressDeny", "egress", "egressDeny"] as const;
const DATREE_SCHEMA_LOCATION =
  "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json";

const goldensDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../test/fixtures/generators/networkpolicy");

const web: PodInfo = { name: "web", namespace: "prod", ip: "10.0.0.1", labels: { app: "web" } };
const idle: PodInfo = { name: "idle", namespace: "prod", ip: "10.0.0.2", labels: { app: "idle" } };
const noResolve: PeerResolver = async () => null;
const inRow: TrafficRow = { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.7", ip_protocol: "TCP" };
const outRow: TrafficRow = { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP" };
const selfRow: TrafficRow = { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.2", ip_protocol: "TCP" };
const badIn: TrafficRow = { ...inRow, traffic_in_out_ip: "not-an-ip" };
const badOut: TrafficRow = { ...outRow, traffic_in_out_ip: "also-not-an-ip" };

interface CrdCase {
  name: string; pod: PodInfo; traffic: TrafficRow[];
  /** Sections the spec must carry; every other anyOf key must be absent. */
  sections: string[]; denyAll: boolean;
}
const cases: CrdCase[] = [
  { name: "deny-all without traffic", pod: idle, traffic: [], sections: ["ingress", "egress"], denyAll: true },
  { name: "deny-all when every rule is dropped", pod: idle, traffic: [selfRow], sections: ["ingress", "egress"], denyAll: true },
  { name: "deny-all when every peer IP is unparseable", pod: web, traffic: [badIn, badOut], sections: ["ingress", "egress"], denyAll: true },
  { name: "ingress only", pod: web, traffic: [inRow], sections: ["ingress"], denyAll: false },
  { name: "egress only", pod: web, traffic: [outRow], sections: ["egress"], denyAll: false },
  { name: "egress only after every ingress peer is dropped", pod: web, traffic: [badIn, outRow], sections: ["egress"], denyAll: false },
  { name: "both directions", pod: web, traffic: [inRow, outRow], sections: ["ingress", "egress"], denyAll: false },
];

async function render(c: CrdCase): Promise<{ yaml: string; spec: Record<string, unknown> }> {
  const g = await generateCiliumPolicyWithComments(c.pod, c.traffic, noResolve);
  const yaml = policyToYAML(g.policy, g.comments);
  return { yaml, spec: (parse(yaml) as { spec: Record<string, unknown> }).spec };
}

for (const c of cases) {
  test(`cilium spec satisfies the CRD anyOf: ${c.name}`, async () => {
    const { yaml, spec } = await render(c);
    const present = CILIUM_SPEC_ANY_OF.filter((k) => k in spec);
    assert.ok(present.length > 0, `spec has none of ${CILIUM_SPEC_ANY_OF.join(", ")}; the CRD rejects it:\n${yaml}`);
    assert.deepEqual(present, c.sections, yaml);
    assert.equal("enableDefaultDeny" in spec, c.denyAll, yaml);
    if (c.denyAll) {
      // Cilium's deny form: one empty rule per denied direction.
      assert.deepEqual(spec.ingress, [{}]);
      assert.deepEqual(spec.egress, [{}]);
      assert.deepEqual(spec.enableDefaultDeny, { ingress: true, egress: true });
    }
  });
}

// Full CRD validation with kubeconform over every generated Cilium document
// and every committed cilium_* golden. Skipped when the binary is not
// installed; KUBECONFORM names it and KUBECONFORM_SCHEMA_LOCATION overrides
// the datree catalog.
test("cilium documents validate against the CRD with kubeconform", async (t) => {
  const bin = process.env.KUBECONFORM ?? "kubeconform";
  if (spawnSync(bin, ["-v"]).error) { t.skip(`${bin} not installed; install kubeconform or set KUBECONFORM`); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kg-netpol-crd-"));
  try {
    const files: string[] = [];
    for (const c of cases) {
      const f = path.join(dir, `${c.name.replaceAll(" ", "_")}.yaml`);
      fs.writeFileSync(f, (await render(c)).yaml);
      files.push(f);
    }
    for (const f of fs.readdirSync(goldensDir)) if (f.startsWith("cilium_") && f.endsWith(".golden.yaml")) files.push(path.join(goldensDir, f));
    const cache = path.join(os.tmpdir(), "kguardian-kubeconform-cache");
    fs.mkdirSync(cache, { recursive: true });
    const location = process.env.KUBECONFORM_SCHEMA_LOCATION ?? DATREE_SCHEMA_LOCATION;
    const r = spawnSync(bin, ["-strict", "-summary", "-cache", cache, "-schema-location", location, ...files], { encoding: "utf8" });
    assert.equal(r.status, 0, `kubeconform failed:\n${r.stdout}${r.stderr}`);
    t.diagnostic(r.stdout.trim());
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
