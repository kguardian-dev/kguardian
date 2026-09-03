import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import {
  generateNetworkPolicy, generateCiliumPolicy, policyToYAML,
  generateNetworkPolicyWithComments, generateCiliumPolicyWithComments, hostNetworkServiceIdentity,
  type PeerResolver, type PeerIdentity, type PodInfo, type TrafficRow, type BrokerPodListEntry,
} from "./networkpolicy.js";

// G2 generator parity — network policy, assistant side.
// Runs the assistant's in-process generators against the same scenarios the
// advisor Go golden tests use and asserts the produced policy — parsed from
// YAML — deep-equals the advisor golden (parsed). YAML serialization differs
// harmlessly between the Go and TS emitters; the POLICY is what must match.

const goldensDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../test/fixtures/generators/networkpolicy",
);
const goldenText = (f: string) => fs.readFileSync(path.join(goldensDir, f), "utf8");
const golden = (f: string) => parse(goldenText(f));
// Every YAML parser drops comments, so the host-network goldens are compared
// twice: the parsed policy, and the ordered list of "#" lines (trimmed —
// column and surrounding blank lines are emitter details).
const commentLines = (text: string): string[] =>
  text.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("#"));

const web: PodInfo = { name: "web", namespace: "prod", ip: "10.0.0.1", labels: { app: "web" } };
const idle: PodInfo = { name: "idle", namespace: "prod", ip: "10.0.0.2", labels: { app: "idle" } };
const traffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.7", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP" },
];

// Dual-stack scenario: an IPv6 pod whose observed peers are two IPv6 addresses
// and — deliberately mixed-family — one IPv4 address. It pins the host mask to
// the address family of each PEER rather than of the pod: /128 for fd00::7 and
// fd00:96::a, /32 for 10.96.0.10. A single /32 applied across the board would
// widen each v6 peer rule to 2^96 addresses.
const web6: PodInfo = { name: "web6", namespace: "prod", ip: "fd00::1", labels: { app: "web" } };
const dualStackTraffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "fd00::7", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "fd00:96::a", traffic_in_out_port: "5432", ip_protocol: "TCP" },
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

test("standard policy — dual-stack CIDR peers matches advisor golden", async () => {
  const got = await roundtrip(await generateNetworkPolicy(web6, dualStackTraffic, noResolve));
  assert.deepEqual(got, golden("standard_dualstack.golden.yaml"));
});

test("cilium policy — dual-stack CIDR peers matches advisor golden", async () => {
  const got = await roundtrip(await generateCiliumPolicy(web6, dualStackTraffic, noResolve));
  assert.deepEqual(got, golden("cilium_dualstack.golden.yaml"));
});

// ---- Host-network peers and targets -----------------------------------------
// Scenarios and resolver identities mirror advisor fixture_golden_test.go
// (TestFixtureGolden_HostNetwork); see test/fixtures/generators/networkpolicy/README.md.

const hostPod = (podName: string, namespace: string, labels: Record<string, string>, node: string, workload: string): PeerIdentity =>
  ({ hostNetwork: true, selector: labels, namespace, podName, workload, node });
const plainPod = (labels: Record<string, string>, namespace: string): PeerIdentity =>
  ({ hostNetwork: false, selector: labels, namespace });

// (a) egress: Prometheus scrapes node-exporter on two nodes + an unresolvable ClusterIP.
const prometheus: PodInfo = { name: "prometheus", namespace: "monitoring", ip: "10.0.0.5", labels: { app: "prometheus" }, hostNetwork: false, workload: "prometheus" };
const egressTraffic: TrafficRow[] = [
  { traffic_type: "EGRESS", traffic_in_out_ip: "192.168.50.101", traffic_in_out_port: "9100", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "192.168.50.102", traffic_in_out_port: "9100", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP" },
];
const resolveEgress: PeerResolver = async (ip) =>
  ip === "192.168.50.101" ? hostPod("node-exporter-abc12", "monitoring", { app: "node-exporter" }, "worker-1", "node-exporter")
  : ip === "192.168.50.102" ? hostPod("node-exporter-def34", "monitoring", { app: "node-exporter" }, "worker-2", "node-exporter")
  : null;

// (b) ingress: a hostNetwork ingress-nginx controller and a normal frontend pod reach web:8080.
const webTarget: PodInfo = { ...web, hostNetwork: false, workload: "web" };
const ingressTraffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "192.168.50.101", ip_protocol: "TCP" },
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.7", ip_protocol: "TCP" },
];
const resolveIngress: PeerResolver = async (ip) =>
  ip === "192.168.50.101" ? hostPod("ingress-nginx-controller-abc12", "ingress-nginx", { "app.kubernetes.io/name": "ingress-nginx" }, "worker-1", "ingress-nginx-controller")
  : ip === "10.0.0.7" ? plainPod({ app: "frontend" }, "prod")
  : null;

// (c) the target itself is host-network: node-exporter scraped by Prometheus.
const nodeExporter: PodInfo = { name: "node-exporter-abc12", namespace: "monitoring", ip: "192.168.50.101", labels: { app: "node-exporter" }, hostNetwork: true, workload: "node-exporter" };
const targetTraffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "9100", traffic_in_out_ip: "10.0.0.5", ip_protocol: "TCP" },
];
const resolveTarget: PeerResolver = async (ip) => (ip === "10.0.0.5" ? plainPod({ app: "prometheus" }, "monitoring") : null);

// (d) a Service whose backing pods are host-network: Prometheus scrapes the
// node-exporter ClusterIP; the db ClusterIP is backed by a normal pod. The
// identity is derived from the broker /pod/info listing exactly as execute.ts
// does, so the filtering is under test too (not just a hand-written identity).
const podList: BrokerPodListEntry[] = [
  { pod_name: "node-exporter-def34", pod_namespace: "monitoring", pod_ip: "192.168.50.102", host_network: true, node_name: "worker-2", pod_obj: { metadata: { labels: { app: "node-exporter" } } } },
  { pod_name: "node-exporter-abc12", pod_namespace: "monitoring", pod_ip: "192.168.50.101", host_network: true, node_name: "worker-1", pod_obj: { metadata: { labels: { app: "node-exporter" } } } },
  { pod_name: "db-0", pod_namespace: "prod", pod_ip: "10.0.0.9", host_network: false, node_name: "worker-3", pod_obj: { metadata: { labels: { app: "db" } } } },
];
const serviceTraffic: TrafficRow[] = [
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.20", traffic_in_out_port: "9100", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP" },
];
const resolveService: PeerResolver = async (ip) => {
  const svc = ip === "10.96.0.20" ? { svc_name: "node-exporter", svc_namespace: "monitoring", selector: { app: "node-exporter" } }
    : ip === "10.96.0.10" ? { svc_name: "db", svc_namespace: "prod", selector: { app: "db" } }
    : null;
  if (!svc) return null;
  return hostNetworkServiceIdentity(svc, podList) ?? { selector: svc.selector, namespace: svc.svc_namespace };
};

const hostCases: { name: string; pod: PodInfo; traffic: TrafficRow[]; resolve: PeerResolver }[] = [
  { name: "egress_peer", pod: prometheus, traffic: egressTraffic, resolve: resolveEgress },
  { name: "ingress_peer", pod: webTarget, traffic: ingressTraffic, resolve: resolveIngress },
  { name: "target", pod: nodeExporter, traffic: targetTraffic, resolve: resolveTarget },
  { name: "service_peer", pod: prometheus, traffic: serviceTraffic, resolve: resolveService },
];

for (const tc of hostCases) {
  test(`standard policy — host-network ${tc.name} matches advisor golden (policy + comments)`, async () => {
    const { policy, comments } = await generateNetworkPolicyWithComments(tc.pod, tc.traffic, tc.resolve);
    const text = policyToYAML(policy, comments);
    const file = `standard_hostnetwork_${tc.name}.golden.yaml`;
    assert.deepEqual(parse(text), golden(file));
    assert.deepEqual(commentLines(text), commentLines(goldenText(file)));
  });

  test(`cilium policy — host-network ${tc.name} matches advisor golden (policy + comments)`, async () => {
    const { policy, comments } = await generateCiliumPolicyWithComments(tc.pod, tc.traffic, tc.resolve);
    const text = policyToYAML(policy, comments);
    const file = `cilium_hostnetwork_${tc.name}.golden.yaml`;
    assert.deepEqual(parse(text), golden(file));
    assert.deepEqual(commentLines(text), commentLines(goldenText(file)));
  });
}

test("host_network null/false leaves output byte-identical to the comment-less path", async () => {
  // An old broker (no host_network) and an explicit false must both produce
  // exactly what policyToYAML(policy) produced before comments existed.
  for (const hostNetwork of [null, undefined, false] as const) {
    const pod: PodInfo = { ...web6, hostNetwork };
    for (const gen of [generateNetworkPolicyWithComments, generateCiliumPolicyWithComments]) {
      const { policy, comments } = await gen(pod, dualStackTraffic, noResolve);
      assert.deepEqual(comments, { header: [], ingress: {}, egress: {} });
      assert.equal(policyToYAML(policy, comments), policyToYAML(policy));
    }
  }
});

test("cilium — host-network peers on different ports do not collapse", async () => {
  // Dedup key is the port list: node-exporter:9100 and kubelet:10250 on the
  // same node must stay two entities rules (with one comment each).
  const traffic: TrafficRow[] = [
    { traffic_type: "EGRESS", traffic_in_out_ip: "192.168.50.101", traffic_in_out_port: "9100", ip_protocol: "TCP" },
    { traffic_type: "EGRESS", traffic_in_out_ip: "192.168.50.102", traffic_in_out_port: "10250", ip_protocol: "TCP" },
  ];
  const { policy, comments } = await generateCiliumPolicyWithComments(prometheus, traffic, resolveEgress);
  const egress = (policy.spec as { egress: { toEntities?: string[] }[] }).egress;
  assert.equal(egress.length, 2);
  assert.deepEqual(egress.map((r) => r.toEntities), [["host", "remote-node"], ["host", "remote-node"]]);
  assert.deepEqual(Object.keys(comments.egress), ["0", "1"]);
});

test("hostNetworkServiceIdentity — filters backends like the advisor", () => {
  const svc = { svc_name: "node-exporter", svc_namespace: "monitoring", selector: { app: "node-exporter" } };
  const ne = { app: "node-exporter", extra: "label" };
  const mk = (pod_name: string, pod_namespace: string, node_name: string, labels: Record<string, string>, host_network: boolean, is_dead = false, pod_ip = ""): BrokerPodListEntry =>
    ({ pod_name, pod_namespace, pod_ip, node_name, host_network, is_dead, pod_obj: { metadata: { labels } } });
  const pods = [
    mk("ne-b", "monitoring", "worker-2", ne, true, false, "192.168.50.102"),
    mk("ne-a", "monitoring", "worker-1", ne, true, false, "192.168.50.101"),
    mk("ne-a-same-node", "monitoring", "worker-1", ne, true, false, "192.168.50.101"), // same node IP ⇒ one backend IP
    mk("ne-dead", "monitoring", "worker-9", ne, true, true),
    mk("ne-other-ns", "prod", "worker-8", ne, true),
    mk("ne-plain", "monitoring", "worker-7", ne, false),
    mk("unrelated", "monitoring", "worker-6", { app: "x" }, true),
  ];
  assert.deepEqual(hostNetworkServiceIdentity(svc, pods), {
    hostNetwork: true, namespace: "monitoring", service: "node-exporter", selector: svc.selector,
    node: "worker-1,worker-2", backendIPs: ["192.168.50.101", "192.168.50.102"],
  });
  assert.equal(hostNetworkServiceIdentity(svc, [mk("ne-plain", "monitoring", "w", ne, false)]), null);
  assert.equal(hostNetworkServiceIdentity({ svc_name: "manual", svc_namespace: "monitoring", selector: {} }, pods), null);
  // Unknown nodes ⇒ empty node ⇒ generator falls back to the observed IP.
  assert.equal(hostNetworkServiceIdentity(svc, [mk("ne", "monitoring", "", ne, true)])?.node, "");
});

test("standard — host-network Service peers are the backend node IPs, never the ClusterIP", async () => {
  const { policy } = await generateNetworkPolicyWithComments(prometheus, serviceTraffic, resolveService);
  const egress = (policy.spec as { egress: { to: { ipBlock?: { cidr: string } }[] }[] }).egress;
  assert.deepEqual(egress[1].to.map((p) => p.ipBlock?.cidr), ["192.168.50.101/32", "192.168.50.102/32"]);
  // A host-network Service with no usable backend IP drops its rule rather than pinning the ClusterIP.
  const noIPs: PeerResolver = async () => ({ hostNetwork: true, namespace: "monitoring", service: "x", node: "", backendIPs: ["junk"] });
  const dropped = await generateNetworkPolicyWithComments(prometheus, serviceTraffic, noIPs);
  assert.equal((dropped.policy.spec as { egress?: unknown[] }).egress, undefined);
});
