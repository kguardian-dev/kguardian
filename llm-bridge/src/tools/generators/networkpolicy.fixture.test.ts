import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import {
  generateNetworkPolicy, generateCiliumPolicy, policyToYAML,
  generateNetworkPolicyWithComments, generateCiliumPolicyWithComments, hostNetworkServiceIdentity,
  makePeerResolver, choosePeerCandidate, parseBrokerTime, newestTimeStamp, identityKey, storedPeerOf,
  type PeerResolver, type PeerIdentity, type PodInfo, type TrafficRow, type BrokerPodListEntry, type BrokerServiceRecord, type PeerLookup,
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

// ---- Cross-namespace peers ----------------------------------------------------
// A CiliumNetworkPolicy endpoint selector without a namespace label is scoped
// to the policy's namespace; cross-namespace peers need
// k8s:io.kubernetes.pod.namespace beside their labels. Mirrors advisor
// crossNamespaceFixture; cilium_endpoint_resolved (same-namespace) is unchanged.
const crossNsTraffic: TrafficRow[] = [
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.0.0.30", traffic_in_out_port: "8989", ip_protocol: "TCP" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.50", traffic_in_out_port: "9090", ip_protocol: "TCP" },
  { traffic_type: "INGRESS", pod_port: "8080", traffic_in_out_ip: "10.0.0.40", ip_protocol: "TCP" },
];
const resolveCrossNs: PeerResolver = async (ip) =>
  ip === "10.0.0.30" ? { selector: { app: "sonarr" }, namespace: "downloads" }
  : ip === "10.0.0.40" ? { selector: { app: "maintainerr" }, namespace: "media" }
  : ip === "10.96.0.50" ? { selector: { app: "prometheus" }, namespace: "monitoring" }
  : null;

test("standard policy — cross-namespace peers match advisor golden", async () => {
  const got = await roundtrip(await generateNetworkPolicy(web, crossNsTraffic, resolveCrossNs));
  assert.deepEqual(got, golden("standard_cross_namespace_peer.golden.yaml"));
});

test("cilium policy — cross-namespace peers carry the namespace label (advisor golden)", async () => {
  const got = await roundtrip(await generateCiliumPolicy(web, crossNsTraffic, resolveCrossNs));
  assert.deepEqual(got, golden("cilium_cross_namespace_peer.golden.yaml"));
});

test("cilium policy — unknown peer namespace leaves the selector as before", async () => {
  const noNs: PeerResolver = async () => ({ selector: { app: "sonarr" } });
  const policy = await generateCiliumPolicy(web, [crossNsTraffic[0]], noNs);
  const egress = (policy.spec as { egress: { toEndpoints: { matchLabels: Record<string, string> }[] }[] }).egress;
  assert.deepEqual(egress[0].toEndpoints[0].matchLabels, { "k8s:app": "sonarr" });
});

// ---- Peer attribution: stale IPs and stored identity (CONTRACT v4) ----------
// Pod IPs are recycled; resolving a row's peer IP against today's pod table
// names whoever holds the IP NOW. The resolver is built from in-memory broker
// reads through makePeerResolver — the same code execute.ts wires to the
// broker — so the guard, the precedence and the stored-identity lookup are
// under golden test, not a hand-written identity. Mirrors advisor
// fixture_golden_test.go (TestFixtureGolden_PeerAttribution); inputs in the
// v4 generators handoff.

const cmangos: PodInfo = { name: "cmangos-database", namespace: "game-servers", ip: "10.244.3.17", labels: { app: "cmangos-database" } };

const v4Pod = (pod_name: string, pod_namespace: string, pod_ip: string, labels: Record<string, string>, node_name: string, workload_name: string, started_at: string | null, is_dead: boolean, extra: Partial<BrokerPodListEntry> = {}): BrokerPodListEntry =>
  ({ ...extra, pod_name, pod_namespace, pod_ip, node_name, workload_name, started_at, is_dead, pod_obj: { metadata: { labels, ...(extra.pod_obj?.metadata ?? {}) } } });

function memoryLookup(pods: BrokerPodListEntry[], svcs: Record<string, BrokerServiceRecord> = {}, byIP: Record<string, BrokerPodListEntry> = {}): PeerLookup {
  return {
    serviceByIP: async (ip) => svcs[ip] ?? null,
    podByIP: async (ip) => byIP[ip] ?? null,
    pods: async () => pods,
  };
}

// (a) legacy rows (no peer_*) from 10.244.12.199 dated May and July; the only
// pod known to hold that IP is autobrr, started in August ⇒ unattributed.
const staleIPTraffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "3306", traffic_in_out_ip: "10.244.12.199", traffic_in_out_port: "51234", ip_protocol: "TCP", time_stamp: "2026-05-21T08:30:00" },
  { traffic_type: "INGRESS", pod_port: "3306", traffic_in_out_ip: "10.244.12.199", traffic_in_out_port: "51235", ip_protocol: "TCP", time_stamp: "2026-07-23T10:00:00" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.244.5.8", traffic_in_out_port: "8080", ip_protocol: "TCP", time_stamp: "2026-07-23T10:00:05" },
];
const staleIPPods: BrokerPodListEntry[] = [
  v4Pod("autobrr-7d9c4b8f6-q2x9k", "home-system", "10.244.12.199", { app: "autobrr" }, "worker-2", "autobrr", "2026-08-04T09:12:41", false),
  v4Pod("cmangos-web-0", "game-servers", "10.244.5.8", { app: "cmangos-web" }, "worker-1", "cmangos-web", "2026-07-01T00:00:00", false),
];

// (b) rows the broker resolved at ingest: pod (the CronJob pod that held the
// IP; autobrr holds it NOW with an unknown start, so by-IP would pick it),
// service, and node (host-network pod).
const storedTraffic: TrafficRow[] = [
  { traffic_type: "INGRESS", pod_port: "3306", traffic_in_out_ip: "10.244.12.199", traffic_in_out_port: "51234", ip_protocol: "TCP", time_stamp: "2026-09-03T05:00:00",
    peer_kind: "pod", peer_namespace: "game-servers", peer_name: "cmangos-backup-29271840-x7k2p", peer_uid: "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6",
    peer_workload_kind: "CronJob", peer_workload_name: "cmangos-backup", peer_resolved_at: "2026-09-03T05:00:00.201118" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "10.96.0.10", traffic_in_out_port: "5432", ip_protocol: "TCP", time_stamp: "2026-09-03T05:00:01",
    peer_kind: "service", peer_namespace: "game-servers", peer_name: "db", peer_uid: null, peer_workload_kind: null, peer_workload_name: null, peer_resolved_at: "2026-09-03T05:00:01.100000" },
  { traffic_type: "EGRESS", traffic_in_out_ip: "192.168.50.101", traffic_in_out_port: "9100", ip_protocol: "TCP", time_stamp: "2026-09-03T05:00:02",
    peer_kind: "node", peer_namespace: "monitoring", peer_name: "node-exporter-abc12", peer_uid: "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3",
    peer_workload_kind: "DaemonSet", peer_workload_name: "node-exporter", peer_resolved_at: "2026-09-03T05:00:02.100000" },
];
const storedPods: BrokerPodListEntry[] = [
  v4Pod("autobrr-7d9c4b8f6-q2x9k", "home-system", "10.244.12.199", { app: "autobrr" }, "worker-2", "autobrr", null, false),
  v4Pod("cmangos-backup-29271840-x7k2p", "game-servers", "10.244.12.199", { app: "cmangos-backup" }, "worker-1", "cmangos-backup", "2026-09-03T04:59:30", true,
    { pod_obj: { metadata: { uid: "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6" } } }),
  v4Pod("node-exporter-abc12", "monitoring", "192.168.50.101", { app: "node-exporter" }, "worker-1", "node-exporter", "2026-08-01T00:00:00", false,
    { host_network: true, pod_obj: { metadata: { uid: "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3" } } }),
];
const storedSvcs: Record<string, BrokerServiceRecord> = {
  "10.96.0.10": { svc_name: "db", svc_namespace: "game-servers", service_spec: { spec: { selector: { app: "db" } } } },
};

const attributionCases: { name: string; traffic: TrafficRow[]; lookup: () => PeerLookup }[] = [
  { name: "stale_ip_peer", traffic: staleIPTraffic, lookup: () => memoryLookup(staleIPPods) },
  { name: "stored_peer_identity", traffic: storedTraffic, lookup: () => memoryLookup(storedPods, storedSvcs) },
];

for (const tc of attributionCases) {
  test(`standard policy — ${tc.name} matches advisor golden (policy + comments)`, async () => {
    const { policy, comments } = await generateNetworkPolicyWithComments(cmangos, tc.traffic, makePeerResolver(tc.lookup()));
    const text = policyToYAML(policy, comments);
    const file = `standard_${tc.name}.golden.yaml`;
    assert.deepEqual(parse(text), golden(file));
    assert.deepEqual(commentLines(text), commentLines(goldenText(file)));
  });

  test(`cilium policy — ${tc.name} matches advisor golden (policy + comments)`, async () => {
    const { policy, comments } = await generateCiliumPolicyWithComments(cmangos, tc.traffic, makePeerResolver(tc.lookup()));
    const text = policyToYAML(policy, comments);
    const file = `cilium_${tc.name}.golden.yaml`;
    assert.deepEqual(parse(text), golden(file));
    assert.deepEqual(commentLines(text), commentLines(goldenText(file)));
  });
}

test("parseBrokerTime — naive broker timestamps are UTC, not local", () => {
  assert.equal(parseBrokerTime("2026-07-23T10:00:00"), Date.UTC(2026, 6, 23, 10, 0, 0));
  assert.equal(parseBrokerTime("2026-07-23T10:00:00.123456"), Date.UTC(2026, 6, 23, 10, 0, 0, 123));
  assert.equal(parseBrokerTime("2026-07-23T12:00:00+02:00"), Date.UTC(2026, 6, 23, 10, 0, 0));
  assert.equal(parseBrokerTime("2026-07-23T10:00:00Z"), Date.UTC(2026, 6, 23, 10, 0, 0));
  for (const bad of ["", "  ", "yesterday", "2026-07-23", null, undefined]) assert.equal(parseBrokerTime(bad), null);
});

// A dead record's time_stamp is when it was last seen alive / marked dead.
const v4DeadPod = (pod_name: string, pod_ip: string, started_at: string | null, time_stamp: string | null, labels: Record<string, string> = {}): BrokerPodListEntry =>
  v4Pod(pod_name, "ns", pod_ip, labels, "", "", started_at, true, { time_stamp });

test("choosePeerCandidate — start-time guard and broker precedence", () => {
  const deadOld = v4DeadPod("job-old", "10.0.0.9", "2026-07-01T00:00:00", "2026-08-01T00:00:00");
  const deadNew = v4DeadPod("job-new", "10.0.0.9", "2026-07-20T00:00:00", "2026-08-01T00:00:00");
  const deadUnknown = v4DeadPod("job-unknown", "10.0.0.9", null, "2026-08-01T00:00:00");
  const deadGoneEarly = v4DeadPod("job-gone", "10.0.0.9", "2026-07-21T00:00:00", "2026-07-22T00:00:00");
  const deadNoStamp = v4DeadPod("job-nostamp", "10.0.0.9", "2026-07-01T00:00:00", null);
  const alive = v4Pod("deploy", "ns", "10.0.0.9", {}, "", "", "2026-07-10T00:00:00", false);
  const aliveUnknown = v4Pod("ghost", "ns", "10.0.0.9", {}, "", "", null, false);
  const all = [deadOld, deadNew, deadUnknown, deadGoneEarly, deadNoStamp, aliveUnknown, alive];
  assert.equal(choosePeerCandidate(all, "2026-07-23T10:00:00")?.pod_name, "deploy", "alive with a known start wins");
  assert.equal(choosePeerCandidate([deadOld, deadUnknown, deadNew, deadGoneEarly, deadNoStamp], "2026-07-23T10:00:00")?.pod_name, "job-new", "newest known start among the dead still alive at flow time");
  assert.equal(choosePeerCandidate(all, "2026-07-05T00:00:00")?.pod_name, "job-old", "guard drops later starts and every unknown start");
  assert.equal(choosePeerCandidate([deadUnknown, aliveUnknown], "2026-07-05T00:00:00"), null, "unknown start is never a candidate (ghost/Pending row), alive or not");
  assert.equal(choosePeerCandidate([deadGoneEarly, deadNoStamp], "2026-07-23T10:00:00"), null, "a dead pod gone before the flow, or with no time_stamp, is not a candidate");
  assert.equal(choosePeerCandidate([deadGoneEarly], "2026-07-21T12:00:00")?.pod_name, "job-gone", "…but it is for a flow while it lived");
  assert.equal(choosePeerCandidate([deadGoneEarly], "2026-07-22T00:00:00")?.pod_name, "job-gone", "last seen exactly at the flow ⇒ eligible");
  assert.equal(choosePeerCandidate([deadNew, alive], "2026-06-01T00:00:00"), null, "every candidate started later ⇒ unattributed");
  assert.equal(choosePeerCandidate(all, "")?.pod_name, "deploy", "no flow time ⇒ no guard");
  assert.equal(choosePeerCandidate([deadOld, aliveUnknown], "")?.pod_name, "ghost", "no flow time ⇒ alive still preferred");
  assert.equal(choosePeerCandidate([alive], "2026-07-10T00:00:00")?.pod_name, "deploy", "equal is not later");
});

test("makePeerResolver — a completed Job pod does not absorb later flows on its recycled IP", async () => {
  const job = v4DeadPod("backup-1", "10.0.0.9", "2026-07-01T00:00:00", "2026-07-01T00:05:00", { app: "backup" });
  const resolve = makePeerResolver(memoryLookup([job]));
  assert.deepEqual(await resolve("10.0.0.9", { peer: null, timeStamp: "2026-07-23T10:00:00" }), { unattributed: true });
  assert.deepEqual(await resolve("10.0.0.9", { peer: null, timeStamp: "2026-07-01T00:02:00" }), { selector: { app: "backup" }, namespace: "ns" });
});

test("makePeerResolver — a ghost row with unknown started_at is unattributed, not the peer", async () => {
  const ghost = v4Pod("ghost", "ns", "10.0.0.9", { app: "ghost" }, "", "", null, false);
  const resolve = makePeerResolver(memoryLookup([ghost]));
  assert.deepEqual(await resolve("10.0.0.9", { peer: null, timeStamp: "2026-07-23T10:00:00" }), { unattributed: true });
});

test("makePeerResolver — guarded-out is unattributed, external is a plain CIDR, stored wins", async () => {
  const autobrr = v4Pod("autobrr", "home-system", "10.244.12.199", { app: "autobrr" }, "w", "autobrr", "2026-08-04T09:12:41", false);
  const resolve = makePeerResolver(memoryLookup([autobrr]));
  const stale = await resolve("10.244.12.199", { peer: null, timeStamp: "2026-07-23T10:00:00" });
  assert.deepEqual(stale, { unattributed: true });
  assert.equal(identityKey(stale), "unattributed");
  const fresh = await resolve("10.244.12.199", { peer: null, timeStamp: "2026-08-05T00:00:00" });
  assert.deepEqual(fresh, { selector: { app: "autobrr" }, namespace: "home-system" });
  assert.equal(identityKey(fresh), "sel:home-system:app=autobrr");
  assert.equal(await resolve("8.8.8.8", { peer: null, timeStamp: "2026-07-23T10:00:00" }), null);
  assert.equal(identityKey(null), "cidr");

  // A stored identity is materialised from the listing, never re-resolved by IP.
  const stored = storedPeerOf({ peer_kind: "pod", peer_namespace: "game-servers", peer_name: "gone", peer_uid: "" });
  assert.deepEqual(await resolve("10.244.12.199", { peer: stored, timeStamp: "2026-09-03T05:00:00" }), { unattributed: true });
  assert.equal(storedPeerOf({ peer_kind: null }), null);
});

test("makePeerResolver — candidates union the listing and the by-IP record", async () => {
  const older = v4Pod("job-1", "prod", "10.0.0.7", { app: "job" }, "", "", "2026-07-01T00:00:00", true, { time_stamp: "2026-08-01T00:00:00" });
  const viaIP = v4Pod("frontend-1", "prod", "10.0.0.7", { app: "frontend" }, "", "", "2026-08-04T00:00:00", false);
  const resolve = makePeerResolver(memoryLookup([older], {}, { "10.0.0.7": viaIP }));
  assert.deepEqual(await resolve("10.0.0.7", { peer: null, timeStamp: "2026-07-15T00:00:00" }), { selector: { app: "job" }, namespace: "prod" });
  assert.deepEqual(await resolve("10.0.0.7", { peer: null, timeStamp: "" }), { selector: { app: "frontend" }, namespace: "prod" });
});

test("same IP, two stored identities ⇒ two rules ordered by identity key", async () => {
  const jobA = v4Pod("job-a", "batch", "10.0.0.5", { app: "a" }, "", "", "2026-07-01T00:00:00", true);
  const jobB = v4Pod("job-b", "batch", "10.0.0.5", { app: "b" }, "", "", "2026-07-02T00:00:00", true);
  const stored = (time_stamp: string, peer_name: string, traffic_in_out_port: string): TrafficRow =>
    ({ traffic_type: "INGRESS", pod_port: "80", traffic_in_out_ip: "10.0.0.5", traffic_in_out_port, ip_protocol: "TCP", time_stamp, peer_kind: "pod", peer_namespace: "batch", peer_name });
  const traffic: TrafficRow[] = [
    stored("2026-07-02T01:00:00", "job-b", "1"),
    stored("2026-07-01T01:00:00", "job-a", "2"),
    { traffic_type: "INGRESS", pod_port: "80", traffic_in_out_ip: "10.0.0.10", traffic_in_out_port: "3", ip_protocol: "TCP", time_stamp: "2026-07-01T01:00:00" },
    stored("2026-07-02T02:00:00", "job-b", "4"),
  ];
  const { policy } = await generateNetworkPolicyWithComments(web, traffic, makePeerResolver(memoryLookup([jobA, jobB])));
  const ingress = (policy.spec as { ingress: { from: { ipBlock?: { cidr: string }; podSelector?: { matchLabels: Record<string, string> } }[] }[] }).ingress;
  assert.deepEqual(ingress.map((r) => r.from[0].ipBlock?.cidr ?? r.from[0].podSelector?.matchLabels), [
    "10.0.0.10/32", { app: "a" }, { app: "b" },
  ]);
});

test("unattributed comment quotes the newest row time_stamp verbatim, or none", async () => {
  assert.equal(newestTimeStamp(["2026-05-21T08:30:00", "2026-07-23T10:00:00", "junk"]), "2026-07-23T10:00:00");
  assert.equal(newestTimeStamp(["junk", ""]), "");
  const unattributed: PeerResolver = async () => ({ unattributed: true });
  const rows: TrafficRow[] = [{ traffic_type: "INGRESS", pod_port: "3306", traffic_in_out_ip: "10.244.12.199", ip_protocol: "TCP" }];
  const { policy, comments } = await generateCiliumPolicyWithComments(cmangos, rows, unattributed);
  assert.deepEqual(comments.ingress, { 0: ["unattributed peer 10.244.12.199"] });
  const ingress = (policy.spec as { ingress: { fromCIDR?: string[]; fromEndpoints?: unknown }[] }).ingress;
  assert.deepEqual(ingress[0].fromCIDR, ["10.244.12.199/32"]);
  assert.equal(ingress[0].fromEndpoints, undefined);
});
