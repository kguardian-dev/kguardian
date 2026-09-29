import { describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import type { PodInfo, PodNodeData } from '../types';

// G2 generator parity — network policy, frontend consumer side.
//
// The advisor (Go) and llm-bridge (TS) generators are proven against the
// shared goldens in test/fixtures/generators/networkpolicy as whole
// documents. The frontend generator has never claimed whole-document parity
// (its metadata name and labels, Cilium `k8s:` prefixing, defaultDeny shape
// and same-namespace namespaceSelector omission all predate this suite), so
// this pins the part that must not drift: the RULES — which peer shape is
// emitted for a host-network peer, with which ports — and the comment lines,
// which the other two suites cannot see because yaml.parse strips them.
//
// Scenarios mirror advisor/pkg/network/fixture_golden_test.go
// (TestFixtureGolden_HostNetwork):
//   (a) egress_peer: prometheus scrapes node-exporter on two nodes plus an
//       external ClusterIP → one ipBlock rule PER NODE IP (standard), ONE
//       toEntities rule carrying both peers' comments (Cilium)
//   (b) ingress_peer: web receives from a same-namespace pod and from a
//       host-network ingress-nginx controller → ipBlock / fromEntities
//   (c) target: node-exporter itself is host-network → normal body + WARNING
//   (d) host_network null (old broker) → legacy podSelector, no comments
//   (f) cross_namespace_peer: peers in other namespaces → standard adds a
//       namespaceSelector (unchanged); Cilium adds
//       k8s:io.kubernetes.pod.namespace to the endpoint selector (the bug fix)
//   (e) service_peer: a ClusterIP whose backing pods are host-network →
//       one ipBlock per backend node IP (NP) / toEntities, comment names <ns>/svc/<name>
//       and lists the backends' nodes

const goldensDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/fixtures/generators/networkpolicy',
);
const goldenText = (f: string) => fs.readFileSync(path.join(goldensDir, f), 'utf8');
const golden = (f: string) => parse(goldenText(f)) as Record<string, unknown>;

// --- broker stand-in ------------------------------------------------------

// The broker's /pod/info listing keeps pod_obj.metadata.labels (compacted);
// Service backends are matched on those, as the advisor does — so every
// record carries them, mirroring its selector labels.
const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default',
  time_stamp: '2026-09-03T00:00:00',
  // v4: a pod with no known start is never a by-IP candidate.
  started_at: '2026-01-01T00:00:00',
  node_name: 'worker-0',
  is_dead: false,
  pod_obj: { metadata: { labels: p.workload_selector_labels ?? {} } },
  ...p,
});

const podsByIp: Record<string, PodInfo> = {
  '192.168.50.101': podRecord({
    pod_name: 'node-exporter-abc12', pod_ip: '192.168.50.101', pod_namespace: 'monitoring', node_name: 'worker-1',
    workload_kind: 'DaemonSet', workload_name: 'node-exporter',
    workload_selector_labels: { app: 'node-exporter' }, host_network: true,
  }),
  '192.168.50.102': podRecord({
    pod_name: 'node-exporter-def34', pod_ip: '192.168.50.102', pod_namespace: 'monitoring', node_name: 'worker-2',
    workload_kind: 'DaemonSet', workload_name: 'node-exporter',
    workload_selector_labels: { app: 'node-exporter' }, host_network: true,
  }),
  '10.0.0.7': podRecord({
    pod_name: 'frontend-0', pod_ip: '10.0.0.7', pod_namespace: 'prod', node_name: 'worker-2',
    workload_name: 'frontend', workload_selector_labels: { app: 'frontend' }, host_network: false,
  }),
  '10.0.0.5': podRecord({
    pod_name: 'prometheus', pod_ip: '10.0.0.5', pod_namespace: 'monitoring', node_name: 'worker-3',
    workload_name: 'prometheus', workload_selector_labels: { app: 'prometheus' }, host_network: false,
  }),
  // (f) cross-namespace pod peers of prod/web
  '10.0.0.30': podRecord({
    pod_name: 'sonarr-0', pod_ip: '10.0.0.30', pod_namespace: 'downloads', node_name: 'worker-2',
    workload_name: 'sonarr', workload_selector_labels: { app: 'sonarr' }, host_network: false,
  }),
  '10.0.0.41': podRecord({
    pod_name: 'maintainerr-0', pod_ip: '10.0.0.41', pod_namespace: 'media', node_name: 'worker-2',
    workload_name: 'maintainerr', workload_selector_labels: { app: 'maintainerr' }, host_network: false,
  }),
  // (j) a kube-dns backend: its name is not the Service's, and its labels
  // carry more than the Service's selector does.
  '10.0.0.53': podRecord({
    pod_name: 'coredns-5d78c9869d-abcde', pod_ip: '10.0.0.53', pod_namespace: 'kube-system', node_name: 'worker-1',
    workload_name: 'coredns', workload_selector_labels: { 'k8s-app': 'kube-dns', 'pod-template-hash': '5d78c9869d' }, host_network: false,
  }),
  // (d) legacy row: host_network unknown
  '10.0.0.40': podRecord({
    pod_name: 'legacy-abc', pod_ip: '10.0.0.40', pod_namespace: 'prod',
    workload_selector_labels: { app: 'legacy' }, host_network: null,
  }),
};
const podsByName = Object.fromEntries(Object.values(podsByIp).map((p) => [p.pod_name, p]));

// The ingress-nginx host-network peer is served by a DIFFERENT record on the
// by-IP route (host_network true) in scenario (b) than node-exporter in (a),
// but both sit on 192.168.50.101. Swap the by-IP table per scenario.
const ingressNginx = podRecord({
  pod_name: 'ingress-nginx-controller-abc12', pod_ip: '192.168.50.101', pod_namespace: 'ingress-nginx', node_name: 'worker-1',
  workload_kind: 'DaemonSet', workload_name: 'ingress-nginx-controller',
  workload_selector_labels: { 'app.kubernetes.io/name': 'ingress-nginx' }, host_network: true,
});
let byIp: Record<string, PodInfo> = podsByIp;
let byName: Record<string, PodInfo> = podsByName;
const useIngressNginx = () => {
  byIp = { ...podsByIp, '192.168.50.101': ingressNginx };
  byName = { ...podsByName, [ingressNginx.pod_name]: ingressNginx };
};
const useDefaults = () => { byIp = podsByIp; byName = podsByName; serviceLookup = {}; };

// (e) Services: node-exporter ClusterIP fronting the two host-network pods
// above; db ClusterIP fronting an ordinary pod-network deployment. Every
// Service lists its ports (targetPort omitted = the port, as the advisor's
// fixtureSvcPorts): with none, an observed port cannot be mapped to a
// targetPort and the rule gains a comment (service_target_port covers that).
const tcp = (...ports: number[]) => ports.map((port) => ({ port, protocol: 'TCP' }));
const services: Record<string, unknown> = {
  '10.96.0.20': { svc_name: 'node-exporter', svc_namespace: 'monitoring', svc_ip: '10.96.0.20',
    service_spec: { spec: { selector: { app: 'node-exporter' }, ports: tcp(9100) } } },
  '10.96.0.10': { svc_name: 'db', svc_namespace: 'prod', svc_ip: '10.96.0.10',
    service_spec: { spec: { selector: { app: 'db' }, ports: tcp(5432) } } },
  // (f) cross-namespace Service peer of prod/web
  '10.96.0.50': { svc_name: 'prometheus', svc_namespace: 'monitoring', svc_ip: '10.96.0.50',
    service_spec: { spec: { selector: { app: 'prometheus' }, ports: tcp(9090) } } },
  // (j) Services whose selector is not `{app: <name>}`: kube-dns selects
  // `k8s-app: kube-dns`, and grafana (same namespace as prometheus) selects
  // on the recommended labels.
  '10.96.0.53': { svc_name: 'kube-dns', svc_namespace: 'kube-system', svc_ip: '10.96.0.53',
    service_spec: { spec: { selector: { 'k8s-app': 'kube-dns' }, ports: [{ port: 53, protocol: 'UDP' }, { port: 53, protocol: 'TCP' }] } } },
  '10.96.0.30': { svc_name: 'grafana', svc_namespace: 'monitoring', svc_ip: '10.96.0.30',
    service_spec: { spec: { selector: { 'app.kubernetes.io/name': 'grafana', 'app.kubernetes.io/instance': 'obs' }, ports: tcp(3000) } } },
};
let serviceLookup: Record<string, unknown> = {};
const useServices = () => { serviceLookup = services; };

vi.mock('../services/api', () => ({
  apiClient: {
    getServiceByIP: vi.fn(async (ip: string) => serviceLookup[ip] ?? null),
    getAllPods: vi.fn(async () => Object.values(byIp)),
    getPodDetailsByIP: vi.fn(async (ip: string) => byIp[ip] ?? null),
    getPodDetailsByName: vi.fn(async (name: string) => byName[name] ?? null),
  },
}));

import { generateNetworkPolicy, policyToYAML } from './networkPolicyGenerator';
import { generateCiliumNetworkPolicy, ciliumPolicyToYAML } from './ciliumPolicyGenerator';

// --- scenarios ------------------------------------------------------------

const target = (pod: Partial<PodInfo> & { pod_name: string; pod_ip: string }, traffic: unknown[]): PodNodeData => {
  const p = podRecord(pod);
  return { id: p.pod_name, label: p.pod_name, pod: p, pods: [p], traffic, isExpanded: false } as PodNodeData;
};
const ingressRow = (ip: string, port: string) => ({ traffic_type: 'INGRESS', pod_port: port, traffic_in_out_ip: ip, ip_protocol: 'TCP', time_stamp: '2026-09-03T00:00:00' });
const egressRow = (ip: string, port: string) => ({ traffic_type: 'EGRESS', traffic_in_out_ip: ip, traffic_in_out_port: port, ip_protocol: 'TCP', time_stamp: '2026-09-03T00:00:00' });

const prometheus = { pod_name: 'prometheus', pod_ip: '10.0.0.5', pod_namespace: 'monitoring', node_name: 'worker-3',
  workload_name: 'prometheus', workload_selector_labels: { app: 'prometheus' }, host_network: false };
const web = { pod_name: 'web', pod_ip: '10.0.0.1', pod_namespace: 'prod', node_name: 'worker-3',
  workload_name: 'web', workload_selector_labels: { app: 'web' }, host_network: false };

const egressPeer = target(prometheus, [
  egressRow('10.96.0.10', '5432'),
  egressRow('192.168.50.101', '9100'),
  egressRow('192.168.50.102', '9100'),
]);
const ingressPeer = target(web, [ingressRow('10.0.0.7', '8080'), ingressRow('192.168.50.101', '8080')]);
const hostnetTarget = target(
  { pod_name: 'node-exporter-abc12', pod_ip: '192.168.50.101', pod_namespace: 'monitoring', node_name: 'worker-1',
    workload_kind: 'DaemonSet', workload_name: 'node-exporter',
    workload_selector_labels: { app: 'node-exporter' }, host_network: true },
  [ingressRow('10.0.0.5', '9100')],
);
const legacyPeer = target(web, [egressRow('10.0.0.40', '5432')]);
// (e) prometheus scrapes node-exporter via its ClusterIP and talks to db via its ClusterIP.
const servicePeer = target(prometheus, [egressRow('10.96.0.20', '9100'), egressRow('10.96.0.10', '5432')]);
// (f) prod/web talks to pods and a Service in OTHER namespaces, and is called from one.
const crossNamespace = target(web, [
  egressRow('10.0.0.30', '8989'),
  egressRow('10.96.0.50', '9090'),
  ingressRow('10.0.0.41', '8080'),
]);

const commentLines = (yaml: string) => yaml.split('\n').filter((l) => l.trimStart().startsWith('#'));

// --- normalisation for cross-generator comparison -------------------------

type Rule = Record<string, unknown>;
const portKey = (p: Record<string, unknown>) => `${p.protocol}:${p.port}`;

/** Strip the Cilium `k8s:` label prefix so advisor/llm-bridge output compares to ours. */
const unprefix = (labels: Record<string, string>) =>
  Object.fromEntries(Object.entries(labels).map(([k, v]) => [k.replace(/^k8s:/, ''), v]));

/**
 * Advisor/llm-bridge always attach a namespaceSelector to a pod peer; the
 * frontend omits it for the target's own namespace (a long-standing,
 * semantically equivalent difference). Drop that one case on both sides.
 */
function normaliseStandardRules(rules: unknown, targetNs: string): Rule[] {
  return ((rules as Rule[] | undefined) ?? [])
    .map((r) => {
      const out: Rule = { ...r };
      for (const key of ['from', 'to']) {
        if (!Array.isArray(out[key])) continue;
        out[key] = (out[key] as Rule[]).map((peer) => {
          const ns = peer.namespaceSelector as { matchLabels?: Record<string, string> } | undefined;
          if (ns?.matchLabels?.['kubernetes.io/metadata.name'] === targetNs) {
            const { namespaceSelector: _drop, ...rest } = peer;
            void _drop;
            return rest;
          }
          return peer;
        });
      }
      out.ports = [...((r.ports as Record<string, unknown>[]) ?? [])].sort((a, b) => portKey(a).localeCompare(portKey(b)));
      return out;
    });
}

function normaliseCiliumRules(rules: unknown): Rule[] {
  return ((rules as Rule[] | undefined) ?? [])
    .map((r) => {
      const out: Rule = { ...r };
      for (const key of ['fromEndpoints', 'toEndpoints']) {
        if (Array.isArray(out[key])) {
          out[key] = (out[key] as { matchLabels: Record<string, string> }[]).map((ep) => ({ matchLabels: unprefix(ep.matchLabels) }));
        }
      }
      // The frontend holds a rule's ports in ONE PortRule, the reference emits
      // one PortRule per port; Cilium ORs both the same way, so compare the
      // flattened, sorted port list.
      if (Array.isArray(out.toPorts)) {
        out.toPorts = [{
          ports: (out.toPorts as { ports: Record<string, unknown>[] }[])
            .flatMap((pr) => pr.ports)
            .sort((a, b) => portKey(a).localeCompare(portKey(b))),
        }];
      }
      return out;
    });
}

const spec = (doc: Record<string, unknown>) => doc.spec as Record<string, unknown>;

// --- standard NetworkPolicy ----------------------------------------------

describe('generateNetworkPolicy — host-network peers', () => {
  test('(a) egress: one ipBlock rule per node IP, comment above each, no selectors', async () => {
    useDefaults();
    const policy = await generateNetworkPolicy(egressPeer);
    const yaml = policyToYAML(policy);
    const doc = parse(yaml);
    expect(normaliseStandardRules(spec(doc).egress, 'monitoring')).toEqual(
      normaliseStandardRules(spec(golden('standard_hostnetwork_egress_peer.golden.yaml')).egress, 'monitoring'),
    );
    expect(spec(doc).policyTypes).toEqual(['Egress']);
    // The only podSelector in the document is the target's; no namespaceSelector at all.
    expect(yaml.match(/podSelector:/g)).toHaveLength(1);
    expect(yaml).not.toContain('namespaceSelector');
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('standard_hostnetwork_egress_peer.golden.yaml')));
    // Each comment sits directly above the rule it explains.
    const lines = yaml.split('\n');
    for (const c of commentLines(yaml)) expect(lines[lines.indexOf(c) + 1]).toBe('  - to:');
    expect(policy.warnings).toBeUndefined();
  });

  test('(b) ingress from a host-network peer: ipBlock alongside the normal pod peer', async () => {
    useIngressNginx();
    const policy = await generateNetworkPolicy(ingressPeer);
    const yaml = policyToYAML(policy);
    expect(normaliseStandardRules(spec(parse(yaml)).ingress, 'prod')).toEqual(
      normaliseStandardRules(spec(golden('standard_hostnetwork_ingress_peer.golden.yaml')).ingress, 'prod'),
    );
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('standard_hostnetwork_ingress_peer.golden.yaml')));
  });

  test('(c) host-network target: body unchanged, leading WARNING block byte-identical to the golden', async () => {
    useDefaults();
    const policy = await generateNetworkPolicy(hostnetTarget);
    const yaml = policyToYAML(policy);
    const want = goldenText('standard_hostnetwork_target.golden.yaml');
    expect(yaml.split('\n').slice(0, 3)).toEqual(want.split('\n').slice(0, 3));
    expect(yaml.split('\n')[3]).toBe('apiVersion: networking.k8s.io/v1');
    const doc = parse(yaml);
    expect(spec(doc).podSelector).toEqual(spec(golden('standard_hostnetwork_target.golden.yaml')).podSelector);
    expect(normaliseStandardRules(spec(doc).ingress, 'monitoring')).toEqual(
      normaliseStandardRules(spec(golden('standard_hostnetwork_target.golden.yaml')).ingress, 'monitoring'),
    );
  });

  test('(e) Service backed by host-network pods: one ipBlock per backend node IP, <ns>/svc/<name> comment', async () => {
    useDefaults();
    useServices();
    const yaml = policyToYAML(await generateNetworkPolicy(servicePeer));
    expect(normaliseStandardRules(spec(parse(yaml)).egress, 'monitoring')).toEqual(
      normaliseStandardRules(spec(golden('standard_hostnetwork_service_peer.golden.yaml')).egress, 'monitoring'),
    );
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('standard_hostnetwork_service_peer.golden.yaml')));
    expect(commentLines(yaml)[0]).toContain('monitoring/svc/node-exporter on node worker-1,worker-2');
    // Post-DNAT: the ClusterIP never appears on the wire, so it is never pinned.
    expect(yaml).not.toContain('10.96.0.20');
  });

  test('(f) cross-namespace peers: namespaceSelector on each, matches golden', async () => {
    useDefaults();
    useServices();
    const doc = parse(policyToYAML(await generateNetworkPolicy(crossNamespace)));
    const want = golden('standard_cross_namespace_peer.golden.yaml');
    // Every peer is cross-namespace here, so no namespaceSelector is dropped by the normaliser.
    expect(normaliseStandardRules(spec(doc).egress, 'prod')).toEqual(normaliseStandardRules(spec(want).egress, 'prod'));
    expect(normaliseStandardRules(spec(doc).ingress, 'prod')).toEqual(normaliseStandardRules(spec(want).ingress, 'prod'));
    expect(spec(doc).policyTypes).toEqual(spec(want).policyTypes);
  });

  test('(d) host_network null (old broker): legacy podSelector rendering, no comments', async () => {
    useDefaults();
    const policy = await generateNetworkPolicy(legacyPeer);
    const yaml = policyToYAML(policy);
    expect(parse(yaml).spec.egress[0].to).toEqual([{ podSelector: { matchLabels: { app: 'legacy' } } }]);
    expect(yaml).not.toContain('#');
    expect(policy.warnings).toBeUndefined();
  });
});

// --- CiliumNetworkPolicy -------------------------------------------------

describe('generateCiliumNetworkPolicy — host-network peers', () => {
  test('(a) egress: ONE toEntities rule for both node peers, both comments above it', async () => {
    useDefaults();
    const policy = await generateCiliumNetworkPolicy(egressPeer);
    const yaml = ciliumPolicyToYAML(policy);
    const doc = parse(yaml);
    expect(normaliseCiliumRules(spec(doc).egress)).toEqual(
      normaliseCiliumRules(spec(golden('cilium_hostnetwork_egress_peer.golden.yaml')).egress),
    );
    expect(yaml).not.toContain('toEndpoints');
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('cilium_hostnetwork_egress_peer.golden.yaml')));
    const lines = yaml.split('\n');
    const last = commentLines(yaml).at(-1)!;
    expect(lines[lines.indexOf(last) + 1]).toBe('  -');
    expect(lines[lines.indexOf(last) + 2]).toBe('    toEntities:');
  });

  test('(a2) host-network peers with DIFFERENT port lists get one entities rule each', async () => {
    useDefaults();
    const twoPortSets = target(prometheus, [
      egressRow('192.168.50.101', '9100'),
      egressRow('192.168.50.102', '9100'),
      egressRow('192.168.50.102', '10250'),
    ]);
    const doc = parse(ciliumPolicyToYAML(await generateCiliumNetworkPolicy(twoPortSets)));
    const egress = spec(doc).egress as Rule[];
    expect(egress).toHaveLength(2);
    expect(egress.every((r) => JSON.stringify(r.toEntities) === '["host","remote-node"]')).toBe(true);
    expect(egress.map((r) => (r.toPorts as { ports: { port: string }[] }[])[0].ports.map((p) => p.port))).toEqual([
      ['9100'],
      ['9100', '10250'],
    ]);
  });

  test('(b) ingress from a host-network peer: fromEntities alongside fromEndpoints', async () => {
    useIngressNginx();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(ingressPeer));
    expect(normaliseCiliumRules(spec(parse(yaml)).ingress)).toEqual(
      normaliseCiliumRules(spec(golden('cilium_hostnetwork_ingress_peer.golden.yaml')).ingress),
    );
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('cilium_hostnetwork_ingress_peer.golden.yaml')));
  });

  test('(c) host-network target: leading WARNING block byte-identical to the golden', async () => {
    useDefaults();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(hostnetTarget));
    const want = goldenText('cilium_hostnetwork_target.golden.yaml');
    expect(yaml.split('\n').slice(0, 3)).toEqual(want.split('\n').slice(0, 3));
    expect(yaml.split('\n')[3]).toBe('apiVersion: cilium.io/v2');
    const got = parse(yaml);
    const wantDoc = golden('cilium_hostnetwork_target.golden.yaml');
    expect(normaliseCiliumRules(spec(got).ingress)).toEqual(normaliseCiliumRules(spec(wantDoc).ingress));
    expect(unprefix((spec(got).endpointSelector as { matchLabels: Record<string, string> }).matchLabels))
      .toEqual(unprefix((spec(wantDoc).endpointSelector as { matchLabels: Record<string, string> }).matchLabels));
  });

  test('(e) Service backed by host-network pods: toEntities, <ns>/svc/<name> comment', async () => {
    useDefaults();
    useServices();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(servicePeer));
    expect(normaliseCiliumRules(spec(parse(yaml)).egress)).toEqual(
      normaliseCiliumRules(spec(golden('cilium_hostnetwork_service_peer.golden.yaml')).egress),
    );
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('cilium_hostnetwork_service_peer.golden.yaml')));
  });

  test('(f) cross-namespace peers: k8s:io.kubernetes.pod.namespace on every endpoint selector, byte-exact key', async () => {
    useDefaults();
    useServices();
    const doc = parse(ciliumPolicyToYAML(await generateCiliumNetworkPolicy(crossNamespace)));
    const want = golden('cilium_cross_namespace_peer.golden.yaml');
    expect(normaliseCiliumRules(spec(doc).egress)).toEqual(normaliseCiliumRules(spec(want).egress));
    expect(normaliseCiliumRules(spec(doc).ingress)).toEqual(normaliseCiliumRules(spec(want).ingress));
    // The namespace label itself must be the exact Cilium key — not stripped
    // by the k8s: normalisation above.
    const namespaces = (dir: unknown, key: string) =>
      ((dir as Rule[]).flatMap((r) => (r[key] as { matchLabels: Record<string, string> }[]) ?? []))
        .map((ep) => ep.matchLabels['k8s:io.kubernetes.pod.namespace']);
    expect(namespaces(spec(doc).egress, 'toEndpoints')).toEqual(['downloads', 'monitoring']);
    expect(namespaces(spec(doc).ingress, 'fromEndpoints')).toEqual(['media']);
    expect(namespaces(spec(want).egress, 'toEndpoints')).toEqual(['downloads', 'monitoring']);
  });

  test('(f2) same-namespace peer stays a bare selector (no namespace label)', async () => {
    useDefaults();
    const doc = parse(ciliumPolicyToYAML(await generateCiliumNetworkPolicy(hostnetTarget)));
    expect((spec(doc).ingress as Rule[])[0].fromEndpoints).toEqual([{ matchLabels: { app: 'prometheus' } }]);
  });

  test('(d) host_network null: legacy toEndpoints, no comments', async () => {
    useDefaults();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(legacyPeer));
    expect(parse(yaml).spec.egress[0].toEndpoints).toEqual([{ matchLabels: { app: 'legacy' } }]);
    expect(yaml).not.toContain('#');
  });
});

// --- no traffic, selector-less Services, supplied listings ----------------

import { apiClient } from '../services/api';
import type { ServiceInfo } from '../types';

const ruleComments = (yaml: string) => commentLines(yaml).map((l) => l.trim());

// (g) no traffic: the reference generators emit an explicit deny-all
// (standard_default_deny / cilium_default_deny). Left implicit, the API
// server defaults policyTypes to [Ingress] and the document denies ingress
// without saying so.
const idle = target(
  { pod_name: 'idle', pod_ip: '10.0.0.99', pod_namespace: 'prod', workload_name: 'idle',
    workload_selector_labels: { app: 'idle' }, host_network: false },
  [],
);

// (h) Services with no `spec.selector`: the API server's own Service, and an
// aggregated API served by manually managed Endpoints. Neither has backend
// labels to select, and both ClusterIPs are gone from the wire after DNAT.
const kubeApi = { svc_name: 'kubernetes', svc_namespace: 'default', svc_ip: '10.96.0.1',
  service_spec: { spec: { clusterIP: '10.96.0.1', ports: [{ port: 443, protocol: 'TCP' }], type: 'ClusterIP' } } };
const metricsApi = { svc_name: 'metrics-api', svc_namespace: 'kube-system', svc_ip: '10.96.0.77', service_spec: { spec: {} } };
// Selector `{}` is selector-less too; a missing spec is UNKNOWN (`service_spec`
// is nullable on the broker), which must not be reported as "has no selector".
const emptySelector = { svc_name: 'ext', svc_namespace: 'db', svc_ip: '10.96.0.90', service_spec: { spec: { selector: {} } } };
const unknownSpec = { svc_name: 'pg', svc_namespace: 'db', svc_ip: '10.96.0.88' };
const emptyManifest = { svc_name: 'pg2', svc_namespace: 'db', svc_ip: '10.96.0.89', service_spec: {} };
const useSelectorlessServices = () => {
  serviceLookup = { ...services, '10.96.0.1': kubeApi, '10.96.0.77': metricsApi, '10.96.0.90': emptySelector, '10.96.0.88': unknownSpec, '10.96.0.89': emptyManifest };
};

// Cilium's CRD accepts a spec only with at least one of these sections.
const expectCnpShape = (doc: Record<string, unknown>) => {
  const s = spec(doc);
  expect(['ingress', 'ingressDeny', 'egress', 'egressDeny'].some((k) => k in s)).toBe(true);
};
const storedKubeApi = { peer_kind: 'service', peer_namespace: 'default', peer_name: 'kubernetes' };

const KUBE_API_IPBLOCK = '# Service default/kubernetes has no selector — ipBlock 10.96.0.1 is its ClusterIP and will not match after DNAT';
const KUBE_API_ENTITY = '# Service default/kubernetes has no selector — kube-apiserver entity covers its endpoints';
const METRICS_API_CIDR = '# Service kube-system/metrics-api has no selector — cidr 10.96.0.77 is its ClusterIP and will not match after DNAT';
// By IP, a Service whose spec was never stored: still an unattributed peer
// rule (as the stored path renders it), saying what the address is.
const PG_UNKNOWN_SELECTOR =
  "# unattributed peer 10.96.0.88 at 2026-09-03T00:00:00 — ClusterIP of Service db/pg, selector unknown: will not match after DNAT; replace with the Service's selector";

describe('generateNetworkPolicy — no traffic and selector-less Services', () => {
  test('(g) no traffic: explicit policyTypes Ingress+Egress and no rules, as the default_deny golden', async () => {
    useDefaults();
    const policy = await generateNetworkPolicy(idle);
    const yaml = policyToYAML(policy);
    const doc = parse(yaml);
    expect(spec(doc).policyTypes).toEqual(spec(golden('standard_default_deny.golden.yaml')).policyTypes);
    expect(spec(doc).ingress).toBeUndefined();
    expect(spec(doc).egress).toBeUndefined();
    expect(yaml).toContain('  policyTypes:\n  - Ingress\n  - Egress');
  });

  test('(h) stored selector-less Service peer keeps its name: ClusterIP ipBlock with the DNAT note, never unattributed', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [
      { ...egressRow('10.96.0.1', '443'), ...storedKubeApi },
    ])));
    expect(spec(parse(yaml)).egress).toEqual([
      { to: [{ ipBlock: { cidr: '10.96.0.1/32' } }], ports: [{ protocol: 'TCP', port: 443 }] },
    ]);
    expect(ruleComments(yaml)).toEqual([KUBE_API_IPBLOCK]);
    expect(yaml).not.toContain('unattributed');
    expect(yaml).not.toContain('app: kubernetes');
  });

  test('(h2) by-IP selector-less Service (no stored peer): the same ipBlock, not a guessed {app: <svc>} selector', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [egressRow('10.96.0.1', '443')])));
    expect(spec(parse(yaml)).egress).toEqual([
      { to: [{ ipBlock: { cidr: '10.96.0.1/32' } }], ports: [{ protocol: 'TCP', port: 443 }] },
    ]);
    expect(ruleComments(yaml)).toEqual([KUBE_API_IPBLOCK]);
    expect(yaml).not.toContain('podSelector:\n        matchLabels:\n          app: kubernetes');
  });

  test('(h3) ingress from the API server (webhook / aggregated API) renders the same way', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = policyToYAML(await generateNetworkPolicy(target(web, [
      { ...ingressRow('10.96.0.1', '8443'), ...storedKubeApi },
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.96.0.1/32' } }], ports: [{ protocol: 'TCP', port: 8443 }] },
    ]);
    expect(ruleComments(yaml)).toEqual([KUBE_API_IPBLOCK]);
  });

  test('(h5) selector `{}` is selector-less; an unknown spec is not', async () => {
    useDefaults();
    useSelectorlessServices();
    const stored = (ns: string, name: string) => ({ peer_kind: 'service', peer_namespace: ns, peer_name: name });
    // spec.selector {} : known selector-less, same rendering as the API server.
    let yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [{ ...egressRow('10.96.0.90', '5432'), ...stored('db', 'ext') }])));
    expect(ruleComments(yaml)).toEqual(['# Service db/ext has no selector — ipBlock 10.96.0.90 is its ClusterIP and will not match after DNAT']);
    // No service_spec at all, or a manifest without spec: stored ⇒ unattributed as before, never "has no selector".
    for (const [ip, name] of [['10.96.0.88', 'pg'], ['10.96.0.89', 'pg2']] as const) {
      yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [{ ...egressRow(ip, '5432'), ...stored('db', name) }])));
      expect(ruleComments(yaml)).toEqual([`# unattributed peer ${ip} at 2026-09-03T00:00:00`]);
      expect(yaml).not.toContain('has no selector');
    }
    // By IP with an unknown spec: unattributed exactly as the stored path is,
    // not a selector-less claim and not a selector guessed from the name
    // (`app: pg`, which this test used to expect and which matches nothing).
    yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [egressRow('10.96.0.88', '5432')])));
    expect(yaml).not.toContain('has no selector');
    expect(ruleComments(yaml)).toEqual([PG_UNKNOWN_SELECTOR]);
    expect(spec(parse(yaml)).egress).toEqual([
      { to: [{ ipBlock: { cidr: '10.96.0.88/32' } }], ports: [{ protocol: 'TCP', port: 5432 }] },
    ]);
  });

  test('a stored Service that is gone from the broker is still unattributed', async () => {
    useDefaults();
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [
      { ...egressRow('10.96.0.1', '443'), ...storedKubeApi },
    ])));
    expect(ruleComments(yaml)).toEqual(['# unattributed peer 10.96.0.1 at 2026-09-03T00:00:00']);
  });
});

describe('generateCiliumNetworkPolicy — no traffic and selector-less Services', () => {
  test('(g) no traffic: enableDefaultDeny both true and no rules, as the default_deny golden', async () => {
    useDefaults();
    const policy = await generateCiliumNetworkPolicy(idle);
    const yaml = ciliumPolicyToYAML(policy);
    const doc = parse(yaml);
    expect(spec(doc).enableDefaultDeny).toEqual(spec(golden('cilium_default_deny.golden.yaml')).enableDefaultDeny);
    // The golden stops there, and Cilium's CRD rejects it (spec needs an
    // ingress or egress section). Cilium's deny form is one empty rule per
    // denied direction; the object stays rule-less, only the YAML carries it.
    expect(spec(doc).ingress).toEqual([{}]);
    expect(spec(doc).egress).toEqual([{}]);
    expect(yaml).toContain('  ingress:\n  - {}\n  egress:\n  - {}');
    expectCnpShape(doc);
    expect(policy.spec.ingress).toBeUndefined();
    expect(policy.spec.egress).toBeUndefined();
  });

  test('(g2) one observed direction with every peer dropped: empty rule for that direction only', async () => {
    useDefaults();
    const doc = parse(ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(prometheus, [egressRow('not-an-ip', '5432')]))));
    expect(spec(doc).enableDefaultDeny).toEqual({ ingress: false, egress: true });
    expect(spec(doc).egress).toEqual([{}]);
    expect(spec(doc).ingress).toBeUndefined();
    expectCnpShape(doc);
  });

  test('(h) the API server Service becomes toEntities: [kube-apiserver], the only form that matches its endpoints', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(prometheus, [
      { ...egressRow('10.96.0.1', '443'), ...storedKubeApi },
    ])));
    expect(spec(parse(yaml)).egress).toEqual([
      { toEntities: ['kube-apiserver'], toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }] },
    ]);
    expect(ruleComments(yaml)).toEqual([KUBE_API_ENTITY]);
    expect(yaml).not.toContain('toCIDR');
    expect(yaml).not.toContain('toEndpoints');
    expectCnpShape(parse(yaml));
  });

  test('(h3) ingress from the API server: fromEntities: [kube-apiserver]', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(web, [
      { ...ingressRow('10.96.0.1', '8443'), ...storedKubeApi },
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { fromEntities: ['kube-apiserver'], toPorts: [{ ports: [{ port: '8443', protocol: 'TCP' }] }] },
    ]);
    expect(ruleComments(yaml)).toEqual([KUBE_API_ENTITY]);
  });

  test('(h4) any other selector-less Service: CIDR of the ClusterIP with the DNAT note (no entity stands for it)', async () => {
    useDefaults();
    useSelectorlessServices();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(prometheus, [egressRow('10.96.0.77', '443')])));
    expect(spec(parse(yaml)).egress).toEqual([
      { toCIDR: ['10.96.0.77/32'], toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }] },
    ]);
    expect(ruleComments(yaml)).toEqual([METRICS_API_CIDR]);
    expect(yaml).not.toContain('app: metrics-api');
  });
});

// (i) Listings the caller already holds are used as-is: no second `/pod/info`
// download, no `/svc/ip` for a Service the listing has, no `/pod/name` for a
// pod it has — and the same document as the fetching path.
describe('generators — supplied pod and Service listings', () => {
  const sources = { pods: Object.values(podsByIp), services: Object.values(services) as ServiceInfo[] };

  test('standard: same rules as the fetching path, with no listing or lookup calls', async () => {
    useDefaults();
    useServices();
    const fetched = policyToYAML(await generateNetworkPolicy(crossNamespace));
    vi.mocked(apiClient.getAllPods).mockClear();
    vi.mocked(apiClient.getServiceByIP).mockClear();
    vi.mocked(apiClient.getPodDetailsByName).mockClear();
    const supplied = policyToYAML(await generateNetworkPolicy(crossNamespace, sources));
    expect(normaliseStandardRules(spec(parse(supplied)).egress, 'prod')).toEqual(normaliseStandardRules(spec(parse(fetched)).egress, 'prod'));
    expect(normaliseStandardRules(spec(parse(supplied)).ingress, 'prod')).toEqual(normaliseStandardRules(spec(parse(fetched)).ingress, 'prod'));
    expect(vi.mocked(apiClient.getAllPods)).not.toHaveBeenCalled();
    expect(vi.mocked(apiClient.getServiceByIP)).not.toHaveBeenCalled();
    expect(vi.mocked(apiClient.getPodDetailsByName)).not.toHaveBeenCalled();
  });

  test('a host-network Service peer still renders its backends from the supplied listing, with the same comment', async () => {
    useDefaults();
    useServices();
    const fetched = policyToYAML(await generateNetworkPolicy(servicePeer));
    vi.mocked(apiClient.getAllPods).mockClear();
    vi.mocked(apiClient.getServiceByIP).mockClear();
    const supplied = policyToYAML(await generateNetworkPolicy(servicePeer, sources));
    expect(normaliseStandardRules(spec(parse(supplied)).egress, 'monitoring')).toEqual(
      normaliseStandardRules(spec(parse(fetched)).egress, 'monitoring'),
    );
    expect(ruleComments(supplied)).toEqual(ruleComments(fetched));
    expect(vi.mocked(apiClient.getAllPods)).not.toHaveBeenCalled();
    expect(vi.mocked(apiClient.getServiceByIP)).not.toHaveBeenCalled();
  });

  test('cilium: same egress as the fetching path, with no listing or lookup calls', async () => {
    useDefaults();
    useServices();
    const fetched = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(crossNamespace));
    vi.mocked(apiClient.getAllPods).mockClear();
    vi.mocked(apiClient.getServiceByIP).mockClear();
    vi.mocked(apiClient.getPodDetailsByName).mockClear();
    const supplied = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(crossNamespace, sources));
    expect(normaliseCiliumRules(spec(parse(supplied)).egress)).toEqual(normaliseCiliumRules(spec(parse(fetched)).egress));
    expect(normaliseCiliumRules(spec(parse(supplied)).ingress)).toEqual(normaliseCiliumRules(spec(parse(fetched)).ingress));
    expect(vi.mocked(apiClient.getAllPods)).not.toHaveBeenCalled();
    expect(vi.mocked(apiClient.getServiceByIP)).not.toHaveBeenCalled();
    expect(vi.mocked(apiClient.getPodDetailsByName)).not.toHaveBeenCalled();
  });

  test('a Service the listing does not have still goes to /svc/ip', async () => {
    useDefaults();
    useSelectorlessServices();
    vi.mocked(apiClient.getServiceByIP).mockClear();
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [egressRow('10.96.0.1', '443')]), sources));
    expect(vi.mocked(apiClient.getServiceByIP)).toHaveBeenCalledWith('10.96.0.1');
    expect(ruleComments(yaml)).toEqual([KUBE_API_IPBLOCK]);
  });

  test('an empty pods listing is not a listing: the generator fetches as before', async () => {
    useDefaults();
    vi.mocked(apiClient.getAllPods).mockClear();
    await generateNetworkPolicy(egressPeer, { pods: [], services: [] });
    expect(vi.mocked(apiClient.getAllPods)).toHaveBeenCalledTimes(1);
  });
});

// (j) A Service peer is selected by the Service's own `spec.selector`, as the
// advisor renders it (standard_policy.go), never by a label guessed from the
// Service's name. The fixtures above all happen to select `{app: <name>}`;
// kube-dns (`k8s-app: kube-dns`) is the one every workload talks to.
describe('generators — a Service peer renders the Service selector', () => {
  const dnsRow = { ...egressRow('10.96.0.53', '53'), ip_protocol: 'UDP' };
  const dnsAndGrafana = target(prometheus, [dnsRow, egressRow('10.96.0.30', '3000')]);
  const kubeDnsPeer = {
    podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } },
    namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } },
  };
  const grafanaLabels = { 'app.kubernetes.io/name': 'grafana', 'app.kubernetes.io/instance': 'obs' };

  test('standard: kube-dns is k8s-app: kube-dns in kube-system; a same-namespace Service has no namespaceSelector', async () => {
    useDefaults();
    useServices();
    const yaml = policyToYAML(await generateNetworkPolicy(dnsAndGrafana));
    expect(spec(parse(yaml)).egress).toEqual([
      { to: [{ podSelector: { matchLabels: grafanaLabels } }], ports: [{ protocol: 'TCP', port: 3000 }] },
      { to: [kubeDnsPeer], ports: [{ protocol: 'UDP', port: 53 }] },
    ]);
    expect(yaml).not.toContain('app: "kube-dns"');
    expect(yaml).not.toContain('app: grafana');
    // The backend pod's extra labels are not the Service's selector.
    expect(yaml).not.toContain('pod-template-hash');
  });

  test('cilium: toEndpoints carries the Service selector plus the peer namespace label', async () => {
    useDefaults();
    useServices();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(dnsAndGrafana));
    expect((spec(parse(yaml)).egress as Rule[]).map((r) => r.toEndpoints)).toEqual([
      [{ matchLabels: grafanaLabels }],
      [{ matchLabels: { 'k8s-app': 'kube-dns', 'k8s:io.kubernetes.pod.namespace': 'kube-system' } }],
    ]);
    expect(yaml).not.toContain('app: "kube-dns"');
  });

  test('a flow to the backend pod collapses into the Service rule and its selector', async () => {
    useDefaults();
    useServices();
    const podRow = { ...egressRow('10.0.0.53', '53'), ip_protocol: 'UDP' };
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, [dnsRow, podRow])));
    expect(spec(parse(yaml)).egress).toEqual([{ to: [kubeDnsPeer], ports: [{ protocol: 'UDP', port: 53 }] }]);
  });

  test('a Service whose spec the broker never stored is pinned with the unattributed note, in both generators', async () => {
    useDefaults();
    useSelectorlessServices();
    const row = egressRow('10.96.0.88', '5432');
    const std = policyToYAML(await generateNetworkPolicy(target(prometheus, [row])));
    expect(spec(parse(std)).egress).toEqual([{ to: [{ ipBlock: { cidr: '10.96.0.88/32' } }], ports: [{ protocol: 'TCP', port: 5432 }] }]);
    const cnp = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(prometheus, [row])));
    expect(spec(parse(cnp)).egress).toEqual([{ toCIDR: ['10.96.0.88/32'], toPorts: [{ ports: [{ port: '5432', protocol: 'TCP' }] }] }]);
    for (const yaml of [std, cnp]) {
      expect(ruleComments(yaml)).toEqual([PG_UNKNOWN_SELECTOR]);
      expect(yaml).not.toContain('app: pg');
      expect(yaml).not.toContain('has no selector');
    }
  });
});

// (k) Service port -> targetPort. Egress to a Service is observed pre-DNAT on
// the Service port; NetworkPolicy and Cilium match the backend pod after
// translation, so the rule allows the targetPort. Mirrors advisor
// serviceTargetPortFixture (case list there) against the shared
// service_target_port goldens, plus malformed ports every generator skips.
describe('generators — Service port mapped to the backend targetPort', () => {
  const tpServices: ServiceInfo[] = [
    { svc_name: 'api', svc_namespace: 'prod', svc_ip: '10.96.1.10', service_spec: { spec: { selector: { app: 'api' }, ports: [
      { name: 'http', port: 80, protocol: 'TCP', targetPort: 8080 },
      { name: 'metrics', port: 9090, protocol: 'TCP', targetPort: 'metrics' },
    ] } } },
    { svc_name: 'cache', svc_namespace: 'prod', svc_ip: '10.96.1.20', service_spec: { spec: { selector: { app: 'cache' }, ports: [{ port: 6379 }] } } },
    { svc_name: 'legacy', svc_namespace: 'prod', svc_ip: '10.96.1.30', service_spec: { spec: { selector: { app: 'legacy' } } } },
    { svc_name: 'exporter', svc_namespace: 'monitoring', svc_ip: '10.96.1.40', service_spec: { spec: { selector: { app: 'node-exporter' }, ports: [
      { name: 'metrics', port: 80, protocol: 'TCP', targetPort: 9100 },
    ] } } },
    { svc_name: 'dns', svc_namespace: 'kube-system', svc_ip: '10.96.1.53', service_spec: { spec: { selector: { 'k8s-app': 'kube-dns' }, ports: [
      { name: 'dns', port: 53, protocol: 'UDP', targetPort: 5353 },
      { name: 'dns-tcp', port: 53, protocol: 'TCP', targetPort: 5354 },
    ] } } },
  ];
  // The exporter Service is backed by ONE host-network pod here, as in the advisor fixture.
  const tpSources = { pods: [podsByIp['192.168.50.101']], services: tpServices };
  const udp = (row: ReturnType<typeof egressRow>) => ({ ...row, ip_protocol: 'UDP' });
  const tpTarget = target(web, [
    egressRow('10.96.1.10', '9090'), egressRow('10.96.1.10', '80'),
    egressRow('10.96.1.20', '6380'), egressRow('10.96.1.20', '6379'),
    egressRow('10.96.1.30', '8443'),
    egressRow('10.96.1.40', '80'),
    udp(egressRow('10.96.1.53', '53')), egressRow('10.96.1.53', '53'),
    egressRow('10.96.1.99', ' 80'), egressRow('10.96.1.99', '0x50'), egressRow('10.96.1.99', '1e2'),
    egressRow('10.96.1.99', '+80'), egressRow('10.96.1.99', '80.0'),
  ]);

  test('standard: rules and comment lines match the golden', async () => {
    useDefaults();
    const yaml = policyToYAML(await generateNetworkPolicy(tpTarget, tpSources));
    const file = 'standard_service_target_port.golden.yaml';
    expect(normaliseStandardRules(spec(parse(yaml)).egress, 'prod')).toEqual(normaliseStandardRules(spec(golden(file)).egress, 'prod'));
    expect(commentLines(yaml)).toEqual(commentLines(goldenText(file)));
    expect(yaml).not.toContain('10.96.1.99');
  });

  test('cilium: rules and comment lines match the golden', async () => {
    useDefaults();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(tpTarget, tpSources));
    const file = 'cilium_service_target_port.golden.yaml';
    expect(normaliseCiliumRules(spec(parse(yaml)).egress)).toEqual(normaliseCiliumRules(spec(golden(file)).egress));
    expect(commentLines(yaml)).toEqual(commentLines(goldenText(file)));
  });

  test('a backend-pod flow collapsed into the Service keeps its container port; ingress is never mapped', async () => {
    useDefaults();
    useServices();
    // kube-dns maps 53/UDP -> 53 in `services`; give the pod flow a port the
    // Service does not expose to prove it is not run through spec.ports.
    const rows = [
      udp(egressRow('10.96.0.53', '53')),
      udp(egressRow('10.0.0.53', '5353')),
      ingressRow('10.96.0.53', '53'),
    ];
    const yaml = policyToYAML(await generateNetworkPolicy(target(prometheus, rows)));
    expect(normaliseStandardRules(spec(parse(yaml)).egress, 'monitoring')[0].ports).toEqual([
      { protocol: 'UDP', port: 53 }, { protocol: 'UDP', port: 5353 },
    ]);
    expect(spec(parse(yaml)).ingress[0].ports).toEqual([{ protocol: 'TCP', port: 53 }]);
    expect(yaml).not.toContain('could not be mapped');
  });
});
