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
// above; db ClusterIP fronting an ordinary pod-network deployment.
const services: Record<string, unknown> = {
  '10.96.0.20': { svc_name: 'node-exporter', svc_namespace: 'monitoring', svc_ip: '10.96.0.20',
    service_spec: { spec: { selector: { app: 'node-exporter' } } } },
  '10.96.0.10': { svc_name: 'db', svc_namespace: 'prod', svc_ip: '10.96.0.10',
    service_spec: { spec: { selector: { app: 'db' } } } },
  // (f) cross-namespace Service peer of prod/web
  '10.96.0.50': { svc_name: 'prometheus', svc_namespace: 'monitoring', svc_ip: '10.96.0.50',
    service_spec: { spec: { selector: { app: 'prometheus' } } } },
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
const ingressRow = (ip: string, port: string) => ({ traffic_type: 'INGRESS', pod_port: port, traffic_in_out_ip: ip, ip_protocol: 'TCP' });
const egressRow = (ip: string, port: string) => ({ traffic_type: 'EGRESS', traffic_in_out_ip: ip, traffic_in_out_port: port, ip_protocol: 'TCP' });

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
      if (Array.isArray(out.toPorts)) {
        out.toPorts = (out.toPorts as { ports: Record<string, unknown>[] }[]).map((pr) => ({
          ports: [...pr.ports].sort((a, b) => portKey(a).localeCompare(portKey(b))),
        }));
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
