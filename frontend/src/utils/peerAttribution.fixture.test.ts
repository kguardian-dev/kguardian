import { beforeEach, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';

// Peer attribution (v4) — the generators' consumer side.
//
// Reproduces the cluster-00 case: `cmangos-database` (game-servers) has
// INGRESS :3306 rows from 10.244.12.199 dated May and July 2026; `autobrr`
// (home-system) started 2026-08-04 and holds that IP now. Before v4 both
// generators resolved the IP at read time and emitted a podSelector for
// autobrr. Now (scratchpad/handoff-v4-generators.md, advisor
// TestFixtureGolden_PeerAttribution):
//
//   stale_ip_peer        — rows with no stored peer, older than every pod
//                          that ever held the IP ⇒ ipBlock + comment quoting
//                          the NEWEST row, never a selector
//   stored_peer_identity — rows whose peer_* name the pod/Service/host-
//                          network pod that held the IP THEN ⇒ the stored
//                          identity wins over the current holder
//
// Rules and comment lines are compared against the shared goldens in
// test/fixtures/generators/networkpolicy in the same normalised form as
// networkPolicyGenerator.fixture.test.ts (the golden comparisons skip until
// the generators branch that adds them is merged).

const goldensDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/fixtures/generators/networkpolicy',
);
const goldenPath = (f: string) => path.join(goldensDir, f);
const hasGolden = (f: string) => fs.existsSync(goldenPath(f));
const goldenText = (f: string) => fs.readFileSync(goldenPath(f), 'utf8');
const golden = (f: string) => parse(goldenText(f)) as Record<string, unknown>;

// --- broker stand-in ------------------------------------------------------

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default',
  time_stamp: '2026-09-03T05:00:00',
  node_name: 'worker-1',
  is_dead: false,
  ...p,
  pod_obj: { metadata: { labels: p.workload_selector_labels ?? {}, ...(p.pod_obj?.metadata ?? {}) } },
});

const cmangosDatabase = podRecord({
  pod_name: 'cmangos-database', pod_ip: '10.244.3.17', pod_namespace: 'game-servers',
  workload_kind: 'StatefulSet', workload_name: 'cmangos-database',
  workload_selector_labels: { app: 'cmangos-database' }, started_at: '2026-05-01T00:00:00',
});
// Holds 10.244.12.199 NOW.
const autobrr = podRecord({
  pod_name: 'autobrr-7d9c4b8f6-q2x9k', pod_ip: '10.244.12.199', pod_namespace: 'home-system', node_name: 'worker-2',
  workload_kind: 'Deployment', workload_name: 'autobrr',
  workload_selector_labels: { app: 'autobrr' }, started_at: '2026-08-04T09:12:41',
});
const cmangosWeb = podRecord({
  pod_name: 'cmangos-web-0', pod_ip: '10.244.5.8', pod_namespace: 'game-servers',
  workload_kind: 'Deployment', workload_name: 'cmangos-web',
  workload_selector_labels: { app: 'cmangos-web' }, started_at: '2026-07-01T00:00:00',
});
// (b) autobrr with UNKNOWN start: a by-IP lookup WOULD pick it.
const autobrrNoStart = { ...autobrr, started_at: null };
// Held 10.244.12.199 at 2026-09-03T05:00 (a CronJob run); dead, record retained.
const cmangosBackup = podRecord({
  pod_name: 'cmangos-backup-29271840-x7k2p', pod_ip: '10.244.12.199', pod_namespace: 'game-servers',
  workload_kind: 'CronJob', workload_name: 'cmangos-backup', workload_selector_labels: { app: 'cmangos-backup' },
  is_dead: true, started_at: '2026-09-03T04:59:30', time_stamp: '2026-09-03T05:00:10',
  pod_obj: { metadata: { uid: '0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6' } },
});
const nodeExporter = podRecord({
  pod_name: 'node-exporter-abc12', pod_ip: '192.168.50.101', pod_namespace: 'monitoring',
  workload_kind: 'DaemonSet', workload_name: 'node-exporter', workload_selector_labels: { app: 'node-exporter' },
  host_network: true, started_at: '2026-08-01T00:00:00',
  pod_obj: { metadata: { uid: '9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3' } },
});
const dbService: ServiceInfo = {
  svc_ip: '10.96.0.10', svc_name: 'db', svc_namespace: 'game-servers', service_spec: { spec: { selector: { app: 'db' } } },
};

let listing: PodInfo[] | (() => never) = [cmangosDatabase, autobrr, cmangosWeb];
let services: Record<string, ServiceInfo> = {};
const byName = () => Object.fromEntries((typeof listing === 'function' ? [] : listing).map((p) => [p.pod_name, p]));

vi.mock('../services/api', () => ({
  apiClient: {
    getServiceByIP: vi.fn(async (ip: string) => services[ip] ?? null),
    getAllPods: vi.fn(async () => (typeof listing === 'function' ? listing() : listing)),
    // Pre-`?at=` broker: always the current holder.
    getPodDetailsByIP: vi.fn(async (ip: string) => (ip === '10.244.12.199' ? autobrr : null)),
    getPodDetailsByName: vi.fn(async (name: string) => byName()[name] ?? null),
  },
}));

import { apiClient } from '../services/api';
import { generateNetworkPolicy, policyToYAML } from './networkPolicyGenerator';
import { generateCiliumNetworkPolicy, ciliumPolicyToYAML } from './ciliumPolicyGenerator';

// --- scenarios (inputs verbatim from the handoff) -------------------------

const target = (pod: PodInfo, traffic: Partial<NetworkTraffic>[]): PodNodeData =>
  ({ id: pod.pod_name, label: pod.pod_name, pod, pods: [pod], traffic, isExpanded: false }) as PodNodeData;

const ingressRow = (ip: string, port: string, peerPort: string, time_stamp: string, extra: Partial<NetworkTraffic> = {}): Partial<NetworkTraffic> => ({
  traffic_type: 'INGRESS', pod_port: port, traffic_in_out_ip: ip, traffic_in_out_port: peerPort, ip_protocol: 'TCP', time_stamp, ...extra,
});
const egressRow = (ip: string, port: string, time_stamp: string, extra: Partial<NetworkTraffic> = {}): Partial<NetworkTraffic> => ({
  traffic_type: 'EGRESS', traffic_in_out_ip: ip, traffic_in_out_port: port, ip_protocol: 'TCP', time_stamp, ...extra,
});

// (a) legacy rows: no stored peer, older than autobrr's start.
const staleIpPeer = target(cmangosDatabase, [
  ingressRow('10.244.12.199', '3306', '51234', '2026-05-21T08:30:00'),
  ingressRow('10.244.12.199', '3306', '51235', '2026-07-23T10:00:00'),
  egressRow('10.244.5.8', '8080', '2026-07-23T10:00:05'),
]);

// (b) stored identities: pod (dead now; autobrr holds the IP), Service, node.
const storedBackup = {
  peer_kind: 'pod', peer_namespace: 'game-servers', peer_name: 'cmangos-backup-29271840-x7k2p',
  peer_uid: '0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6', peer_workload_kind: 'CronJob', peer_workload_name: 'cmangos-backup',
};
const storedDb = { peer_kind: 'service', peer_namespace: 'game-servers', peer_name: 'db' };
const storedNodeExporter = {
  peer_kind: 'node', peer_namespace: 'monitoring', peer_name: 'node-exporter-abc12',
  peer_uid: '9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3', peer_workload_kind: 'DaemonSet', peer_workload_name: 'node-exporter',
};
const storedPeerIdentity = target(cmangosDatabase, [
  ingressRow('10.244.12.199', '3306', '51234', '2026-09-03T05:00:00', storedBackup),
  egressRow('10.96.0.10', '5432', '2026-09-03T05:00:01', storedDb),
  egressRow('192.168.50.101', '9100', '2026-09-03T05:00:02', storedNodeExporter),
]);
const useStoredScenario = () => {
  listing = [autobrrNoStart, cmangosBackup, nodeExporter, cmangosDatabase];
  services = { '10.96.0.10': dbService };
};

const commentLines = (yaml: string) => yaml.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('#'));
const spec = (doc: Record<string, unknown>) => doc.spec as Record<string, unknown>;
type Rule = Record<string, unknown>;
const unprefix = (labels: Record<string, string>) =>
  Object.fromEntries(Object.entries(labels).map(([k, v]) => [k.replace(/^k8s:/, ''), v]));
/** Advisor always attaches a namespaceSelector; the frontend omits it for the target's own namespace. */
const normaliseStandard = (rules: unknown, ns: string): Rule[] =>
  ((rules as Rule[] | undefined) ?? []).map((r) => {
    const out: Rule = { ...r };
    for (const dir of ['from', 'to']) {
      if (!Array.isArray(out[dir])) continue;
      out[dir] = (out[dir] as Rule[]).map((peer) => {
        const sel = peer.namespaceSelector as { matchLabels?: Record<string, string> } | undefined;
        if (sel?.matchLabels?.['kubernetes.io/metadata.name'] === ns) {
          const { namespaceSelector: _drop, ...rest } = peer;
          void _drop;
          return rest;
        }
        return peer;
      });
    }
    return out;
  });
const normaliseCilium = (rules: unknown): Rule[] =>
  ((rules as Rule[] | undefined) ?? []).map((r) => {
    const out: Rule = { ...r };
    for (const dir of ['fromEndpoints', 'toEndpoints']) {
      if (Array.isArray(out[dir])) {
        out[dir] = (out[dir] as { matchLabels: Record<string, string> }[]).map((ep) => ({ matchLabels: unprefix(ep.matchLabels) }));
      }
    }
    return out;
  });

beforeEach(() => {
  listing = [cmangosDatabase, autobrr, cmangosWeb];
  services = {};
  vi.mocked(apiClient.getPodDetailsByIP).mockClear();
});

// --- standard NetworkPolicy ----------------------------------------------

describe('generateNetworkPolicy — peer attribution', () => {
  test('(a) stale_ip_peer: ipBlock + comment quoting the newest row; never a selector for autobrr', async () => {
    const policy = await generateNetworkPolicy(staleIpPeer);
    const yaml = policyToYAML(policy);
    const doc = parse(yaml);
    expect(spec(doc).policyTypes).toEqual(['Ingress', 'Egress']);
    expect(spec(doc).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(normaliseStandard(spec(doc).egress, 'game-servers')).toEqual([
      { to: [{ podSelector: { matchLabels: { app: 'cmangos-web' } } }], ports: [{ protocol: 'TCP', port: 8080 }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(yaml).not.toContain('home-system');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00']);
    // The comment sits directly above the rule it explains.
    const lines = yaml.split('\n');
    expect(lines[lines.findIndex((l) => l.trim().startsWith('#')) + 1]).toBe('  - from:');
  });

  test.skipIf(!hasGolden('standard_stale_ip_peer.golden.yaml'))('(a) golden: standard_stale_ip_peer', async () => {
    const yaml = policyToYAML(await generateNetworkPolicy(staleIpPeer));
    const want = golden('standard_stale_ip_peer.golden.yaml');
    expect(normaliseStandard(spec(parse(yaml)).ingress, 'game-servers')).toEqual(normaliseStandard(spec(want).ingress, 'game-servers'));
    expect(normaliseStandard(spec(parse(yaml)).egress, 'game-servers')).toEqual(normaliseStandard(spec(want).egress, 'game-servers'));
    expect(spec(parse(yaml)).policyTypes).toEqual(spec(want).policyTypes);
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('standard_stale_ip_peer.golden.yaml')));
  });

  test('(b) stored_peer_identity: stored pod / Service / host-network pod win over the current IP holder', async () => {
    useStoredScenario();
    const yaml = policyToYAML(await generateNetworkPolicy(storedPeerIdentity));
    const doc = parse(yaml);
    expect(normaliseStandard(spec(doc).ingress, 'game-servers')).toEqual([
      { from: [{ podSelector: { matchLabels: { app: 'cmangos-backup' } } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(normaliseStandard(spec(doc).egress, 'game-servers')).toEqual([
      { to: [{ podSelector: { matchLabels: { app: 'db' } } }], ports: [{ protocol: 'TCP', port: 5432 }] },
      { to: [{ ipBlock: { cidr: '192.168.50.101/32' } }], ports: [{ protocol: 'TCP', port: 9100 }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual([
      '# host-network peer monitoring/node-exporter on node worker-1 — podSelector cannot match host traffic',
    ]);
  });

  test.skipIf(!hasGolden('standard_stored_peer_identity.golden.yaml'))('(b) golden: standard_stored_peer_identity', async () => {
    useStoredScenario();
    const yaml = policyToYAML(await generateNetworkPolicy(storedPeerIdentity));
    const want = golden('standard_stored_peer_identity.golden.yaml');
    expect(normaliseStandard(spec(parse(yaml)).ingress, 'game-servers')).toEqual(normaliseStandard(spec(want).ingress, 'game-servers'));
    expect(normaliseStandard(spec(parse(yaml)).egress, 'game-servers')).toEqual(normaliseStandard(spec(want).egress, 'game-servers'));
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('standard_stored_peer_identity.golden.yaml')));
  });

  test('stored pod no longer in the listing ⇒ unattributed (never re-resolved by IP)', async () => {
    useStoredScenario();
    listing = [autobrrNoStart, cmangosDatabase];
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-03T05:00:00', storedBackup),
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-09-03T05:00:00']);
  });

  test('stored pod whose uid no longer matches ⇒ unattributed', async () => {
    useStoredScenario();
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-03T05:00:00', { ...storedBackup, peer_uid: 'ffffffff-0000-0000-0000-000000000000' }),
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-09-03T05:00:00']);
  });

  test('stored Service gone (or recycled ClusterIP) ⇒ unattributed', async () => {
    useStoredScenario();
    services = { '10.96.0.10': { ...dbService, svc_name: 'other' } };
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [egressRow('10.96.0.10', '5432', '2026-09-03T05:00:01', storedDb)])));
    expect(spec(parse(yaml)).egress).toEqual([
      { to: [{ ipBlock: { cidr: '10.96.0.10/32' } }], ports: [{ protocol: 'TCP', port: 5432 }] },
    ]);
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.96.0.10 at 2026-09-03T05:00:01']);
  });

  test('same IP, two stored identities (Job A then Job B) ⇒ two rules, ordered by identity key', async () => {
    const jobA = podRecord({ pod_name: 'job-a-1', pod_ip: '10.244.12.199', pod_namespace: 'game-servers', is_dead: true,
      workload_kind: 'Job', workload_name: 'job-a', workload_selector_labels: { app: 'job-a' } });
    const jobB = podRecord({ pod_name: 'job-b-1', pod_ip: '10.244.12.199', pod_namespace: 'game-servers',
      workload_kind: 'Job', workload_name: 'job-b', workload_selector_labels: { app: 'job-b' } });
    listing = [cmangosDatabase, jobA, jobB];
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-03T05:00:00', { peer_kind: 'pod', peer_namespace: 'game-servers', peer_name: 'job-b-1' }),
      ingressRow('10.244.12.199', '3306', '51235', '2026-09-03T04:00:00', { peer_kind: 'pod', peer_namespace: 'game-servers', peer_name: 'job-a-1' }),
    ])));
    expect(normaliseStandard(spec(parse(yaml)).ingress, 'game-servers')).toEqual([
      { from: [{ podSelector: { matchLabels: { app: 'job-a' } } }], ports: [{ protocol: 'TCP', port: 3306 }] },
      { from: [{ podSelector: { matchLabels: { app: 'job-b' } } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
  });

  test('same IP, old (guarded out) and new rows ⇒ selector rule (sel:) before the unattributed rule', async () => {
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-07-23T10:00:00'),
      ingressRow('10.244.12.199', '3306', '51235', '2026-09-01T10:00:00'),
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'home-system' } }, podSelector: { matchLabels: { app: 'autobrr' } } }], ports: [{ protocol: 'TCP', port: 3306 }] },
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00']);
  });

  test('started_at == time_stamp stays a candidate (guard is strictly later)', async () => {
    const doc = parse(policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-08-04T09:12:41'),
    ]))));
    expect((spec(doc).ingress as Rule[])[0].from).toEqual([
      { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'home-system' } }, podSelector: { matchLabels: { app: 'autobrr' } } },
    ]);
  });

  test('by-IP: an alive holder with NULL started_at (ghost / Pending) is not a candidate ⇒ unattributed', async () => {
    listing = [cmangosDatabase, autobrrNoStart];
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-01T10:00:00'),
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-09-01T10:00:00']);
  });

  test('a guarded-out pod backed by a Service is NOT redirected to the Service identity', async () => {
    // autobrr's Service is also a peer; the May row from autobrr's IP must stay unattributed.
    const autobrrSvc: ServiceInfo = { svc_ip: '10.96.0.20', svc_name: 'autobrr', svc_namespace: 'home-system',
      service_spec: { spec: { selector: { app: 'autobrr' } } } };
    services = { '10.96.0.20': autobrrSvc };
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-05-21T08:30:00'),
      egressRow('10.96.0.20', '7474', '2026-09-01T10:00:00'),
    ])));
    const doc = parse(yaml);
    expect(spec(doc).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect((spec(doc).egress as Rule[])[0].to).toEqual([
      { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'home-system' } }, podSelector: { matchLabels: { app: 'autobrr' } } },
    ]);
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-05-21T08:30:00']);
  });

  test('listing unavailable: a by-IP answer with NULL started_at is unattributed too', async () => {
    listing = () => { throw new Error('broker down'); };
    vi.mocked(apiClient.getPodDetailsByIP).mockResolvedValueOnce(autobrrNoStart);
    const yaml = policyToYAML(await generateNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-01T10:00:00'),
    ])));
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-09-01T10:00:00']);
  });

  test('listing unavailable: by-IP fallback passes ?at= and still guards the (pre-?at=) broker answer', async () => {
    listing = () => { throw new Error('broker down'); };
    const yaml = policyToYAML(await generateNetworkPolicy(staleIpPeer));
    expect(vi.mocked(apiClient.getPodDetailsByIP)).toHaveBeenCalledWith('10.244.12.199', '2026-05-21T08:30:00');
    expect(vi.mocked(apiClient.getPodDetailsByIP)).toHaveBeenCalledWith('10.244.12.199', '2026-07-23T10:00:00');
    expect(spec(parse(yaml)).ingress).toEqual([
      { from: [{ ipBlock: { cidr: '10.244.12.199/32' } }], ports: [{ protocol: 'TCP', port: 3306 }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00']);
  });
});

// --- CiliumNetworkPolicy -------------------------------------------------

describe('generateCiliumNetworkPolicy — peer attribution', () => {
  test('(a) stale_ip_peer: fromCIDR + comment, no fromEndpoints for autobrr', async () => {
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(staleIpPeer));
    const doc = parse(yaml);
    expect(spec(doc).ingress).toEqual([
      { fromCIDR: ['10.244.12.199/32'], toPorts: [{ ports: [{ port: '3306', protocol: 'TCP' }] }] },
    ]);
    expect(normaliseCilium(spec(doc).egress)).toEqual([
      { toEndpoints: [{ matchLabels: { app: 'cmangos-web' } }], toPorts: [{ ports: [{ port: '8080', protocol: 'TCP' }] }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00']);
    const lines = yaml.split('\n');
    expect(lines[lines.findIndex((l) => l.trim().startsWith('#')) + 1]).toBe('  -');
  });

  test.skipIf(!hasGolden('cilium_stale_ip_peer.golden.yaml'))('(a) golden: cilium_stale_ip_peer', async () => {
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(staleIpPeer));
    const want = golden('cilium_stale_ip_peer.golden.yaml');
    expect(normaliseCilium(spec(parse(yaml)).ingress)).toEqual(normaliseCilium(spec(want).ingress));
    expect(normaliseCilium(spec(parse(yaml)).egress)).toEqual(normaliseCilium(spec(want).egress));
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('cilium_stale_ip_peer.golden.yaml')));
  });

  test('(b) stored_peer_identity: endpoint selectors of the stored peers, entities for the stored node', async () => {
    useStoredScenario();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(storedPeerIdentity));
    const doc = parse(yaml);
    expect(normaliseCilium(spec(doc).ingress)).toEqual([
      { fromEndpoints: [{ matchLabels: { app: 'cmangos-backup' } }], toPorts: [{ ports: [{ port: '3306', protocol: 'TCP' }] }] },
    ]);
    expect(normaliseCilium(spec(doc).egress)).toEqual([
      { toEndpoints: [{ matchLabels: { app: 'db' } }], toPorts: [{ ports: [{ port: '5432', protocol: 'TCP' }] }] },
      { toEntities: ['host', 'remote-node'], toPorts: [{ ports: [{ port: '9100', protocol: 'TCP' }] }] },
    ]);
    expect(yaml).not.toContain('autobrr');
    expect(commentLines(yaml)).toEqual([
      '# host-network peer monitoring/node-exporter on node worker-1 — endpointSelector cannot match host traffic',
    ]);
  });

  test.skipIf(!hasGolden('cilium_stored_peer_identity.golden.yaml'))('(b) golden: cilium_stored_peer_identity', async () => {
    useStoredScenario();
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(storedPeerIdentity));
    const want = golden('cilium_stored_peer_identity.golden.yaml');
    expect(normaliseCilium(spec(parse(yaml)).ingress)).toEqual(normaliseCilium(spec(want).ingress));
    expect(normaliseCilium(spec(parse(yaml)).egress)).toEqual(normaliseCilium(spec(want).egress));
    expect(commentLines(yaml)).toEqual(commentLines(goldenText('cilium_stored_peer_identity.golden.yaml')));
  });

  test('stored pod gone ⇒ fromCIDR + unattributed comment', async () => {
    useStoredScenario();
    listing = [autobrrNoStart, cmangosDatabase];
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(target(cmangosDatabase, [
      ingressRow('10.244.12.199', '3306', '51234', '2026-09-03T05:00:00', storedBackup),
    ])));
    expect((spec(parse(yaml)).ingress as Rule[])[0].fromCIDR).toEqual(['10.244.12.199/32']);
    expect(yaml).not.toContain('fromEndpoints');
    expect(commentLines(yaml)).toEqual(['# unattributed peer 10.244.12.199 at 2026-09-03T05:00:00']);
  });
});
