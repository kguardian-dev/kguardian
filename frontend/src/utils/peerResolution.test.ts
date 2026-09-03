import { describe, expect, test } from 'vitest';
import type { NetworkTraffic, PodInfo, ServiceInfo } from '../types';
import {
  buildPeerIndex,
  isPlaceholderPod,
  parseBrokerTime,
  peerGroupIdentity,
  peerKey,
  peerSelectorLabels,
  podEligibleAt,
  rankPods,
  resolvePeer,
  selectPodByIp,
} from './peerResolution';

// The bug, as diagnosed live on cluster-00 (2026-09-03): `cmangos-database`
// (game-servers) has INGRESS :3306 rows from 10.244.12.199 dated 2026-05-21
// and 2026-07-23; `autobrr` (home-system) started 2026-08-04 and holds that
// IP now. A by-IP lookup at read time attributes the May/July flows to
// autobrr. These fixtures are the frontend half of that reproduction.

const pod = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default',
  time_stamp: '2026-09-03T05:00:00',
  node_name: 'node-a',
  is_dead: false,
  ...p,
});

const autobrr = pod({
  pod_name: 'autobrr-7d9c4b8f6-q2x9k', pod_ip: '10.244.12.199', pod_namespace: 'home-system',
  workload_kind: 'Deployment', workload_name: 'autobrr', workload_selector_labels: { app: 'autobrr' },
  pod_obj: { metadata: { labels: { app: 'autobrr' } } }, started_at: '2026-08-04T09:12:41',
});

const row = (r: Partial<NetworkTraffic>): NetworkTraffic => ({
  uuid: 'u', pod_name: 'cmangos-database-0', pod_namespace: 'game-servers', pod_ip: '10.244.3.17',
  pod_port: '3306', ip_protocol: 'TCP', traffic_type: 'INGRESS', traffic_in_out_ip: '10.244.12.199',
  traffic_in_out_port: '51234', decision: 'ALLOW', time_stamp: '2026-05-21T10:00:00',
  ...r,
});

describe('parseBrokerTime', () => {
  test('naive broker timestamps are UTC, not local time', () => {
    expect(parseBrokerTime('2026-08-04T09:12:41')).toBe(Date.UTC(2026, 7, 4, 9, 12, 41));
    expect(parseBrokerTime('2026-08-04T09:12:41.123456')).toBe(Date.UTC(2026, 7, 4, 9, 12, 41, 123));
  });
  test('RFC3339 input keeps its zone', () => {
    expect(parseBrokerTime('2026-08-04T09:12:41Z')).toBe(Date.UTC(2026, 7, 4, 9, 12, 41));
    expect(parseBrokerTime('2026-08-04T11:12:41+02:00')).toBe(Date.UTC(2026, 7, 4, 9, 12, 41));
  });
  test('absent / garbage → null', () => {
    expect(parseBrokerTime(null)).toBeNull();
    expect(parseBrokerTime('')).toBeNull();
    expect(parseBrokerTime('yesterday')).toBeNull();
  });
});

describe('start-time guard', () => {
  test('a pod started after the flow is excluded', () => {
    expect(podEligibleAt(autobrr, parseBrokerTime('2026-05-21T10:00:00'))).toBe(false);
    expect(podEligibleAt(autobrr, parseBrokerTime('2026-07-23T10:00:00'))).toBe(false);
  });
  test('a pod started before (or exactly at) the flow is a candidate', () => {
    expect(podEligibleAt(autobrr, parseBrokerTime('2026-08-05T10:00:00'))).toBe(true);
    expect(podEligibleAt(autobrr, parseBrokerTime('2026-08-04T09:12:41'))).toBe(true);
  });
  test('unknown started_at is EXCLUDED (ghost / Pending record)', () => {
    expect(podEligibleAt({ started_at: null, is_dead: false, time_stamp: '2026-09-01T00:00:00' }, parseBrokerTime('2026-05-21T10:00:00'))).toBe(false);
    expect(podEligibleAt({ is_dead: false, time_stamp: '2026-09-01T00:00:00' }, parseBrokerTime('2026-05-21T10:00:00'))).toBe(false);
  });
  test('a dead record is bounded by its time_stamp (last seen / marked dead)', () => {
    const flow = parseBrokerTime('2026-08-10T00:00:00');
    const finishedJob = { started_at: '2026-08-01T00:00:00', is_dead: true, time_stamp: '2026-08-01T00:10:00' };
    expect(podEligibleAt(finishedJob, flow)).toBe(false);
    expect(podEligibleAt({ ...finishedJob, time_stamp: '2026-08-10T00:00:00' }, flow)).toBe(true);
    expect(podEligibleAt({ ...finishedJob, time_stamp: '2026-08-11T00:00:00' }, flow)).toBe(true);
    expect(podEligibleAt({ ...finishedJob, time_stamp: null as unknown as string }, flow)).toBe(false);
    // Alive: the time_stamp bound does not apply.
    expect(podEligibleAt({ ...finishedJob, is_dead: false }, flow)).toBe(true);
  });
  test('unparseable flow time excludes every candidate', () => {
    expect(podEligibleAt(autobrr, null)).toBe(false);
  });
});

describe('selectPodByIp — broker precedence', () => {
  const flow = parseBrokerTime('2026-09-03T05:00:00');
  test('alive before dead', () => {
    const dead = pod({ pod_name: 'old', pod_ip: '10.0.0.1', is_dead: true, started_at: '2026-09-01T00:00:00' });
    const alive = pod({ pod_name: 'new', pod_ip: '10.0.0.1', started_at: '2026-08-01T00:00:00' });
    expect(selectPodByIp([dead, alive], flow).pod).toBe(alive);
  });
  test('among dead: newest started_at; a NULL start is not a candidate at all', () => {
    const a = pod({ pod_name: 'a', pod_ip: '10.0.0.1', is_dead: true, started_at: '2026-08-01T00:00:00' });
    const b = pod({ pod_name: 'b', pod_ip: '10.0.0.1', is_dead: true, started_at: '2026-08-02T00:00:00' });
    const ghost = pod({ pod_name: 'ghost', pod_ip: '10.0.0.1', is_dead: false, started_at: null, time_stamp: '2026-09-02T00:00:00' });
    expect(rankPods([ghost, a, b]).map((p) => p.pod_name)).toEqual(['ghost', 'b', 'a']);
    // The alive ghost would win on precedence; the guard removes it first.
    expect(selectPodByIp([ghost, a, b], flow).pod).toBe(b);
    expect(selectPodByIp([ghost], flow)).toEqual({ pod: null, guardedOut: true });
  });
  test('no candidates → nothing, not guarded out', () => {
    expect(selectPodByIp(undefined, flow)).toEqual({ pod: null, guardedOut: false });
    expect(selectPodByIp([], flow)).toEqual({ pod: null, guardedOut: false });
  });
  test('every candidate started after the flow → guarded out', () => {
    expect(selectPodByIp([autobrr], parseBrokerTime('2026-05-21T10:00:00'))).toEqual({ pod: null, guardedOut: true });
  });
  test('a dead Job pod whose time_stamp is before the flow → guarded out (recycled IP, later flow)', () => {
    const job = pod({ pod_name: 'volsync-src-abc', pod_ip: '10.0.0.1', is_dead: true, started_at: '2026-08-01T00:00:00', time_stamp: '2026-08-01T00:10:00' });
    expect(selectPodByIp([job], parseBrokerTime('2026-08-10T00:00:00'))).toEqual({ pod: null, guardedOut: true });
    expect(selectPodByIp([job], parseBrokerTime('2026-08-01T00:05:00')).pod).toBe(job);
    const dying = { ...job, time_stamp: null as unknown as string };
    expect(selectPodByIp([dying], parseBrokerTime('2026-08-01T00:05:00'))).toEqual({ pod: null, guardedOut: true });
  });
});

describe('resolvePeer — autobrr / cmangos-database', () => {
  const index = buildPeerIndex([autobrr]);

  test('legacy row (no stored peer) older than the current holder → unattributed, never autobrr', () => {
    for (const at of ['2026-05-21T10:00:00', '2026-07-23T10:00:00']) {
      const peer = resolvePeer(row({ time_stamp: at }), index);
      expect(peer).toEqual({ kind: 'unattributed', ip: '10.244.12.199', at });
      expect(peerKey(peer)).toBe('unattributed:10.244.12.199');
    }
  });

  test('legacy row younger than the holder start → autobrr by IP', () => {
    const peer = resolvePeer(row({ time_stamp: '2026-09-03T05:00:00' }), index);
    expect(peer).toEqual({ kind: 'pod', pod: autobrr, stored: false });
    expect(peerKey(peer)).toBe('pod:home-system/autobrr-7d9c4b8f6-q2x9k');
  });

  test('stored peer wins over the current IP holder; a gone record is a placeholder keyed as unattributed', () => {
    const peer = resolvePeer(row({
      time_stamp: '2026-07-23T10:00:00',
      peer_kind: 'pod', peer_namespace: 'game-servers', peer_name: 'cmangos-backup-29271840-x7k2p',
      peer_uid: '0d1e2f3a', peer_workload_kind: 'CronJob', peer_workload_name: 'cmangos-backup',
      peer_resolved_at: '2026-07-23T10:00:01',
    }), index);
    expect(peer.kind).toBe('pod');
    if (peer.kind !== 'pod') return;
    expect(peer.stored).toBe(true);
    expect(peer.pod.pod_name).toBe('cmangos-backup-29271840-x7k2p');
    expect(peer.pod.pod_namespace).toBe('game-servers');
    expect(peer.pod.workload_kind).toBe('CronJob');
    expect(peer.pod.is_dead).toBe(true);
    // Placeholder: no labels → no selector may be built from it, and it
    // renders as the Unattributed node (never autobrr, never a named node).
    expect(isPlaceholderPod(peer.pod)).toBe(true);
    expect(peerSelectorLabels(peer.pod)).toBeNull();
    expect(peerGroupIdentity(peer.pod)).toBe('cmangos-backup');
    expect(peerKey(peer)).toBe('unattributed:10.244.12.199');
  });

  test('stored peer whose record is present resolves to that record', () => {
    const peer = resolvePeer(row({
      time_stamp: '2026-09-03T05:00:00',
      peer_kind: 'pod', peer_namespace: 'home-system', peer_name: autobrr.pod_name,
    }), index);
    expect(peer).toEqual({ kind: 'pod', pod: autobrr, stored: true });
  });

  test('stored peer is matched by (namespace, name); a uid mismatch is a different pod', () => {
    const withUid = pod({ ...autobrr, pod_obj: { metadata: { uid: 'uid-1', labels: { app: 'autobrr' } } } });
    const idx = buildPeerIndex([withUid]);
    const base = { time_stamp: '2026-09-03T05:00:00', peer_kind: 'pod', peer_namespace: 'home-system', peer_name: autobrr.pod_name };
    expect(resolvePeer(row({ ...base, peer_uid: 'uid-1' }), idx)).toEqual({ kind: 'pod', pod: withUid, stored: true });
    expect(resolvePeer(row({ ...base, peer_uid: null }), idx)).toEqual({ kind: 'pod', pod: withUid, stored: true });
    const mismatch = resolvePeer(row({ ...base, peer_uid: 'uid-2' }), idx);
    expect(mismatch.kind).toBe('pod');
    if (mismatch.kind === 'pod') expect(isPlaceholderPod(mismatch.pod)).toBe(true);
    // Wrong namespace: not that pod either.
    const wrongNs = resolvePeer(row({ ...base, peer_namespace: 'prod' }), idx);
    if (wrongNs.kind === 'pod') expect(isPlaceholderPod(wrongNs.pod)).toBe(true);
  });

  test('stored node peer = host-network pod', () => {
    const nodeExporter = pod({
      pod_name: 'node-exporter-abc12', pod_ip: '192.168.50.101', pod_namespace: 'monitoring',
      workload_kind: 'DaemonSet', workload_name: 'node-exporter', host_network: true, started_at: '2026-01-01T00:00:00',
    });
    const idx = buildPeerIndex([nodeExporter]);
    const peer = resolvePeer(row({
      traffic_in_out_ip: '192.168.50.101', peer_kind: 'node', peer_namespace: 'monitoring', peer_name: 'node-exporter-abc12',
    }), idx);
    expect(peer).toEqual({ kind: 'node', pod: nodeExporter, stored: true });
    // Same by IP when the record says host_network.
    expect(resolvePeer(row({ traffic_in_out_ip: '192.168.50.101' }), idx)).toEqual({ kind: 'node', pod: nodeExporter, stored: false });
  });

  test('stored service peer: the Service of that ns/name with a selector; gone / recycled / selector-less ⇒ svc null', () => {
    const svc: ServiceInfo = { svc_ip: '10.96.0.10', svc_name: 'db', svc_namespace: 'prod', service_spec: { spec: { selector: { app: 'db' } } } };
    const headless: ServiceInfo = { svc_ip: '10.96.0.11', svc_name: 'ext', svc_namespace: 'prod', service_spec: { spec: {} } };
    const idx = buildPeerIndex([], [svc, headless]);
    const stored = resolvePeer(row({ traffic_in_out_ip: '10.96.0.10', peer_kind: 'service', peer_namespace: 'prod', peer_name: 'db' }), idx);
    expect(stored).toEqual({ kind: 'service', namespace: 'prod', name: 'db', svc, stored: true });
    const recycled = resolvePeer(row({ traffic_in_out_ip: '10.96.0.10', peer_kind: 'service', peer_namespace: 'prod', peer_name: 'old-db' }), idx);
    expect(recycled).toEqual({ kind: 'service', namespace: 'prod', name: 'old-db', svc: null, stored: true });
    const noSelector = resolvePeer(row({ traffic_in_out_ip: '10.96.0.11', peer_kind: 'service', peer_namespace: 'prod', peer_name: 'ext' }), idx);
    expect(noSelector).toEqual({ kind: 'service', namespace: 'prod', name: 'ext', svc: null, stored: true });
    expect(peerKey(stored)).toBe('svc:prod/db');
    expect(peerKey(recycled)).toBeNull();
  });

  test('by IP: the row IP IS a ClusterIP ⇒ service (never inferred from a backend pod holding an IP)', () => {
    const svc: ServiceInfo = { svc_ip: '10.96.0.10', svc_name: 'db', svc_namespace: 'prod', service_spec: { spec: { selector: { app: 'db' } } } };
    const idx = buildPeerIndex([autobrr], [svc]);
    expect(resolvePeer(row({ traffic_in_out_ip: '10.96.0.10' }), idx)).toEqual({ kind: 'service', namespace: 'prod', name: 'db', svc, stored: false });
    // autobrr's IP with a flow older than autobrr: guarded out, not a Service.
    expect(resolvePeer(row({ traffic_in_out_ip: '10.244.12.199', time_stamp: '2026-07-23T10:00:00' }), idx).kind).toBe('unattributed');
  });

  test('null peer, IP nobody ever held → unknown (caller falls back to Service-by-IP / external)', () => {
    expect(resolvePeer(row({ traffic_in_out_ip: '203.0.113.9' }), index)).toEqual({ kind: 'unknown' });
    expect(resolvePeer(row({ traffic_in_out_ip: null }), index)).toEqual({ kind: 'unknown' });
  });

  test('pod_ips (dual-stack) are indexed too', () => {
    const dual = pod({ pod_name: 'dual', pod_ip: '10.0.0.9', pod_ips: ['10.0.0.9', 'fd00::9'], started_at: '2026-01-01T00:00:00' });
    const idx = buildPeerIndex([dual]);
    expect(resolvePeer(row({ traffic_in_out_ip: 'fd00::9' }), idx)).toEqual({ kind: 'pod', pod: dual, stored: false });
  });

  test('unrecognised peer_kind falls through to the guarded by-IP path', () => {
    expect(resolvePeer(row({ time_stamp: '2026-05-21T10:00:00', peer_kind: 'something-new', peer_name: 'x' }), index).kind).toBe('unattributed');
  });
});

describe('peerSelectorLabels', () => {
  test('workload selector labels, then pod labels, else null — never guessed', () => {
    expect(peerSelectorLabels(pod({ pod_name: 'a', pod_ip: '10.0.0.1', workload_selector_labels: { app: 'api' }, pod_obj: { metadata: { labels: { app: 'api', 'pod-template-hash': 'x' } } } }))).toEqual({ app: 'api' });
    expect(peerSelectorLabels(pod({ pod_name: 'b', pod_ip: '10.0.0.2', pod_obj: { metadata: { labels: { app: 'api' } } } }))).toEqual({ app: 'api' });
    expect(peerSelectorLabels(pod({ pod_name: 'c', pod_ip: '10.0.0.3', workload_selector_labels: {}, pod_obj: { metadata: { labels: {} } } }))).toBeNull();
    expect(peerSelectorLabels(pod({ pod_name: 'd', pod_ip: '10.0.0.4' }))).toBeNull();
  });
});

describe('rankPods tie-break', () => {
  test('identical is_dead / started_at / time_stamp ⇒ <ns>/<name> ascending', () => {
    const a = pod({ pod_name: 'web-1', pod_ip: '10.0.0.1', pod_namespace: 'prod', is_dead: true, started_at: '2026-09-01T00:00:00', time_stamp: '2026-09-02T00:00:00' });
    const b = pod({ pod_name: 'job-new', pod_ip: '10.0.0.1', pod_namespace: 'prod', is_dead: true, started_at: '2026-09-01T00:00:00', time_stamp: '2026-09-02T00:00:00' });
    expect(rankPods([a, b]).map((p) => p.pod_name)).toEqual(['job-new', 'web-1']);
  });
});
