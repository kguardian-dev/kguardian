import { expect, test } from 'vitest';
import type { AuditVerdict, PodInfo } from '../types';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';
import { buildWorkloadRows, workloadOf } from './workloads';

const pod = (name: string, over: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false,
  workload_kind: 'Deployment', workload_name: 'api', capture_level: 'full', ...over,
});

const profile = (over: Partial<WorkloadProfileSummary> = {}): WorkloadProfileSummary => ({
  namespace: 'payments', kind: 'Deployment', name: 'api', hash: 'h', syscallCount: 42, architectures: ['x86_64'], updatedAt: 't',
  capture: { level: 'full', complete: true, pods: [{ name: 'api-1', level: 'full' }] },
  cr: null,
  ...over,
});

const verdict = (over: Partial<AuditVerdict> = {}): AuditVerdict => ({
  id: 1, policy_uid: 'u', policy_namespace: 'payments', policy_name: 'api-ingress', direction: 'Ingress',
  src_namespace: 'observability', src_pod: 'prometheus-0', dst_namespace: 'payments', dst_pod: 'api-1',
  dst_port: 8080, protocol: 'TCP', reason: null, observed_at: 't', verdict: 'Allow', ...over,
});

test('groups live pods into one row per workload, keyed like seccomp profiles', () => {
  const rows = buildWorkloadRows([pod('api-1'), pod('api-2'), pod('db-0', { workload_kind: 'StatefulSet', workload_name: 'db' })], []);
  expect(rows.map((r) => r.key)).toEqual(['payments/Deployment/api', 'payments/StatefulSet/db']);
  expect(rows[0].pods.map((p) => p.pod_name)).toEqual(['api-1', 'api-2']);
});

test('a bare pod is its own workload of kind Pod', () => {
  expect(workloadOf(pod('debug', { workload_kind: null, workload_name: null }))).toEqual({ namespace: 'payments', kind: 'Pod', name: 'debug' });
});

test('dead pods do not create rows, but a profile keeps a scaled-to-zero workload listed', () => {
  const rows = buildWorkloadRows(
    [pod('old-1', { workload_name: 'old', is_dead: true }), pod('job-1', { workload_kind: 'CronJob', workload_name: 'report', is_dead: true })],
    [profile({ kind: 'CronJob', name: 'report' })],
  );
  expect(rows.map((r) => r.key)).toEqual(['payments/CronJob/report']);
  expect(rows[0].pods).toEqual([]);
});

test('seccomp state, drift and capture come from the profile', () => {
  const drift = { missing: ['ptrace'], extra: [], inSync: false };
  const [row] = buildWorkloadRows(
    [pod('api-1')],
    [profile({ cr: { name: 'deployment-api', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 41, distribution: { ready: 3, total: 3, state: 'Ready' }, drift } })],
  );
  expect(row.seccomp).toBe('enforcing');
  expect(row.drift).toEqual(drift);
  expect(row.capture.complete).toBe(true);
});

test('without a profile, capture is derived from the pods and never assumed full', () => {
  const [row] = buildWorkloadRows([pod('api-1'), pod('api-2', { capture_level: 'low' })], []);
  expect(row.seccomp).toBe('none');
  expect(row.drift).toBeNull();
  expect(row.capture).toMatchObject({ level: 'low', complete: false });
});

test('audit verdicts attribute to the subject pod: destination for ingress, source for egress', () => {
  const rows = buildWorkloadRows(
    [pod('api-1'), pod('prometheus-0', { pod_namespace: 'observability', workload_kind: 'StatefulSet', workload_name: 'prometheus' })],
    [],
    [
      verdict(),
      verdict({ id: 2, verdict: 'WouldDeny' }),
      verdict({ id: 3, direction: 'Egress', policy_namespace: 'observability', policy_name: 'prom-egress' }),
    ],
  );
  const api = rows.find((r) => r.name === 'api')!;
  const prom = rows.find((r) => r.name === 'prometheus')!;
  expect(api.network).toEqual({ state: 'audit', policies: ['payments/api-ingress'], wouldDeny: 1, verdicts: 2 });
  expect(prom.network).toEqual({ state: 'audit', policies: ['observability/prom-egress'], wouldDeny: 0, verdicts: 1 });
});

test('a verdict about a pod that has since been replaced still counts for its workload', () => {
  const rows = buildWorkloadRows([pod('api-old', { is_dead: true }), pod('api-new')], [], [verdict({ dst_pod: 'api-old' })]);
  expect(rows[0].network.state).toBe('audit');
});

test('no verdict means "unreported", not "no policy"', () => {
  const [row] = buildWorkloadRows([pod('api-1')], [], [verdict({ dst_pod: 'someone-else' })]);
  expect(row.network).toEqual({ state: 'unreported' });
});

import { crDistribution, hasBlockingDrift, syscallsDimensionFromSeccomp, verdictsForNamespace } from './workloads';

test('while the profile list is unavailable, a row without a profile is unknown: no CR state, no drift, no capture claim', () => {
  const [row] = buildWorkloadRows([pod('api-1')], [], [], { seccompUnavailable: true });
  expect(row.seccomp).toBe('unknown');
  expect(row.drift).toBeNull();
  expect(row.capture).toBeNull();
  // A row that does have a profile is known regardless.
  const [known] = buildWorkloadRows([pod('api-1')], [profile()], [], { seccompUnavailable: true });
  expect(known.seccomp).toBe('none');
  expect(known.capture).toMatchObject({ level: 'full', complete: true });
});

test('per-workload fallback reads answer for their row: a profile, or null for "the Broker has none"', () => {
  const fallback = new Map([
    ['payments/Deployment/api', profile({ cr: { name: 'deployment-api', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 41, distribution: { ready: 3, total: 3, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true } } })],
    ['payments/StatefulSet/db', null],
  ]);
  const rows = buildWorkloadRows(
    [pod('api-1'), pod('db-0', { workload_kind: 'StatefulSet', workload_name: 'db', capture_level: 'low' }), pod('w-0', { workload_name: 'worker' })],
    [],
    [],
    { seccompUnavailable: true, seccompFallback: fallback },
  );
  const by = (n: string) => rows.find((r) => r.name === n)!;
  expect(by('api').seccomp).toBe('enforcing');
  expect(by('db').seccomp).toBe('none');
  expect(by('db').capture).toMatchObject({ level: 'low', complete: false });
  expect(by('worker').seccomp).toBe('unknown');
  expect(by('worker').capture).toBeNull();
  // Once the list has loaded it is authoritative: a stale fallback read does not outrank "no profile".
  const [loaded] = buildWorkloadRows([pod('api-1')], [], [], { seccompUnavailable: false, seccompFallback: fallback });
  expect(loaded.profile).toBeNull();
  expect(loaded.seccomp).toBe('none');
});

test('verdictsForNamespace keeps verdicts by subject namespace, so a cluster-scoped policy still counts', () => {
  const cluster = { policy_namespace: '', policy_name: 'cluster-baseline-audit' };
  const kept = verdictsForNamespace(
    [
      verdict({ id: 1, ...cluster, dst_namespace: 'payments', dst_pod: 'api-1' }),
      verdict({ id: 2, ...cluster, dst_namespace: 'observability', dst_pod: 'grafana-1' }),
      // Egress: the subject is the source.
      verdict({ id: 3, ...cluster, direction: 'Egress', src_namespace: 'payments', src_pod: 'api-1', dst_namespace: 'observability', dst_pod: 'grafana-1' }),
      verdict({ id: 4, ...cluster, direction: 'Egress', src_namespace: 'observability', src_pod: 'grafana-1', dst_namespace: 'payments', dst_pod: 'api-1' }),
    ],
    'payments',
  );
  expect(kept.map((v) => v.id)).toEqual([1, 3]);
  // A subject whose pod the Broker no longer knows still belongs to its namespace.
  expect(verdictsForNamespace([verdict({ ...cluster, dst_namespace: 'payments', dst_pod: null })], 'payments')).toHaveLength(1);
  // And the rows attribute them.
  const [row] = buildWorkloadRows([pod('api-1')], [], kept);
  expect(row.network).toEqual({ state: 'audit', policies: ['cluster-baseline-audit'], wouldDeny: 0, verdicts: 2 });
});

test('only observed syscalls the CR lacks are a drift; allowed-but-unobserved is not', () => {
  expect(hasBlockingDrift(null)).toBe(false);
  expect(hasBlockingDrift({ missing: [], extra: ['mount'], inSync: false })).toBe(false);
  expect(hasBlockingDrift({ missing: ['ptrace'], extra: [], inSync: false })).toBe(true);
});

test('crDistribution prefers the CR\'s own status.distribution and qualifies it with the Broker\'s count when they differ', () => {
  const broker = { ready: 55, total: 55, state: 'Ready', present: 55 };
  expect(crDistribution({ distribution: broker, statusDistribution: { ready: 60, total: 60, state: 'Ready' } })).toEqual({
    primary: { ready: 60, total: 60, state: 'Ready' },
    reporting: broker,
  });
  // The same numbers need no qualifier; no mirrored status falls back to the Broker's.
  expect(crDistribution({ distribution: broker, statusDistribution: { ready: 55, total: 55, state: 'Ready' } }).reporting).toBeNull();
  expect(crDistribution({ distribution: broker, statusDistribution: null })).toEqual({ primary: broker, reporting: null });
  expect(crDistribution({ distribution: broker })).toEqual({ primary: broker, reporting: null });
  // A mirrored status without a state word gets one from its own numbers.
  expect(crDistribution({ distribution: broker, statusDistribution: { ready: 30, total: 60 } as never }).primary.state).toBe('Partial');
});

test('syscallsDimensionFromSeccomp carries the observed set, capture and CR, with posture and denials unknown', () => {
  const dim = syscallsDimensionFromSeccomp(
    profile({
      syscallCount: 104, architectures: ['SCMP_ARCH_AARCH64'], hash: 'd209', updatedAt: '2026-09-14T00:33:32Z',
      capture: { level: 'full', complete: false, pods: [{ name: 'a', level: 'full' }, { name: 'b', level: 'low' }] },
      cr: {
        name: 'media-transform-api', defaultAction: 'SCMP_ACT_LOG', hash: 'x', syscallCount: 140,
        distribution: { ready: 55, total: 55, state: 'Ready' }, statusDistribution: { ready: 60, total: 60, state: 'Ready' },
        drift: { missing: [], extra: ['mount'], inSync: false },
      },
    }),
  );
  expect(dim.status).toBe('unknown');
  expect(dim.denials).toBeNull();
  expect(dim.observed).toEqual({ syscallCount: 104, hash: 'd209', architectures: ['SCMP_ARCH_AARCH64'], updatedAt: '2026-09-14T00:33:32Z' });
  expect(dim.capture).toEqual({ level: 'full', complete: false, incompletePods: 1 });
  // The Broker's count stays `distribution` (what the profile contract means by it); the CR's own status rides along.
  expect(dim.cr).toEqual({
    name: 'media-transform-api', defaultAction: 'SCMP_ACT_LOG', mode: 'audit', syscallCount: 140, inSync: false, missing: [], extra: ['mount'],
    distribution: { ready: 55, total: 55, state: 'Ready' },
    statusDistribution: { ready: 60, total: 60, state: 'Ready' },
  });
  // The Broker truncates the pod list, so its own incomplete count wins when present.
  expect(syscallsDimensionFromSeccomp(profile({ capture: { level: 'low', complete: false, pods: [{ name: 'a', level: 'low' }], incomplete: 7, more: 6 } })).capture!.incompletePods).toBe(7);
  expect(syscallsDimensionFromSeccomp(profile({ cr: { name: 'c', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 1, distribution: { ready: 1, total: 1, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true } } })).cr!.mode).toBe('enforce');
  expect(syscallsDimensionFromSeccomp(profile({ capture: undefined })).capture).toBeNull();
});
