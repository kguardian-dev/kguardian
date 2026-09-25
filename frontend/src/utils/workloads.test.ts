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
