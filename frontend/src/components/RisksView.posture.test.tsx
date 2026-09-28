// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { RisksView } from './RisksView';
import api from '../services/api';
import type { AuditVerdict } from '../types';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';

// The posture strip on Risks: shared StatTile, a seccomp tile counted for the
// header namespace only, and severity pills from the dedicated scale.

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  vi.spyOn(api, 'getAuditVerdicts').mockResolvedValue([]);
});

const profile = (ns: string, name: string, action: string | null): WorkloadProfileSummary => ({
  namespace: ns, kind: 'Deployment', name, hash: 'h', syscallCount: 10, architectures: [], updatedAt: 't',
  cr: action
    ? { name: `deployment-${name}`, defaultAction: action, hash: 'x', syscallCount: 10, distribution: { ready: 1, total: 1, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true } }
    : null,
});

const view = (over: Partial<Parameters<typeof RisksView>[0]> = {}) =>
  render(
    <RisksView pods={[]} namespace="payments" onSelectPod={() => {}} onBuildPolicy={() => {}} onOpenAudit={() => {}} {...over} />,
  );

test('the view is titled Risks', () => {
  view();
  expect(screen.getByRole('heading', { name: 'Risks' })).not.toBeNull();
});

test('seccomp tile counts enforcing profiles in this namespace and links to Workloads', () => {
  const onOpenWorkloads = vi.fn();
  view({
    onOpenWorkloads,
    seccompProfiles: [
      profile('payments', 'api', 'SCMP_ACT_ERRNO'),
      profile('payments', 'worker', 'SCMP_ACT_LOG'),
      profile('observability', 'grafana', 'SCMP_ACT_ERRNO'),
    ],
  });
  const tile = screen.getByRole('button', { name: /Seccomp enforcing/ });
  expect(tile.textContent).toContain('1/2');
  fireEvent.click(tile);
  expect(onOpenWorkloads).toHaveBeenCalledWith('seccomp');
});

test('no profile list, no seccomp tile (never a false 0/0)', () => {
  view();
  expect(screen.queryByText('Seccomp enforcing')).toBeNull();
});

test('sensitive-syscall pills use the severity scale, and medium is not brand indigo', () => {
  const pod = { pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'n', is_dead: false };
  view({
    pods: [{
      id: 'payments-api', label: 'api', pod, pods: [pod], traffic: [], isExpanded: false,
      syscalls: [{ pod_name: 'api-1', pod_namespace: 'payments', syscalls: 'read,bpf,chroot', arch: 'x86_64', time_stamp: 't' }],
    }],
  });
  const medium = screen.getByText('chroot');
  expect(medium.className).toContain('text-severity-medium');
  expect(medium.className).not.toContain('hubble-accent');
  expect(screen.getByText('bpf').className).toContain('text-severity-critical');
});

test('syscall names that collide with Object.prototype are not sensitive', () => {
  const pod = { pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'n', is_dead: false };
  view({
    pods: [{
      id: 'payments-api', label: 'api', pod, pods: [pod], traffic: [], isExpanded: false,
      syscalls: [{ pod_name: 'api-1', pod_namespace: 'payments', syscalls: 'constructor,toString,__proto__', arch: 'x86_64', time_stamp: 't' }],
    }],
  });
  expect(screen.queryByText('Sensitive syscalls', { selector: 'h3' })).toBeNull();
  expect(screen.queryByText('constructor')).toBeNull();
});

test('while the profile list is unavailable the seccomp tile stays, with a dash and the reason', () => {
  view({ seccompUnavailable: 'the profile list could not be read (canceling statement due to statement timeout)' });
  const tile = screen.getByText('Seccomp enforcing').closest('[title]')!;
  expect(tile.textContent).toContain('—');
  expect(tile.textContent).not.toMatch(/\d/);
  expect(tile.getAttribute('title')).toMatch(/statement timeout/);
});

test('would-deny verdicts come from the cluster-wide window and are kept by the subject pod\'s namespace, so a cluster-scoped policy counts', async () => {
  const v = (id: number, over: Partial<AuditVerdict>): AuditVerdict => ({
    id, policy_uid: 'u', policy_namespace: '', policy_name: 'cluster-baseline-audit', direction: 'Ingress',
    src_namespace: 'observability', src_pod: 'prometheus-0', dst_namespace: 'payments', dst_pod: 'api-1',
    dst_port: 8080, protocol: 'TCP', reason: null, observed_at: 't', verdict: 'WouldDeny', ...over,
  });
  const spy = vi.spyOn(api, 'getAuditVerdicts').mockResolvedValue([
    v(1, {}),
    v(2, { dst_namespace: 'observability', dst_pod: 'grafana-1' }),
    // Egress: the subject is the source.
    v(3, { direction: 'Egress', src_namespace: 'payments', src_pod: 'api-1', dst_namespace: 'observability', dst_pod: 'grafana-1' }),
    v(4, { direction: 'Egress', src_namespace: 'observability', src_pod: 'grafana-1', dst_namespace: 'payments', dst_pod: 'api-1' }),
  ]);
  view();
  expect(await screen.findByText('2 would-deny')).not.toBeNull();
  expect(screen.getByText('cluster-baseline-audit')).not.toBeNull();
  expect(spy).toHaveBeenCalledWith({ verdict: 'WouldDeny', limit: 500 });
});

test('a failed verdict read is an error in the would-deny section, never "No standout findings" or an empty list', async () => {
  vi.spyOn(api, 'getAuditVerdicts').mockRejectedValue(new Error('canceling statement due to statement timeout'));
  view();
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/Could not read audit verdicts: canceling statement due to statement timeout/);
  expect(alert.textContent).toMatch(/unknown, not zero/);
  expect(screen.queryByText('No standout findings')).toBeNull();
  expect(screen.queryByText(/No would-deny verdicts/)).toBeNull();
});

test('the header Refresh retries a failed verdict read and clears the error once it succeeds', async () => {
  const v: AuditVerdict = {
    id: 1, policy_uid: 'u', policy_namespace: '', policy_name: 'cluster-baseline-audit', direction: 'Ingress',
    src_namespace: 'observability', src_pod: 'prometheus-0', dst_namespace: 'payments', dst_pod: 'api-1',
    dst_port: 8080, protocol: 'TCP', reason: null, observed_at: 't', verdict: 'WouldDeny',
  };
  const spy = vi.spyOn(api, 'getAuditVerdicts').mockRejectedValueOnce(new Error('canceling statement due to statement timeout')).mockResolvedValueOnce([v]);
  const props = { pods: [], namespace: 'payments', onSelectPod: () => {}, onBuildPolicy: () => {}, onOpenAudit: () => {} };
  const { rerender } = render(<RisksView {...props} refreshTick={0} />);
  expect((await screen.findByRole('alert')).textContent).toMatch(/Could not read audit verdicts/);
  rerender(<RisksView {...props} refreshTick={1} />);
  expect(await screen.findByText('1 would-deny')).not.toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(spy).toHaveBeenCalledTimes(2);
});
