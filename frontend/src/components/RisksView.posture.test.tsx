// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { RisksView } from './RisksView';
import api from '../services/api';
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
