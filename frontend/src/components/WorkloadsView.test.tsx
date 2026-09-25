// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { AuditVerdict, PodInfo } from '../types';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';

afterEach(cleanup);

const profiles: WorkloadProfileSummary[] = [
  {
    namespace: 'payments', kind: 'Deployment', name: 'api', hash: 'h', syscallCount: 61, architectures: ['x86_64'], updatedAt: 't',
    capture: { level: 'full', complete: true, pods: [{ name: 'api-1', level: 'full' }] },
    cr: {
      name: 'deployment-api', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 61,
      distribution: { ready: 3, total: 3, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true },
    },
  },
];

const verdicts: AuditVerdict[] = [
  {
    id: 1, policy_uid: 'u', policy_namespace: 'observability', policy_name: 'grafana-ingress', direction: 'Ingress',
    src_namespace: 'payments', src_pod: 'api-1', dst_namespace: 'observability', dst_pod: 'grafana-1',
    dst_port: 3000, protocol: 'TCP', reason: null, observed_at: 't', verdict: 'WouldDeny',
  },
];

vi.mock('../hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles, loading: false, error: null, refresh: async () => {} }),
}));
vi.mock('../services/api', () => ({ default: { getAuditVerdicts: async () => verdicts } }));

import { WorkloadsView } from './WorkloadsView';

const pod = (name: string, ns: string, kind: string, workload: string, over: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: ns, time_stamp: 't', node_name: 'worker-1', is_dead: false,
  workload_kind: kind, workload_name: workload, capture_level: 'high', ...over,
});

const pods = [
  pod('api-1', 'payments', 'Deployment', 'api', { capture_level: 'full' }),
  pod('grafana-1', 'observability', 'Deployment', 'grafana'),
  pod('source-controller-0', 'flux-system', 'Deployment', 'source-controller'),
];

const renderView = (over: Partial<Parameters<typeof WorkloadsView>[0]> = {}) => {
  const onOpenWorkload = vi.fn();
  const onControlChange = vi.fn();
  render(
    <WorkloadsView
      allPods={pods}
      namespace="payments"
      allNamespaces
      onOpenWorkload={onOpenWorkload}
      onControlChange={onControlChange}
      {...over}
    />,
  );
  return { onOpenWorkload, onControlChange };
};

const rows = () => screen.getAllByTestId('workload-row');

test('one row per workload across all namespaces, with network, seccomp and capture state', async () => {
  renderView();
  await waitFor(() => expect(within(rows()[1]).queryByText('Audit')).not.toBeNull());
  expect(rows().map((r) => r.querySelector('a')!.textContent)).toEqual(['source-controller', 'grafana', 'api']);

  const [flux, grafana, api] = rows();
  // Cluster-wide: the namespace is shown under the name.
  expect(within(flux).getByText(/flux-system/)).not.toBeNull();
  // Network: only an audit verdict is a positive signal; otherwise "not reported".
  expect(within(flux).getByText('Not reported')).not.toBeNull();
  expect(within(grafana).getByText('1 would-deny')).not.toBeNull();
  // Seccomp: enforcing is the posture green with a lock, never critical red.
  const enforcing = within(api).getByText('Enforcing');
  expect(enforcing.className).toContain('text-state-enforcing');
  expect(enforcing.className).not.toContain('hubble-error');
  expect(within(grafana).getByText('no profile')).not.toBeNull();
  // Capture: derived from pods when there is no profile, never assumed full.
  expect(within(grafana).getByText('· partial')).not.toBeNull();
  expect(within(api).getByText('full')).not.toBeNull();
});

test('narrowed to the header namespace when not showing all namespaces', () => {
  renderView({ allNamespaces: false, namespace: 'observability' });
  expect(rows()).toHaveLength(1);
  expect(within(rows()[0]).getByText('grafana')).not.toBeNull();
});

test('control=seccomp keeps only profiled workloads and shows the seccomp columns', () => {
  renderView({ control: 'seccomp' });
  expect(rows()).toHaveLength(1);
  expect(screen.getByRole('columnheader', { name: 'Syscalls' })).not.toBeNull();
  expect(within(rows()[0]).getByText('deployment-api')).not.toBeNull();
  expect(within(rows()[0]).getByText('61')).not.toBeNull();
});

test('clicking a row opens that workload; the control tabs switch mode', () => {
  const { onOpenWorkload, onControlChange } = renderView();
  fireEvent.click(rows()[2]);
  expect(onOpenWorkload).toHaveBeenCalledWith(expect.objectContaining({ namespace: 'payments', kind: 'Deployment', name: 'api' }));
  // The name is also a real link, so it can be opened in a new tab or copied.
  expect(rows()[2].querySelector('a')!.getAttribute('href')).toBe('#/workload?ns=payments&kind=Deployment&name=api');

  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp' }));
  expect(onControlChange).toHaveBeenCalledWith('seccomp');
});

test('the seccomp posture tile links into the seccomp columns', () => {
  const { onControlChange } = renderView();
  fireEvent.click(screen.getByRole('button', { name: /Seccomp enforcing/ }));
  expect(onControlChange).toHaveBeenCalledWith('seccomp');
});
