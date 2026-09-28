// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { PodInfo } from '../types';

// The picker showed every workload whose traffic read timed out as "0 conns",
// indistinguishable from a workload that really is idle — and the editor
// then built a deny-all from that "zero". The map's data hook marks such
// workloads; the picker has to show the mark.

vi.mock('./NetworkPolicyEditor', () => ({ default: () => null }));

import { PolicyBuilderModal } from './PolicyBuilderModal';
import type { PolicyWorkload } from './NetworkPolicyEditor';

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'argocd', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const workload = (name: string, traffic: unknown[], extra: Partial<PolicyWorkload> = {}): PolicyWorkload => {
  const pod = podRecord({ pod_name: `${name}-0`, pod_ip: '10.0.0.1', pod_identity: name });
  return { id: name, label: name, pod, pods: [pod], traffic, isExpanded: false, ...extra } as PolicyWorkload;
};

afterEach(cleanup);

test('a workload whose traffic read failed says so instead of "0 conns"', () => {
  render(
    <PolicyBuilderModal
      onClose={() => {}}
      initialPod={null}
      workloads={[workload('argo-rollouts', [], { trafficError: true }), workload('argocd-server', [])]}
    />,
  );
  expect(screen.getByText('traffic read failed')).toBeTruthy();
  expect(screen.getAllByText(/conns$/)).toHaveLength(1);
  expect(screen.getByText('0 conns')).toBeTruthy();
  expect(screen.getByRole('status').textContent).toContain('Traffic reads failed for 1 workload;');
});

test('the status line counts workloads with a failed read, not reads', () => {
  render(
    <PolicyBuilderModal
      onClose={() => {}}
      initialPod={null}
      workloads={[workload('a', [], { trafficError: true }), workload('b', [], { trafficError: true }), workload('c', [])]}
    />,
  );
  expect(screen.getByRole('status').textContent).toContain('Traffic reads failed for 2 workloads;');
});

test('a failed syscall read is shown instead of a hidden zero', () => {
  render(
    <PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[workload('argocd-repo-server', [{}], { syscallsError: true })]} />,
  );
  expect(screen.getByText('1 conns')).toBeTruthy();
  expect(screen.getByText('syscall read failed')).toBeTruthy();
});

// TOOL-15: while the pod listing is still loading the picker used to show
// "No workloads in this namespace" and advise switching namespaces.
test('while loading with nothing listed yet, a loading row replaces the empty state', () => {
  render(<PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[]} loading />);
  expect(screen.getByRole('status').textContent).toContain('Loading workloads');
  expect(screen.queryByText('No workloads in this namespace')).toBeNull();
  expect(screen.queryByText(/Switch namespaces/)).toBeNull();
});

test('not loading and nothing listed: the empty state and its advice as before', () => {
  render(<PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[]} />);
  expect(screen.getByText('No workloads in this namespace')).toBeTruthy();
  expect(screen.getByText(/Switch namespaces/)).toBeTruthy();
  expect(screen.queryByText(/Loading workloads/)).toBeNull();
});

test('loading with workloads already listed shows the list, not the loading row', () => {
  render(<PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[workload('argocd-server', [{}])]} loading />);
  expect(screen.getByText('argocd-server')).toBeTruthy();
  expect(screen.queryByText(/Loading workloads/)).toBeNull();
});

test('loading with workloads listed and a search that matches none says no match, not loading', () => {
  render(<PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[workload('argocd-server', [{}])]} loading />);
  fireEvent.change(screen.getByPlaceholderText(/Search workloads/), { target: { value: 'zzz' } });
  expect(screen.getByText('No matching workloads')).toBeTruthy();
  expect(screen.queryByText(/Loading workloads/)).toBeNull();
});

test('with every read complete the picker is unchanged', () => {
  render(
    <PolicyBuilderModal onClose={() => {}} initialPod={null} workloads={[workload('argocd-server', [{}, {}, {}])]} />,
  );
  expect(screen.getByText('3 conns')).toBeTruthy();
  expect(screen.queryByText('traffic read failed')).toBeNull();
  expect(screen.queryByText('syscall read failed')).toBeNull();
  expect(screen.queryByRole('status')).toBeNull();
});
