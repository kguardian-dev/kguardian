// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { RisksView } from './RisksView';
import api from '../services/api';
import type { PodNodeData } from '../types';

// Risks took no loading or error input and ignored failed per-pod reads, so
// it read "No standout findings" with Workloads 0 / Blocked 0 / Sensitive
// syscalls 0 while the namespace was still loading, indefinitely after the
// pod listing failed, and when every pod's reads had failed. A compute feed
// that was down was likewise summed up as "no compute contention".

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  vi.spyOn(api, 'getAuditVerdicts').mockResolvedValue([]);
});

const p = { pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'n', is_dead: false };
const node = (over: Partial<PodNodeData> = {}) =>
  ({ id: 'payments-api', label: 'api', pod: p, pods: [p], traffic: [], syscalls: undefined, isExpanded: false, ...over }) as PodNodeData;

type Props = Parameters<typeof RisksView>[0];
const view = (over: Partial<Props> = {}) => (
  <RisksView pods={[]} namespace="payments" onSelectPod={() => {}} onBuildPolicy={() => {}} onOpenAudit={() => {}} {...over} />
);

const tile = (label: string) => screen.getByText(label).closest('div')!.parentElement!;
const settleAudit = () => waitFor(() => expect(api.getAuditVerdicts).toHaveBeenCalled());

test('while the namespace is loading: no clean empty state, the pod counts are unknown', async () => {
  render(view({ podsLoading: true }));
  await settleAudit();
  await new Promise((r) => setTimeout(r, 0));
  expect(screen.queryByText('No standout findings')).toBeNull();
  expect(screen.getByRole('status', { name: /Reading the workloads in payments/ })).not.toBeNull();
  for (const label of ['Workloads', 'Blocked connections', 'Sensitive syscalls', 'Egress fan-out']) {
    expect(tile(label).textContent).toContain('—');
  }
});

test('the pod listing failed: an error, never "No standout findings"', async () => {
  render(view({ podsError: 'timeout of 35000ms exceeded' }));
  await settleAudit();
  await new Promise((r) => setTimeout(r, 0));
  expect(screen.queryByText('No standout findings')).toBeNull();
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toMatch(/Could not read the workloads in payments: timeout of 35000ms exceeded/);
  expect(alert.textContent).toMatch(/unknown, not zero/);
  expect(tile('Blocked connections').textContent).toContain('—');
});

test('every read of the only pod failed: its zeros are unknown, and the empty state does not claim otherwise', async () => {
  render(view({ pods: [node({ trafficError: true, syscallsError: true })], failedReads: { traffic: 1, syscalls: 1 } }));
  await settleAudit();
  await new Promise((r) => setTimeout(r, 0));
  expect(screen.queryByText('No standout findings')).toBeNull();
  expect(screen.getByText(/1 traffic read and 1 syscall read failed/)).not.toBeNull();
  expect(tile('Blocked connections').textContent).toContain('—');
  expect(tile('Sensitive syscalls').textContent).toContain('—');
  expect(tile('Egress fan-out').textContent).toContain('—');
  expect(tile('Workloads').textContent).toContain('1');
});

test('a tile with findings takes you to them; a tile counting nothing is not a button', async () => {
  const scrollIntoView = vi.fn();
  // jsdom has no layout, so scrollIntoView is not implemented on elements.
  Object.defineProperty(Element.prototype, 'scrollIntoView', { value: scrollIntoView, writable: true, configurable: true });
  const drop = (uuid: string) => ({
    uuid, pod_name: 'api-1', pod_namespace: 'payments', pod_ip: '10.0.0.1', pod_port: '8080',
    ip_protocol: 'TCP', traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.9', traffic_in_out_port: '5432',
    decision: 'DROP', time_stamp: 't',
  });
  render(view({ pods: [node({ traffic: [drop('a'), drop('b')] })] }));
  await settleAudit();
  // Scoped to the strip: with findings present, the section header carries the
  // same words as the tile.
  const strip = () => within(screen.getByRole('group', { name: 'Posture' }));
  await waitFor(() => expect(strip().getByRole('button', { name: /Blocked connections/ }).textContent).toContain('2'));

  fireEvent.click(strip().getByRole('button', { name: /Blocked connections/ }));
  expect(scrollIntoView).toHaveBeenCalled();

  // Nothing to show means nothing to scroll to: the tile stays a plain number.
  expect(strip().getByText('Egress fan-out').closest('div')!.parentElement!.textContent).toContain('0');
  expect(strip().queryByRole('button', { name: /Egress fan-out/ })).toBeNull();
  // The workload count has no section of its own and is never a button.
  expect(strip().queryByRole('button', { name: /Workloads/ })).toBeNull();
});

test('a loaded namespace with nothing to report still reads "No standout findings"', async () => {
  render(view({ pods: [node()] }));
  await waitFor(() => expect(screen.getByText('No standout findings')).not.toBeNull());
  expect(tile('Blocked connections').textContent).toContain('0');
});

test('the compute feed is down with no cached findings: compute is unknown, not "no compute contention"', async () => {
  render(view({ pods: [node()], computeEnabled: true, computeUnavailable: true }));
  await waitFor(() => expect(screen.getByText('No standout findings')).not.toBeNull());
  expect(screen.queryByText(/compute contention,/)).toBeNull();
  expect(screen.getByText(/Compute findings are unknown: the live compute feed is not answering/)).not.toBeNull();
});
