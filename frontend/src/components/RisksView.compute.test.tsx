// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { RisksView } from './RisksView';
import api from '../services/api';
import type { ComputeFinding } from '../types/compute';

// Fix #3: the compute node filter must never strand the user — it resets on
// a namespace change and when the picked node no longer has a finding, and
// a Clear control is shown whenever a filter is active.

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  vi.spyOn(api, 'getAuditVerdicts').mockResolvedValue([]);
});

const finding = (pod: string, nodeName: string): ComputeFinding => ({
  kind: 'cpu-throttled', severity: 'medium',
  victim: { pod_uid: `uid-${pod}`, namespace: 'payments', pod_name: pod, container: 'app', container_uid: `uid-${pod}/app`, node: nodeName },
  culprit: null,
  evidence: { window_minutes: 5, cpu_psi_some10_max: 0, cpu_psi_full10_max: 0, runq_p99_us_max: null, throttled_ratio: 0.3, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
  first_seen: 't', last_seen: 't', message: `${pod} is throttled`,
});

const view = (over: Partial<Parameters<typeof RisksView>[0]> = {}) => (
  <RisksView
    pods={[]}
    namespace="payments"
    onSelectPod={() => {}}
    onBuildPolicy={() => {}}
    onOpenAudit={() => {}}
    computeEnabled
    computeFindings={[finding('api-1', 'worker-1'), finding('etl-1', 'worker-2')]}
    onViewWorkload={() => {}}
    {...over}
  />
);

const select = () => screen.getByLabelText('Filter compute findings by node') as HTMLSelectElement;

test('picking a node filters the list and offers Clear', () => {
  render(view());
  expect(screen.getByText('api-1 · app')).not.toBeNull();
  fireEvent.change(select(), { target: { value: 'worker-2' } });
  expect(screen.queryByText('api-1 · app')).toBeNull();
  expect(screen.getByText('etl-1 · app')).not.toBeNull();
  fireEvent.click(screen.getByText('Clear'));
  expect(select().value).toBe('all');
  expect(screen.getByText('api-1 · app')).not.toBeNull();
});

test('a namespace change resets the filter', () => {
  const { rerender } = render(view());
  fireEvent.change(select(), { target: { value: 'worker-2' } });
  expect(select().value).toBe('worker-2');
  rerender(view({ namespace: 'batch' }));
  expect(select().value).toBe('all');
  expect(screen.queryByText('Clear')).toBeNull();
});

test('when the picked node no longer has a finding the filter falls back to all (no empty list)', () => {
  const { rerender } = render(view());
  fireEvent.change(select(), { target: { value: 'worker-2' } });
  rerender(view({ computeFindings: [finding('api-1', 'worker-1'), finding('api-2', 'worker-1')] }));
  expect(screen.getByText('api-1 · app')).not.toBeNull();
  expect(screen.getByText('api-2 · app')).not.toBeNull();
  expect(screen.queryByText('No compute findings on this node.')).toBeNull();
});

test('truncated: one-line notice naming the victim cap', () => {
  render(view({ computeMeta: { truncated: true, victimsEvaluated: 500, historyDisabled: false } }));
  expect(screen.getByTestId('compute-truncated').textContent).toBe('Findings evaluated for the first 500 victims; narrow by namespace or node.');
  cleanup();
  render(view({ computeMeta: { truncated: false, victimsEvaluated: 2, historyDisabled: false } }));
  expect(screen.queryByTestId('compute-truncated')).toBeNull();
});

test('history disabled: the Compute stat tile carries the hint even when other findings exist', () => {
  render(view({ computeMeta: { truncated: false, victimsEvaluated: null, historyDisabled: true } }));
  expect(screen.getByText('Compute (history off)')).not.toBeNull();
  cleanup();
  render(view());
  expect(screen.queryByText('Compute (history off)')).toBeNull();
  expect(screen.getByText('Compute')).not.toBeNull();
});

test('history disabled: the empty state says findings cannot be computed', async () => {
  render(view({ computeFindings: [], computeMeta: { truncated: false, victimsEvaluated: null, historyDisabled: true } }));
  // The empty state appears once the audit-verdict fetch has settled.
  expect(await screen.findByText(/history retention is disabled/)).not.toBeNull();
});

test('blame share wording is kind-aware; an opted-out culprit reads "—" with a usage-unknown tooltip', () => {
  const culprit = (over: Partial<NonNullable<ComputeFinding['culprit']>> = {}) => ({
    kind: 'pod', ref: 'batch/etl-1/worker', pod_uid: 'uid-etl', namespace: 'batch', pod_name: 'etl-1', container_uid: null,
    blame_share: 0.71, cpu_usage_millis: 1900, cpu_request_millis: 500, ...over,
  });
  const cpu: ComputeFinding = { ...finding('api-1', 'worker-1'), kind: 'noisy-neighbor', culprit: culprit() };
  const mem: ComputeFinding = { ...finding('api-2', 'worker-1'), kind: 'memory-pressure', culprit: culprit({ pod_name: 'hog-1', blame_share: 0.55, cpu_usage_millis: null }) };
  render(view({ computeFindings: [cpu, mem] }));
  const cpuSpan = screen.getByText(/← batch\/etl-1/);
  expect(cpuSpan.textContent).toBe('← batch/etl-1 (71%, 1.90 cores)');
  expect(cpuSpan.getAttribute('title')).toBe('71% of its CPU wait; using 1.90 cores');
  const memSpan = screen.getByText(/← batch\/hog-1/);
  expect(memSpan.textContent).toBe('← batch/hog-1 (55%, —)');
  expect(memSpan.getAttribute('title')).toBe('55% of node memory overage; usage unknown (opted out of sampling)');
});

test('resources findings offer "View workload", never a Policy button', () => {
  const onViewWorkload = vi.fn();
  render(view({ onViewWorkload }));
  expect(screen.queryByText('Policy')).toBeNull();
  fireEvent.click(screen.getAllByText('View workload')[0]);
  expect(onViewWorkload).toHaveBeenCalledWith('payments', 'api-1');
});
