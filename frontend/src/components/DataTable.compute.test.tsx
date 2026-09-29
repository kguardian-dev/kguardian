// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import DataTable from './DataTable';
import type { PodInfo, PodNodeData } from '../types';
import type { ComputeBlame, ComputeContainer, PodComputeData } from '../types/compute';

// Fix #6: the blame "Share" column is over EVERY blame entry the pod's
// containers carry, not the ten rows shown — a cut-off tail must not inflate
// the visible shares to 100%.

afterEach(cleanup);

const pod: PodInfo = { pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false };

// 12 culprits: the top one waited 100 of a 100 + 11×50 = 650 total.
const blame: ComputeBlame[] = [
  { cgroup_id: 1, kind: 'pod', ref: 'batch/etl-1/worker', container_uid: null, count: 1, wait_ns: 100_000_000 },
  ...Array.from({ length: 11 }, (_, i) => ({ cgroup_id: 10 + i, kind: 'system', ref: `system.slice/unit-${i}.service`, container_uid: null, count: 1, wait_ns: 50_000_000 })),
];
const container = { container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1', cpu_usage_millis: 100, cpu_request_millis: 250, cpu_limit_millis: 500, cpu_nr_periods: 50, cpu_period_usec: 100000, cpu_throttled_usec: 0, cpu_psi_some10: 0, cpu_psi_full10: 0, mem_working_set: 1000, mem_request: 2000, mem_limit: 4000, mem_psi_some10: 0, mem_psi_full10: 0, runq_p99_us: null, blame } as unknown as ComputeContainer;
const compute: PodComputeData = {
  cpuPct: 20, memPct: 25, cpuDenominator: 'limit', memDenominator: 'limit', status: 'ok', findings: [], sparkCpu: [], sparkMem: [], sparkWindow: { from: 0, to: 0 },
  cpuMillis: 100, memBytes: 1000, cpuCapacityMillis: 500, memCapacityBytes: 4000, containers: [container],
};
const selected: PodNodeData = { id: 'payments-api', label: 'api', pod, pods: [pod], traffic: [], isExpanded: false, compute };

test('blame share is computed over the full blame list, and only the top 10 rows are shown', () => {
  const { container: root } = render(<DataTable selectedPod={selected} allPodsLookup={[pod]} services={[]} />);
  // Sections start collapsed, so the panel opens on three headers and nothing
  // else. Open Compute the way a reader does.
  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  const table = root.querySelector('[data-testid="compute-blame"]')!;
  const rows = [...table.querySelectorAll('tbody tr')];
  expect(rows).toHaveLength(10);
  const share = rows[0].querySelectorAll('td')[3].textContent;
  expect(share).toBe('15%'); // 100 / 650, not 100 / (100 + 9×50) = 18%
  // The two rows cut off are said to exist: 100 of 650 ns is 15%.
  expect(screen.getByTestId('compute-blame-hidden').textContent).toBe('2 more culprits not listed · 15% of the wait');
});

// The broker keeps only the heaviest few culprits per container and reports
// the rest as a count and a summed wait. Shares are over both, and the panel
// says the list is not complete.
test('culprits the broker left off count toward the shares and are said to exist', () => {
  const bounded = {
    ...container,
    blame: blame.slice(0, 5), // 100 + 4×50 = 300 listed
    blame_omitted: 7,
    blame_omitted_wait_ns: 350_000_000,
  } as unknown as ComputeContainer;
  const pod1 = { ...selected, compute: { ...compute, containers: [bounded] } };
  const { container: root } = render(<DataTable selectedPod={pod1} allPodsLookup={[pod]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  const rows = [...root.querySelectorAll('[data-testid="compute-blame"] tbody tr')];
  expect(rows).toHaveLength(5);
  expect(rows[0].querySelectorAll('td')[3].textContent).toBe('15%'); // 100 / 650, not 100 / 300
  expect(screen.getByTestId('compute-blame-hidden').textContent).toBe('7 more culprits not listed · 54% of the wait');
});

test('a complete blame list claims nothing hidden', () => {
  const whole = { ...container, blame: blame.slice(0, 3), blame_omitted: 0, blame_omitted_wait_ns: 0 } as unknown as ComputeContainer;
  const pod1 = { ...selected, compute: { ...compute, containers: [whole] } };
  render(<DataTable selectedPod={pod1} allPodsLookup={[pod]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  expect(screen.getByTestId('compute-blame')).not.toBeNull();
  expect(screen.queryByTestId('compute-blame-hidden')).toBeNull();
});

// The compute header and empty state must not blame the node when it is the
// broker's compute read that is failing (App passes `computeUnavailable`).
const bare: PodNodeData = { ...selected, compute: undefined };
const openCompute = () => fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));

test('healthy poll with data: the header counts containers and the gauges render', () => {
  render(<DataTable selectedPod={selected} allPodsLookup={[pod]} services={[]} />);
  const header = screen.getByRole('button', { name: /^Compute \(/ });
  expect(header.textContent).toBe('Compute (1 container)');
  expect(header.getAttribute('title')).toBeNull();
  openCompute();
  expect(screen.getByTestId('compute-blame')).not.toBeNull();
});

test('healthy poll without data: the node-agent empty state is unchanged', () => {
  render(<DataTable selectedPod={bare} allPodsLookup={[pod]} services={[]} />);
  expect(screen.getByRole('button', { name: /^Compute \(/ }).textContent).toBe('Compute (0 containers)');
  openCompute();
  expect(screen.getByText('No compute data for this workload')).not.toBeNull();
  expect(screen.getByText(/Compute metrics arrive from the node agent/)).not.toBeNull();
  expect(screen.queryByText('Compute metrics unavailable')).toBeNull();
});

test('failing poll without data: the panel says the read is failing instead of claiming 0 containers', () => {
  render(<DataTable selectedPod={bare} allPodsLookup={[pod]} services={[]} computeUnavailable />);
  const header = screen.getByRole('button', { name: /^Compute \(/ });
  expect(header.textContent).toBe('Compute (unavailable)');
  openCompute();
  expect(screen.getByText('Compute metrics unavailable')).not.toBeNull();
  expect(screen.getByText(/the broker's compute read keeps failing and is retried with back-off/)).not.toBeNull();
  expect(screen.queryByText('No compute data for this workload')).toBeNull();
});

test('failing poll with last-good data: the data stays, and the header says it is from the last good read', () => {
  render(<DataTable selectedPod={selected} allPodsLookup={[pod]} services={[]} computeUnavailable />);
  const header = screen.getByRole('button', { name: /^Compute \(/ });
  expect(header.textContent).toBe('Compute (1 container)');
  expect(header.getAttribute('title')).toMatch(/last successful read/);
  openCompute();
  expect(screen.getByTestId('compute-blame')).not.toBeNull();
  expect(screen.queryByText('Compute metrics unavailable')).toBeNull();
});

test('failing poll, pod outside the namespace: the outage is not blamed on it', () => {
  render(<DataTable selectedPod={{ ...bare, isExternal: true }} allPodsLookup={[pod]} services={[]} computeUnavailable />);
  expect(screen.queryByText('Compute (unavailable)')).toBeNull();
  expect(screen.queryByText('Compute metrics unavailable')).toBeNull();
});
