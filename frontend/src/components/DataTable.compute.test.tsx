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
});
