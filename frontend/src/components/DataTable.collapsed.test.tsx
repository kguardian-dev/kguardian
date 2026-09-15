// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import DataTable from './DataTable';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';
import type { ComputeContainer, PodComputeData } from '../types/compute';

// The panel shares the screen with the map, and a selection now focuses the
// graph as well as opening the card. So it opens on its three section headers
// and nothing else: the reader opens the one they came for.
//
// It also no longer repeats the workload's name, namespace or replica list.
// All three are on the card that is open on the map, and here they cost a
// fixed block of the space the sections need.

afterEach(cleanup);

const pod: PodInfo = {
  pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments',
  time_stamp: 't', node_name: 'worker-1', is_dead: false,
};
const other: PodInfo = { ...pod, pod_name: 'api-2', pod_ip: '10.0.0.2' };

const container = {
  container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1',
  container: 'app', node: 'worker-1', cpu_usage_millis: 100, cpu_request_millis: 250,
  cpu_limit_millis: 500, cpu_nr_periods: 50, cpu_period_usec: 100000, cpu_throttled_usec: 0,
  cpu_psi_some10: 0, cpu_psi_full10: 0, mem_working_set: 1000, mem_request: 2000,
  mem_limit: 4000, mem_psi_some10: 0, mem_psi_full10: 0, runq_p99_us: null, blame: [],
} as unknown as ComputeContainer;

const compute: PodComputeData = {
  cpuPct: 20, memPct: 25, cpuDenominator: 'limit', memDenominator: 'limit', status: 'ok',
  findings: [], sparkCpu: [], sparkMem: [], sparkWindow: { from: 0, to: 0 },
  cpuMillis: 100, memBytes: 1000, cpuCapacityMillis: 500, memCapacityBytes: 4000,
  containers: [container],
};

const traffic = [{
  uuid: 't1', pod_name: 'api-1', pod_namespace: 'payments', pod_ip: '10.0.0.1',
  pod_port: '443', traffic_in_out_ip: '10.0.0.9', traffic_in_out_port: '8080',
  traffic_type: 'EGRESS', ip_protocol: 'TCP', time_stamp: 't',
}] as unknown as NetworkTraffic[];

const selected = (over: Partial<PodNodeData> = {}): PodNodeData => ({
  id: 'payments-api', label: 'api', pod, pods: [pod, other], traffic,
  isExpanded: false, compute,
  syscalls: [{ pod_name: 'api-1', syscalls: 'read,write,openat' }],
  ...over,
} as PodNodeData);

const render1 = (sel: PodNodeData) =>
  render(<DataTable selectedPod={sel} allPodsLookup={[pod, other]} services={[]} />);

// `aria-expanded` is read rather than the section's content, and that is
// deliberate. A section renders its body only when it is open AND has data,
// so asserting on content passes for a fixture that simply has none — the
// first version of this test did exactly that and survived flipping every
// default back to open. The attribute is bound straight to the state, so it
// cannot be satisfied by an empty fixture.
const sections = () => [
  screen.getByRole('button', { name: /Network Traffic/ }),
  screen.getByRole('button', { name: /^Compute \(/ }),
  screen.getByRole('button', { name: /System Calls/ }),
];

test('opens with every section shut', () => {
  render1(selected());
  for (const s of sections()) expect(s.getAttribute('aria-expanded')).toBe('false');
});

test('a section opens when its header is clicked, and only that one', () => {
  render1(selected());
  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  const [traffic, compute, syscalls] = sections();
  expect(compute.getAttribute('aria-expanded')).toBe('true');
  expect(traffic.getAttribute('aria-expanded')).toBe('false');
  expect(syscalls.getAttribute('aria-expanded')).toBe('false');
});

// A section left open from the previous workload would show that one's data
// under this one's name for a frame.
test('selecting a different workload shuts the sections again', () => {
  const { rerender } = render1(selected());
  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  expect(sections()[1].getAttribute('aria-expanded')).toBe('true');

  rerender(
    <DataTable
      selectedPod={selected({ id: 'payments-worker', label: 'worker' })}
      allPodsLookup={[pod, other]}
      services={[]}
    />,
  );
  for (const s of sections()) expect(s.getAttribute('aria-expanded')).toBe('false');
});

// An external node carries a fourth block. It must open shut too, or the
// panel still has one thing expanded on exactly the nodes with the most ports
// to list.
test('an external node opens with its traffic profile shut as well', () => {
  const external = selected({
    isExternal: true,
    externalNamespace: 'internet',
  } as Partial<PodNodeData>);
  render1(external);
  // Fetched unconditionally: a `queryByRole` guarded by `if (profile)` would
  // silently degrade into a duplicate of the first test the day a fixture
  // change stops rendering this block.
  const profile = screen.getByRole('button', { name: /Traffic Profile/ });
  expect(profile.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(profile);
  expect(profile.getAttribute('aria-expanded')).toBe('true');
  // The three always-present sections are shut regardless.
  for (const s of sections()) expect(s.getAttribute('aria-expanded')).toBe('false');
});

test('the identity header is gone: no name, namespace or replica list', () => {
  const { container } = render1(selected());
  const text = container.textContent ?? '';
  // Asserted on the VALUES in the fixture, not on the labels that used to sit
  // beside them. An earlier version of this test checked for `Namespace:` and
  // `Replicas`, which left the workload's name free to come back untouched and
  // the namespace free to return under any other label — two of the three
  // things the test names. `api` covers both the entity name and the replica
  // names (`api-1`, `api-2`); `payments` is the namespace.
  expect(text).not.toMatch(/api/);
  expect(text).not.toMatch(/payments/);
  // Nothing renders the old labels either.
  expect(text).not.toMatch(/Replicas/);
  expect(text).not.toMatch(/Namespace/);
});

// The panel is three fixed sections. Compute used to render only for a pod
// with gauges and System Calls only for one with recorded syscalls, so the
// panel's shape changed between selections and "this workload has none" was
// indistinguishable from "this section does not exist".
const bare = (): PodNodeData => ({
  id: 'payments-bare', label: 'bare', pod, pods: [pod], traffic: [],
  isExpanded: false,
} as unknown as PodNodeData);

test('a workload with no compute and no syscalls still shows all three sections', () => {
  render1(bare());
  const [traffic, compute, syscalls] = sections();
  expect(traffic).toBeTruthy();
  expect(compute).toBeTruthy();
  expect(syscalls).toBeTruthy();
  for (const s of [traffic, compute, syscalls]) expect(s.getAttribute('aria-expanded')).toBe('false');
  // The count is still spelled out rather than the header being dropped.
  expect(compute.textContent).toMatch(/0 containers/);
});

test('opening an empty section explains why it is empty', () => {
  render1(bare());

  fireEvent.click(screen.getByRole('button', { name: /^Compute \(/ }));
  expect(screen.getByText(/No compute data for this workload/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: /System Calls/ }));
  expect(screen.getByText(/No syscalls recorded/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  expect(screen.getByText(/No network traffic recorded/)).toBeTruthy();
});
