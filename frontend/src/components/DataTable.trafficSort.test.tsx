// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import DataTable from './DataTable';
import type { NetworkTraffic, PodInfo, PodNodeData, SyscallInfo } from '../types';

// Timestamps: the broker's time_stamp is naive UTC. `new Date(s)` read it as
// local time, so an AEST browser showed 8:05 AM for a flow at 6:05 PM.
// Sorting: the headers looked clickable and did nothing.

afterEach(cleanup);

const pod: PodInfo = {
  pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments',
  time_stamp: 't', node_name: 'worker-1', is_dead: false,
};

const flow = (over: Partial<NetworkTraffic>): NetworkTraffic =>
  ({
    uuid: `u${Math.random()}`, pod_name: 'api-1', pod_namespace: 'payments',
    pod_ip: '10.0.0.1', pod_port: '0', traffic_in_out_ip: '10.0.0.9',
    traffic_in_out_port: '0', ip_protocol: 'TCP', traffic_type: 'EGRESS',
    decision: 'ALLOW', time_stamp: '2026-09-16T00:00:00',
    ...over,
  }) as NetworkTraffic;

const selected = (over: Partial<PodNodeData>): PodNodeData =>
  ({ id: 'payments-api', label: 'api', pod, pods: [pod], traffic: [], ...over }) as unknown as PodNodeData;

const renderFor = (sel: PodNodeData) =>
  render(<DataTable selectedPod={sel} allPodsLookup={[pod]} services={[]} />);

const openTraffic = (traffic: NetworkTraffic[]) => {
  const r = renderFor(selected({ traffic }));
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  return r;
};

const header = (name: RegExp) => screen.getByRole('columnheader', { name });
const ariaSort = (name: RegExp) => header(name).getAttribute('aria-sort');
/** The port each body row connected to, in display order. */
const portOrder = () =>
  screen.getAllByRole('row').slice(1).map(r => r.textContent!.match(/TCP :(\d+)/)![1]);

const inSydney = (run: () => void) => {
  const tz = process.env.TZ;
  process.env.TZ = 'Australia/Sydney';
  try {
    run();
  } finally {
    process.env.TZ = tz;
  }
};

test('traffic timestamps read the naive UTC time in the local zone, with the zone named', () =>
  inSydney(() => {
    openTraffic([flow({ time_stamp: '2026-09-15T08:05:23.998754', traffic_in_out_port: '6379' })]);
    // 08:05 UTC is 18:05 AEST. The old rendering showed 8:05:23 AM.
    const cell = screen.getByText(/6:05:23|18:05:23/);
    expect(cell.textContent).toMatch(/AEST|GMT\+10/);
    expect(screen.queryByText(/8:05:23/)).toBeNull();
  }));

test('syscall timestamps go through the same formatter', () =>
  inSydney(() => {
    const syscalls: SyscallInfo[] = [
      { pod_name: 'api-1', pod_namespace: 'payments', syscalls: 'read,write', arch: 'x86_64', time_stamp: '2026-09-15T08:05:23' },
    ];
    renderFor(selected({ syscalls }));
    fireEvent.click(screen.getByRole('button', { name: /System Calls/ }));
    const cell = screen.getByText(/6:05:23|18:05:23/);
    expect(cell.textContent).toMatch(/AEST|GMT\+10/);
  }));

// Three flows: the newest and oldest are allowed, the middle one dropped.
const mixed = () => [
  flow({ decision: 'ALLOW', traffic_in_out_port: '1', time_stamp: '2026-09-16T03:00:00' }),
  flow({ decision: 'DROP', traffic_in_out_port: '2', time_stamp: '2026-09-16T02:00:00' }),
  flow({ decision: 'ALLOW', traffic_in_out_port: '3', time_stamp: '2026-09-16T01:00:00' }),
];

test('the default order is DROP first then newest, and the Decision header says so', () => {
  openTraffic(mixed());
  expect(portOrder()).toEqual(['2', '1', '3']);
  expect(ariaSort(/Decision/)).toBe('descending');
  expect(ariaSort(/Timestamp/)).toBeNull();
  expect(ariaSort(/Direction/)).toBeNull();
});

test('Timestamp sorts newest first regardless of decision, and again for oldest first', () => {
  openTraffic(mixed());
  fireEvent.click(screen.getByRole('button', { name: /Timestamp/ }));
  expect(portOrder()).toEqual(['1', '2', '3']);
  expect(ariaSort(/Timestamp/)).toBe('descending');
  expect(ariaSort(/Decision/)).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: /Timestamp/ }));
  expect(portOrder()).toEqual(['3', '2', '1']);
  expect(ariaSort(/Timestamp/)).toBe('ascending');
});

test('Decision toggles to ALLOW first, newest within the group', () => {
  openTraffic(mixed());
  fireEvent.click(screen.getByRole('button', { name: /Decision/ }));
  expect(portOrder()).toEqual(['1', '3', '2']);
  expect(ariaSort(/Decision/)).toBe('ascending');
  fireEvent.click(screen.getByRole('button', { name: /Decision/ }));
  expect(portOrder()).toEqual(['2', '1', '3']);
  expect(ariaSort(/Decision/)).toBe('descending');
});

test('Direction groups EGRESS before INGRESS, newest within each', () => {
  openTraffic([
    flow({ traffic_type: 'INGRESS', pod_port: '1', traffic_in_out_port: '9', time_stamp: '2026-09-16T03:00:00' }),
    flow({ traffic_type: 'EGRESS', traffic_in_out_port: '2', time_stamp: '2026-09-16T02:00:00' }),
    flow({ traffic_type: 'EGRESS', traffic_in_out_port: '3', time_stamp: '2026-09-16T01:00:00' }),
  ]);
  fireEvent.click(screen.getByRole('button', { name: /Direction/ }));
  expect(portOrder()).toEqual(['2', '3', '1']);
  expect(ariaSort(/Direction/)).toBe('ascending');
});

test('the Timestamp sort orders by the UTC instant, not the digits read as local time', () =>
  inSydney(() => {
    // Read as local time the naive row would be 02:00Z and fall below the
    // offset row (10:00Z); read as UTC (12:00Z) it is the newer one.
    openTraffic([
      flow({ traffic_in_out_port: '1', time_stamp: '2026-09-16T20:00:00+10:00' }),
      flow({ traffic_in_out_port: '2', time_stamp: '2026-09-16T12:00:00' }),
    ]);
    fireEvent.click(screen.getByRole('button', { name: /Timestamp/ }));
    expect(portOrder()).toEqual(['2', '1']);
  }));

test('selecting another workload returns to the default order', () => {
  const { rerender } = openTraffic(mixed());
  fireEvent.click(screen.getByRole('button', { name: /Timestamp/ }));
  expect(ariaSort(/Timestamp/)).toBe('descending');

  const other: PodInfo = { ...pod, pod_name: 'api-2', pod_ip: '10.0.0.2' };
  rerender(
    <DataTable
      selectedPod={{ ...selected({ traffic: mixed() }), id: 'payments-api-2', pod: other, pods: [other] } as PodNodeData}
      allPodsLookup={[pod, other]}
      services={[]}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  expect(ariaSort(/Decision/)).toBe('descending');
  expect(portOrder()).toEqual(['2', '1', '3']);
});
