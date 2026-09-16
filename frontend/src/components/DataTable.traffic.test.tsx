// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import DataTable from './DataTable';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';

// The Summary cell and the verdict tally, modelled on a wirelogs-style view.
//
// Summary is protocol plus the port that was CONNECTED TO, which is the one
// that names the service: the peer's port on an egress flow, our own on an
// ingress one. There are no TCP flags in it, because the drop probe observes
// whether a handshake completed and never sees the individual segments.

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

const withTraffic = (traffic: NetworkTraffic[]): PodNodeData =>
  ({ id: 'payments-api', label: 'api', pod, pods: [pod], traffic }) as unknown as PodNodeData;

const openTraffic = (sel: PodNodeData) => {
  const r = render(<DataTable selectedPod={sel} allPodsLookup={[pod]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  return r;
};

const rowFor = (text: RegExp) => {
  const cell = screen.getAllByText(text)[0];
  return cell.closest('tr')!;
};

test('an egress flow summarises as the protocol and the port it connected to', () => {
  openTraffic(withTraffic([
    flow({ traffic_type: 'EGRESS', ip_protocol: 'TCP', traffic_in_out_port: '8080' }),
  ]));
  expect(within(rowFor(/TCP :8080/)).getByText('TCP :8080')).toBeTruthy();
});

test('an ingress flow summarises on OUR port, not the peer ephemeral one', () => {
  // The peer's source port is ephemeral and names nothing; the port being
  // served is ours.
  openTraffic(withTraffic([
    flow({ traffic_type: 'INGRESS', ip_protocol: 'TCP', pod_port: '6379', traffic_in_out_port: '51234' }),
  ]));
  expect(screen.getByText('TCP :6379')).toBeTruthy();
  expect(screen.queryByText('TCP :51234')).toBeNull();
});

test('the protocol carries through rather than being assumed TCP', () => {
  openTraffic(withTraffic([
    flow({ traffic_type: 'EGRESS', ip_protocol: 'UDP', traffic_in_out_port: '53' }),
  ]));
  expect(screen.getByText('UDP :53')).toBeTruthy();
});

test('a flow with no usable port summarises as the protocol alone', () => {
  // Port '0' is the broker's "not recorded"; ":0" would read as a real port.
  const { container } = openTraffic(withTraffic([
    flow({ traffic_type: 'EGRESS', ip_protocol: 'TCP', traffic_in_out_port: '0' }),
  ]));
  expect(container.textContent).not.toMatch(/TCP :0/);
});

test('the tally counts allowed, dropped and the completion ratio', () => {
  openTraffic(withTraffic([
    flow({ decision: 'ALLOW', traffic_in_out_port: '8080' }),
    flow({ decision: 'ALLOW', traffic_in_out_port: '8081' }),
    flow({ decision: 'DROP', traffic_in_out_port: '8082' }),
  ]));
  expect(screen.getByText('2')).toBeTruthy();
  expect(screen.getByText('1')).toBeTruthy();
  // 2 of 3 completed.
  expect(screen.getByText('67% completed')).toBeTruthy();
});

test('the tally reflects the whole workload, not the filtered page', () => {
  // It answers "how is this workload doing". A number that moved with every
  // filter change would answer nothing, and the section header already says
  // how much of the set is on screen.
  openTraffic(withTraffic([
    flow({ decision: 'ALLOW', traffic_in_out_port: '8080' }),
    flow({ decision: 'DROP', traffic_in_out_port: '8081' }),
  ]));
  expect(screen.getByText('50% completed')).toBeTruthy();

  // Narrow to denied only: the tally must not become 0% completed.
  const decisionSelect = [...document.querySelectorAll('select')].find((sel) =>
    [...sel.options].some((o) => o.value === 'DROP'),
  )!;
  fireEvent.change(decisionSelect, { target: { value: 'DROP' } });
  expect(decisionSelect.value).toBe('DROP');
  expect(screen.getByText('50% completed')).toBeTruthy();
});
