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

// F-17: the table must agree with the map. A stored peer whose pod record
// is gone (pruned) or superseded (a StatefulSet slot restarted under the
// same name, new uid) is labelled by its stored workload, namespace and pod
// name; "Unattributed" is kept for a row with NO stored identity that the
// start-time guard excluded.
const redisNow: PodInfo = {
  pod_name: 'argocd-redis-ha-server-1', pod_ip: '10.62.101.1', pod_namespace: 'argocd', time_stamp: '2026-09-28T16:00:00',
  node_name: 'ip-10-62-100-1', is_dead: false, pod_identity: 'redis-ha', workload_kind: 'StatefulSet', workload_name: 'argocd-redis-ha-server',
  pod_obj: { metadata: { uid: 'redis-uid-now' } }, started_at: '2026-09-28T15:56:43',
};
const storedFrom = (name: string, uid: string, ip: string, kind: string, workload: string) => flow({
  traffic_type: 'INGRESS', pod_port: '6379', traffic_in_out_ip: ip, traffic_in_out_port: '0', time_stamp: '2026-09-26T13:06:51',
  peer_kind: 'pod', peer_namespace: 'argocd', peer_name: name, peer_uid: uid, peer_workload_kind: kind, peer_workload_name: workload,
});

test('a stored peer whose record has a different uid now is labelled by its stored workload, not Unattributed', () => {
  render(<DataTable selectedPod={withTraffic([storedFrom('argocd-redis-ha-server-1', 'redis-uid-before-restart', '10.62.77.3', 'StatefulSet', 'argocd-redis-ha-server')])} allPodsLookup={[pod, redisNow]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  const row = rowFor(/argocd-redis-ha-server-1/);
  expect(within(row).getByText('argocd-redis-ha-server')).toBeTruthy();
  expect(within(row).getByText('ns: argocd')).toBeTruthy();
  expect(within(row).getByText('argocd-redis-ha-server-1')).toBeTruthy();
  expect(screen.queryByText('Unattributed')).toBeNull();
});

test('a stored peer whose record is gone from the listing is labelled by its stored workload too', () => {
  render(<DataTable selectedPod={withTraffic([storedFrom('argocd-redis-ha-haproxy-7f9d9c8b5-old01', 'gone', '10.62.55.9', 'Deployment', 'argocd-redis-ha-haproxy')])} allPodsLookup={[pod]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  const row = rowFor(/argocd-redis-ha-haproxy-7f9d9c8b5-old01/);
  expect(within(row).getByText('argocd-redis-ha-haproxy')).toBeTruthy();
  expect(within(row).getByText('ns: argocd')).toBeTruthy();
  expect(screen.queryByText('Unattributed')).toBeNull();
});

test('a row with no stored identity that the start-time guard excluded stays Unattributed', () => {
  // 10.62.101.1 is redisNow's IP; the flow predates redisNow's start.
  render(<DataTable selectedPod={withTraffic([flow({ traffic_type: 'INGRESS', pod_port: '6379', traffic_in_out_ip: '10.62.101.1', time_stamp: '2026-09-20T00:00:00' })])} allPodsLookup={[pod, redisNow]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
  expect(screen.getByText('Unattributed')).toBeTruthy();
  expect(screen.queryByText('argocd-redis-ha-server')).toBeNull();
});
