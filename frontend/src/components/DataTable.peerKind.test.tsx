// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import DataTable from './DataTable';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';
import { buildExternalNodes } from '../utils/externalPeers';
import { PRIVATE_PEER_TOOLTIP, buildPeerIndex, resolvePeer, type PeerResolution } from '../utils/peerResolution';

// A peer is labelled "Pod" only when it resolved to a pod record (stored on
// the row, or the guarded by-IP lookup). On EKS the ALB's network interfaces
// in IP target mode are VPC-private addresses no pod, node or Service record
// holds; their flows used to read "POD 10.20.30.40 ns: private" in the
// Private network card's traffic table, because every row of an aggregate
// card was labelled with the card's first member as if it were a pod.

afterEach(cleanup);

const api: PodInfo = {
  pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments',
  time_stamp: '2026-09-01T00:00:00', node_name: 'worker-1', is_dead: false, pod_identity: 'api',
};
const ledger: PodInfo = {
  pod_name: 'ledger-1', pod_ip: '10.0.0.7', pod_namespace: 'payments',
  time_stamp: '2026-09-01T00:00:00', node_name: 'worker-1', is_dead: false, pod_identity: 'ledger', started_at: '2026-09-01T00:00:00',
};
const lookup = [api, ledger];

const flow = (ip: string, over: Partial<NetworkTraffic> = {}): NetworkTraffic =>
  ({
    uuid: `u-${ip}-${over.traffic_type ?? 'EGRESS'}`, pod_name: 'api-1', pod_namespace: 'payments',
    pod_ip: '10.0.0.1', pod_port: '0', traffic_in_out_ip: ip,
    traffic_in_out_port: '443', ip_protocol: 'TCP', traffic_type: 'EGRESS',
    decision: 'ALLOW', time_stamp: '2026-09-16T00:00:00',
    ...over,
  }) as NetworkTraffic;

const local = (traffic: NetworkTraffic[]): PodNodeData =>
  ({ id: 'payments-api', label: 'api', pod: api, pods: [api], traffic }) as unknown as PodNodeData;

/** The aggregate cards exactly as the map builds them. */
const externalCards = (traffic: NetworkTraffic[]): PodNodeData[] => {
  const pods = [local(traffic)];
  const index = buildPeerIndex(lookup, []);
  const rowPeers = new Map<NetworkTraffic, PeerResolution>(traffic.map((t) => [t, resolvePeer(t, index)]));
  const localPodByName = new Map(pods.map((p) => [p.pod.pod_name, p]));
  return buildExternalNodes({
    pods, services: [], rowPeers, localPodByName, localPodByWorkload: new Map(),
    svcIpToLocalPod: new Map(), podNameToSvcIp: new Map(),
  });
};

const openTraffic = (sel: PodNodeData) => {
  render(<DataTable selectedPod={sel} allPodsLookup={lookup} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));
};

/** The table cell naming the peer at `ip`. */
const peerCell = (ip: string) => screen.getAllByText(new RegExp(`^${ip.replace(/\./g, '\\.')}(:\\d+)?$`))[0].closest('td')!;

test('the Private network card: each unresolved private IP is a Private IP, never a Pod', () => {
  const cards = externalCards([flow('10.20.30.40'), flow('10.20.30.41')]);
  const priv = cards.find((c) => c.id === 'external-private-out')!;
  expect(priv).toBeTruthy();
  openTraffic(priv);

  for (const ip of ['10.20.30.40', '10.20.30.41']) {
    const cell = peerCell(ip);
    expect(cell.textContent).not.toMatch(/Pod/);
    expect(cell.textContent).toMatch(/Private IP/);
    expect(cell.querySelector(`[title="${PRIVATE_PEER_TOOLTIP}"]`)).not.toBeNull();
    // Not the card's first member standing in for every row.
    expect(cell.textContent).not.toMatch(/ns: private/);
  }
  // The local side really is a pod.
  expect(peerCell('10.0.0.1').textContent).toMatch(/Pod/);
});

test('the Internet card: a public IP is Internet, never a Pod', () => {
  const cards = externalCards([flow('140.82.112.3')]);
  openTraffic(cards.find((c) => c.id === 'external-internet-out')!);
  const cell = peerCell('140.82.112.3');
  expect(cell.textContent).not.toMatch(/Pod/);
  expect(cell.textContent).toMatch(/Internet/);
});

test('from a local workload: private is Private IP, public is Internet, a resolved pod is Pod', () => {
  openTraffic(local([flow('10.20.30.40'), flow('140.82.112.3'), flow('10.0.0.7')]));
  const priv = peerCell('10.20.30.40');
  expect(priv.textContent).toMatch(/Private IP/);
  expect(priv.textContent).not.toMatch(/Pod/);
  expect(peerCell('140.82.112.3').textContent).toMatch(/Internet/);
  const pod = peerCell('10.0.0.7');
  expect(pod.textContent).toMatch(/Pod/);
  expect(pod.textContent).toMatch(/ledger/);
});
