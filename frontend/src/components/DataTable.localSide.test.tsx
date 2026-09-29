// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import DataTable from './DataTable';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';
import { buildExternalNodes } from '../utils/externalPeers';
import { buildPeerIndex, resolvePeer, type PeerResolution } from '../utils/peerResolution';

// The local side of an aggregate card's row is the pod that captured it.
//
// Seen on the dev cluster (EKS, VPC CNI reuses pod IPs within hours): the
// argocd namespace's Private network card listed argocd-server's ingress
// from 10.62.2.89 with the destination "Pod php-monolith-payments-queue-
// worker-deployment, ns domain-monolith-dev-03". That pod held 10.62.98.20
// until 00:54 UTC and was dead; argocd-server-d6c47d55b-lwpsv took the
// address at 04:16 and captured the rows at 04:16:42. The table looked the
// row's pod_ip up in a map where the last record in the listing won.

afterEach(cleanup);

const IP = '10.62.98.20';

const argocd: PodInfo = {
  pod_name: 'argocd-server-d6c47d55b-lwpsv', pod_ip: IP, pod_namespace: 'argocd',
  pod_identity: 'argocd-server', time_stamp: '2026-09-29T08:37:35.266555', node_name: 'n1',
  is_dead: false, started_at: '2026-09-29T04:16:18',
};
const php: PodInfo = {
  pod_name: 'php-monolith-payments-queue-worker-deployment-6ff8d67689-6qvxr', pod_ip: IP,
  pod_namespace: 'domain-monolith-dev-03', pod_identity: 'php-monolith-payments-queue-worker-deployment',
  time_stamp: '2026-09-29T00:54:40.311056', node_name: 'n2', is_dead: true, started_at: '2026-09-25T23:35:02',
};
// The dead record comes last, as it did in the dev listing.
const lookup = [argocd, php];

const ingress = (n: number): NetworkTraffic =>
  ({
    uuid: `u${n}`, pod_name: argocd.pod_name, pod_namespace: 'argocd', pod_ip: IP, pod_port: '8080',
    traffic_in_out_ip: '10.62.2.89', traffic_in_out_port: '0', ip_protocol: 'TCP', traffic_type: 'INGRESS',
    decision: 'ALLOW', time_stamp: `2026-09-29T04:16:4${n}.368071`,
  }) as NetworkTraffic;

test('the Private network card names the capturing pod as the destination, not a former holder of its IP', () => {
  const traffic = [ingress(1), ingress(2)];
  const pods = [{ id: 'argocd-server', label: 'argocd-server', pod: argocd, pods: [argocd], traffic } as unknown as PodNodeData];
  const index = buildPeerIndex(lookup, []);
  const rowPeers = new Map<NetworkTraffic, PeerResolution>(traffic.map((t) => [t, resolvePeer(t, index)]));
  const cards = buildExternalNodes({
    pods, services: [], rowPeers, localPodByName: new Map(pods.map((p) => [p.pod.pod_name, p])),
    localPodByWorkload: new Map(), svcIpToLocalPod: new Map(), podNameToSvcIp: new Map(),
  });
  const priv = cards.find((c) => c.id === 'external-private-in')!;
  expect(priv).toBeTruthy();

  render(<DataTable selectedPod={priv} allPodsLookup={lookup} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));

  const rows = screen.getAllByText(`${IP}:8080`).map((cell) => cell.closest('tr')!);
  expect(rows).toHaveLength(2);
  for (const row of rows) {
    expect(within(row).getByText('argocd-server')).toBeTruthy();
    expect(within(row).getByText('ns: argocd')).toBeTruthy();
    expect(within(row).queryByText(/php-monolith/)).toBeNull();
    expect(within(row).queryByText(/domain-monolith-dev-03/)).toBeNull();
  }
});

test('a capturing pod the listing no longer has keeps its own name from the row', () => {
  const traffic = [ingress(1)];
  const priv = { id: 'external-private-in', label: 'Private network', pod: argocd, pods: [], traffic, isExternal: true } as unknown as PodNodeData;

  render(<DataTable selectedPod={priv} allPodsLookup={[php]} services={[]} />);
  fireEvent.click(screen.getByRole('button', { name: /Network Traffic/ }));

  const row = screen.getByText(`${IP}:8080`).closest('tr')!;
  expect(within(row).getByText(argocd.pod_name)).toBeTruthy();
  expect(within(row).getByText('ns: argocd')).toBeTruthy();
  expect(within(row).queryByText(/php-monolith/)).toBeNull();
});
