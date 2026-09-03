// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { PodInfo, PodNodeData } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';

// The Policy Builder must render the host-network shapes the generators emit
// without crashing or showing an empty pod-label editor: an ipBlock peer with
// its explanatory note (standard), a read-only entities chip (Cilium), and the
// leading WARNING block when the target itself is host-network.

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const nodeExporter = podRecord({
  pod_name: 'node-exporter-abc12', pod_ip: '10.0.0.20', pod_namespace: 'monitoring', node_name: 'worker-1',
  workload_kind: 'DaemonSet', workload_name: 'node-exporter',
  workload_selector_labels: { app: 'node-exporter' }, host_network: true,
});
const prometheus = podRecord({
  pod_name: 'prometheus-0', pod_ip: '10.0.0.9', pod_namespace: 'monitoring',
  workload_selector_labels: { app: 'prometheus' }, host_network: false,
});
const byIp: Record<string, PodInfo> = { '10.0.0.20': nodeExporter, '10.0.0.9': prometheus };
const byName: Record<string, PodInfo> = { [nodeExporter.pod_name]: nodeExporter, [prometheus.pod_name]: prometheus };

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn(async (ip: string) => byIp[ip] ?? null),
    getPodDetailsByName: vi.fn(async (name: string) => byName[name] ?? null),
    getClusterEnvironment: vi.fn(async () => UNKNOWN_CLUSTER_ENVIRONMENT),
  };
  return { apiClient, default: apiClient };
});
vi.mock('../services/seccompApi', () => ({
  seccompApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue(null) }),
}));

import NetworkPolicyEditor from './NetworkPolicyEditor';

const target = (pod: PodInfo, traffic: unknown[]): PodNodeData =>
  ({ id: pod.pod_name, label: pod.pod_name, pod, pods: [pod], traffic, isExpanded: false }) as PodNodeData;

const web = podRecord({ pod_name: 'web', pod_ip: '10.0.0.1', pod_namespace: 'prod', workload_selector_labels: { app: 'web' } });
const hostnetEgress = target(web, [
  { traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.20', traffic_in_out_port: '9100', ip_protocol: 'TCP' },
]);
const hostnetTarget = target(
  podRecord({ pod_name: 'node-exporter-abc12', pod_ip: '10.0.0.20', pod_namespace: 'monitoring', node_name: 'worker-1',
    workload_name: 'node-exporter', workload_selector_labels: { app: 'node-exporter' }, host_network: true }),
  [{ traffic_type: 'INGRESS', pod_port: '9100', traffic_in_out_ip: '10.0.0.9', ip_protocol: 'TCP' }],
);

const NOTE = 'host-network peer monitoring/node-exporter on node worker-1 — podSelector cannot match host traffic';
const CILIUM_NOTE = 'host-network peer monitoring/node-exporter on node worker-1 — endpointSelector cannot match host traffic';

afterEach(cleanup);

test('standard visual editor: host-network peer shows as an ipBlock with its note, no label editor', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={hostnetEgress} />);
  // YAML view first (the default) — the comment line is in the document.
  const pre = await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes(`# ${NOTE}`));
  expect(pre.textContent).toContain('cidr: 10.0.0.20/32');

  fireEvent.click(screen.getByText('Visual Editor'));
  expect(await screen.findByText(NOTE)).toBeTruthy();
  const cidr = screen.getByDisplayValue('10.0.0.20/32') as HTMLInputElement;
  expect(cidr).toBeTruthy();
  // The scope selector reflects the peer type; nothing asks for pod labels.
  expect((screen.getByDisplayValue('External (IP Block)') as HTMLSelectElement).value).toBe('external');
  expect(screen.queryByPlaceholderText(/label key/i)).toBeNull();
});

test('cilium visual editor: host-network peer renders read-only entities chips', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={hostnetEgress} />);
  fireEvent.click(screen.getByText('Cilium Policy'));
  const pre = await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('toEntities:'));
  expect(pre.textContent).toContain('- host\n    - remote-node');
  expect(pre.textContent).not.toContain('toEndpoints');

  fireEvent.click(screen.getByText('Visual Editor'));
  expect(await screen.findByText('To Entities')).toBeTruthy();
  expect(screen.getByText('host')).toBeTruthy();
  expect(screen.getByText('remote-node')).toBeTruthy();
  expect(screen.getByText(CILIUM_NOTE)).toBeTruthy();
});

test('host-network target: WARNING banner shown in both YAML and visual views', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={hostnetTarget} />);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('WARNING: monitoring/node-exporter runs with hostNetwork: true.');
  expect(alert.textContent).toContain('CiliumClusterwideNetworkPolicy');
  fireEvent.click(screen.getByText('Visual Editor'));
  expect(screen.getByRole('alert').textContent).toContain('hostNetwork: true');
  // The body is still rendered — the target selector and the normal peer.
  expect(await screen.findByText(/prometheus/)).toBeTruthy();
});
