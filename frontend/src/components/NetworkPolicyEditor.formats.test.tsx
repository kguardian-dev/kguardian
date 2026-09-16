// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { PodInfo, PodNodeData } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';
import { quoteYamlValue } from '../utils/networkPolicyGenerator';

// The network tab offers the same kind of format switch as the seccomp tab:
// an AuditNetworkPolicy (kguardian CR, nothing dropped), the plain
// NetworkPolicy, or a CiliumNetworkPolicy where the CNI can read one.

let cni = 'unknown';

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const api = podRecord({ pod_name: 'api-0', pod_ip: '10.0.0.9', pod_namespace: 'prod', workload_selector_labels: { app: 'api' } });

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn(async (ip: string) => (ip === '10.0.0.9' ? api : null)),
    getPodDetailsByName: vi.fn(async () => null),
    getClusterEnvironment: vi.fn(async () => ({ ...UNKNOWN_CLUSTER_ENVIRONMENT, cni })),
  };
  return { apiClient, default: apiClient };
});
vi.mock('../services/seccompApi', () => ({
  seccompApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue(null) }),
}));

import NetworkPolicyEditor from './NetworkPolicyEditor';

const web = podRecord({ pod_name: 'web', pod_ip: '10.0.0.1', pod_namespace: 'prod', workload_selector_labels: { app: 'web' } });
const target: PodNodeData = {
  id: 'web', label: 'web', pod: web, pods: [web], isExpanded: false,
  traffic: [{ traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.9', traffic_in_out_port: '8080', ip_protocol: 'TCP' }],
} as PodNodeData;

const yamlHeader = () => {
  const pre = document.querySelector('pre');
  return (pre?.textContent ?? '').split('\n').slice(0, 2);
};
const header = (apiVersion: string, kind: string) => [`apiVersion: ${quoteYamlValue(apiVersion)}`, `kind: ${quoteYamlValue(kind)}`];

afterEach(() => {
  cleanup();
  cni = 'unknown';
});

test('the network tab offers Audit, NetworkPolicy and Cilium; Audit only swaps the header lines', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));
  const group = screen.getByRole('radiogroup', { name: 'Network policy format' });
  const radios = group.querySelectorAll('[role=radio]');
  // Named for the kind it produces, like the other two: a reader picking a
  // format should see the resource they are about to get.
  expect([...radios].map((r) => r.textContent?.trim())).toEqual(['AuditNetworkPolicy', 'NetworkPolicy', 'CiliumNetworkPolicy']);
  expect(yamlHeader()).toEqual(header('networking.k8s.io/v1', 'NetworkPolicy'));

  fireEvent.click(screen.getByRole('radio', { name: /Audit/ }));
  expect(yamlHeader()).toEqual(header('kguardian.dev/v1alpha1', 'AuditNetworkPolicy'));
  expect(screen.getByText('Audit Network Policy Builder')).toBeTruthy();
  expect(screen.getByText('Save Audit Policy')).toBeTruthy();

  fireEvent.click(screen.getByRole('radio', { name: 'NetworkPolicy' }));
  expect(yamlHeader()).toEqual(header('networking.k8s.io/v1', 'NetworkPolicy'));
});

test('Cilium is offered but disabled, with the reason, when the CNI is known not to be Cilium', async () => {
  cni = 'calico';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));
  // The environment lands asynchronously; wait for the disabled state.
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect((cilium as HTMLButtonElement).disabled).toBe(true));
  expect(cilium.getAttribute('title')).toMatch(/calico/);
});

test('on a Cilium cluster the Cilium format is selectable and the tab strip is Network / Seccomp', async () => {
  cni = 'cilium';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} />);
  const tabs = await screen.findAllByRole('tab');
  expect(tabs.map((t) => t.textContent?.trim())).toEqual(['Network Policy', 'Seccomp Profile']);
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect(cilium.getAttribute('aria-checked')).toBe('true'));
  expect(screen.getByText('Cilium Network Policy Builder')).toBeTruthy();
});

test('switching to Seccomp and back to Network restores the Cilium format', async () => {
  cni = 'cilium';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} />);
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect(cilium.getAttribute('aria-checked')).toBe('true'));
  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp Profile' }));
  expect(screen.getByText('Seccomp Profile Builder')).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: 'Network Policy' }));
  expect(screen.getByText('Cilium Network Policy Builder')).toBeTruthy();
});

// The format buttons sit directly under the Network Policy / Seccomp Profile
// tab strip, which marks its selection with white on a solid accent. These
// used to mark theirs with accent text on a 20%-accent fill: the same hue at
// both ends, which is barely legible on the dark surface. Asserted on the
// classes because the contrast IS the styling here, and a revert to the old
// pair is silent otherwise.
test('the selected format reads as selected: white on a solid accent, like the tabs above it', async () => {
  cni = 'unknown';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));

  const selected = screen.getByRole('radio', { name: 'NetworkPolicy' });
  expect(selected.getAttribute('aria-checked')).toBe('true');
  expect(selected.className).toContain('bg-hubble-accent');
  expect(selected.className).toContain('text-white');
  // The washed-out fill is what made it unreadable.
  expect(selected.className).not.toContain('bg-hubble-accent/20');
  expect(selected.className).not.toContain('text-hubble-accent');

  // An unselected one stays quiet, the same way the tab strip does.
  const unselected = screen.getByRole('radio', { name: /AuditNetworkPolicy/ });
  expect(unselected.getAttribute('aria-checked')).toBe('false');
  expect(unselected.className).not.toContain('text-white');
});

// Cilium is a FORMAT of the network tab, sitting in the same switch as Audit
// and NetworkPolicy. Picking it used to swap the header icon (shield to a
// network glyph) and retitle the modal "Cilium Policy Builder", so choosing a
// format read as switching to a different tool. The other two formats never
// did that, which is what made it look wrong.
const headerIcon = () => {
  const h2 = document.querySelector('h2')!;
  const iconBox = h2.parentElement!.previousElementSibling!;
  return iconBox.querySelector('svg')!.getAttribute('class') ?? '';
};

test('the builder header holds still across every network format', async () => {
  cni = 'unknown';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));

  expect(screen.getByText('Network Policy Builder')).toBeTruthy();
  expect(headerIcon()).toContain('lucide-shield');

  fireEvent.click(screen.getByRole('radio', { name: /AuditNetworkPolicy/ }));
  expect(screen.getByText('Audit Network Policy Builder')).toBeTruthy();
  expect(headerIcon()).toContain('lucide-shield');

  fireEvent.click(screen.getByRole('radio', { name: 'CiliumNetworkPolicy' }));
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: CiliumNetworkPolicy'));
  // Same icon as its siblings, and a title in the same family rather than one
  // that drops the "Network" the other two carry.
  expect(headerIcon()).toContain('lucide-shield');
  expect(headerIcon()).not.toContain('lucide-network');
  expect(screen.getByText('Cilium Network Policy Builder')).toBeTruthy();
});
