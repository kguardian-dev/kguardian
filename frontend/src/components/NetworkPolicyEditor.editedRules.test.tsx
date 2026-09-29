// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { parse } from 'yaml';
import type { PodInfo, PodNodeData } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';

// What the visual editor shows about a rule must be what the export does.
// An empty `from` / `to` matches every peer, and a Cilium rule with no
// endpoint, CIDR or entity does too, so a rule with no peers used to be
// exported as allow-all while the editor said "No sources defined".

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const api = podRecord({ pod_name: 'api-0', pod_ip: '10.0.0.9', pod_namespace: 'prod', started_at: '2026-01-01T00:00:00', workload_selector_labels: { app: 'api' } });

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn(async (ip: string) => (ip === '10.0.0.9' ? api : null)),
    getPodDetailsByName: vi.fn(async () => null),
    getClusterEnvironment: vi.fn(async () => UNKNOWN_CLUSTER_ENVIRONMENT),
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
  traffic: [{ traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.9', traffic_in_out_port: '8080', ip_protocol: 'TCP', time_stamp: '2026-09-03T00:00:00' }],
} as PodNodeData;

const yamlText = () => document.querySelector('pre')?.textContent ?? '';
const waitForYaml = (needle: string) =>
  screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes(needle));
const toVisual = () => fireEvent.click(screen.getByText('Visual Editor'));
const toYaml = () => fireEvent.click(screen.getByText('YAML View'));

afterEach(cleanup);

test('removing the last destination: the rule says it allows nothing, and the export denies egress', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  fireEvent.click(screen.getByTitle('Remove destination'));
  expect(screen.getByText('No destinations: this rule allows nothing and is left out of the YAML. Add a destination to include it.')).toBeTruthy();

  toYaml();
  const doc = parse(yamlText());
  expect(doc.spec.policyTypes).toEqual(['Egress']);
  expect(doc.spec.egress).toBeUndefined();
  expect(yamlText()).not.toContain('- to:');
  // Nothing renders, so the policy is deny-all egress and the editor says so.
  expect(screen.getByRole('alert').textContent).toContain('denies all egress');
});

test('a newly added ingress rule is left out of the export until it has a source', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  fireEvent.click(screen.getAllByText('Add Rule')[0]);
  fireEvent.click(screen.getAllByText('Add Port')[0]);
  expect(screen.getByText('No sources: this rule allows nothing and is left out of the YAML. Add a source to include it.')).toBeTruthy();

  toYaml();
  const doc = parse(yamlText());
  // Ingress is now covered with no rule: deny, not `- from:` (allow all).
  expect(doc.spec.policyTypes).toEqual(['Egress', 'Ingress']);
  expect(doc.spec.ingress).toBeUndefined();
  expect(doc.spec.egress).toEqual([{ to: [{ podSelector: { matchLabels: { app: 'api' } } }], ports: [{ protocol: 'TCP', port: 8080 }] }]);
});

test('a rule with sources but no ports says it allows every port', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  fireEvent.click(screen.getByTitle('Remove port'));
  expect(screen.getByText('All ports: no port restriction')).toBeTruthy();
});

// Clearing the port field used to store 0 and export `port: 0`, which the
// API server rejects; a named port could not be typed at all.
test('a cleared port blocks the export and says so; a named port is exported as a name', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  const input = screen.getByDisplayValue('8080') as HTMLInputElement;
  fireEvent.change(input, { target: { value: '' } });
  expect(input.getAttribute('aria-invalid')).toBe('true');

  toYaml();
  expect(document.querySelector('pre')).toBeNull();
  const notice = screen.getByText(/not a valid port/);
  expect(notice.textContent).toContain('egress rule 1: port ""');
  expect(notice.textContent).not.toContain('port: 0');

  toVisual();
  fireEvent.change(screen.getByPlaceholderText('80 or http'), { target: { value: 'http' } });
  toYaml();
  expect(parse(yamlText()).spec.egress[0].ports).toEqual([{ protocol: 'TCP', port: 'http' }]);
});

test('cilium: a rule with ports but no peer is flagged and left out, never an L4-only allow-all', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="cilium" />);
  await waitForYaml('kind: CiliumNetworkPolicy');
  toVisual();
  fireEvent.click(screen.getAllByText('Add Rule')[0]);
  fireEvent.click(screen.getAllByText('Add Port')[0]);
  expect(screen.getByText('No peers: this rule allows nothing and is left out of the YAML. Add an endpoint or a CIDR to include it.')).toBeTruthy();

  toYaml();
  const doc = parse(yamlText());
  expect(doc.spec.ingress).toBeUndefined();
  expect(doc.spec.egress).toHaveLength(1);
  expect(doc.spec.egress[0].toEndpoints).toEqual([{ matchLabels: { app: 'api' } }]);
});

// The port check guards what a user types, not what was observed: rows with no
// usable port (ICMP carries pod_port "0") are skipped by the generators, so
// "Build policy" on such traffic still exports, in both formats.
const withIcmp: PodNodeData = {
  ...target,
  traffic: [
    ...target.traffic!,
    { traffic_type: 'INGRESS', pod_port: '0', traffic_in_out_ip: '10.0.0.9', ip_protocol: 'ICMP', time_stamp: '2026-09-03T00:00:00' },
    { traffic_type: 'EGRESS', traffic_in_out_port: '0', traffic_in_out_ip: '10.0.0.9', ip_protocol: 'ICMP', time_stamp: '2026-09-03T00:00:00' },
  ],
} as PodNodeData;

test('observed ICMP / port 0 rows: the generated policy exports in both formats, without port 0', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={withIcmp} initialPolicyType="network" />);
  await waitForYaml('app: api');
  expect(screen.queryByText(/not a valid port/)).toBeNull();
  const doc = parse(yamlText());
  expect(doc.spec.policyTypes).toEqual(['Egress']);
  expect(doc.spec.egress).toEqual([{ to: [{ podSelector: { matchLabels: { app: 'api' } } }], ports: [{ protocol: 'TCP', port: 8080 }] }]);

  fireEvent.click(screen.getByRole('radio', { name: /CiliumNetworkPolicy/ }));
  await waitForYaml('kind: CiliumNetworkPolicy');
  expect(screen.queryByText(/not a valid port/)).toBeNull();
  const cnp = parse(yamlText());
  expect(cnp.spec.ingress).toBeUndefined();
  expect(cnp.spec.egress).toEqual([{ toEndpoints: [{ matchLabels: { app: 'api' } }], toPorts: [{ ports: [{ port: '8080', protocol: 'TCP' }] }] }]);
});

test('cilium: an emptied port field is flagged and blocks the export instead of writing port: ""', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="cilium" />);
  await waitForYaml('kind: CiliumNetworkPolicy');
  toVisual();
  const input = screen.getByDisplayValue('8080') as HTMLInputElement;
  fireEvent.change(input, { target: { value: '' } });
  expect(input.getAttribute('aria-invalid')).toBe('true');
  toYaml();
  expect(document.querySelector('pre')).toBeNull();
  expect(screen.getByText(/not a valid port/).textContent).toContain('egress rule 1: port ""');
  // 0 is Cilium's "any port" and is accepted.
  toVisual();
  fireEvent.change(document.querySelector('input[aria-invalid="true"]')!, { target: { value: '0' } });
  toYaml();
  expect(parse(yamlText()).spec.egress[0].toPorts).toEqual([{ ports: [{ port: '0', protocol: 'TCP' }] }]);
});

// A selector left with no labels selects everything in its scope; the chip
// row, where the labels were, says so rather than going blank.
test('removing the last pod label: the chip row reads "all pods in the namespace" and the YAML has podSelector {}', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  expect(screen.queryByText('all pods in the namespace')).toBeNull();
  fireEvent.click(screen.getByTitle('Remove label'));
  expect(screen.getByText('all pods in the namespace')).toBeTruthy();
  toYaml();
  expect(parse(yamlText()).spec.egress[0].to).toEqual([{ podSelector: {} }]);
});

test('switching a peer to any namespace shows "matches every namespace" until a label is added', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  fireEvent.change(screen.getByDisplayValue('In Namespace (Same Namespace)'), { target: { value: 'inCluster' } });
  expect(screen.getByText('matches every namespace')).toBeTruthy();
});

// A typed ipBlock CIDR gets the port field's treatment: `cidr: ""` used to export.
test('an empty or malformed ipBlock CIDR is flagged and blocks the export, naming the field', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await waitForYaml('app: api');
  toVisual();
  fireEvent.click(screen.getByText('Add Destination'));
  const cidr = screen.getByDisplayValue('0.0.0.0/0') as HTMLInputElement;
  fireEvent.change(cidr, { target: { value: '' } });
  expect(cidr.getAttribute('aria-invalid')).toBe('true');
  toYaml();
  expect(document.querySelector('pre')).toBeNull();
  expect(screen.getByText(/not a valid CIDR/).textContent).toContain('egress rule 1: cidr ""');

  toVisual();
  fireEvent.change(screen.getByPlaceholderText('0.0.0.0/0 or 10.0.0.0/8'), { target: { value: 'fd00::/64' } });
  toYaml();
  expect(parse(yamlText()).spec.egress[0].to).toEqual([{ podSelector: { matchLabels: { app: 'api' } } }, { ipBlock: { cidr: 'fd00::/64' } }]);
});

test('cilium: an emptied CIDR is flagged and blocks the export', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="cilium" />);
  await waitForYaml('kind: CiliumNetworkPolicy');
  toVisual();
  fireEvent.click(screen.getByText('Add CIDR'));
  const cidr = screen.getByDisplayValue('0.0.0.0/0') as HTMLInputElement;
  fireEvent.change(cidr, { target: { value: '' } });
  expect(cidr.getAttribute('aria-invalid')).toBe('true');
  toYaml();
  expect(screen.getByText(/not a valid CIDR/).textContent).toContain('egress rule 1: cidr ""');
});
