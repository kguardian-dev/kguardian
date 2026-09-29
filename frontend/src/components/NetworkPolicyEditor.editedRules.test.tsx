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
