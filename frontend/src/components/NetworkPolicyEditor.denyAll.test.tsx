// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { PodInfo, ServiceInfo } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';

// A workload with no observed traffic used to produce a policy with only a
// podSelector, presented with the normal "generated from observed network
// traffic" footer and an enabled Save button. The API server defaults that
// document to policyTypes [Ingress]: deny-all ingress, said nowhere. The
// generator now writes the reference deny-all out explicitly and the editor
// has to say what it is, where it cannot be dismissed.

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const kubeApi: ServiceInfo = {
  svc_ip: '10.96.0.1', svc_name: 'kubernetes', svc_namespace: 'default',
  service_spec: { spec: { clusterIP: '10.96.0.1', type: 'ClusterIP' } },
};

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn(async (ip: string) => (ip === '10.96.0.1' ? kubeApi : null)),
    getPodDetailsByIP: vi.fn(async () => null),
    getPodDetailsByName: vi.fn(async () => null),
    getClusterEnvironment: vi.fn(async () => UNKNOWN_CLUSTER_ENVIRONMENT),
  };
  return { apiClient, default: apiClient };
});
vi.mock('../services/seccompApi', () => ({
  seccompApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue(null) }),
}));

import NetworkPolicyEditor, { type PolicyWorkload } from './NetworkPolicyEditor';

const coredns = podRecord({ pod_name: 'coredns-64d5bdd46-5vj6l', pod_ip: '10.0.0.53', pod_namespace: 'kube-system',
  pod_identity: 'kube-dns', workload_selector_labels: { 'k8s-app': 'kube-dns' } });
const workload = (traffic: unknown[], extra: Partial<PolicyWorkload> = {}): PolicyWorkload =>
  ({ id: 'kube-dns', label: 'kube-dns', pod: coredns, pods: [coredns], traffic, isExpanded: false, ...extra }) as PolicyWorkload;

const yamlText = () => document.querySelector('pre')?.textContent ?? '';
const waitForYaml = (needle: string) =>
  screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes(needle));

afterEach(cleanup);

test('no traffic: explicit deny-all YAML, a non-dismissible error saying so, honest footer and Save label', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([])} initialPolicyType="network" />);
  await waitForYaml('kind: NetworkPolicy');
  expect(yamlText()).toContain('  policyTypes:\n  - Ingress\n  - Egress');
  expect(yamlText()).not.toContain('ingress:');

  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('No traffic observed, so this policy allows nothing');
  expect(alert.textContent).toContain('denies all ingress and egress');
  // Not dismissible (the CNI advisory beside it, an info note, still is).
  expect(within(alert).queryByRole('button', { name: 'Dismiss policy notice' })).toBeNull();

  expect(screen.getByText(/No traffic was observed for this workload and the policy has no rules/)).toBeTruthy();
  expect(screen.queryByText(/generated from observed network traffic/)).toBeNull();
  expect(screen.getByRole('button', { name: 'Save Deny-All Policy' })).toBeTruthy();
});

test('a failed traffic read is named as the cause, not presented as zero traffic', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([], { trafficError: true })} initialPolicyType="network" />);
  await waitForYaml('kind: NetworkPolicy');
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('Traffic read failed, so this policy allows nothing');
  expect(alert.textContent).toContain('not evidence');
  expect(screen.getByText(/The traffic read for this workload failed and the policy has no rules/)).toBeTruthy();
  expect(within(alert).queryByRole('button', { name: 'Dismiss policy notice' })).toBeNull();
});

test('the audit format keeps the deny-all warning and its Save label', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([])} initialPolicyType="network" />);
  await waitForYaml('kind: NetworkPolicy');
  fireEvent.click(screen.getByRole('radio', { name: /AuditNetworkPolicy/ }));
  expect(screen.getByRole('alert').textContent).toContain('allows nothing');
  // The format stays out of the label, as it does for every other policy.
  expect(screen.getByRole('button', { name: 'Save Deny-All Policy' })).toBeTruthy();
});

test('the Cilium format: enableDefaultDeny both true, same warning', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([])} initialPolicyType="cilium" />);
  await waitForYaml('kind: CiliumNetworkPolicy');
  expect(yamlText()).toContain('  enableDefaultDeny:\n    ingress: true\n    egress: true');
  // The CRD requires an ingress or egress section; Cilium's deny form is one empty rule per direction.
  expect(yamlText()).toContain('  ingress:\n  - {}');
  expect(yamlText()).toContain('  egress:\n  - {}');
  expect(screen.getByRole('alert').textContent).toContain('No traffic observed, so this policy allows nothing');
  expect(screen.getByRole('button', { name: 'Save Deny-All Policy' })).toBeTruthy();
});

// A direction that was observed but produced no rule (every peer unparseable)
// keeps its policyType and nothing else: that denies THAT direction only, and
// the words must not claim both.
const unparseableEgress = [{ traffic_type: 'EGRESS', traffic_in_out_ip: 'not-an-ip', traffic_in_out_port: '5432', ip_protocol: 'TCP' }];

test('one covered direction with no rules: the warning, footer and Save name that direction only', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload(unparseableEgress)} initialPolicyType="network" />);
  await waitForYaml('kind: NetworkPolicy');
  expect(yamlText()).toContain('  policyTypes:\n  - Egress');
  expect(yamlText()).not.toContain('- Ingress');
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('This policy has no rules and allows nothing');
  expect(alert.textContent).toContain('denies all egress');
  expect(alert.textContent).not.toContain('ingress and egress');
  expect(screen.getByText(/^This policy has no rules but still covers egress: applying it denies all egress\.$/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Save Deny-All Egress Policy' })).toBeTruthy();
});

test('one covered direction, Cilium: enableDefaultDeny egress only, an empty egress rule, egress wording', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload(unparseableEgress)} initialPolicyType="cilium" />);
  await waitForYaml('kind: CiliumNetworkPolicy');
  expect(yamlText()).toContain('  enableDefaultDeny:\n    ingress: false\n    egress: true');
  expect(yamlText()).toContain('  egress:\n  - {}');
  expect(yamlText()).not.toContain('\n  ingress:');
  expect(screen.getByRole('alert').textContent).toContain('denies all egress');
  expect(screen.getByRole('button', { name: 'Save Deny-All Egress Policy' })).toBeTruthy();
});

test('deleting the last rule in the visual editor surfaces the same one-direction warning', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([
    { traffic_type: 'EGRESS', traffic_in_out_ip: '52.1.2.3', traffic_in_out_port: '443', ip_protocol: 'TCP' },
  ])} initialPolicyType="network" />);
  await waitForYaml('cidr: 52.1.2.3/32');
  expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(screen.getByText('Visual Editor'));
  fireEvent.click(screen.getByTitle('Remove rule'));
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('This policy has no rules and allows nothing');
  expect(alert.textContent).toContain('denies all egress');
  expect(screen.getByRole('button', { name: 'Save Deny-All Egress Policy' })).toBeTruthy();
});

// A multi-pod workload where one member's read failed but others succeeded
// has rules, so it is not deny-all, but its peers may be missing; that must
// not read as "generated from observed network traffic".
test('rules plus a failed member read: a dismissible incomplete-traffic warning and an honest footer', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([
    { traffic_type: 'EGRESS', traffic_in_out_ip: '52.1.2.3', traffic_in_out_port: '443', ip_protocol: 'TCP' },
  ], { trafficError: true })} initialPolicyType="network" />);
  await waitForYaml('cidr: 52.1.2.3/32');
  expect(screen.queryByRole('alert')).toBeNull();
  const note = screen.getByText(/Traffic for this workload is incomplete/).closest('[role="note"]')!;
  expect(note.textContent).toContain('peers may be missing');
  expect(within(note as HTMLElement).getByRole('button', { name: 'Dismiss policy notice' })).toBeTruthy();
  expect(screen.getByText(/generated from incomplete network traffic/)).toBeTruthy();
  expect(screen.queryByText(/generated from observed network traffic/)).toBeNull();
  expect(screen.getByRole('button', { name: 'Save Policy' })).toBeTruthy();
});

test('the warning tracks the document: adding a rule in the visual editor clears it', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([])} initialPolicyType="network" />);
  await waitForYaml('kind: NetworkPolicy');
  fireEvent.click(screen.getByText('Visual Editor'));
  expect(screen.getByRole('alert')).toBeTruthy();
  fireEvent.click(screen.getAllByText('Add Rule')[0]);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByRole('button', { name: 'Save Policy' })).toBeTruthy();
});

test('a workload with traffic shows neither the warning nor the deny-all label', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([
    { traffic_type: 'EGRESS', traffic_in_out_ip: '52.1.2.3', traffic_in_out_port: '443', ip_protocol: 'TCP' },
  ])} initialPolicyType="network" />);
  await waitForYaml('cidr: 52.1.2.3/32');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByRole('button', { name: 'Save Policy' })).toBeTruthy();
  expect(screen.getByText(/generated from observed network traffic/)).toBeTruthy();
});

// TOOL-16: the visual editor labelled every ipBlock "External (IP Block)"
// with the hint "External traffic outside the cluster" — node IPs of
// host-network peers and Service ClusterIPs included. The label now comes
// from the rule comment, and the hint stays only for a real external peer.
test('visual editor: a selector-less Service ipBlock is labelled as a cluster Service IP, a public IP stays external', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={workload([
    { traffic_type: 'EGRESS', traffic_in_out_ip: '10.96.0.1', traffic_in_out_port: '443', ip_protocol: 'TCP',
      peer_kind: 'service', peer_namespace: 'default', peer_name: 'kubernetes' },
    { traffic_type: 'EGRESS', traffic_in_out_ip: '52.1.2.3', traffic_in_out_port: '443', ip_protocol: 'TCP' },
  ])} initialPolicyType="network" />);
  await waitForYaml('# Service default/kubernetes has no selector — ipBlock 10.96.0.1 is its ClusterIP and will not match after DNAT');
  expect(yamlText()).not.toContain('unattributed');

  fireEvent.click(screen.getByText('Visual Editor'));
  expect(await screen.findByText('Service default/kubernetes has no selector — ipBlock 10.96.0.1 is its ClusterIP and will not match after DNAT')).toBeTruthy();
  expect((screen.getByDisplayValue('Cluster Service IP') as HTMLSelectElement).value).toBe('external');
  expect((screen.getByDisplayValue('External (IP Block)') as HTMLSelectElement).value).toBe('external');
  expect(screen.getAllByText('External traffic outside the cluster')).toHaveLength(1);
  expect(screen.getByDisplayValue('10.96.0.1/32')).toBeTruthy();
  expect(screen.getByDisplayValue('52.1.2.3/32')).toBeTruthy();
});
