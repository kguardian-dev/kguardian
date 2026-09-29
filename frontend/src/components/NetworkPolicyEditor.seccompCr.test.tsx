// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { parse } from 'yaml';
import type { PodInfo, PodNodeData } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';
import { CR_ARCHITECTURES, CR_DEFAULT_ACTIONS, CR_RULE_ACTIONS } from '../types/seccompWorkload';

// The kguardian SeccompProfile CR is the default seccomp export, and its CRD
// enumerates the actions and architectures it accepts. The editor offered
// the whole seccomp vocabulary, so picking SCMP_ACT_TRAP or S390X produced a
// manifest `kubectl apply` rejects.

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn(async () => null),
    getPodDetailsByName: vi.fn(async () => null),
    getClusterEnvironment: vi.fn(async () => UNKNOWN_CLUSTER_ENVIRONMENT),
  };
  return { apiClient, default: apiClient };
});
vi.mock('../services/seccompApi', () => ({
  seccompApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue(null) }),
}));

import NetworkPolicyEditor from './NetworkPolicyEditor';

const web: PodInfo = {
  pod_name: 'web-0', pod_ip: '10.0.0.1', pod_namespace: 'prod', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false,
  workload_kind: 'Deployment', workload_name: 'web', workload_selector_labels: { app: 'web' },
};
const target = {
  id: 'web', label: 'web', pod: web, pods: [web], isExpanded: false, traffic: [],
  syscalls: [{ pod_name: 'web-0', pod_namespace: 'prod', syscalls: 'read,write', arch: 'x86_64', time_stamp: '2026-09-03T00:00:00' }],
} as PodNodeData;

const exportText = () => document.querySelector('pre')?.textContent ?? '';
const optionsOf = (select: HTMLElement) => [...select.querySelectorAll('option')].map((o) => o.value);
const archButtons = () =>
  screen.getByText('Architectures').parentElement!.querySelectorAll('button');
const blockedNotice = () => screen.queryByText(/The kguardian SeccompProfile CRD does not accept/);
const toVisual = () => fireEvent.click(screen.getByText('Visual Editor'));
const toExport = () => fireEvent.click(screen.getByText('Export View'));

afterEach(cleanup);

test('kguardian CR: the editor offers only what the CRD accepts', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="seccomp" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: SeccompProfile'));
  toVisual();
  expect(optionsOf(screen.getByDisplayValue('SCMP_ACT_ERRNO'))).toEqual([...CR_DEFAULT_ACTIONS]);
  expect(optionsOf(screen.getByDisplayValue('SCMP_ACT_ALLOW'))).toEqual([...CR_RULE_ACTIONS]);
  expect([...archButtons()].map((b) => `SCMP_ARCH_${b.textContent}`)).toEqual([...CR_ARCHITECTURES]);
});

test('an action or architecture chosen for another format blocks the kguardian CR export and says why', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="seccomp" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: SeccompProfile'));
  // SPO takes the full vocabulary.
  fireEvent.click(screen.getByRole('radio', { name: 'Security Profiles Operator CR' }));
  toVisual();
  const defaultAction = screen.getByDisplayValue('SCMP_ACT_ERRNO');
  expect(optionsOf(defaultAction)).toContain('SCMP_ACT_TRAP');
  fireEvent.change(defaultAction, { target: { value: 'SCMP_ACT_TRAP' } });
  fireEvent.click(within(screen.getByText('Architectures').parentElement!).getByText('S390X'));
  toExport();
  expect(exportText()).toContain('defaultAction: SCMP_ACT_TRAP');

  fireEvent.click(screen.getByRole('radio', { name: 'kguardian CR' }));
  const error = blockedNotice()!;
  expect(error.getAttribute('role')).toBe('alert');
  expect(error.textContent).toContain('defaultAction SCMP_ACT_TRAP');
  expect(error.textContent).toContain('architecture SCMP_ARCH_S390X');
  // No manifest the API server would reject is shown (or copied / downloaded).
  expect(document.querySelector('pre')).toBeNull();

  // The visual editor keeps the chosen values visible, marked, so they can be changed.
  toVisual();
  const select = screen.getByDisplayValue(/SCMP_ACT_TRAP/) as HTMLSelectElement;
  expect(select.value).toBe('SCMP_ACT_TRAP');
  expect(optionsOf(select)).toEqual([...CR_DEFAULT_ACTIONS, 'SCMP_ACT_TRAP']);
  expect(blockedNotice()!.textContent).toContain('defaultAction SCMP_ACT_TRAP');
  fireEvent.change(select, { target: { value: 'SCMP_ACT_KILL_PROCESS' } });
  fireEvent.click(within(screen.getByText('Architectures').parentElement!).getByText('S390X'));
  expect(blockedNotice()).toBeNull();

  toExport();
  const doc = parse(exportText());
  expect(doc.kind).toBe('SeccompProfile');
  expect(doc.spec.defaultAction).toBe('SCMP_ACT_KILL_PROCESS');
  expect(doc.spec.architectures).toEqual(['SCMP_ARCH_X86_64']);
});
