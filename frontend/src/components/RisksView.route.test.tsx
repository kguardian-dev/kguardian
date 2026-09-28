// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';

afterEach(cleanup);

// RisksRoute feeds the posture strip from the seccomp profile list hook.
const seccomp: { profiles: WorkloadProfileSummary[]; loading: boolean; error: string | null } = { profiles: [], loading: true, error: null };
vi.mock('../hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles: seccomp.profiles, loading: seccomp.loading, error: seccomp.error, refresh: async () => {} }),
}));
const getAuditVerdicts = vi.fn(async () => []);
vi.mock('../services/api', () => ({ default: { getAuditVerdicts: () => getAuditVerdicts() } }));

import { RisksRoute } from './RisksView';

const route = () => render(<RisksRoute pods={[]} namespace="payments" onSelectPod={() => {}} onBuildPolicy={() => {}} onOpenAudit={() => {}} />);
const tile = () => screen.getByText('Seccomp enforcing').closest('[title]')!;

test('the seccomp tile is present with a dash while the list loads, and after it failed, instead of disappearing', () => {
  Object.assign(seccomp, { profiles: [], loading: true, error: null });
  route();
  expect(tile().textContent).toContain('—');
  expect(tile().getAttribute('title')).toMatch(/not answered the profile list yet/);
  cleanup();
  Object.assign(seccomp, { profiles: [], loading: false, error: 'canceling statement due to statement timeout' });
  route();
  expect(tile().textContent).toContain('—');
  expect(tile().textContent).not.toMatch(/0\/0/);
  expect(tile().getAttribute('title')).toMatch(/statement timeout/);
});

test('a loaded list counts, and a successful empty list is an honest 0/0', () => {
  Object.assign(seccomp, {
    loading: false, error: null,
    profiles: [{ namespace: 'payments', kind: 'Deployment', name: 'api', hash: 'h', syscallCount: 1, architectures: [], updatedAt: 't', cr: { name: 'c', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 1, distribution: { ready: 1, total: 1, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true } } }],
  });
  route();
  expect(tile().textContent).toContain('1/1');
  cleanup();
  Object.assign(seccomp, { profiles: [], loading: false, error: null });
  route();
  expect(tile().textContent).toContain('0/0');
});

test('the route threads the header Refresh through to the verdict read', async () => {
  Object.assign(seccomp, { profiles: [], loading: false, error: null });
  getAuditVerdicts.mockClear();
  const props = { pods: [], namespace: 'payments', onSelectPod: () => {}, onBuildPolicy: () => {}, onOpenAudit: () => {} };
  const { rerender } = render(<RisksRoute {...props} refreshTick={0} />);
  expect(getAuditVerdicts).toHaveBeenCalledTimes(1);
  rerender(<RisksRoute {...props} refreshTick={1} />);
  expect(getAuditVerdicts).toHaveBeenCalledTimes(2);
});
