// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { AuditVerdict } from '../types';

const getAuditVerdicts = vi.fn<(opts?: Record<string, unknown>) => Promise<AuditVerdict[]>>();
vi.mock('../services/api', () => ({
  default: { getAuditVerdicts: (o?: Record<string, unknown>) => getAuditVerdicts(o) },
}));

import AuditVerdictsPanel from './AuditVerdictsPanel';

afterEach(() => {
  cleanup();
  getAuditVerdicts.mockReset();
});

let nextId = 1;
const verdict = (over: Partial<AuditVerdict> = {}): AuditVerdict => ({
  id: nextId++, policy_uid: 'u', policy_namespace: '', policy_name: 'cluster-baseline-audit', direction: 'Ingress',
  src_namespace: 'argocd', src_pod: 'argocd-server-1', dst_namespace: 'payments', dst_pod: 'api-1',
  dst_port: 8080, protocol: 'TCP', reason: null, observed_at: '2026-09-28T12:57:04.215869', verdict: 'WouldDeny',
  ...over,
});

const open = () => render(<AuditVerdictsPanel isOpen onClose={() => {}} />);
const bodyRows = () => screen.getAllByRole('row').slice(1);
const inSydney = async (run: () => Promise<void>) => {
  const tz = process.env.TZ;
  process.env.TZ = 'Australia/Sydney';
  try {
    await run();
  } finally {
    process.env.TZ = tz;
  }
};

test('WHEN shows the naive UTC observed_at in the local zone, with the zone named', () =>
  inSydney(async () => {
    getAuditVerdicts.mockResolvedValue([verdict({ observed_at: '2026-09-28T12:57:04.215869' })]);
    open();
    // 12:57 UTC is 22:57 AEST. The old rendering showed 12:57 PM.
    const cell = await screen.findByText(/10:57:04|22:57:04/);
    expect(cell.textContent).toMatch(/AEST|GMT\+10/);
    expect(screen.queryByText(/12:57:04/)).toBeNull();
  }));

test('the WHEN sort compares instants, so a naive row is not misplaced against an offset one', () =>
  inSydney(async () => {
    // Read as local time the naive row would be 02:57Z and sort below the
    // 10:00Z row; read as UTC (12:57Z) it is the newer of the two.
    getAuditVerdicts.mockResolvedValue([
      verdict({ observed_at: '2026-09-28T20:00:00+10:00', dst_pod: 'older-by-offset' }),
      verdict({ observed_at: '2026-09-28T12:57:04', dst_pod: 'newer-naive' }),
    ]);
    open();
    await screen.findByText(/newer-naive/);
    const order = bodyRows().map(r => (within(r).getByText(/payments\//).textContent ?? ''));
    expect(order).toEqual(['payments/newer-naive', 'payments/older-by-offset']);
  }));

test('an API failure renders the error state, not the "no verdicts" empty state', async () => {
  getAuditVerdicts.mockRejectedValue(new Error('Network Error'));
  open();
  const box = await screen.findByText(/Failed to load audit verdicts/);
  expect(box.textContent).toContain('Network Error');
  expect(screen.queryByText(/No would-deny verdicts/)).toBeNull();
  expect(screen.queryByText(/has not recorded/)).toBeNull();
});

test('a successful empty response keeps the empty state', async () => {
  getAuditVerdicts.mockResolvedValue([]);
  open();
  expect(await screen.findByText('No would-deny verdicts in the rolling window')).toBeTruthy();
  expect(screen.getByText('The evaluator has not recorded any audited flows for this window yet.')).toBeTruthy();
  expect(screen.queryByText(/Failed to load/)).toBeNull();
});

test('one row past the cap is requested, and the footer says older verdicts exist', async () => {
  getAuditVerdicts.mockResolvedValue(Array.from({ length: 401 }, (_, i) => verdict({ dst_pod: `api-${i}` })));
  open();
  await screen.findByText(/older verdicts exist/);
  expect(getAuditVerdicts).toHaveBeenCalledWith(expect.objectContaining({ limit: 401 }));
  expect(bodyRows()).toHaveLength(400);
  expect(screen.getByText(/Showing 400 of the 400 newest verdicts; older verdicts exist/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'All (400)' })).toBeTruthy();
});

test('a response within the cap keeps the plain count', async () => {
  getAuditVerdicts.mockResolvedValue([verdict(), verdict(), verdict()]);
  open();
  await screen.findByText(/Showing 3 of 3 most recent verdicts/);
  expect(screen.queryByText(/older verdicts exist/)).toBeNull();
});

test('the workload namespace filter uses the verdict subject: destination for Ingress, source for Egress', async () => {
  getAuditVerdicts.mockResolvedValue([
    verdict({ direction: 'Ingress', src_namespace: 'argocd', dst_namespace: 'payments', dst_pod: 'api-1' }),
    verdict({ direction: 'Egress', src_namespace: 'payments', src_pod: 'api-2', dst_namespace: 'kube-system', dst_pod: 'kube-dns-1' }),
    verdict({ direction: 'Ingress', src_namespace: 'payments', dst_namespace: 'argocd', dst_pod: 'argocd-repo-1' }),
  ]);
  open();
  await screen.findByText(/argocd-repo-1/);
  const select = screen.getByLabelText('Workload namespace') as HTMLSelectElement;
  // kube-system is only ever a peer, never the subject, so it is not offered.
  expect(Array.from(select.options).map(o => o.value)).toEqual(['', 'argocd', 'payments']);

  fireEvent.change(select, { target: { value: 'payments' } });
  expect(screen.getByText(/api-1/)).toBeTruthy();
  expect(screen.getByText(/kube-dns-1/)).toBeTruthy();
  expect(screen.queryByText(/argocd-repo-1/)).toBeNull();
  expect(screen.getByText(/Showing 2 of 3/)).toBeTruthy();

  fireEvent.change(select, { target: { value: 'argocd' } });
  expect(screen.getByText(/argocd-repo-1/)).toBeTruthy();
  expect(screen.queryByText(/kube-dns-1/)).toBeNull();
});

test('a filtered-out view says so and offers to clear the filters', async () => {
  getAuditVerdicts.mockResolvedValue([verdict({ dst_namespace: 'payments' })]);
  open();
  await screen.findByText(/api-1/);
  const select = screen.getByLabelText('Workload namespace') as HTMLSelectElement;
  fireEvent.change(select, { target: { value: 'payments' } });
  fireEvent.click(screen.getByRole('button', { name: /^Allow\s*\(/ }));
  expect(screen.getByText('No allow verdicts in the rolling window')).toBeTruthy();
  expect(screen.getByText('Nothing matched the current filters.')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
  expect(select.value).toBe('');
});

test('the empty state names the tab properly and points at the rows on the other tab', async () => {
  getAuditVerdicts.mockResolvedValue([verdict({ verdict: 'Allow' }), verdict({ verdict: 'Allow' })]);
  open();
  expect(await screen.findByText('No would-deny verdicts in the rolling window')).toBeTruthy();
  expect(screen.getByText('2 allow verdicts are on the Allow tab.')).toBeTruthy();
  expect(screen.queryByText(/woulddeny/)).toBeNull();
  expect(screen.queryByText(/has not recorded/)).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: /^Allow\s*\(2\)/ }));
  expect(bodyRows()).toHaveLength(2);
});

test('the Allow tab with only would-deny rows names their count instead of claiming nothing was recorded', async () => {
  getAuditVerdicts.mockResolvedValue([verdict({ verdict: 'WouldDeny' })]);
  open();
  await screen.findByText(/api-1/);
  fireEvent.click(screen.getByRole('button', { name: /^Allow\s*\(0\)/ }));
  expect(screen.getByText('No allow verdicts in the rolling window')).toBeTruthy();
  expect(screen.getByText('1 would-deny verdict is on the Would-Deny tab.')).toBeTruthy();
});

test('an empty state under a truncated load says the filters only saw the 400 newest', async () => {
  // Kept: one Allow row for argocd, then 399 would-deny rows for payments; the
  // 401st row is sliced off and only tells us the window is truncated.
  getAuditVerdicts.mockResolvedValue([
    verdict({ verdict: 'Allow', dst_namespace: 'argocd', dst_pod: 'argocd-repo-1' }),
    ...Array.from({ length: 400 }, (_, i) => verdict({ dst_namespace: 'payments', dst_pod: `api-${i}` })),
  ]);
  open();
  await screen.findByText(/older verdicts exist/);
  fireEvent.change(screen.getByLabelText('Workload namespace'), { target: { value: 'argocd' } });
  expect(screen.getByText('No would-deny verdicts among the 400 newest')).toBeTruthy();
  expect(
    screen.getByText('Nothing in the 400 newest verdicts matched the current filters; older verdicts exist.'),
  ).toBeTruthy();
  expect(screen.queryByText(/in the rolling window/)).toBeNull();
});

test('the other-tab hint under a truncated load also says older verdicts exist', async () => {
  getAuditVerdicts.mockResolvedValue(Array.from({ length: 401 }, (_, i) => verdict({ verdict: 'Allow', dst_pod: `api-${i}` })));
  open();
  expect(await screen.findByText('No would-deny verdicts among the 400 newest')).toBeTruthy();
  expect(screen.getByText('400 allow verdicts are on the Allow tab; older verdicts exist.')).toBeTruthy();
});

test('an empty window under a direction filter says which direction was empty', async () => {
  getAuditVerdicts.mockResolvedValue([]);
  open();
  await screen.findByText(/has not recorded any audited flows/);
  fireEvent.click(screen.getByRole('button', { name: 'Egress' }));
  expect(await screen.findByText('The evaluator has not recorded any egress flows for this window yet.')).toBeTruthy();
  expect(getAuditVerdicts).toHaveBeenLastCalledWith({ limit: 401, direction: 'Egress' });
});
