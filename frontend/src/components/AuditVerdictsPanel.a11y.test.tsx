// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import type { AuditVerdict } from '../types';
import AuditVerdictsPanel from './AuditVerdictsPanel';

// The read stays pending until a test settles it, like the 13 to 30 s reads on a busy broker.
let settle: (rows: AuditVerdict[]) => void = () => {};
const getAuditVerdicts = vi.fn(() => new Promise<AuditVerdict[]>((resolve) => { settle = resolve; }));
vi.mock('../services/api', () => ({ default: { getAuditVerdicts: () => getAuditVerdicts() } }));

afterEach(cleanup);

const verdict = (over: Partial<AuditVerdict>): AuditVerdict => ({
  id: 1,
  policy_uid: 'u',
  policy_namespace: '',
  policy_name: 'deny-egress',
  direction: 'Egress',
  src_namespace: 'payments',
  src_pod: 'api-1',
  dst_namespace: null,
  dst_pod: null,
  dst_port: 443,
  protocol: 'TCP',
  reason: null,
  observed_at: '2026-09-28T10:00:00',
  verdict: 'Allow',
  ...over,
});

test('opens with focus on the Would-Deny tab, not on Refresh, which loading disables a moment later', async () => {
  render(<AuditVerdictsPanel isOpen onClose={() => {}} />);
  const tab = screen.getByRole('button', { name: /^Would-Deny/ });
  expect(document.activeElement).toBe(tab);
  expect((screen.getByTitle('Refresh') as HTMLButtonElement).disabled).toBe(true);

  await act(async () => {
    settle([]);
  });
  expect((screen.getByTitle('Refresh') as HTMLButtonElement).disabled).toBe(false);
  expect(document.activeElement).toBe(tab);
});

test('accent-coloured text and icons use the accent foreground token, never the brand fill colour', async () => {
  render(<AuditVerdictsPanel isOpen onClose={() => {}} />);
  await act(async () => {
    settle([verdict({ id: 1, verdict: 'Allow' }), verdict({ id: 2, verdict: 'WouldDeny' })]);
  });
  // The cluster-scoped tag on the visible Would-Deny row, the sidebar's and
  // the footer's "1 allow", and the Allow tab's icon.
  expect(screen.getAllByText('(cluster)')[0].className).toContain('text-accent-fg');
  const allows = screen.getAllByText(/^1 allow$/);
  expect(allows.length).toBe(2);
  for (const el of allows) expect(el.className).toContain('text-accent-fg');
  expect(screen.getByRole('button', { name: /^Allow/ }).querySelector('span')!.className).toBe('text-accent-fg');
  expect(screen.getByRole('dialog').innerHTML).not.toContain('text-hubble-accent');
});
