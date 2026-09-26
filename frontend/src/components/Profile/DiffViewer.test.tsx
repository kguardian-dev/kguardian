// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { DiffViewer } from './DiffViewer';
import { diffLines } from '../../utils/profileView';
import { checkoutDiff, checkoutDiff1to2 } from '../../fixtures/profile';
import type { ProfileDiff } from '../../types/profile';

afterEach(cleanup);

test('diffLines: scalar changes, field changes and digest add/remove from the contract example', () => {
  const l = diffLines(checkoutDiff);
  expect(l.podSecurity).toEqual([
    { kind: 'change', text: 'PSS level: baseline → restricted' },
    { kind: 'change', text: 'pod securityContext.seccompProfileType: unset → RuntimeDefault' },
    { kind: 'change', text: 'app allowPrivilegeEscalation: unset → false' },
  ]);
  expect(l.images).toEqual([
    { kind: 'add', text: 'app sha256:9f2c0d1e7a4b…' },
    { kind: 'remove', text: 'app sha256:0c3d5e7f9a1b…' },
  ]);
  // Unchanged scalars are null in the contract and emit nothing.
  expect(l.syscalls).toEqual([]);
  expect(l.network).toEqual([]);
});

test('diffLines: syscalls, capture level, network rules and CR changes', () => {
  const l = diffLines(checkoutDiff1to2);
  expect(l.syscalls).toEqual([
    { kind: 'add', text: 'epoll_pwait2' },
    { kind: 'add', text: 'openat2' },
    { kind: 'remove', text: 'select' },
    { kind: 'change', text: 'capture level: high → full' },
  ]);
  expect(l.network).toEqual([
    { kind: 'add', text: 'egress TCP/443 external:203.0.113.10' },
    { kind: 'remove', text: 'egress TCP/6379 pod:payments/StatefulSet/redis' },
  ]);
  const withCr: ProfileDiff = structuredClone(checkoutDiff1to2);
  withCr.dimensions.syscalls.cr = { from: null, to: { name: 'deployment-checkout', defaultAction: 'SCMP_ACT_LOG', hash: 'h' } };
  withCr.dimensions.network.audited = { from: false, to: true };
  expect(diffLines(withCr).syscalls.at(-1)).toEqual({ kind: 'change', text: 'SeccompProfile CR: none → deployment-checkout (SCMP_ACT_LOG)' });
  expect(diffLines(withCr).network.at(-1)).toEqual({ kind: 'change', text: 'covered by audit policy: false → true' });
});

test('renders +/−/~ lines with screen-reader words, and collapses unchanged dimensions', () => {
  render(<DiffViewer diff={checkoutDiff1to2} />);
  const syscalls = screen.getByRole('region', { name: 'Syscalls changes' });
  const items = within(syscalls).getAllByRole('listitem');
  expect(items.map((i) => i.dataset.kind)).toEqual(['add', 'add', 'remove', 'change']);
  expect(items[0].textContent).toBe('+Added: epoll_pwait2');
  expect(items[2].textContent).toBe('−Removed: select');
  const ps = screen.getByRole('region', { name: 'Pod security changes' });
  expect(within(ps).getByText('no change')).not.toBeNull();
  expect(within(ps).queryByRole('list')).toBeNull();
  expect(screen.getByTestId('diff-viewer').querySelector('p')!.textContent).toMatch(/^v1 \(.*\) → v2 \(/);
});

test('no change between revisions says so', () => {
  const same: ProfileDiff = structuredClone(checkoutDiff);
  same.changed = false;
  render(<DiffViewer diff={same} />);
  expect(screen.getByText('No policy-relevant change between these revisions.')).not.toBeNull();
});

test('a first revision (from = null) says everything is added', () => {
  const first: ProfileDiff = { ...structuredClone(checkoutDiff1to2), from: null };
  render(<DiffViewer diff={first} />);
  expect(screen.getByText(/everything shows as added/)).not.toBeNull();
});
