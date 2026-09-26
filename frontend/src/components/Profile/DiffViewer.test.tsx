// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { DiffViewer } from './DiffViewer';
import { diffLines } from '../../utils/profileView';
import { checkoutDiff, checkoutDiff2to4, checkoutDiffTrimmed } from '../../fixtures/profile';
import type { ProfileDiff } from '../../types/profile';

afterEach(cleanup);

test('diffLines: the captured default diff (v3 → v4) — level and container field changes only', () => {
  const l = diffLines(checkoutDiff.body);
  expect(l.podSecurity).toEqual([
    { kind: 'change', text: 'PSS level: baseline → restricted' },
    { kind: 'change', text: 'migrate securityContext.allowPrivilegeEscalation: unset → false' },
    { kind: 'change', text: 'migrate securityContext.capabilitiesDrop: unset → ALL' },
  ]);
  // Unchanged dimensions (and null scalars) emit nothing.
  expect(l.images).toEqual([]);
  expect(l.syscalls).toEqual([]);
  expect(l.network).toEqual([]);
});

test('diffLines: the captured trimmed-predecessor diff — containers, pod fields, syscalls and rules all added', () => {
  const l = diffLines(checkoutDiffTrimmed.body);
  expect(l.images).toEqual([
    { kind: 'add', text: 'container app' },
    { kind: 'add', text: 'container migrate' },
  ]);
  expect(l.podSecurity[0]).toEqual({ kind: 'change', text: 'PSS level: unset → baseline' });
  expect(l.podSecurity).toContainEqual({ kind: 'change', text: 'pod serviceAccountName: unset → checkout' });
  expect(l.syscalls).toEqual([
    { kind: 'add', text: 'accept4' },
    { kind: 'add', text: 'exit_group' },
    { kind: 'add', text: 'read' },
    { kind: 'add', text: 'write' },
    { kind: 'change', text: 'capture level: unset → medium' },
  ]);
  expect(l.network).toContainEqual({ kind: 'add', text: 'egress TCP/443 external:203.0.113.10' });
});

test('diffLines: removals, digests and a CR change (not in any capture, derived from the default diff)', () => {
  const d: ProfileDiff = structuredClone(checkoutDiff.body);
  d.dimensions.images = { changed: true, containersAdded: [], containersRemoved: ['legacy-proxy'], containers: [{ name: 'app', added: ['sha256:4a1b77c04a1b77c0aa'], removed: ['sha256:5b2c88d15b2c88d1bb'] }] };
  d.dimensions.syscalls = { changed: true, added: [], removed: ['select'], captureLevel: null, cr: { from: null, to: { name: 'deployment-checkout', defaultAction: 'SCMP_ACT_LOG', hash: 'h' } } };
  d.dimensions.network = { changed: true, added: [], removed: [{ direction: 'egress', protocol: 'TCP', port: 6379, peer: 'pod:payments/StatefulSet/redis' }] };
  const l = diffLines(d);
  expect(l.images).toEqual([
    { kind: 'remove', text: 'container legacy-proxy' },
    { kind: 'add', text: 'app sha256:4a1b77c04a1b…' },
    { kind: 'remove', text: 'app sha256:5b2c88d15b2c…' },
  ]);
  expect(l.syscalls).toEqual([
    { kind: 'remove', text: 'select' },
    { kind: 'change', text: 'SeccompProfile CR: none → deployment-checkout (SCMP_ACT_LOG)' },
  ]);
  expect(l.network).toEqual([{ kind: 'remove', text: 'egress TCP/6379 pod:payments/StatefulSet/redis' }]);
});

test('renders +/~ lines with screen-reader words, and collapses unchanged dimensions', () => {
  render(<DiffViewer diff={checkoutDiff2to4.body} />);
  const net = screen.getByRole('region', { name: 'Network changes' });
  const items = within(net).getAllByRole('listitem');
  expect(items.map((i) => i.dataset.kind)).toEqual(['add']);
  expect(items[0].textContent).toBe('+Added: egress TCP/443 external:198.51.100.20');
  const ps = within(screen.getByRole('region', { name: 'Pod security changes' })).getAllByRole('listitem');
  expect(ps[0].textContent).toBe('~Changed: PSS level: baseline → restricted');
  const images = screen.getByRole('region', { name: 'Images changes' });
  expect(within(images).getByText('no change')).not.toBeNull();
  expect(within(images).queryByRole('list')).toBeNull();
  expect(screen.getByTestId('diff-viewer').querySelector('p')!.textContent).toMatch(/^v2 \(.*\) → v4 \(/);
});

test('fromTrimmed: says earlier versions were trimmed, not "first revision"', () => {
  render(<DiffViewer diff={checkoutDiffTrimmed.body} />);
  const header = screen.getByTestId('diff-viewer').querySelector('p')!.textContent!;
  expect(header).toContain('Earlier versions were trimmed by retention');
  expect(header).not.toContain('First revision');
});

test('from = null without fromTrimmed is the first revision', () => {
  render(<DiffViewer diff={{ ...checkoutDiffTrimmed.body, fromTrimmed: false }} />);
  expect(screen.getByText(/First revision/)).not.toBeNull();
});

test('no change between revisions says so', () => {
  render(<DiffViewer diff={{ ...checkoutDiff.body, changed: false }} />);
  expect(screen.getByText('No policy-relevant change between these revisions.')).not.toBeNull();
});
