// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Boxes, Server } from 'lucide-react';
import { CommandPalette, type Command } from './CommandPalette';

afterEach(cleanup);

test('the command palette dialog has an accessible name', () => {
  render(<CommandPalette onClose={() => {}} commands={[]} />);
  expect(screen.getByRole('dialog', { name: 'Search and commands' })).toBeTruthy();
});

// The palette's input has autoFocus, so it holds focus before Modal's effects
// run: the opener must be recorded before that, or closing loses it.
function Opener({ withRail }: { withRail: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button>Before</button>
      {withRail ? (
        <div role="dialog" aria-modal="true" aria-label="Navigation">
          <button>Collapse sidebar</button>
          <button onClick={() => setOpen(true)}>Workloads</button>
        </div>
      ) : (
        <button onClick={() => setOpen(true)}>Expand sidebar</button>
      )}
      {open && <CommandPalette onClose={() => setOpen(false)} commands={[]} />}
    </div>
  );
}

test.each([
  ['a page button', false, 'Expand sidebar'],
  ['an item of the rail underneath', true, 'Workloads'],
])('closing the palette returns focus to its opener (%s), not the body or the first item', (_, withRail, opener) => {
  render(<Opener withRail={withRail} />);
  const btn = screen.getByRole('button', { name: opener });
  btn.focus();
  fireEvent.click(btn);
  const input = screen.getByRole('dialog', { name: 'Search and commands' }).querySelector('input')!;
  expect(document.activeElement).toBe(input);
  fireEvent.keyDown(input, { key: 'Escape' });
  expect(screen.queryByRole('dialog', { name: 'Search and commands' })).toBeNull();
  expect(document.activeElement).toBe(btn);
});

const namespaces = (n: number): Command[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `ns-${i}`,
    group: 'Namespaces',
    label: `domain-livestream-dev-${String(i + 1).padStart(2, '0')}`,
    icon: Boxes,
    run: () => {},
  }));

const input = () => screen.getByPlaceholderText(/Jump to a view/);

test('a capped group says how many more matches it hides, until typing narrows it', () => {
  render(<CommandPalette onClose={() => {}} commands={namespaces(9)} />);
  expect(screen.getAllByRole('button').filter((b) => b.textContent?.startsWith('domain-')).length).toBe(8);
  expect(screen.getByText('1 more, keep typing to narrow the list')).toBeTruthy();

  fireEvent.change(input(), { target: { value: 'dev-09' } });
  expect(screen.getByText('domain-livestream-dev-09')).toBeTruthy();
  expect(screen.queryByText(/more, keep typing/)).toBeNull();
});

test('the overflow row is not a result: arrows and Enter never land on it', () => {
  const runs: string[] = [];
  const commands = namespaces(10).map((c) => ({ ...c, run: () => runs.push(c.label) }));
  render(<CommandPalette onClose={() => {}} commands={commands} />);
  for (let i = 0; i < 12; i++) fireEvent.keyDown(input(), { key: 'ArrowDown' });
  fireEvent.keyDown(input(), { key: 'Enter' });
  expect(runs).toEqual(['domain-livestream-dev-08']);
});

// The shape App supplies: keywords is a space-separated string of extra terms
// (a workload's member pod names), matched as a substring, not fuzzily.
test('keywords match as a substring, so a member pod name finds its workload', () => {
  render(
    <CommandPalette
      onClose={() => {}}
      commands={[
        { id: 'w-redis', group: 'Workloads', label: 'redis-ha', hint: 'argocd', icon: Server, keywords: 'argocd-redis-ha-server-0 argocd-redis-ha-server-1', run: () => {} },
        { id: 'w-server', group: 'Workloads', label: 'argocd-server', hint: 'argocd', icon: Server, run: () => {} },
      ]}
    />,
  );
  fireEvent.change(input(), { target: { value: 'ha-server-0' } });
  expect(screen.getByText('redis-ha')).toBeTruthy();
  expect(screen.queryByText('argocd-server')).toBeNull();
});

test('the active row icon uses the accent foreground token, which keeps AA contrast on the dark card', () => {
  render(<CommandPalette onClose={() => {}} commands={namespaces(1)} />);
  const icon = screen.getByRole('button', { name: /domain-livestream-dev-01/ }).querySelector('svg')!;
  expect(icon.getAttribute('class')).toContain('text-accent-fg');
  expect(icon.getAttribute('class')).not.toContain('text-hubble-accent');
});
