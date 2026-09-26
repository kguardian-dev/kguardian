// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { CommandPalette } from './CommandPalette';

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
