// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { useRef, useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useDialogFocus } from './useDialogFocus';

afterEach(cleanup);

// The opener unmounts while the dialog is open, like the rail's expand
// button: focus must still come back to the (remounted) opener.
function Harness() {
  const [open, setOpen] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLButtonElement>(null);
  useDialogFocus({ open, dialogRef, returnFocusRef: openerRef, onClose: () => setOpen(false), initialFocus: 'nav button' });
  return (
    <div>
      {!open && <button ref={openerRef} onClick={() => setOpen(true)}>Expand sidebar</button>}
      <button>Outside</button>
      {open && (
        <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="Navigation">
          <button>Collapse</button>
          <nav>
            <button>Risks</button>
            <button onClick={() => setOpen(false)}>Workloads</button>
          </nav>
        </div>
      )}
    </div>
  );
}

const active = () => (document.activeElement as HTMLElement | null)?.textContent;

test('opening focuses the first nav item, not the body', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  expect(active()).toBe('Risks');
});

test('Tab and Shift+Tab stay inside the dialog', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  screen.getByText('Workloads').focus();
  fireEvent.keyDown(window, { key: 'Tab' });
  expect(active()).toBe('Collapse');
  fireEvent.keyDown(window, { key: 'Tab', shiftKey: true });
  expect(active()).toBe('Workloads');
  // Focus somehow outside: Tab pulls it back in.
  screen.getByText('Outside').focus();
  fireEvent.keyDown(window, { key: 'Tab' });
  expect(active()).toBe('Collapse');
});

test('Esc closes and returns focus to the opener, even though it remounted', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(active()).toBe('Expand sidebar');
});

test('closing by picking a nav item also returns focus to the opener', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  fireEvent.click(screen.getByText('Workloads'));
  expect(active()).toBe('Expand sidebar');
});

test('Esc belongs to the dialog: an Esc elsewhere on the page does not close it', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  fireEvent.keyDown(screen.getByText('Outside'), { key: 'Escape' });
  expect(screen.getByRole('dialog')).toBeTruthy();
});

function ExternalClose() {
  const [open, setOpen] = useState(true);
  const dialogRef = useRef<HTMLDivElement>(null);
  const toggleRef = useRef<HTMLButtonElement>(null);
  useDialogFocus({ open, dialogRef, returnFocusRef: toggleRef, onClose: () => setOpen(false) });
  return (
    <div>
      {/* Stands in for a resize to desktop: something outside the dialog closes it. */}
      <button ref={toggleRef} onClick={() => {}}>Collapse sidebar</button>
      <button data-testid="layout" onMouseDown={() => setOpen(false)}>layout change</button>
      {open && (
        <div ref={dialogRef} role="dialog">
          <button>Risks</button>
        </div>
      )}
    </div>
  );
}

test('closed from outside (a layout change): focus goes to the toggle, not the body', () => {
  render(<ExternalClose />);
  expect(active()).toBe('Risks');
  fireEvent.mouseDown(screen.getByTestId('layout'));
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(active()).toBe('Collapse sidebar');
});

test('Esc still closes when a click inside left focus on the body (the backdrop must not stay up)', () => {
  render(<Harness />);
  fireEvent.click(screen.getByText('Expand sidebar'));
  (document.activeElement as HTMLElement).blur();
  expect(document.activeElement).toBe(document.body);
  fireEvent.keyDown(document.body, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).toBeNull();
});
