// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { useRef, useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useDismissable } from './useDismissable';

// Explicit: @testing-library's auto-cleanup only self-registers when vitest
// runs with `globals: true`, which this project does not. Without it, mounted
// trees pile up across tests and their document listeners stay live.
afterEach(cleanup);

// This hook exists because the rail dropdowns each hand-rolled the
// outside-click half and neither closed on Escape. The listeners are attached
// to `document`, so the risk is not the happy path but the bookkeeping: firing
// while closed, and leaking listeners after unmount.

function Menu({ onClose, open = true }: { onClose: () => void; open?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useDismissable(open, onClose, ref);
  return (
    <div>
      <div ref={ref} data-testid="menu">
        <button data-testid="inside">inside</button>
      </div>
      <button data-testid="outside">outside</button>
    </div>
  );
}

test('closes on pointer-down outside the ref', () => {
  const onClose = vi.fn();
  render(<Menu onClose={onClose} />);
  fireEvent.mouseDown(screen.getByTestId('outside'));
  expect(onClose).toHaveBeenCalledTimes(1);
});

test('does not close on pointer-down inside the ref', () => {
  // Clicking an item in the menu must not dismiss it before the item's own
  // handler runs.
  const onClose = vi.fn();
  render(<Menu onClose={onClose} />);
  fireEvent.mouseDown(screen.getByTestId('inside'));
  expect(onClose).not.toHaveBeenCalled();
});

test('closes on Escape', () => {
  const onClose = vi.fn();
  render(<Menu onClose={onClose} />);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(onClose).toHaveBeenCalledTimes(1);
});

test('ignores other keys', () => {
  const onClose = vi.fn();
  render(<Menu onClose={onClose} />);
  fireEvent.keyDown(document, { key: 'Enter' });
  fireEvent.keyDown(document, { key: 'a' });
  expect(onClose).not.toHaveBeenCalled();
});

test('is inert while closed', () => {
  // Every mounted dropdown shares `document`, so a hook that listened while
  // closed would fire every other menu's onClose on any stray click.
  const onClose = vi.fn();
  render(<Menu onClose={onClose} open={false} />);
  fireEvent.mouseDown(screen.getByTestId('outside'));
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(onClose).not.toHaveBeenCalled();
});

test('removes its listeners on unmount', () => {
  // A leaked document listener keeps calling into an unmounted component.
  const onClose = vi.fn();
  const { unmount } = render(<Menu onClose={onClose} />);
  unmount();
  fireEvent.mouseDown(document.body);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(onClose).not.toHaveBeenCalled();
});

test('stops listening once the caller closes it', () => {
  function Toggle() {
    const [open, setOpen] = useState(true);
    const ref = useRef<HTMLDivElement>(null);
    useDismissable(open, () => setOpen(false), ref);
    return (
      <div>
        <div ref={ref}>menu</div>
        <span data-testid="state">{open ? 'open' : 'closed'}</span>
        <button data-testid="outside">outside</button>
      </div>
    );
  }
  render(<Toggle />);
  fireEvent.mouseDown(screen.getByTestId('outside'));
  expect(screen.getByTestId('state').textContent).toBe('closed');

  // Second dismissal must be a no-op rather than an error from a stale handler.
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.getByTestId('state').textContent).toBe('closed');
});
