// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Modal } from './Modal';

// @testing-library's auto-cleanup only self-registers under `globals: true`.
afterEach(cleanup);

// The Modal replaced four hand-rolled overlays, none of which trapped focus,
// closed on Esc, or locked body scroll. Those behaviours are the reason the
// primitive exists, so they are what these pin — a regression here is an
// accessibility regression, which no visual review reliably catches.

// jsdom performs no layout, so `offsetParent` is null for every element. The
// trap filters on it to skip hidden controls, which would leave nothing to
// cycle through. Report a parent so the filter behaves as it does in a browser.
let offsetParentSpy: ReturnType<typeof vi.spyOn>;
beforeAll(() => {
  offsetParentSpy = vi
    .spyOn(HTMLElement.prototype, 'offsetParent', 'get')
    .mockReturnValue(document.body);
});
afterAll(() => offsetParentSpy.mockRestore());

test('renders nothing while closed', () => {
  render(<Modal isOpen={false} onClose={vi.fn()} title="Settings">body</Modal>);
  expect(screen.queryByRole('dialog')).toBeNull();
});

test('exposes dialog semantics and labels itself from the title', () => {
  render(<Modal isOpen onClose={vi.fn()} title="Settings">body</Modal>);
  const dialog = screen.getByRole('dialog');
  expect(dialog.getAttribute('aria-modal')).toBe('true');

  const labelledBy = dialog.getAttribute('aria-labelledby');
  expect(labelledBy).toBeTruthy();
  expect(document.getElementById(labelledBy!)?.textContent).toBe('Settings');
});

test('omits the label association when there is no title to point at', () => {
  // A dangling aria-labelledby is worse than none: it names the dialog after
  // nothing.
  render(<Modal isOpen onClose={vi.fn()} hideHeader>body</Modal>);
  expect(screen.getByRole('dialog').getAttribute('aria-labelledby')).toBeNull();
});

test('closes on Escape', () => {
  const onClose = vi.fn();
  render(<Modal isOpen onClose={onClose} title="Settings">body</Modal>);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(onClose).toHaveBeenCalledTimes(1);
});

test('closes on backdrop click but not on panel click', () => {
  // The panel stops propagation; without that, any click inside the dialog
  // would dismiss it.
  const onClose = vi.fn();
  const { container } = render(<Modal isOpen onClose={onClose} title="Settings">body</Modal>);

  fireEvent.click(screen.getByRole('dialog'));
  expect(onClose).not.toHaveBeenCalled();

  const backdrop = container.querySelector('.absolute.inset-0')!;
  fireEvent.click(backdrop);
  expect(onClose).toHaveBeenCalledTimes(1);
});

test('disableBackdropClose keeps the dialog open on backdrop click', () => {
  const onClose = vi.fn();
  const { container } = render(
    <Modal isOpen onClose={onClose} title="Deleting" disableBackdropClose>body</Modal>,
  );
  fireEvent.click(container.querySelector('.absolute.inset-0')!);
  expect(onClose).not.toHaveBeenCalled();
});

test('locks body scroll while open and restores it on close', () => {
  const { rerender } = render(<Modal isOpen onClose={vi.fn()} title="Settings">body</Modal>);
  expect(document.body.style.overflow).toBe('hidden');

  rerender(<Modal isOpen={false} onClose={vi.fn()} title="Settings">body</Modal>);
  // Unmount is deferred through the exit transition, so the lock lifts with it.
  return waitFor(() => expect(document.body.style.overflow).not.toBe('hidden'));
});

test('moves focus into the dialog and restores it to the trigger on close', async () => {
  const trigger = document.createElement('button');
  document.body.appendChild(trigger);
  trigger.focus();
  expect(document.activeElement).toBe(trigger);

  const { rerender } = render(
    <Modal isOpen onClose={vi.fn()} title="Settings">
      <button>first</button>
    </Modal>,
  );
  await waitFor(() => expect(document.activeElement).not.toBe(trigger));
  expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true);

  rerender(<Modal isOpen={false} onClose={vi.fn()} title="Settings"><button>first</button></Modal>);
  await waitFor(() => expect(document.activeElement).toBe(trigger));
  trigger.remove();
});

test('Tab cycles within the dialog instead of escaping to the page behind', async () => {
  render(
    <Modal isOpen onClose={vi.fn()} title="Settings">
      <button>first</button>
      <button>last</button>
    </Modal>,
  );
  // The header's Close button is part of the dialog, so the cycle is
  // [Close, first, last] — the wrap lands on Close, not on the first child the
  // caller rendered.
  const close = screen.getByRole('button', { name: 'Close' });
  const last = screen.getByRole('button', { name: 'last' });

  last.focus();
  fireEvent.keyDown(document, { key: 'Tab' });
  await waitFor(() => expect(document.activeElement).toBe(close));

  close.focus();
  fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
  await waitFor(() => expect(document.activeElement).toBe(last));
});

test('an explicit width in className suppresses the size default', () => {
  // Otherwise two conflicting max-w utilities land on the element and which one
  // wins depends on stylesheet order, which is exactly the drift this avoids.
  render(<Modal isOpen onClose={vi.fn()} title="Wide" className="max-w-[1200px]">body</Modal>);
  const cls = screen.getByRole('dialog').className;
  expect(cls).toContain('max-w-[1200px]');
  expect(cls).not.toContain('max-w-lg');
});
