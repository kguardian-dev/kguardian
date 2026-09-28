// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, expect, test, vi } from 'vitest';
import { useState } from 'react';
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

test('a hidden-header modal takes its name from ariaLabel and never points at a title it did not render', () => {
  render(<Modal isOpen onClose={vi.fn()} hideHeader title="Ignored" ariaLabel="Named">body</Modal>);
  const d = screen.getByRole('dialog', { name: 'Named' });
  expect(d.getAttribute('aria-labelledby')).toBeNull();
});

// Two dialogs open at once: the command palette over the Policy Builder, the
// export modal over the seccomp drawer. Every Modal listens on the document and
// stopPropagation does not reach sibling listeners, so one Escape closed both.
test('stacked: Escape closes only the dialog on top', () => {
  const lower = vi.fn();
  const upper = vi.fn();
  render(
    <>
      <Modal isOpen onClose={lower} title="Policy Builder">picker</Modal>
      <Modal isOpen onClose={upper} hideHeader ariaLabel="Search and commands">palette</Modal>
    </>,
  );
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(upper).toHaveBeenCalledTimes(1);
  expect(lower).not.toHaveBeenCalled();
});

function DrawerWithExport() {
  const [drawer, setDrawer] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [name, setName] = useState('');
  return (
    <Modal isOpen={drawer} onClose={() => setDrawer(false)} title="argocd-server">
      <input aria-label="CR name" value={name} onChange={(e) => setName(e.target.value)} />
      <button onClick={() => setExporting(true)}>Export CR</button>
      {exporting && (
        <Modal isOpen onClose={() => setExporting(false)} title="Export SeccompProfile CR">
          <button>Download</button>
        </Modal>
      )}
    </Modal>
  );
}

test('nested: one Escape closes the export modal and keeps the drawer with its staged edits', async () => {
  render(<DrawerWithExport />);
  fireEvent.change(screen.getByLabelText('CR name'), { target: { value: 'argocd-server-full' } });
  fireEvent.click(screen.getByText('Export CR'));
  expect(screen.getByRole('dialog', { name: 'Export SeccompProfile CR' })).toBeTruthy();

  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.queryByRole('dialog', { name: 'Export SeccompProfile CR' })).toBeNull();
  expect(screen.getByRole('dialog', { name: 'argocd-server' })).toBeTruthy();
  expect((screen.getByLabelText('CR name') as HTMLInputElement).value).toBe('argocd-server-full');

  fireEvent.keyDown(document, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'argocd-server' })).toBeNull());
});

test('a dialog fading out no longer takes the Escape meant for the one beneath it', () => {
  const lower = vi.fn();
  const upper = vi.fn();
  const { rerender } = render(
    <>
      <Modal isOpen onClose={lower} title="Drawer">a</Modal>
      <Modal isOpen onClose={upper} title="Export">b</Modal>
    </>,
  );
  rerender(
    <>
      <Modal isOpen onClose={lower} title="Drawer">a</Modal>
      <Modal isOpen={false} onClose={upper} title="Export">b</Modal>
    </>,
  );
  // The upper node is still mounted for its exit transition, under aria-hidden.
  expect(document.querySelectorAll('[role="dialog"]').length).toBe(2);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(lower).toHaveBeenCalledTimes(1);
  expect(upper).not.toHaveBeenCalled();
});

test('the key listener is registered once, and Escape calls the latest onClose', () => {
  // Callers pass fresh arrow functions every render; re-registering on each
  // one meant a listener added during a dispatch was skipped for that Escape.
  const add = vi.spyOn(document, 'addEventListener');
  const first = vi.fn();
  const second = vi.fn();
  const { rerender } = render(<Modal isOpen onClose={first} title="Settings">body</Modal>);
  const keydowns = () => add.mock.calls.filter(([type]) => type === 'keydown').length;
  const before = keydowns();
  rerender(<Modal isOpen onClose={second} title="Settings">body</Modal>);
  rerender(<Modal isOpen onClose={() => second()} title="Settings">body</Modal>);
  expect(keydowns()).toBe(before);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(first).not.toHaveBeenCalled();
  expect(second).toHaveBeenCalledTimes(1);
  add.mockRestore();
});

test('opening from closed moves focus in once the panel has mounted', async () => {
  // Settings is always mounted, closed. The panel appears a frame after isOpen
  // flips, so a focus effect keyed on isOpen alone found nothing to focus.
  const trigger = document.createElement('button');
  document.body.appendChild(trigger);
  trigger.focus();
  const { rerender } = render(<Modal isOpen={false} onClose={vi.fn()} title="Settings"><button>first</button></Modal>);
  rerender(<Modal isOpen onClose={vi.fn()} title="Settings"><button>first</button></Modal>);
  await waitFor(() => expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true));
  trigger.remove();
});

test('Tab with focus outside the dialog pulls it in instead of walking the page behind the backdrop', async () => {
  const outside = document.createElement('button');
  document.body.appendChild(outside);
  render(
    <Modal isOpen onClose={vi.fn()} title="Settings">
      <button>first</button>
      <button>last</button>
    </Modal>,
  );
  outside.focus();
  fireEvent.keyDown(document, { key: 'Tab' });
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Close' })));
  outside.focus();
  fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: 'last' })));
  outside.remove();
});

test('stacked: Tab in the dialog on top is never pulled into the one beneath', () => {
  render(
    <>
      <Modal isOpen onClose={vi.fn()} title="Policy Builder"><button>pick</button></Modal>
      <Modal isOpen onClose={vi.fn()} hideHeader ariaLabel="Search and commands">
        <input aria-label="Command" />
        <button>go</button>
      </Modal>
    </>,
  );
  const input = screen.getByLabelText('Command');
  input.focus();
  // From the top dialog's first item, Shift+Tab wraps to its last item.
  fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'go' }));
  fireEvent.keyDown(document, { key: 'Tab' });
  expect(document.activeElement).toBe(input);
});

test('initialFocus names the element to focus instead of the first focusable', () => {
  render(
    <Modal isOpen onClose={vi.fn()} title="Policy Builder" initialFocus="input">
      <input aria-label="Search workloads" />
    </Modal>,
  );
  expect(document.activeElement).toBe(screen.getByLabelText('Search workloads'));
});

test('a child that took focus itself (autoFocus) keeps it; the header Close button does not take it over', () => {
  render(
    <Modal isOpen onClose={vi.fn()} title="Policy Builder">
      <input aria-label="Search workloads" autoFocus />
    </Modal>,
  );
  expect(document.activeElement).toBe(screen.getByLabelText('Search workloads'));
});

// The Policy Builder swaps its picker dialog for the editor dialog in one
// render, so the editor's opener is a picker button that no longer exists.
function PickerThenEditor() {
  const [step, setStep] = useState<'closed' | 'picker' | 'editor'>('closed');
  return (
    <div>
      <button onClick={() => setStep('picker')}>Policy Builder</button>
      {step === 'picker' && (
        <Modal isOpen onClose={() => setStep('closed')} title="Policy Builder">
          <button onClick={() => setStep('editor')}>argocd-server</button>
        </Modal>
      )}
      {step === 'editor' && (
        <Modal isOpen onClose={() => setStep('closed')} hideHeader ariaLabel="Policy editor">
          <button>Copy YAML</button>
        </Modal>
      )}
    </div>
  );
}

test('closing a dialog that replaced the one it was opened from returns focus to the original trigger', () => {
  render(<PickerThenEditor />);
  const rail = screen.getByRole('button', { name: 'Policy Builder' });
  rail.focus();
  fireEvent.click(rail);
  const pick = screen.getByRole('button', { name: 'argocd-server' });
  pick.focus();
  fireEvent.click(pick);
  expect(screen.getByRole('dialog', { name: 'Policy editor' })).toBeTruthy();
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(document.activeElement).toBe(rail);
});
