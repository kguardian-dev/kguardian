// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { useCallback, useState, type ReactNode } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CveDrawer } from './CveDrawer';
import AIAssistant from '../AIAssistant';
import { Modal } from '../ui/Modal';
import { VulnApi } from '../../services/vulnApi';
import { ProfileApi } from '../../services/profileApi';
import { vulnCapture } from '../../fixtures/vulns';
import { AssistantDockContext, assistantDockWidth, drawerMinWidth, useAssistantDockState } from '../../hooks/useAssistantDock';
import { UI_DIMENSIONS } from '../../constants/ui';
import type { Exposure } from '../../types/vulns';

// "Ask AI" on a CVE opens the assistant beside the drawer, never on top of
// it: the drawer's right edge moves to where the docked panel begins and
// comes back when the panel closes. Esc and focus follow the topmost thing.

const exposure = vulnCapture<Exposure>('exposure-CVE-2099-0001').body;
const api = new VulnApi({
  fetchImpl: (async (input: RequestInfo | URL) => {
    const path = new URL(String(input), 'http://x').pathname;
    return path.endsWith('/exposure')
      ? new Response(JSON.stringify(exposure), { status: 200 })
      : new Response('busy', { status: 503 });
  }) as typeof fetch,
});
const noProfiles = new ProfileApi({ fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch });

const originalWidth = window.innerWidth;
function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { value: width, configurable: true, writable: true });
  window.dispatchEvent(new Event('resize'));
}
beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  setViewport(1280);
});
afterEach(() => {
  cleanup();
  setViewport(originalWidth);
});

// The assistant and drawer wired the way App wires them.
function Shell({ drawerAtStart = true }: { drawerAtStart?: boolean }) {
  const [drawerOpen, setDrawerOpen] = useState(drawerAtStart);
  const [aiOpen, setAiOpen] = useState(false);
  const [width, setWidth] = useState(0);
  const dock = useAssistantDockState(width);
  const [prefill, setPrefill] = useState<{ text: string; nonce: number }>();
  const onLayoutChange = useCallback((side: boolean, collapsed: boolean, w?: number) => {
    setWidth(assistantDockWidth(side, collapsed, w ?? UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH));
  }, []);
  return (
    <AssistantDockContext.Provider value={dock}>
      <button onClick={() => setDrawerOpen(true)}>Open CVE</button>
      <button onClick={() => setAiOpen(true)}>Rail assistant</button>
      {drawerOpen && (
        <CveDrawer
          id={exposure.id}
          onClose={() => setDrawerOpen(false)}
          onOpenWorkload={() => {}}
          onShowOnMap={() => {}}
          onAskAI={(text) => {
            setPrefill({ text, nonce: Date.now() });
            setAiOpen(true);
          }}
          api={api}
          profileApi={noProfiles}
        />
      )}
      {aiOpen && (
        <AIAssistant
          isOpen
          onClose={() => {
            setAiOpen(false);
            setWidth(0);
          }}
          onLayoutChange={onLayoutChange}
          namespace="payments"
          podNames={[]}
          prefill={prefill}
        />
      )}
    </AssistantDockContext.Provider>
  );
}

function Docked({ width, children }: { width: number; children: ReactNode }) {
  return <AssistantDockContext.Provider value={useAssistantDockState(width)}>{children}</AssistantDockContext.Provider>;
}

const drawer = () => screen.getByRole('dialog', { name: exposure.id });
// The fixed layer that holds the drawer and its backdrop: its right edge is the hook.
const drawerLayer = () => drawer().closest<HTMLElement>('.fixed.inset-0')!;
const assistant = () => screen.queryByRole('complementary', { name: 'AI Assistant' });

async function askAI() {
  const ask = await screen.findByRole('button', { name: 'Ask AI' });
  ask.focus();
  fireEvent.click(ask);
  return ask;
}

function dragAssistantTo(clientX: number) {
  fireEvent.mouseDown(screen.getByTitle('Drag to resize'));
  fireEvent.mouseMove(document, { clientX });
}

test('docked: the drawer ends where the assistant begins, and gets its width back on close', async () => {
  render(<Shell />);
  await screen.findByRole('dialog', { name: exposure.id });
  expect(drawerLayer().style.right).toBe('');

  const ask = await askAI();
  expect(assistant()).not.toBeNull();
  expect(drawerLayer().style.right).toBe(`${UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH}px`);
  // Focus moved into the assistant, onto the prefilled input.
  const input = screen.getByPlaceholderText(/Ask about traffic/) as HTMLTextAreaElement;
  expect(document.activeElement).toBe(input);
  expect(input.value).toContain(exposure.id);

  // Collapsed, the drawer only gives up the bar's width.
  fireEvent.click(screen.getByRole('button', { name: 'Collapse panel' }));
  expect(drawerLayer().style.right).toBe(`${UI_DIMENSIONS.AI_PANEL_COLLAPSED_WIDTH}px`);
  fireEvent.click(screen.getByRole('button', { name: 'Expand AI Assistant' }));
  expect(drawerLayer().style.right).toBe(`${UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH}px`);

  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  expect(assistant()).toBeNull();
  expect(drawerLayer().style.right).toBe('');
  expect(document.activeElement).toBe(ask);
});

test('at 1280px with the assistant dragged to its maximum, the drawer keeps max(280px, 20vw) beside it', async () => {
  render(<Shell />);
  await askAI();
  const room = 1280 - drawerMinWidth(1280);
  expect(drawerMinWidth(1280)).toBe(280);

  dragAssistantTo(0); // as wide as the drag allows
  // Mid-drag the drawer edge follows without its transition.
  expect(drawerLayer().className).not.toContain('transition-[right]');
  expect(assistant()!.style.width).toBe(`${room}px`);
  expect(drawerLayer().style.right).toBe(`${room}px`);
  fireEvent.mouseUp(document);
  expect(drawerLayer().className).toContain('transition-[right]');
  expect(drawerLayer().style.right).toBe(`${room}px`);
});

test('an assistant already wider than that gives way when a drawer opens, and gets its width back after', async () => {
  render(<Shell drawerAtStart={false} />);
  fireEvent.click(screen.getByRole('button', { name: 'Rail assistant' }));
  dragAssistantTo(0);
  fireEvent.mouseUp(document);
  const maxAlone = 1280 * UI_DIMENSIONS.AI_PANEL_MAX_WIDTH_RATIO;
  expect(assistant()!.style.width).toBe(`${maxAlone}px`);

  fireEvent.click(screen.getByRole('button', { name: 'Open CVE' }));
  await screen.findByRole('dialog', { name: exposure.id });
  const room = 1280 - drawerMinWidth(1280);
  expect(assistant()!.style.width).toBe(`${room}px`);
  expect(drawerLayer().style.right).toBe(`${room}px`);

  fireEvent.keyDown(document.body, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: exposure.id })).toBeNull());
  expect(assistant()!.style.width).toBe(`${maxAlone}px`);
});

test('Esc closes the assistant first, then the drawer; the scroll lock goes with the drawer', async () => {
  render(<Shell />);
  const ask = await askAI();
  const input = screen.getByPlaceholderText(/Ask about traffic/);

  fireEvent.keyDown(input, { key: 'Escape' });
  expect(assistant()).toBeNull();
  expect(drawer()).toBeTruthy();
  expect(document.activeElement).toBe(ask);
  expect(document.body.style.overflow).toBe('hidden');

  fireEvent.keyDown(ask, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: exposure.id })).toBeNull());
  expect(document.body.style.overflow).toBe('');
});

// jsdom lays nothing out, so the trap would see no visible items and do nothing.
function withLayout() {
  return vi.spyOn(HTMLElement.prototype, 'offsetParent', 'get').mockImplementation(function (this: HTMLElement) {
    return this.parentElement;
  });
}

test('focus in the docked assistant is not pulled back into the drawer', async () => {
  const offsetParent = withLayout();
  try {
    render(<Shell />);
    await askAI();
    const input = screen.getByPlaceholderText(/Ask about traffic/);
    // fireEvent returns false when a handler called preventDefault.
    expect(fireEvent.keyDown(input, { key: 'Tab' })).toBe(true);
    expect(fireEvent.keyDown(input, { key: 'Tab', shiftKey: true })).toBe(true);
    // Focus outside both is still pulled back into the drawer.
    document.body.focus();
    expect(fireEvent.keyDown(document.body, { key: 'Tab' })).toBe(false);
  } finally {
    offsetParent.mockRestore();
  }
});

test('beside the docked assistant the drawer drops aria-modal; alone it is modal again', async () => {
  render(<Shell />);
  await screen.findByRole('dialog', { name: exposure.id });
  expect(drawer().getAttribute('aria-modal')).toBe('true');
  await askAI();
  expect(drawer().hasAttribute('aria-modal')).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  expect(drawer().getAttribute('aria-modal')).toBe('true');
});

test('with the assistant closed the drawer still traps Tab and closes on Esc', async () => {
  const offsetParent = withLayout();
  try {
    render(<Shell />);
    await screen.findByRole('dialog', { name: exposure.id });
    const outside = screen.getByRole('button', { name: 'Open CVE' });
    outside.focus();
    expect(fireEvent.keyDown(outside, { key: 'Tab' })).toBe(false);
    expect(drawer().contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: exposure.id })).toBeNull());
  } finally {
    offsetParent.mockRestore();
  }
});

test('modal assistant: stacks over the drawer, which keeps its width; Esc closes only the assistant', async () => {
  localStorage.setItem('kguardian.ai-assistant.view-mode', 'modal');
  render(<Shell />);
  const ask = await askAI();
  const chat = await screen.findByRole('dialog', { name: 'AI Assistant' });
  expect(drawerLayer().style.right).toBe('');
  await waitFor(() => expect(chat.contains(document.activeElement)).toBe(true));

  fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'AI Assistant' })).toBeNull());
  expect(drawer()).toBeTruthy();
  expect(document.activeElement).toBe(ask);
});

test('centred dialogs ignore the docked assistant and stay aria-modal', async () => {
  render(
    <Docked width={448}>
      <Modal isOpen onClose={() => {}} title="Centred">
        <button>ok</button>
      </Modal>
    </Docked>,
  );
  const dialog = await screen.findByRole('dialog', { name: 'Centred' });
  expect(dialog.closest<HTMLElement>('.fixed.inset-0')!.style.right).toBe('');
  expect(dialog.getAttribute('aria-modal')).toBe('true');
});
