// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { useCallback, useState } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CveDrawer } from './CveDrawer';
import AIAssistant from '../AIAssistant';
import { VulnApi } from '../../services/vulnApi';
import { ProfileApi } from '../../services/profileApi';
import { vulnCapture } from '../../fixtures/vulns';
import { AssistantDockContext, assistantDockWidth } from '../../hooks/useAssistantDock';
import { UI_DIMENSIONS } from '../../constants/ui';
import type { Exposure } from '../../types/vulns';

// "Ask AI" on a CVE opens the assistant beside the drawer, not on top of it:
// the drawer's right edge moves to where the docked panel begins and comes
// back when the panel closes. Esc and focus follow the topmost thing.

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

const originalMatchMedia = window.matchMedia;
beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  cleanup();
  window.matchMedia = originalMatchMedia;
});

// The assistant and drawer wired the way App wires them.
function Shell() {
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [aiOpen, setAiOpen] = useState(false);
  const [dock, setDock] = useState(0);
  const [prefill, setPrefill] = useState<{ text: string; nonce: number }>();
  const onLayoutChange = useCallback((side: boolean, collapsed: boolean, width?: number) => {
    setDock(assistantDockWidth(side, collapsed, width ?? UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH));
  }, []);
  return (
    <AssistantDockContext.Provider value={dock}>
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
            setDock(0);
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

test('Tab inside the docked assistant stays with it, not pulled back into the drawer', async () => {
  // jsdom lays nothing out, so the trap would see no visible items and do nothing.
  const offsetParent = vi.spyOn(HTMLElement.prototype, 'offsetParent', 'get').mockImplementation(function (this: HTMLElement) {
    return this.parentElement;
  });
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

test('too little room beside a wide assistant: the drawer overlays the edge as before', async () => {
  // Every width query matches: the window is narrower than dock + minimum.
  window.matchMedia = ((query: string) => ({
    matches: query.startsWith('(max-width'),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  })) as unknown as typeof window.matchMedia;
  render(
    <AssistantDockContext.Provider value={900}>
      <CveDrawer id={exposure.id} onClose={() => {}} onOpenWorkload={() => {}} onShowOnMap={() => {}} onAskAI={() => {}} api={api} profileApi={noProfiles} />
    </AssistantDockContext.Provider>,
  );
  await screen.findByRole('dialog', { name: exposure.id });
  expect(drawerLayer().style.right).toBe('');
});

test('centred dialogs ignore the docked assistant', async () => {
  const { Modal } = await import('../ui/Modal');
  render(
    <AssistantDockContext.Provider value={448}>
      <Modal isOpen onClose={() => {}} title="Centred">
        <button>ok</button>
      </Modal>
    </AssistantDockContext.Provider>,
  );
  const dialog = await screen.findByRole('dialog', { name: 'Centred' });
  expect(dialog.closest<HTMLElement>('.fixed.inset-0')!.style.right).toBe('');
});
