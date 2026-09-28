// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { StrictMode, useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Bot, Share2 } from 'lucide-react';
import AIAssistant from './AIAssistant';
import { Sidebar } from './Sidebar';

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(cleanup);

// The rail as App renders it, plus a view's own "Ask AI" button that may
// stay (a drawer that remains open) or leave with its view when the panel opens.
function Shell({ ask = 'none', collapsed = false }: { ask?: 'none' | 'stays' | 'leaves'; collapsed?: boolean }) {
  const [open, setOpen] = useState(false);
  const [showAsk, setShowAsk] = useState(ask !== 'none');
  return (
    <div>
      <Sidebar
        version="t"
        collapsed={collapsed}
        items={[
          { id: 'map', label: 'Network Map', icon: Share2, group: 'Views', active: true, onClick: () => {} },
          { id: 'assistant', label: 'AI Assistant', icon: Bot, group: 'Tools', hint: 'Ask about cluster traffic & policies', active: open, onClick: () => setOpen(true) },
        ]}
      />
      {showAsk && (
        <button
          onClick={() => {
            setOpen(true);
            if (ask === 'leaves') setShowAsk(false);
          }}
        >
          Ask AI
        </button>
      )}
      {open && <AIAssistant isOpen onClose={() => setOpen(false)} namespace="argocd" podNames={[]} />}
    </div>
  );
}

const railItem = () => screen.getByRole('button', { name: /AI Assistant|Ask about cluster traffic/ });

function openFrom(button: HTMLElement) {
  button.focus();
  fireEvent.click(button);
  const panel = screen.getByRole('complementary', { name: 'AI Assistant' });
  expect(panel.contains(document.activeElement)).toBe(true);
  return panel;
}

// The app mounts under StrictMode, which runs mount effects twice: an opener
// captured in an effect would be re-captured after the textarea took focus.
it('closing the docked panel with its Close button returns focus to the rail item that opened it (StrictMode)', () => {
  render(<StrictMode><Shell /></StrictMode>);
  const rail = railItem();
  openFrom(rail);
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  expect(screen.queryByRole('complementary', { name: 'AI Assistant' })).toBeNull();
  expect(document.activeElement).toBe(rail);
});

it('Escape in the docked panel returns focus the same way (StrictMode)', () => {
  render(<StrictMode><Shell /></StrictMode>);
  const rail = railItem();
  openFrom(rail);
  fireEvent.keyDown(screen.getByPlaceholderText(/Ask about traffic/), { key: 'Escape' });
  expect(screen.queryByRole('complementary', { name: 'AI Assistant' })).toBeNull();
  expect(document.activeElement).toBe(rail);
});

it('a view\'s "Ask AI" button that is still on the page gets focus back, not the rail', () => {
  render(<Shell ask="stays" />);
  const ask = screen.getByRole('button', { name: 'Ask AI' });
  openFrom(ask);
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  expect(document.activeElement).toBe(ask);
});

it('when the opener has left the page, focus goes to the rail item, found even with the rail collapsed', () => {
  render(<Shell ask="leaves" collapsed />);
  openFrom(screen.getByRole('button', { name: 'Ask AI' }));
  expect(screen.queryByRole('button', { name: 'Ask AI' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  // Collapsed, the item shows no label; its name is the hint.
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Ask about cluster traffic & policies' }));
});

it('in modal mode the Modal still returns focus to the opener (unchanged)', () => {
  localStorage.setItem('kguardian.ai-assistant.view-mode', 'modal');
  render(<Shell />);
  const rail = railItem();
  rail.focus();
  fireEvent.click(rail);
  expect(screen.getByRole('dialog', { name: 'AI Assistant' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }));
  expect(document.activeElement).toBe(rail);
});
