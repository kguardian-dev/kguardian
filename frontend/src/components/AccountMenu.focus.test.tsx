// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, beforeEach, expect, test, vi } from 'vitest';
import { useState } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AccountMenu } from './AccountMenu';
import { SettingsPanel } from './SettingsPanel';
import { AuthProvider } from '../contexts/AuthContext';
import { ThemeProvider } from '../contexts/ThemeContext';
import { ClusterProvider } from '../contexts/ClusterContext';
import { SettingsProvider } from '../contexts/SettingsContext';

beforeEach(() => {
  localStorage.clear();
  // No SSO: the userinfo probe fails and the menu shows local access.
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// jsdom performs no layout; the Modal's Tab trap skips controls without an offsetParent.
let offsetParentSpy: ReturnType<typeof vi.spyOn>;
beforeAll(() => {
  offsetParentSpy = vi.spyOn(HTMLElement.prototype, 'offsetParent', 'get').mockReturnValue(document.body);
});
afterAll(() => offsetParentSpy.mockRestore());

// The rail footer as App renders it: the menu opens Settings, which is
// mounted closed alongside it.
function Rail() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  return (
    <ThemeProvider>
      <SettingsProvider>
        <ClusterProvider>
          <AuthProvider>
            <AccountMenu onOpenSettings={() => setSettingsOpen(true)} />
            <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} namespaces={[]} />
          </AuthProvider>
        </ClusterProvider>
      </SettingsProvider>
    </ThemeProvider>
  );
}

async function openSettingsFromMenu() {
  const account = screen.getByRole('button', { name: /Local access/ });
  account.focus();
  fireEvent.click(account);
  const item = screen.getByRole('button', { name: 'Settings' });
  // Chrome and Edge focus a clicked button; that item then unmounts with the menu.
  item.focus();
  fireEvent.click(item);
  const dialog = await screen.findByRole('dialog', { name: 'Settings' });
  await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
  expect(screen.queryByRole('button', { name: 'Settings' })).toBeNull();
  return account;
}

test.each([
  ['Escape', () => fireEvent.keyDown(document, { key: 'Escape' })],
  ['Done', () => fireEvent.click(screen.getByRole('button', { name: 'Done' }))],
])('Settings opened from the account menu returns focus to the account button on %s', async (_, close) => {
  render(<Rail />);
  const account = await openSettingsFromMenu();
  close();
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Settings' })).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(account));
  // Still there once the dialog node has left the DOM after its exit transition.
  await new Promise((r) => setTimeout(r, 250));
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(document.activeElement).toBe(account);
});
