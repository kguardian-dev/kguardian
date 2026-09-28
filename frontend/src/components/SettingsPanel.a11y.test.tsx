// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SettingsPanel } from './SettingsPanel';
import { SettingsProvider } from '../contexts/SettingsContext';
import { ClusterProvider } from '../contexts/ClusterContext';

afterEach(() => {
  cleanup();
  localStorage.clear();
});

// jsdom performs no layout; the Modal's Tab trap skips controls without an offsetParent.
let offsetParentSpy: ReturnType<typeof vi.spyOn>;
beforeAll(() => {
  offsetParentSpy = vi.spyOn(HTMLElement.prototype, 'offsetParent', 'get').mockReturnValue(document.body);
});
afterAll(() => offsetParentSpy.mockRestore());

function Wrapped({ isOpen }: { isOpen: boolean }) {
  return (
    <ClusterProvider>
      <SettingsProvider>
        <SettingsPanel isOpen={isOpen} onClose={() => {}} namespaces={['argocd', 'kube-system']} />
      </SettingsProvider>
    </ClusterProvider>
  );
}

test('every switch and select is named by its row label and described by its hint', () => {
  render(<Wrapped isOpen />);
  const external = screen.getByRole('switch', { name: 'Show external endpoints' });
  expect(screen.getByRole('switch', { name: 'Show DaemonSet peers' })).toBeTruthy();
  expect(screen.getByRole('switch', { name: 'Show traffic edges' })).toBeTruthy();
  expect(screen.getByRole('combobox', { name: 'Default namespace' })).toBeTruthy();
  expect(screen.getByRole('combobox', { name: 'Layout direction' })).toBeTruthy();

  const hint = document.getElementById(external.getAttribute('aria-describedby')!);
  expect(hint?.textContent).toBe('Internet / cross-cluster traffic nodes');
  // A row without a hint leaves no dangling description.
  expect(screen.getByRole('switch', { name: 'Show traffic edges' }).getAttribute('aria-describedby')).toBeNull();

  expect(external.getAttribute('aria-checked')).toBe('true');
  fireEvent.click(external);
  expect(external.getAttribute('aria-checked')).toBe('false');
});

test('opening moves focus into the dialog, Tab stays inside, and closing returns it to the opener', async () => {
  // The panel is mounted closed with the app and opened later, like the
  // account menu does; that path used to leave focus on the body.
  const account = document.createElement('button');
  const header = document.createElement('button');
  document.body.append(account, header);
  const { rerender } = render(<Wrapped isOpen={false} />);
  account.focus();

  rerender(<Wrapped isOpen />);
  const dialog = await screen.findByRole('dialog', { name: 'Settings' });
  await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));

  header.focus();
  fireEvent.keyDown(document, { key: 'Tab' });
  expect(dialog.contains(document.activeElement)).toBe(true);

  rerender(<Wrapped isOpen={false} />);
  await waitFor(() => expect(document.activeElement).toBe(account));
  account.remove();
  header.remove();
});
