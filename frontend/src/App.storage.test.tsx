// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

// A browser set to block all site data throws SecurityError the moment
// `localStorage` is touched. The theme and cluster providers and App's rail
// preference read it unguarded, so the error boundary replaced the whole UI
// with "Something went wrong". Settings and the reload guard already fell
// back to their defaults; now every preference does.

vi.mock('./components/NetworkGraph', () => ({ default: () => <div data-testid="map" /> }));
vi.mock('./components/DataTable', () => ({ default: () => <div /> }));
vi.mock('./hooks/usePodData', () => ({
  usePodData: () => ({
    pods: [],
    compute: { findings: [], enabled: false, supported: false, unavailable: false, history: new Map() },
    allPodsLookup: [], services: [], failedReads: { traffic: 0, syscalls: 0 },
    loading: false, error: null, refreshData: () => {},
  }),
}));
vi.mock('./hooks/useNamespaces', () => ({
  useNamespaces: () => ({ namespaces: ['payments'], loading: false, error: null }),
}));
vi.mock('./hooks/useClusterEnvironment', () => ({
  useClusterEnvironment: () => ({ cni: 'unknown', cniVersion: null, hubble: 'unknown' }),
}));
vi.mock('./services/api', () => ({ default: { getAuditVerdicts: async () => [] } }));

import App from './App';
import { ThemeProvider } from './contexts/ThemeContext';
import { SettingsProvider } from './contexts/SettingsContext';
import { ClusterProvider } from './contexts/ClusterContext';
import { AuthProvider } from './contexts/AuthContext';
import { initialViewMode, DEFAULT_VIEW_MODE } from './utils/assistantViewMode';

const blocked = () => { throw new DOMException('The operation is insecure.', 'SecurityError'); };

beforeEach(() => {
  vi.spyOn(window, 'localStorage', 'get').mockImplementation(blocked);
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))));
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  window.history.replaceState(null, '', '#/map?ns=payments');
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', window.location.pathname);
});

test('blocked storage: the app renders on its defaults, and changing a preference does not crash it', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  render(
    <ThemeProvider>
      <AuthProvider>
        <SettingsProvider>
          <ClusterProvider>
            <App />
          </ClusterProvider>
        </SettingsProvider>
      </AuthProvider>
    </ThemeProvider>,
  );
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Network Map' })).not.toBeNull());
  expect(document.documentElement.classList.contains('dark')).toBe(true);

  fireEvent.click(screen.getByRole('button', { name: 'Collapse sidebar' }));
  await waitFor(() => expect(screen.getAllByRole('button', { name: 'Expand sidebar' }).length).toBeGreaterThan(0));
  expect(screen.queryByText(/Something went wrong/)).toBeNull();
});

test('blocked storage: the assistant opens in its default view mode', () => {
  expect(initialViewMode()).toBe(DEFAULT_VIEW_MODE);
});
