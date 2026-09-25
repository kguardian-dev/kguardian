// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

// The route layer end to end through App: old links redirect in place,
// the nav and header name the new views, and the scope chip says what a
// view is showing. Heavy children are stubbed; the redirect logic itself is
// unit-tested in utils/routes.test.ts.

vi.mock('./components/NetworkGraph', () => ({ default: () => <div data-testid="map" /> }));
vi.mock('./components/DataTable', () => ({ default: () => <div /> }));
vi.mock('./components/WorkloadsView', () => ({
  default: (p: { control?: string; allNamespaces: boolean }) => (
    <div data-testid="workloads" data-control={p.control ?? ''} data-all={String(p.allNamespaces)} />
  ),
}));
vi.mock('./components/WorkloadView', () => ({
  default: (p: { ns: string; kind: string; name: string }) => <div data-testid="workload">{`${p.ns}/${p.kind}/${p.name}`}</div>,
}));
vi.mock('./hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles: [], loading: false, error: null, refresh: async () => {} }),
}));
vi.mock('./hooks/usePodData', () => ({
  usePodData: () => ({
    pods: [],
    compute: { findings: [], enabled: false, supported: false, history: new Map() },
    allPodsLookup: [],
    services: [],
    loading: false,
    error: null,
    refreshData: () => {},
  }),
}));
vi.mock('./hooks/useNamespaces', () => ({
  useNamespaces: () => ({ namespaces: ['payments', 'observability'], loading: false }),
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

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', window.location.pathname);
});

const renderAt = (hash: string) => {
  window.history.replaceState(null, '', hash);
  return render(
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
};

const hashParams = () => new URLSearchParams(window.location.hash.split('?')[1] ?? '');

test('#/findings redirects to #/risks in place, keeping the namespace', async () => {
  const before = window.history.length;
  renderAt('#/findings?ns=observability');
  await waitFor(() => expect(window.location.hash.startsWith('#/risks')).toBe(true));
  expect(hashParams().get('ns')).toBe('observability');
  expect(window.history.length).toBe(before); // replaced, not pushed: Back doesn't bounce
  expect(screen.getByRole('heading', { level: 1, name: 'Risks' })).not.toBeNull();
  expect(screen.getByTestId('scope-chip').textContent).toContain('observability');
});

test('#/seccomp redirects to the Workloads seccomp columns', async () => {
  renderAt('#/seccomp?ns=payments');
  await waitFor(() => expect(window.location.hash.startsWith('#/workloads')).toBe(true));
  expect(hashParams().get('control')).toBe('seccomp');
  expect(hashParams().get('ns')).toBe('payments');
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.control).toBe('seccomp'));
});

test('Workloads is cluster-wide by default; the chip says so, and picking a namespace narrows it', async () => {
  renderAt('#/workloads?ns=payments');
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('true'));
  expect(screen.getByTestId('scope-chip').textContent).toBe('All namespaces');
});

test('on Workloads the namespace selector offers All namespaces and narrows on pick', async () => {
  renderAt('#/workloads?ns=payments');
  const select = (await screen.findByLabelText('Namespace:')) as HTMLSelectElement;
  expect(select.value).toBe('');
  fireEvent.change(select, { target: { value: 'observability' } });
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('false'));
  expect(hashParams().get('ns')).toBe('observability');
  expect(hashParams().get('scope')).toBe('ns');
  fireEvent.change(select, { target: { value: '' } });
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('true'));
});

test('a narrowed Workloads view can be widened from the chip', async () => {
  renderAt('#/workloads?ns=payments&scope=ns');
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('false'));
  expect(screen.getByTestId('scope-chip').textContent).toContain('payments');
  fireEvent.click(screen.getByRole('button', { name: 'Show all namespaces' }));
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('true'));
  expect(hashParams().get('scope')).toBeNull();
});

test('the workload route passes its ns/kind/name through, even for a namespace with no live pods', async () => {
  renderAt('#/workload?ns=batch&kind=CronJob&name=report');
  await waitFor(() => expect(screen.getByTestId('workload').textContent).toBe('batch/CronJob/report'));
  expect(screen.getByRole('heading', { level: 1, name: 'report' })).not.toBeNull();
});

test('the rail names the renamed views', async () => {
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Network Map' })).not.toBeNull());
  expect(screen.getAllByText('Risks').length).toBeGreaterThan(0);
  expect(screen.getAllByText('Workloads').length).toBeGreaterThan(0);
  expect(screen.queryByText('Findings')).toBeNull();
  expect(screen.queryByText('Seccomp Profiles')).toBeNull();
});
