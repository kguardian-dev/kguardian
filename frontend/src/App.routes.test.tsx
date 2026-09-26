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
  default: (p: { control?: string; allNamespaces: boolean; refreshTick?: number; onOpenWorkload: (x: Record<string, string>) => void }) => (
    <div data-testid="workloads" data-control={p.control ?? ''} data-all={String(p.allNamespaces)} data-tick={String(p.refreshTick ?? 0)}>
      <button onClick={() => p.onOpenWorkload({ ns: 'payments', kind: 'Deployment', name: 'checkout', scope: 'ns' })}>open checkout</button>
    </div>
  ),
}));
vi.mock('./components/WorkloadView', () => ({
  default: (p: { ns: string; kind: string; name: string; tab?: string; to?: string; onBack: () => void; onParamsChange: (x: Record<string, string | undefined>) => void }) => (
    <div>
      <div data-testid="workload" data-tab={p.tab ?? ''} data-to={p.to ?? ''}>{`${p.ns}/${p.kind}/${p.name}`}</div>
      <button onClick={p.onBack}>back</button>
      <button onClick={() => p.onParamsChange({ tab: 'versions', to: '2' })}>versions</button>
    </div>
  ),
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
  // The old view was namespace-scoped; the redirect keeps that scope.
  expect(hashParams().get('scope')).toBe('ns');
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

test('Workloads has no Refresh of its own: the header Refresh reloads its data', async () => {
  renderAt('#/workloads?ns=payments');
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.tick).toBe('0'));
  const refreshButtons = screen.getAllByRole('button', { name: /Refresh/ });
  expect(refreshButtons).toHaveLength(1);
  fireEvent.click(refreshButtons[0]);
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.tick).toBe('1'));
});

test('Back from a workload page restores the list scope and control it came from', async () => {
  renderAt('#/workload?ns=payments&kind=Deployment&name=api&scope=ns&control=seccomp');
  await waitFor(() => expect(screen.getByTestId('workload')).not.toBeNull());
  fireEvent.click(screen.getByText('back'));
  await waitFor(() => expect(window.location.hash.startsWith('#/workloads')).toBe(true));
  expect(Object.fromEntries(hashParams())).toEqual({ ns: 'payments', scope: 'ns', control: 'seccomp' });
  await waitFor(() => expect(screen.getByTestId('workloads').dataset.all).toBe('false'));
});

test('profile tabs live in the URL, replace the history entry, and Back drops them', async () => {
  renderAt('#/workloads?ns=payments&scope=ns');
  await waitFor(() => expect(screen.getByTestId('workloads')).not.toBeNull());
  window.location.hash = '#/workload?ns=payments&kind=Deployment&name=checkout&scope=ns';
  await waitFor(() => expect(screen.getByTestId('workload').dataset.tab).toBe(''));
  const depth = window.history.length;
  fireEvent.click(screen.getByText('versions'));
  await waitFor(() => expect(screen.getByTestId('workload').dataset.tab).toBe('versions'));
  expect(screen.getByTestId('workload').dataset.to).toBe('2');
  // Replaced, not pushed: browser Back from a tab returns to the list.
  expect(window.history.length).toBe(depth);
  expect(Object.fromEntries(hashParams())).toEqual({ ns: 'payments', kind: 'Deployment', name: 'checkout', scope: 'ns', tab: 'versions', to: '2' });
  fireEvent.click(screen.getByText('back'));
  await waitFor(() => expect(window.location.hash.startsWith('#/workloads')).toBe(true));
  expect(Object.fromEntries(hashParams())).toEqual({ ns: 'payments', scope: 'ns' });
});

test('a deep link straight to a profile tab opens that tab', async () => {
  renderAt('#/workload?ns=payments&kind=Deployment&name=checkout&tab=podSecurity');
  await waitFor(() => expect(screen.getByTestId('workload').dataset.tab).toBe('podSecurity'));
});

test('Back from a workload opened from the list pops the list entry instead of pushing a new one', async () => {
  renderAt('#/workloads?ns=payments&scope=ns');
  await waitFor(() => expect(screen.getByTestId('workloads')).not.toBeNull());
  fireEvent.click(screen.getByText('open checkout'));
  await waitFor(() => expect(screen.getByTestId('workload').textContent).toBe('payments/Deployment/checkout'));
  // A tab change replaces the entry, so the list is still the one below.
  fireEvent.click(screen.getByText('versions'));
  await waitFor(() => expect(screen.getByTestId('workload').dataset.tab).toBe('versions'));
  const back = vi.spyOn(window.history, 'back');
  const depth = window.history.length;
  fireEvent.click(screen.getByText('back'));
  expect(back).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(window.location.hash).toBe('#/workloads?ns=payments&scope=ns'));
  expect(window.history.length).toBe(depth);
  back.mockRestore();
});

test('Back from a deep-linked workload (no list below it) navigates to the list', async () => {
  renderAt('#/workload?ns=payments&kind=Deployment&name=checkout&scope=ns&tab=versions');
  await waitFor(() => expect(screen.getByTestId('workload')).not.toBeNull());
  const back = vi.spyOn(window.history, 'back');
  fireEvent.click(screen.getByText('back'));
  expect(back).not.toHaveBeenCalled();
  await waitFor(() => expect(window.location.hash).toBe('#/workloads?ns=payments&scope=ns'));
  back.mockRestore();
});
