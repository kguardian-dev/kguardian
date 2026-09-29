// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { PodInfo, PodNodeData } from './types';

// App's joins for the map's data flow: which views turn the pod and compute
// hooks on (F-24), that no run starts for a namespace nobody asked for
// (F-02), what an unknown deep link does (MAP-10), the header counts (F-16)
// and the palette's pod-name search plus select-and-focus (MAP-14). The hooks
// and heavy children are stubbed; each of those has its own tests.

const podDataCalls: unknown[][] = [];
const podDataState = {
  pods: [] as PodNodeData[], loading: false, error: null as string | null,
  servicesError: null as string | null, servicesListing: [] as unknown[] | null,
  failedReads: { traffic: 0, syscalls: 0 } as { traffic: number; syscalls: number; shed?: true },
};
const nsState = { namespaces: ['payments', 'other'], loading: false, error: null as string | null };

vi.mock('./components/NetworkGraph', () => ({ default: () => <div data-testid="map" /> }));
vi.mock('./components/DataTable', () => ({ default: () => <div /> }));
vi.mock('./components/ImagesView', () => ({ default: () => <div data-testid="images" /> }));
vi.mock('./components/WorkloadsView', () => ({ default: () => <div data-testid="workloads" /> }));
vi.mock('./components/PolicyBuilderModal', () => ({
  PolicyBuilderModal: (p: { loading?: boolean; podsLookup?: unknown[]; services?: unknown[]; error?: string | null }) => (
    <div data-testid="policy-builder" data-loading={String(p.loading)} data-lookup={String(p.podsLookup !== undefined && p.services !== undefined)} data-services={String(p.services !== undefined)} data-error={p.error ?? ''} />
  ),
}));
vi.mock('./hooks/usePodData', () => ({
  usePodData: (...args: unknown[]) => {
    podDataCalls.push(args);
    return {
      pods: podDataState.pods,
      compute: { findings: [], enabled: false, supported: false, unavailable: false, history: new Map() },
      allPodsLookup: [],
      services: [],
      servicesListing: podDataState.servicesListing,
      servicesError: podDataState.servicesError,
      failedReads: podDataState.failedReads,
      loading: podDataState.loading,
      error: podDataState.error,
      refreshData: () => {},
    };
  },
}));
vi.mock('./hooks/useNamespaces', () => ({
  useNamespaces: () => ({ namespaces: nsState.namespaces, loading: nsState.loading, error: nsState.error }),
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
  podDataCalls.length = 0;
  podDataState.pods = [];
  podDataState.loading = false;
  podDataState.error = null;
  podDataState.servicesError = null;
  podDataState.servicesListing = [];
  podDataState.failedReads = { traffic: 0, syscalls: 0 };
  nsState.namespaces = ['payments', 'other'];
  nsState.loading = false;
  nsState.error = null;
  localStorage.clear();
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))));
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', window.location.pathname);
});

const tree = () => (
  <ThemeProvider>
    <AuthProvider>
      <SettingsProvider>
        <ClusterProvider>
          <App />
        </ClusterProvider>
      </SettingsProvider>
    </AuthProvider>
  </ThemeProvider>
);

const renderAt = (hash: string) => {
  window.history.replaceState(null, '', hash);
  return render(tree());
};

const hashParams = () => new URLSearchParams(window.location.hash.split('?')[1] ?? '');
const lastCall = () => podDataCalls[podDataCalls.length - 1];
const lastOpts = () => lastCall()[2] as { enabled: boolean; compute: boolean };

const pod = (name: string): PodInfo => ({ pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'w', is_dead: false });
const workloads = (): PodNodeData[] => [
  { id: 'payments-api', label: 'api', pod: pod('api-1'), pods: [pod('api-1'), pod('api-2')], traffic: [], isExpanded: false },
  { id: 'payments-worker', label: 'worker', pod: pod('worker-1'), pods: [pod('worker-1')], traffic: [], isExpanded: false },
];

test('the Images view reads no pod data and polls no compute; the map does both; Workloads reads pods only', async () => {
  renderAt('#/images?ns=payments');
  await waitFor(() => expect(screen.getByTestId('images')).not.toBeNull());
  expect(lastOpts()).toEqual({ enabled: false, compute: false });
  cleanup();

  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Network Map' })).not.toBeNull());
  expect(lastOpts()).toEqual({ enabled: true, compute: true });
  cleanup();

  renderAt('#/workloads?ns=payments');
  await waitFor(() => expect(screen.getByTestId('workloads')).not.toBeNull());
  expect(lastOpts()).toEqual({ enabled: true, compute: false });
  cleanup();

  renderAt('#/risks?ns=payments');
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Risks' })).not.toBeNull());
  expect(lastOpts()).toEqual({ enabled: true, compute: true });
});

test('opening the Policy Builder from the Images view turns pod data on: its picker needs the workloads', async () => {
  renderAt('#/images?ns=payments');
  await waitFor(() => expect(screen.getByTestId('images')).not.toBeNull());
  expect(lastOpts().enabled).toBe(false);
  fireEvent.click(screen.getAllByText('Policy Builder')[0].closest('button')!);
  await waitFor(() => expect(screen.getByTestId('policy-builder')).not.toBeNull());
  expect(lastOpts().enabled).toBe(true);
  expect(lastOpts().compute).toBe(false); // still no gauges to draw
  // The builder gets the listings App holds (no second inventory download).
  expect(screen.getByTestId('policy-builder').dataset.lookup).toBe('true');
});

// TOOL-15's picker half: while the namespace is still loading the picker
// must not read "No workloads in this namespace".
test('the Policy Builder is told pod data is still loading', async () => {
  podDataState.loading = true;
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('Loading…')).not.toBeNull());
  fireEvent.click(screen.getAllByText('Policy Builder')[0].closest('button')!);
  await waitFor(() => expect(screen.getByTestId('policy-builder').dataset.loading).toBe('true'));
});

test('without a URL namespace nothing is fetched until the list arrives, then the first run is for a real namespace', async () => {
  nsState.namespaces = [];
  nsState.loading = true;
  const view = renderAt('#/map');
  await waitFor(() => expect(podDataCalls.length).toBeGreaterThan(0));
  // Every render so far asked for nothing: no run for the hardcoded default.
  expect(podDataCalls.every((c) => (c[2] as { enabled: boolean }).enabled === false)).toBe(true);
  expect(lastOpts().compute).toBe(false);
  // And the wait itself is loading: the skeleton and "Loading…", never
  // "No workloads in default" over an empty selector.
  expect(screen.getByText('Loading…')).not.toBeNull();
  expect(screen.queryByText(/No workloads in/)).toBeNull();
  expect(screen.queryByText(/0 workloads/)).toBeNull();

  nsState.namespaces = ['payments', 'other'];
  nsState.loading = false;
  view.rerender(tree());
  await waitFor(() => expect(lastOpts().enabled).toBe(true));
  expect(lastCall()[0]).toBe('payments');
  await waitFor(() => expect(hashParams().get('ns')).toBe('payments'));
});

test('a deep link to a known namespace fetches at once, before the namespace list has answered', async () => {
  nsState.namespaces = ['payments'];
  nsState.loading = true;
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(podDataCalls.length).toBeGreaterThan(0));
  expect(lastCall()[0]).toBe('payments');
  expect(lastOpts()).toEqual({ enabled: true, compute: true });
});

test('an unknown namespace deep link is rewritten to the namespace shown, with a dismissible notice', async () => {
  renderAt('#/map?ns=does-not-exist&lens=bogus');
  await waitFor(() => expect(hashParams().get('ns')).toBe('payments'));
  expect(hashParams().get('lens')).toBeNull();
  const notice = screen.getByTestId('route-notice');
  expect(notice.textContent).toMatch(/Namespace "does-not-exist" has no monitored pods; showing payments/);
  expect(notice.textContent).toMatch(/Unknown lens "bogus" ignored/);
  expect(screen.getByTestId('scope-chip').textContent).toContain('payments');
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
  expect(screen.queryByTestId('route-notice')).toBeNull();
});

// A shed or timed-out /pod/namespaces used to replace the deep link's
// namespace with default and rewrite the URL to it, with the notice on top.
test('a namespace list that failed to load leaves a deep link alone: no rewrite, no notice, the link still loads', async () => {
  nsState.namespaces = ['argocd']; // the URL seed is all the hook has
  nsState.error = 'Service Unavailable';
  renderAt('#/map?ns=argocd');
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Network Map' })).not.toBeNull());
  await new Promise((r) => setTimeout(r, 0));
  expect(window.location.hash).toBe('#/map?ns=argocd');
  expect(screen.queryByTestId('route-notice')).toBeNull();
  expect(lastCall()[0]).toBe('argocd');
  expect(lastOpts().enabled).toBe(true);
});

test('on the Images view the palette does not offer the last namespace\'s workloads', async () => {
  podDataState.pods = workloads(); // whatever loaded last, frozen while pod data is off
  renderAt('#/images?ns=other');
  await waitFor(() => expect(screen.getByTestId('images')).not.toBeNull());
  fireEvent.keyDown(window, { key: 'k', metaKey: true });
  await screen.findByPlaceholderText(/Jump to a view/);
  expect(screen.queryByText('api')).toBeNull();
  expect(screen.queryByText('worker')).toBeNull();
  expect(screen.getAllByText('Network Map').length).toBeGreaterThan(1); // the palette still lists the views (the rail has one too)
});

test('a known namespace deep link is left alone, with no notice', async () => {
  renderAt('#/map?ns=other');
  await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Network Map' })).not.toBeNull());
  await new Promise((r) => setTimeout(r, 0));
  expect(window.location.hash).toBe('#/map?ns=other');
  expect(screen.queryByTestId('route-notice')).toBeNull();
});

test('the header counts workloads and pods apart', async () => {
  podDataState.pods = workloads();
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('2 workloads · 3 pods')).not.toBeNull());
  cleanup();
  podDataState.pods = [workloads()[1]];
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('1 workload · 1 pod')).not.toBeNull());
});

test('while the first run is in flight the header says so and the skeleton shows, not the empty state', async () => {
  podDataState.loading = true;
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('Loading…')).not.toBeNull());
  expect(screen.queryByText(/No workloads in/)).toBeNull();
  expect(screen.queryByText(/0 pods/)).toBeNull();
});

test('a palette pick matches a member pod name and focuses the workload like a click', async () => {
  podDataState.pods = workloads();
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('2 workloads · 3 pods')).not.toBeNull());

  fireEvent.keyDown(window, { key: 'k', metaKey: true });
  const input = await screen.findByPlaceholderText(/Jump to a view/);
  // A real pod name, not the identity: it used to find nothing.
  fireEvent.change(input, { target: { value: 'api-2' } });
  await waitFor(() => expect(screen.getByText('api')).not.toBeNull());
  expect(screen.queryByText('worker')).toBeNull();
  fireEvent.keyDown(input, { key: 'Enter' });

  await waitFor(() => expect(hashParams().get('pod')).toBe('payments-api'));
  expect(hashParams().get('focus')).toBe('payments-api'); // opened AND focused, as a card click does
});

// A timed-out or shed /pod/info used to come back as `[]`, and the map said
// "No workloads in payments — This namespace has no observed pods yet".
test('a pod listing that failed shows the error, never the empty state', async () => {
  podDataState.error = 'timeout of 35000ms exceeded';
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('Workloads in payments could not be loaded')).not.toBeNull());
  expect(screen.getByText('timeout of 35000ms exceeded')).not.toBeNull();
  expect(screen.queryByText(/No workloads in/)).toBeNull();
  expect(screen.queryByTestId('map')).toBeNull();
});

test('a Refresh that failed keeps the loaded graph, with the error above it', async () => {
  podDataState.pods = workloads();
  podDataState.error = 'Service Unavailable';
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByTestId('map')).not.toBeNull());
  expect(screen.getByText('Error: Service Unavailable')).not.toBeNull();
  expect(screen.queryByText(/could not be loaded/)).toBeNull();
});

test('a failed pod listing: the header says so instead of "0 workloads · 0 pods"', async () => {
  podDataState.error = 'timeout of 35000ms exceeded';
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('Workloads in payments could not be loaded')).not.toBeNull());
  expect(screen.getByText('Could not load')).not.toBeNull();
  expect(screen.queryByText(/0 workloads/)).toBeNull();
});

test('a failed pod listing reaches the Policy Builder, so its picker does not say "No workloads"', async () => {
  podDataState.error = 'timeout of 35000ms exceeded';
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByText('Could not load')).not.toBeNull());
  fireEvent.click(screen.getAllByText('Policy Builder')[0].closest('button')!);
  await waitFor(() => expect(screen.getByTestId('policy-builder').dataset.error).toBe('timeout of 35000ms exceeded'));
});

// A failed Service read used to blank the whole map with the pod listing's
// error state. It is a warning over a map that still loads.
test('a failed Service listing is a warning over the map, and the Policy Builder is told the listing is unknown', async () => {
  podDataState.pods = workloads();
  podDataState.servicesError = 'Service Unavailable';
  podDataState.servicesListing = null;
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByTestId('map')).not.toBeNull());
  expect(screen.getByText(/Service attribution is unavailable/).textContent).toMatch(/Refresh to retry/);
  expect(screen.queryByText(/could not be loaded/)).toBeNull();
  fireEvent.click(screen.getAllByText('Policy Builder')[0].closest('button')!);
  // Not `[]` ("no Services"): absent, so the generators look Services up by IP.
  await waitFor(() => expect(screen.getByTestId('policy-builder').dataset.services).toBe('false'));
});

test('reads the Broker shed are explained on the map, not only as badges on each card', async () => {
  podDataState.pods = workloads();
  podDataState.failedReads = { traffic: 3, syscalls: 2, shed: true };
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByTestId('map')).not.toBeNull());
  expect(screen.getByText(/5 reads were refused by the Broker because it is busy/).textContent).toMatch(/Refresh to read them again/);
});

test('other failed reads are explained too', async () => {
  podDataState.pods = workloads();
  podDataState.failedReads = { traffic: 1, syscalls: 0 };
  renderAt('#/map?ns=payments');
  await waitFor(() => expect(screen.getByTestId('map')).not.toBeNull());
  expect(screen.getByText(/1 read failed/).textContent).toMatch(/Refresh to read them again/);
});

test('a first load that takes a while says so on the skeleton; a quick one does not flash it', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    podDataState.loading = true;
    renderAt('#/map?ns=payments');
    await vi.waitFor(() => expect(screen.getByText('Loading…')).not.toBeNull());
    await vi.advanceTimersByTimeAsync(3_000);
    expect(screen.queryByTestId('pods-elapsed')).toBeNull();
    await vi.advanceTimersByTimeAsync(3_000);
    await vi.waitFor(() => expect(screen.getByTestId('pods-elapsed').textContent).toMatch(/Reading the workloads… \d+s\. .*up to 35 s/));
  } finally {
    vi.useRealTimers();
  }
});
