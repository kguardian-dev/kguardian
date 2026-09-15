// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import type { PodNodeData } from './types';

// App's wiring had no coverage at all, and three separate one-line reverts in
// it left the whole suite green: dropping `paramsForSelection` (selection
// stops focusing, the headline behaviour), dropping the second `usePodData`
// argument (sparklines never seed), and handing NetworkGraph the RESOLVED pod
// id instead of the raw one (every card collapses the moment an external peer
// is selected — the regression App's own comment warns about).
//
// Each of those is a seam: the units on either side are tested and correct,
// and nothing asserted that App joins them. This file asserts the joins, and
// nothing else. The heavy children are stubbed to props-in/props-out so the
// test does not depend on ReactFlow, ELK or the DOM of the panel.

const graphProps: Record<string, unknown>[] = [];
const podDataCalls: unknown[][] = [];

vi.mock('./components/NetworkGraph', () => ({
  default: (props: Record<string, unknown>) => {
    graphProps.push(props);
    const select = props.onPodSelect as (p: Partial<PodNodeData> | null) => void;
    return (
      <div>
        <button onClick={() => select({ id: 'payments-api' })}>select-api</button>
        {/* An id NetworkGraph synthesises for itself: it is never in `pods`,
            so a resolved-id lookup yields null for it. */}
        <button onClick={() => select({ id: 'ext-93.184.216.34-out' })}>select-external</button>
        <button onClick={() => select(null)}>clear</button>
        <span data-testid="focused">{String(props.focusedNodeId ?? '')}</span>
        <span data-testid="selected">{String(props.selectedPodId ?? '')}</span>
      </div>
    );
  },
}));

vi.mock('./components/DataTable', () => ({ default: () => <div /> }));

const podFixture = {
  id: 'payments-api',
  label: 'api',
  pod: {
    pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments',
    time_stamp: 't', node_name: 'worker-1', is_dead: false,
  },
  pods: [],
  traffic: [],
} as unknown as PodNodeData;

vi.mock('./hooks/usePodData', () => ({
  usePodData: (...args: unknown[]) => {
    podDataCalls.push(args);
    return {
      pods: [podFixture],
      compute: { findings: [], enabled: false, supported: false, history: new Map() },
      allPodsLookup: [],
      services: [],
      loading: false,
      error: null,
      refreshData: () => {},
    };
  },
}));

vi.mock('./hooks/useNamespaces', () => ({
  useNamespaces: () => ({ namespaces: ['payments'], loading: false }),
}));

vi.mock('./hooks/useClusterEnvironment', () => ({
  useClusterEnvironment: () => ({ cni: 'unknown', cniVersion: null, hubble: 'unknown' }),
}));

import App from './App';
import { ThemeProvider } from './contexts/ThemeContext';
import { SettingsProvider } from './contexts/SettingsContext';
import { ClusterProvider } from './contexts/ClusterContext';
import { AuthProvider } from './contexts/AuthContext';

beforeEach(() => {
  graphProps.length = 0;
  podDataCalls.length = 0;
  window.location.hash = '#/map?ns=payments';
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
  window.location.hash = '';
});

const renderApp = () =>
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

const latestGraph = () => graphProps[graphProps.length - 1];

test('selecting a card focuses it: App binds pod and focus together', async () => {
  const { getByText, getByTestId } = renderApp();
  await waitFor(() => expect(getByText('select-api')).toBeTruthy());

  fireEvent.click(getByText('select-api'));

  // Both params, from one click. Reverting App to the pre-PR inline params
  // object leaves `focus` at whatever it already was — which is nothing.
  await waitFor(() => expect(getByTestId('focused').textContent).toBe('payments-api'));
  expect(getByTestId('selected').textContent).toBe('payments-api');
  expect(decodeURIComponent(window.location.hash)).toMatch(/focus=payments-api/);
});

test('the graph is handed the RAW selected id, not the resolved pod', async () => {
  // `ext-…-out` is a node NetworkGraph synthesises; it is not in `pods`, so
  // `selectedPod` resolves to null for it. Passing the resolved id here would
  // collapse the card the instant an external peer was selected.
  const { getByText, getByTestId } = renderApp();
  await waitFor(() => expect(getByText('select-external')).toBeTruthy());

  fireEvent.click(getByText('select-external'));

  await waitFor(() => expect(getByTestId('selected').textContent).toBe('ext-93.184.216.34-out'));
  expect(getByTestId('focused').textContent).toBe('ext-93.184.216.34-out');
});

test('the selected id reaches usePodData, which is what seeds the sparklines', async () => {
  const { getByText } = renderApp();
  await waitFor(() => expect(getByText('select-api')).toBeTruthy());

  fireEvent.click(getByText('select-api'));

  // Dropping the second argument leaves every seed test green and no card
  // ever charted.
  await waitFor(() => expect(podDataCalls[podDataCalls.length - 1]).toEqual(['payments', 'payments-api']));
});

test('clearing the selection clears the focus with it', async () => {
  const { getByText, getByTestId } = renderApp();
  await waitFor(() => expect(getByText('select-api')).toBeTruthy());

  fireEvent.click(getByText('select-api'));
  await waitFor(() => expect(getByTestId('focused').textContent).toBe('payments-api'));

  fireEvent.click(getByText('clear'));
  await waitFor(() => expect(getByTestId('selected').textContent).toBe(''));
  // A focus left behind would keep the map isolated around a card that is no
  // longer open, with no card to explain why.
  expect(getByTestId('focused').textContent).toBe('');
  expect(latestGraph()).toBeTruthy();
});

// The panel is sized by CSS, and jsdom does no layout, so this asserts the
// mechanism rather than the resulting pixels: a `maxHeight` that lets the
// panel take its content's height, not a `height` that pins it to the cap.
//
// It is here because removing the workload's identity from the panel was
// asked for "to maximise space", and with a fixed height it freed none: the
// three collapsed headers simply sat above ~150px of blank panel and the map
// did not grow. Reverting either element to a fixed `height` fails this.
test('the bottom panel is capped, not pinned, so it can shrink to its content', async () => {
  const { container, getByText } = renderApp();
  await waitFor(() => expect(getByText('select-api')).toBeTruthy());
  fireEvent.click(getByText('select-api'));

  const panel = await waitFor(() => {
    const el = [...container.querySelectorAll('div')].find(
      (d) => d.style.maxHeight !== '' && d.style.opacity === '1',
    );
    expect(el).toBeTruthy();
    return el!;
  });
  // Capped by the drag height, free to be shorter.
  expect(panel.style.maxHeight).not.toBe('');
  expect(panel.style.height).toBe('');

  // The scrolling element carries the cap too, so an open section scrolls
  // inside the panel instead of the panel growing past it.
  const scroller = panel.querySelector('.overflow-auto') as HTMLElement | null;
  expect(scroller).toBeTruthy();
  expect(scroller!.style.maxHeight).not.toBe('');
  expect(scroller!.style.height).toBe('');
});
