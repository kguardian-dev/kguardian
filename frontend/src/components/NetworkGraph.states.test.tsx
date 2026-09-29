// @vitest-environment jsdom
import { afterEach, beforeAll, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import NetworkGraph from './NetworkGraph';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';

// The map's honest states: every workload hidden by the Traffic filter is
// said so in the canvas (F-03), a workload whose traffic read failed keeps
// its card (F-08), a synthesised card's data reaches the caller so the
// traffic panel can open for it (F-15), and the summary counts workloads
// and pods apart (F-16).

vi.mock('elkjs/lib/elk.bundled.js', () => ({
  default: class {
    layout(graph: { children: { id: string }[] }) {
      return Promise.resolve({ children: graph.children.map((c, i) => ({ ...c, x: i * 400, y: 0 })) });
    }
  },
}));

beforeAll(() => {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

afterEach(cleanup);

const pod = (name: string): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'kguardian', time_stamp: 't', node_name: 'worker-1', is_dead: false, pod_identity: name,
});
const node = (id: string, over: Partial<PodNodeData> = {}): PodNodeData =>
  ({ id, label: id, pod: pod(id), pods: [pod(id)], traffic: [], isExpanded: false, ...over }) as PodNodeData;

type Props = Partial<Parameters<typeof NetworkGraph>[0]>;
const graph = (pods: PodNodeData[], props: Props = {}) => (
  <NetworkGraph
    pods={pods}
    allPodsLookup={pods.flatMap((p) => p.pods)}
    services={[]}
    showExternalNodes
    onToggleExternalNodes={() => {}}
    showDaemonSetNodes={false}
    onToggleDaemonSetNodes={() => {}}
    showTraffic
    onToggleTraffic={() => {}}
    layoutDirection="LR"
    onToggleLayoutDirection={() => {}}
    onPodSelect={() => {}}
    selectedPodId={null}
    focusedNodeId={null}
    onFocusChange={() => {}}
    {...props}
  />
);

const silent = ['kguardian-broker', 'kguardian', 'kguardian-frontend', 'kguardian-llm-bridge', 'kguardian-supplychain'].map((n) => node(n));

test('every workload hidden by the Traffic filter: the canvas says so and offers to show them', async () => {
  const onToggleTraffic = vi.fn();
  const { container, getByTestId, getByText } = render(graph(silent, { onToggleTraffic }));
  const state = await waitFor(() => getByTestId('traffic-filter-empty'));
  expect(state.textContent).toMatch(/5 workloads have no recorded flows/);
  expect(state.textContent).toMatch(/Traffic filter/);
  expect(container.querySelectorAll('.react-flow__node').length).toBe(0);
  fireEvent.click(getByText('Show them'));
  expect(onToggleTraffic).toHaveBeenCalledTimes(1);
});

test('one hidden workload reads in the singular', async () => {
  const { getByTestId } = render(graph([silent[0]]));
  const state = await waitFor(() => getByTestId('traffic-filter-empty'));
  expect(state.textContent).toMatch(/1 workload has no recorded flows/);
});

test('the state is not shown with the filter off, nor for a namespace that really has no pods', async () => {
  const off = render(graph(silent, { showTraffic: false }));
  await waitFor(() => expect(off.container.querySelectorAll('.react-flow__node').length).toBe(5));
  expect(off.queryByTestId('traffic-filter-empty')).toBeNull();
  cleanup();
  const none = render(graph([]));
  await new Promise((r) => setTimeout(r, 0));
  expect(none.queryByTestId('traffic-filter-empty')).toBeNull();
});

test('a workload whose traffic read failed keeps its card, badged, and is not counted as hidden', async () => {
  const pods = [node('argo-rollouts', { trafficError: true }), node('quiet')];
  const { container, queryByTestId } = render(graph(pods));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBe(1));
  expect(container.textContent).toMatch(/argo-rollouts/);
  expect(container.textContent).toMatch(/traffic read failed/);
  expect(container.textContent).not.toMatch(/quiet/);
  // One card is drawn, so the blank-canvas state must not appear over it.
  expect(queryByTestId('traffic-filter-empty')).toBeNull();
});

const egressTo = (ip: string): NetworkTraffic =>
  ({ uuid: ip, traffic_in_out_ip: ip, traffic_in_out_port: '443', ip_protocol: 'TCP', traffic_type: 'EGRESS', decision: 'ALLOW', time_stamp: '2026-09-28T00:00:00' }) as NetworkTraffic;

test('selecting a synthesised card reports its data to the caller; a local card reports null', async () => {
  const onSelectedExternal = vi.fn();
  const pods = [node('repo-server', { traffic: [egressTo('140.82.112.3'), egressTo('185.199.108.133')] })];
  const { container, rerender } = render(graph(pods, { onSelectedExternal, selectedPodId: 'external-internet-out' }));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBe(2));
  await waitFor(() => {
    const last = onSelectedExternal.mock.calls[onSelectedExternal.mock.calls.length - 1]?.[0] as PodNodeData | null | undefined;
    expect(last?.id).toBe('external-internet-out');
  });
  const reported = onSelectedExternal.mock.calls[onSelectedExternal.mock.calls.length - 1][0] as PodNodeData;
  expect(reported.isExternal).toBe(true);
  expect(reported.traffic).toHaveLength(2); // what the traffic panel groups by port

  rerender(graph(pods, { onSelectedExternal, selectedPodId: 'repo-server' }));
  await waitFor(() => expect(onSelectedExternal).toHaveBeenLastCalledWith(null));
});

test('the summary counts workloads, and its tooltip carries the pod count', async () => {
  const two = node('api', { pods: [pod('api-1'), pod('api-2')], traffic: [egressTo('140.82.112.3')] });
  const one = node('worker', { traffic: [egressTo('140.82.112.3')] });
  const { getAllByTestId } = render(graph([two, one]));
  const badge = await waitFor(() => getAllByTestId('summary-workloads')[0]);
  expect(badge.textContent).toBe('2');
  expect(badge.getAttribute('title')).toBe('2 workloads (3 pods) in the current namespace');
});

test('a failing compute poll is named in the summary instead of gauges silently missing', async () => {
  const withGauges = render(graph([node('api', { traffic: [egressTo('140.82.112.3')] })], { computeUnavailable: true }));
  const note = await waitFor(() => withGauges.getAllByTestId('compute-unavailable')[0]);
  expect(note.textContent).toMatch(/compute unavailable/);
  cleanup();
  const healthy = render(graph([node('api', { traffic: [egressTo('140.82.112.3')] })]));
  await waitFor(() => expect(healthy.container.querySelectorAll('.react-flow__node').length).toBeGreaterThan(0));
  expect(healthy.queryAllByTestId('compute-unavailable')).toHaveLength(0);
});

// The focus pill was its own panel at top-center and the toolbar a later
// panel at top-right, both absolutely positioned at the same z-index. Once
// the lens group and toggles grew past half the map (a 1280px laptop with the
// rail open) the toolbar was drawn over the pill and its "Show all" could not
// be clicked. The pill now stacks under the toolbar in the same panel, so the
// two can never overlap.
test('the focus pill stacks under the toolbar, in the same panel, and its exit control works', async () => {
  const onFocusChange = vi.fn();
  const pods = [node('repo-server', { traffic: [egressTo('140.82.112.3')] })];
  const { container, getByRole, getAllByLabelText } = render(
    graph(pods, { focusedNodeId: 'repo-server', onFocusChange, lens: 'vulns', onLensChange: () => {} }),
  );
  const exit = await waitFor(() => getByRole('button', { name: /Show all/ }));

  // Not a separately positioned panel that another panel can cover.
  expect(container.querySelector('.react-flow__panel.top.center')).toBeNull();
  const panel = exit.closest('.react-flow__panel')!;
  expect(panel.classList.contains('right')).toBe(true);
  // After the toolbar in document order, i.e. below it in the flex stack.
  const lens = getAllByLabelText('Map lens')[0];
  expect(panel.contains(lens)).toBe(true);
  expect(lens.compareDocumentPosition(exit) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(panel.textContent).toMatch(/Focused on repo-server/);

  // A native button: in the tab order, and a click leaves focus.
  expect(exit.tagName).toBe('BUTTON');
  expect(exit.tabIndex).toBe(0);
  fireEvent.click(exit);
  expect(onFocusChange).toHaveBeenCalledWith(null);

  // Esc still leaves focus too.
  onFocusChange.mockClear();
  fireEvent.keyDown(window, { key: 'Escape' });
  expect(onFocusChange).toHaveBeenCalledWith(null);

  // The lens picker stays usable while focused.
  expect((lens as HTMLSelectElement).disabled).toBe(false);
});
