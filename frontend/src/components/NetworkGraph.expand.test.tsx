// @vitest-environment jsdom
import { afterEach, beforeAll, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import NetworkGraph from './NetworkGraph';
import { NODE_HEIGHT_EXPANDED } from '../utils/compute';
import type { PodInfo, PodNodeData } from '../types';

// Selecting a card is what opens it, so the graph — not the card, and not
// usePodData — owns `isExpanded`. There is no expander control any more.
//
// The open body is part of the CARD, not an overlay floating above it, so its
// height is an ELK input and the space is genuinely reserved. That costs a
// layout run per selection, which these tests assert rather than hide. The
// trade is deliberate: an overlay avoids the layout but `elk.spacing.nodeNode`
// is 80px against a ~200px body, so it would cover the neighbouring card and,
// living inside the owner node's React tree, swallow that card's clicks.
//
// What keeps the layout affordable is that expansion IS selection: exactly one
// card is ever open, so the card that grows and the card that shrinks cancel
// out instead of the graph accumulating height with every card ever opened.

// ELK is stubbed: the real engine resolves through a worker, which would make
// this a race, and the only thing worth asserting is the graph it is handed.
const { elkGraphs } = vi.hoisted(() => ({ elkGraphs: [] as { children: { id: string; height: number }[] }[] }));
vi.mock('elkjs/lib/elk.bundled.js', () => ({
  default: class {
    layout(graph: { children: { id: string; height: number }[] }) {
      elkGraphs.push(graph);
      return Promise.resolve({ children: graph.children.map((c, i) => ({ ...c, x: i * 400, y: 0 })) });
    }
  },
}));

beforeAll(() => {
  // React Flow measures its pane with a ResizeObserver; jsdom has none.
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

afterEach(() => {
  cleanup();
  elkGraphs.length = 0;
});

const pod = (name: string): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false,
});
// The cards only count their traffic rows here — edges are off (showTraffic
// false), so the rows never go through peer resolution.
const node = (id: string, flows: number): PodNodeData =>
  ({ id, label: id, pod: pod(id), pods: [pod(id)], traffic: Array.from({ length: flows }, () => ({})) }) as unknown as PodNodeData;

const pods = [node('api', 3), node('worker', 1)];

const graph = (selectedPodId: string | null, onPodSelect: (p: PodNodeData | null) => void = () => {}) => (
  <NetworkGraph
    pods={pods}
    allPodsLookup={pods.map((p) => p.pod)}
    services={[]}
    showExternalNodes={false}
    onToggleExternalNodes={() => {}}
    showDaemonSetNodes={false}
    onToggleDaemonSetNodes={() => {}}
    showTraffic={false}
    onToggleTraffic={() => {}}
    layoutDirection="LR"
    onToggleLayoutDirection={() => {}}
    onPodSelect={onPodSelect}
    selectedPodId={selectedPodId}
    focusedNodeId={null}
    onFocusChange={() => {}}
  />
);

// Focus fixture. `api` egresses to `cache` carrying a STORED peer identity
// (`peer_kind`/`peer_name`), which is the path peer resolution takes before
// it ever looks at an IP — so this produces a genuine edge between two local
// nodes. `db` is unconnected.
//
// Three nodes is the minimum that can distinguish the two outcomes: with two,
// "isolated to the neighbourhood" and "drew the whole map" render identically,
// which is how the previous version of this test passed while describing
// behaviour that blanked the map.
const flow = (type: 'EGRESS' | 'INGRESS', peerName: string, ip: string) => ({
  traffic_in_out_ip: ip,
  traffic_type: type,
  peer_kind: 'pod',
  peer_name: peerName,
  peer_namespace: 'payments',
  time_stamp: 't',
});

const focusPod = (name: string, traffic: unknown[]): PodNodeData =>
  ({ id: name, label: name, pod: pod(name), pods: [pod(name)], traffic }) as unknown as PodNodeData;

// Every workload needs at least one flow: with the Traffic view on, `keepOnMap`
// drops a local pod that has neither traffic nor compute gauges, so a pod with
// an empty `traffic` array never reaches the map to be isolated away.
//
// `db`'s peer names a workload that is not in the namespace listing, so it
// resolves to a placeholder and draws no edge — an unconnected card that is
// still on the map, which is exactly what focus has to remove.
const focusPods = [
  focusPod('api', [flow('EGRESS', 'cache', '10.0.0.2')]),
  focusPod('cache', [flow('INGRESS', 'api', '10.0.0.1')]),
  focusPod('db', [flow('EGRESS', 'ghost', '10.0.0.9')]),
];

const graphFocused = (focusedNodeId: string | null, showTraffic: boolean) => (
  <NetworkGraph
    pods={focusPods}
    allPodsLookup={focusPods.map((p) => p.pod)}
    services={[]}
    showExternalNodes={false}
    onToggleExternalNodes={() => {}}
    showDaemonSetNodes={false}
    onToggleDaemonSetNodes={() => {}}
    showTraffic={showTraffic}
    onToggleTraffic={() => {}}
    layoutDirection="LR"
    onToggleLayoutDirection={() => {}}
    onPodSelect={() => {}}
    selectedPodId={focusedNodeId}
    focusedNodeId={focusedNodeId}
    onFocusChange={() => {}}
  />
);

/** The heights ELK was last asked to reserve, by node id. */
const lastReservedHeights = () =>
  new Map(elkGraphs[elkGraphs.length - 1].children.map((c) => [c.id, c.height]));

const laidOut = (container: HTMLElement) =>
  waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBe(pods.length));

test('nothing selected: no card is open', async () => {
  const { container } = render(graph(null));
  await laidOut(container);
  expect(container.textContent).not.toMatch(/connections/);
});

test('the selected card — and only it — is open', async () => {
  // A deep link (`?pod=api`) lands with the card already selected, so this
  // covers first paint as well as the click.
  const { container } = render(graph('api'));
  await waitFor(() => expect(container.textContent).toMatch(/3 connections/));
  // The other card stays shut: one open body, never two.
  expect(container.textContent).not.toMatch(/1 connections/);
});

test('moving the selection moves the open card, never opening a second', async () => {
  const { container, rerender } = render(graph('api'));
  await waitFor(() => expect(container.textContent).toMatch(/3 connections/));

  rerender(graph('worker'));
  await waitFor(() => expect(container.textContent).toMatch(/1 connections/));
  expect(container.textContent).not.toMatch(/3 connections/);
});

test('there is no expander control: the card itself is the only target', async () => {
  const { container } = render(graph(null));
  await laidOut(container);
  // The chevron carried these labels. Selecting the card is now the whole
  // interaction, and a second smaller target for it would let "selected" and
  // "open" disagree.
  expect(container.querySelector('[aria-label="Expand"]')).toBeNull();
  expect(container.querySelector('[aria-label="Collapse"]')).toBeNull();
});

test('the open card has its height reserved, and gives it back when closed', async () => {
  // The property the whole approach exists for. ELK is told the open card is
  // taller, so the cards below it are placed clear of the body rather than
  // being covered by it. If this ever stops being a layout input, the body
  // overlaps its neighbour and swallows that neighbour's clicks.
  const { container, rerender } = render(graph(null));
  await laidOut(container);
  const shut = lastReservedHeights();

  rerender(graph('api'));
  await waitFor(() => expect(container.textContent).toMatch(/3 connections/));
  const open = lastReservedHeights();

  expect(open.get('api')! - shut.get('api')!).toBe(NODE_HEIGHT_EXPANDED);
  // Only the open card grows; the rest of the graph is untouched.
  expect(open.get('worker')).toBe(shut.get('worker'));

  rerender(graph(null));
  await waitFor(() => expect(container.textContent).not.toMatch(/connections/));
  expect(lastReservedHeights()).toEqual(shut);
});

test('selection re-runs layout, and the swap is one net change', async () => {
  // The acknowledged cost, asserted rather than hidden. Reserving space means
  // ELK runs on selection — as it already did on every expander click before
  // this. What keeps it bounded is that one card closes as another opens, so
  // the graph never accumulates height.
  const { container, rerender } = render(graph(null));
  await laidOut(container);
  const runsWhenShut = elkGraphs.length;
  const totalShut = [...lastReservedHeights().values()].reduce((a, b) => a + b, 0);

  rerender(graph('api'));
  await waitFor(() => expect(container.textContent).toMatch(/3 connections/));
  expect(elkGraphs.length).toBeGreaterThan(runsWhenShut);
  const totalOneOpen = [...lastReservedHeights().values()].reduce((a, b) => a + b, 0);

  rerender(graph('worker'));
  await waitFor(() => expect(container.textContent).toMatch(/1 connections/));

  // Moving the selection is a swap, not an accumulation: the total height with
  // `worker` open equals the total with `api` open.
  expect([...lastReservedHeights().values()].reduce((a, b) => a + b, 0)).toBe(totalOneOpen);
  expect(totalOneOpen).toBe(totalShut + NODE_HEIGHT_EXPANDED);
});

// Selecting a card focuses it as well as opening it. There is no focus
// control on the card any more: the crosshair was a third target on a card
// that already had two, and it let "selected" and "focused" drift apart.
test('there is no focus control on a card', async () => {
  const { container } = render(graph(null));
  await laidOut(container);
  expect(container.querySelector('[aria-label="Focus on connections"]')).toBeNull();
  expect(container.querySelector('[aria-label="Exit focus"]')).toBeNull();
});

// Focus isolates the node and its direct peers.
test('focusing a card isolates it to its neighbourhood', async () => {
  const { container } = render(graphFocused('api', true));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBe(2));
  expect(container.textContent).toMatch(/api/);
  expect(container.textContent).toMatch(/cache/);
  // The unconnected workload is the one that has to disappear; without a
  // third node there is nothing here that isolation could remove.
  expect(container.textContent).not.toMatch(/db/);
  expect(container.textContent).toMatch(/Focused on/);
});

// The guard. Selection focuses, and selection is now an ordinary click, so
// focus must never be the thing that empties the screen. `allEdges` is empty
// whenever the Traffic toggle is off, and a workload whose flows are all
// unattributed draws no edges even with it on — so a neighbourhood of one is
// reachable in a normal cluster, not a corner case.
test('focusing a card with no peers leaves the whole map drawn', async () => {
  const { container } = render(graphFocused('api', false));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBe(3));
  // And the pill must not claim an isolation that did not happen.
  expect(container.textContent).not.toMatch(/Focused on/);
});

// Selection is the only expander since the chevron went, so it has to be able
// to shut a card as well as open one. Without this, a click on the card you
// already have open does nothing at all, and the only ways out both drop the
// focus as a side effect.
test('clicking the open card closes it, and clicking another moves the selection', async () => {
  const onPodSelect = vi.fn();
  const { container } = render(graph('api', onPodSelect));
  await laidOut(container);

  const nodeEl = (id: string) => container.querySelector(`.react-flow__node[data-id="${id}"]`)!;

  fireEvent.click(nodeEl('api'));
  expect(onPodSelect).toHaveBeenCalledWith(null);

  onPodSelect.mockClear();
  fireEvent.click(nodeEl('worker'));
  expect(onPodSelect).toHaveBeenCalledTimes(1);
  expect(onPodSelect.mock.calls[0][0]).toMatchObject({ id: 'worker' });
});
