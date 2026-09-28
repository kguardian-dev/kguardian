// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { NodeReportingBanner, type NodeStatusLoad } from './NodeReportingBanner';
import type { NodeStatusResponse } from '../utils/nodeReporting';

afterEach(cleanup);

// 2026-09-28T12:37:00Z, the review's capture time.
const NOW = Date.UTC(2026, 8, 28, 12, 37, 0);
const now = () => NOW;

/** The F-19 cluster: two stuck controllers, one healthy node, one gone, one just joined. */
const fixture: NodeStatusResponse = {
  staleAfterSecs: 900,
  nodes: [
    { node: 'ip-10-62-123-205', lastPodPostAt: '2026-09-28T08:03:40Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:35:00Z', stale: true },
    { node: 'ip-10-62-65-125', lastPodPostAt: '2026-09-28T07:37:12Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true },
    { node: 'ip-10-62-66-9', lastPodPostAt: '2026-09-28T12:36:10Z', alivePods: 41, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: false },
    { node: 'ip-10-62-70-1', lastPodPostAt: '2026-09-26T01:00:00Z', alivePods: 0, lastHeartbeatAt: '2026-09-26T01:02:00Z', stale: true },
    { node: 'ip-10-62-71-2', lastPodPostAt: null, alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:30Z', stale: true },
  ],
};

const ok = (status: NodeStatusResponse): NodeStatusLoad => ({ kind: 'ok', status });

async function renderWith(load: () => Promise<NodeStatusLoad>, refreshTick = 0) {
  const view = render(<NodeReportingBanner load={load} now={now} refreshTick={refreshTick} />);
  await act(async () => {});
  return view;
}

test('names the running controllers that stopped posting, not the healthy or departed nodes', async () => {
  await renderWith(async () => ok(fixture));
  const banner = screen.getByTestId('node-reporting-banner');
  // "since" is the newest known last post among them: none has reported after 08:03.
  // The node with a heartbeat but no row at all counts too (its rows were pruned or never posted).
  expect(banner.textContent).toMatch(/^3 nodes have not reported pods since \d{2}:\d{2} \(5h ago\)\./);
  expect(banner.textContent).toContain('missing from the namespace picker, Workloads and the maps');
  const tooltip = banner.getAttribute('title') ?? '';
  expect(tooltip).toContain('ip-10-62-123-205: last pod post');
  expect(tooltip).toContain('ip-10-62-65-125: last pod post');
  expect(tooltip).toContain('ip-10-62-71-2: no pod post on record');
  expect(tooltip).not.toContain('ip-10-62-66-9');
  expect(tooltip).not.toContain('ip-10-62-70-1');
  expect(banner.getAttribute('role')).toBe('status');
});

test('a node with a heartbeat and no pod row at all is reported as never having posted', async () => {
  await renderWith(async () => ok({ staleAfterSecs: 900, nodes: [fixture.nodes[4]] }));
  expect(screen.getByTestId('node-reporting-banner').textContent).toContain('1 node has not reported any pods.');
});

test('singular wording for one node', async () => {
  await renderWith(async () => ok({ ...fixture, nodes: fixture.nodes.slice(1, 3) }));
  expect(screen.getByTestId('node-reporting-banner').textContent).toContain('1 node has not reported pods since');
});

test('renders nothing when every node reports', async () => {
  await renderWith(async () => ok({ staleAfterSecs: 900, nodes: [fixture.nodes[2]] }));
  expect(screen.queryByTestId('node-reporting-banner')).toBeNull();
});

test('renders nothing on an older broker (404) and stops asking', async () => {
  const load = vi.fn(async (): Promise<NodeStatusLoad> => ({ kind: 'unsupported' }));
  const { rerender } = await renderWith(load);
  expect(screen.queryByTestId('node-reporting-banner')).toBeNull();
  rerender(<NodeReportingBanner load={load} now={now} refreshTick={1} />);
  await act(async () => {});
  expect(load).toHaveBeenCalledTimes(1);
});

test('renders nothing on a failed read and never throws', async () => {
  await renderWith(async () => ({ kind: 'error' }));
  expect(screen.queryByTestId('node-reporting-banner')).toBeNull();
});

test('a failed refresh keeps the last good answer; the Refresh button reloads', async () => {
  let calls = 0;
  const load = vi.fn(async (): Promise<NodeStatusLoad> => (++calls === 1 ? ok(fixture) : { kind: 'error' }));
  const { rerender } = await renderWith(load);
  expect(screen.getByTestId('node-reporting-banner')).toBeTruthy();
  rerender(<NodeReportingBanner load={load} now={now} refreshTick={1} />);
  await act(async () => {});
  expect(load).toHaveBeenCalledTimes(2);
  expect(screen.getByTestId('node-reporting-banner')).toBeTruthy();
});
