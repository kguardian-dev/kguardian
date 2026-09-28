import { describe, expect, it } from 'vitest';
import { HEARTBEAT_GRACE_MS, ageLabel, describeNodes, describeSilence, silentNodes, type NodeStatusResponse } from './nodeReporting';

const NOW = Date.UTC(2026, 8, 28, 12, 37, 0);

const status = (nodes: NodeStatusResponse['nodes'], staleAfterSecs = 900): NodeStatusResponse => ({ staleAfterSecs, nodes });

describe('silentNodes', () => {
  it('keeps stale nodes whose heartbeat is inside the window, in name order', () => {
    const s = silentNodes(
      status([
        { node: 'ip-b', lastPodPostAt: '2026-09-28T07:37:12Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true },
        { node: 'ip-a', lastPodPostAt: '2026-09-28T08:03:40', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:35:00', stale: true },
      ]),
      NOW,
    );
    expect(s.nodes.map((n) => n.node)).toEqual(['ip-a', 'ip-b']);
    // Naive broker timestamps are UTC; the newest last post is the "since".
    expect(s.sinceMs).toBe(Date.UTC(2026, 8, 28, 8, 3, 40));
  });

  it('drops healthy nodes and departed nodes, and nodes with no heartbeat to judge by', () => {
    const s = silentNodes(
      status([
        { node: 'fresh', lastPodPostAt: '2026-09-28T12:36:10Z', alivePods: 3, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: false },
        { node: 'gone', lastPodPostAt: '2026-09-26T01:00:00Z', alivePods: 0, lastHeartbeatAt: '2026-09-26T01:02:00Z', stale: true },
        { node: 'no-heartbeat', lastPodPostAt: '2026-09-28T07:00:00Z', alivePods: 0, lastHeartbeatAt: null, stale: true },
      ]),
      NOW,
    );
    expect(s.nodes).toEqual([]);
    expect(s.sinceMs).toBeNull();
  });

  it('counts a node with a fresh heartbeat and no pod row: pruned by retention or never able to post', () => {
    const s = silentNodes(
      status([
        { node: 'no-row', lastPodPostAt: null, alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:30Z', stale: true },
        { node: 'stuck', lastPodPostAt: '2026-09-28T07:37:12Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true },
      ]),
      NOW,
    );
    expect(s.nodes.map((n) => n.node)).toEqual(['no-row', 'stuck']);
    // "since" ignores the node with nothing on record.
    expect(s.sinceMs).toBe(Date.UTC(2026, 8, 28, 7, 37, 12));
    expect(describeNodes(s)).toBe(
      `no-row: no pod post on record\nstuck: last pod post ${new Date(Date.UTC(2026, 8, 28, 7, 37, 12)).toLocaleString(undefined, { timeZoneName: 'short' })}`,
    );
  });

  it('judges the heartbeat against the broker window, inclusive, never tighter than two missed heartbeats', () => {
    const at = (secsAgo: number) => new Date(NOW - secsAgo * 1000).toISOString();
    const rows = (heartbeatAgo: number, staleAfterSecs = 900) =>
      status([{ node: 'n', lastPodPostAt: at(3600), alivePods: 0, lastHeartbeatAt: at(heartbeatAgo), stale: true }], staleAfterSecs);
    expect(silentNodes(rows(900), NOW).nodes).toHaveLength(1);
    expect(silentNodes(rows(901), NOW).nodes).toHaveLength(0);
    // PEER_STALE_ALIVE_SECS below the 300 s heartbeat cadence must not hide every node.
    expect(HEARTBEAT_GRACE_MS).toBe(600_000);
    expect(silentNodes(rows(500, 100), NOW).nodes).toHaveLength(1);
    expect(silentNodes(rows(601, 100), NOW).nodes).toHaveLength(0);
    expect(silentNodes(rows(1700, 1800), NOW).nodes).toHaveLength(1);
  });
});

describe('describeSilence', () => {
  it('counts and ages the silence', () => {
    const one = silentNodes(
      status([{ node: 'n', lastPodPostAt: '2026-09-28T07:37:12Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true }]),
      NOW,
    );
    expect(describeSilence(one, NOW)).toMatch(/^1 node has not reported pods since \d{2}:\d{2} \(5h ago\)$/);
    expect(describeSilence({ nodes: [], sinceMs: null }, NOW)).toBe('0 nodes have not reported any pods');
  });

  it('says "any pods" when no post is on record for any of them', () => {
    const none = silentNodes(
      status([
        { node: 'a', lastPodPostAt: null, alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true },
        { node: 'b', lastPodPostAt: null, alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true },
      ]),
      NOW,
    );
    expect(describeSilence(none, NOW)).toBe('2 nodes have not reported any pods');
  });
});

describe('ageLabel', () => {
  it('is coarse and never negative', () => {
    expect(ageLabel(-5000)).toBe('0s');
    expect(ageLabel(45_000)).toBe('45s');
    expect(ageLabel(12 * 60_000)).toBe('12m');
    expect(ageLabel(5 * 3_600_000)).toBe('5h');
    expect(ageLabel(3 * 86_400_000)).toBe('3d');
  });
});
