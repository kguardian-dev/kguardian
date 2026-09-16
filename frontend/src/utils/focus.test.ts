import { expect, test } from 'vitest';
import { focusEdges, focusNeighborhood } from './focus';

// The graph in these tests:
//   api -> cache, api -> db   (paths the focused card is on)
//   cache -> db               (a path between two of its peers)
//   lonely -> ghost           (nothing to do with api)
const edges = [
  { source: 'api', target: 'cache' },
  { source: 'api', target: 'db' },
  { source: 'cache', target: 'db' },
  { source: 'lonely', target: 'ghost' },
];

test('the neighbourhood is the focused node plus one hop, either direction', () => {
  expect(focusNeighborhood('api', edges)).toEqual(new Set(['api', 'cache', 'db']));
  // `db` is only ever a target, so this also covers the upstream direction.
  expect(focusNeighborhood('db', edges)).toEqual(new Set(['db', 'api', 'cache']));
});

test('no focused node means no filtering', () => {
  expect(focusNeighborhood(null, edges)).toBeNull();
});

test('a node with no edges does not isolate, so the map stays whole', () => {
  // Reachable in a normal cluster: the Traffic toggle off empties the edge
  // list entirely, and unattributed flows draw no edge even with it on.
  expect(focusNeighborhood('api', [])).toBeNull();
  expect(focusNeighborhood('orphan', edges)).toBeNull();
});

test('focus keeps only the paths the focused node is an endpoint of', () => {
  expect(focusEdges('api', edges)).toEqual([
    { source: 'api', target: 'cache' },
    { source: 'api', target: 'db' },
  ]);
});

test('a path between two peers is dropped even though both ends are drawn', () => {
  // The reported bug: `cache` and `db` are both on screen as peers of `api`,
  // and the traffic between them was drawn as if it were one of api's paths.
  const kept = focusEdges('api', edges);
  expect(kept).not.toContainEqual({ source: 'cache', target: 'db' });
  expect(kept.some((e) => e.source === 'cache' && e.target === 'db')).toBe(false);
});

test('every node the neighbourhood draws still has an edge to the focused node', () => {
  // Nothing can be left stranded: the set is built from incident edges, and
  // those are exactly the edges kept.
  const nodes = focusNeighborhood('api', edges)!;
  const kept = focusEdges('api', edges);
  for (const id of nodes) {
    if (id === 'api') continue;
    expect(kept.some((e) => e.source === id || e.target === id)).toBe(true);
  }
});

test('edges unrelated to the focused node never appear', () => {
  expect(focusEdges('api', edges)).not.toContainEqual({ source: 'lonely', target: 'ghost' });
});
