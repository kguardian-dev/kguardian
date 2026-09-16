// What the map draws while a card is focused.
//
// Both rules live here rather than inline in NetworkGraph because neither is
// observable through the rendered DOM: ReactFlow only emits edge elements once
// its nodes have been measured, which never happens under jsdom. Inline, the
// edge rule could be changed to anything at all and every test would still
// pass.

/** The shape both rules need. ReactFlow's `Edge` is a superset. */
export interface FocusEdge {
  source: string;
  target: string;
}

/**
 * The nodes to draw while `focusedNodeId` is focused: that node plus everything
 * one hop away. `null` means focus does not apply and the whole map is drawn.
 *
 * A neighbourhood of one is treated as no focus at all. A card can genuinely
 * have no edges (the Traffic toggle off, or flows whose peer identity was never
 * stored), and isolating to it would leave a single card on an empty map for
 * what is now an ordinary click.
 */
export function focusNeighborhood<E extends FocusEdge>(
  focusedNodeId: string | null,
  edges: readonly E[],
): Set<string> | null {
  if (!focusedNodeId) return null;
  const ids = new Set<string>([focusedNodeId]);
  for (const e of edges) {
    if (e.source === focusedNodeId) ids.add(e.target);
    if (e.target === focusedNodeId) ids.add(e.source);
  }
  return ids.size < 2 ? null : ids;
}

/**
 * The edges to draw while `focusedNodeId` is focused: only those it is an
 * ENDPOINT of.
 *
 * Keeping every edge whose two ends both sit in the neighbourhood also draws
 * peer-to-peer traffic — two of the focused workload's peers talking to each
 * other, a path the focused workload is not on. Focus answers "what does this
 * workload talk to", so those edges are noise.
 *
 * Every drawn node keeps at least one edge: the neighbourhood is built from
 * edges incident to the focused node, so whatever put a node in the set is
 * itself kept here.
 */
export function focusEdges<E extends FocusEdge>(
  focusedNodeId: string,
  edges: readonly E[],
): E[] {
  return edges.filter((e) => e.source === focusedNodeId || e.target === focusedNodeId);
}
