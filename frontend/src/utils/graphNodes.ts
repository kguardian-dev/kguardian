// React Flow node reconciliation for the map (pure, so it is testable
// without ReactFlow / ELK).
//
// Two different events touch the node list and they must NOT be conflated:
//   - a LAYOUT result (ELK finished for the current node set): every node is
//     placed at its computed position — `placeNodes`;
//   - a DATA tick (the 5 s compute poll rebuilt the node objects, a card was
//     selected, a gauge changed): the existing nodes keep their positions —
//     including one the user just dragged — and only `data` / `selected`
//     are replaced — `mergeNodeData`.
// Conflating the two was the bug where a dragged card snapped back every 5 s.

import type { Node } from 'reactflow';

export type Positions = ReadonlyMap<string, { x: number; y: number }>;

/** Off-canvas parking spot for a node ELK has not placed (never visible). */
export const UNPLACED = { x: -9999, y: -9999 } as const;

/**
 * Nodes for a fresh layout. Returns [] while ELK has placed none of the
 * current set, so the graph stays hidden rather than flashing at (0,0).
 */
export function placeNodes(displayNodes: readonly Node[], positions: Positions): Node[] {
  const hasPositions = displayNodes.length > 0 && displayNodes.some((n) => positions.has(n.id));
  if (!hasPositions) return [];
  return displayNodes.map((node) => ({
    ...node,
    position: positions.get(node.id) ?? { ...UNPLACED },
  }));
}

/**
 * A layout-signature change (namespace switch, node added/removed, a card
 * expanded): drop every card that is no longer in the current set so the
 * previous namespace's cards do not linger until ELK lands. Cards that are
 * still present keep their positions (an expansion toggle must not blank the
 * graph); a wholly new set goes blank, then lays out — the original
 * behaviour. Returns `prev` itself when nothing was dropped.
 */
export function pruneNodes(prev: readonly Node[], currentIds: ReadonlySet<string>): Node[] {
  const kept = prev.filter((n) => currentIds.has(n.id));
  return kept.length === prev.length ? (prev as Node[]) : kept;
}

/**
 * A data tick over an already-laid-out list: same nodes, same positions
 * (dragged or laid out), new `data` / `selected`. Nodes that are not in
 * `prev` are NOT added and nodes missing from `next` are NOT removed here —
 * both change the layout signature and arrive through `placeNodes` once
 * ELK has run. Returns `prev` itself when nothing changed.
 */
export function mergeNodeData(prev: readonly Node[], next: readonly Node[]): Node[] {
  if (prev.length === 0) return prev as Node[];
  const byId = new Map(next.map((n) => [n.id, n]));
  let changed = false;
  const out = prev.map((n) => {
    const fresh = byId.get(n.id);
    if (!fresh || (fresh.data === n.data && (fresh.selected ?? false) === (n.selected ?? false))) return n;
    changed = true;
    return { ...n, data: fresh.data, selected: fresh.selected };
  });
  return changed ? out : (prev as Node[]);
}

// ---------------------------------------------------------------------------
// Viewport policy after a layout.
//
// ELK re-runs whenever the layout signature changes, and historically every
// layout ended in `fitView`, which yanked the viewport back to the centre of
// the graph when all the user did was expand one card. Only a change to the
// SET of nodes / edges (namespace switch, toggle of external or DaemonSet
// nodes, focus mode, layout direction) deserves a refit. A change that keeps
// the same nodes and edges — a card expanded or collapsed, gauges arriving on
// a poll tick — is laid out in place: the viewport stays where it is, and if
// the toggled card grew out of view we pan to it, nothing else.
// ---------------------------------------------------------------------------

export interface LayoutParts {
  direction: string;
  /** node id → per-node layout bits, first char = expanded (0/1). */
  nodes: ReadonlyMap<string, string>;
  edges: readonly string[];
}

export type LayoutIntent = { kind: 'refit' } | { kind: 'in-place'; toggledId: string | null };

export function layoutSignatureOf(parts: LayoutParts): string {
  const nodes = [...parts.nodes.entries()].map(([id, bits]) => `${id}:${bits}`);
  return `${parts.direction}|${nodes.join(',')}|${parts.edges.join(',')}`;
}

/**
 * Decide how the viewport should react once the next layout lands.
 * Same node ids, same edges, same direction ⇒ in place; `toggledId` is the
 * card the viewport should follow, or null when nothing worth following
 * moved (only gauges arrived).
 *
 * Selecting a card opens it AND closes the previously open one, so the
 * ordinary case is TWO bits flipping at once. The card to follow is the one
 * that OPENED: it is the card that just grew, the one the user asked for,
 * and the only one that can have grown out of view. Following the card that
 * closed — or giving up and following neither, which a plain "exactly one
 * changed" rule does — would leave the user's own selection off screen.
 */
export function layoutIntent(prev: LayoutParts | null, next: LayoutParts): LayoutIntent {
  if (!prev) return { kind: 'refit' };
  if (prev.direction !== next.direction) return { kind: 'refit' };
  if (prev.nodes.size !== next.nodes.size) return { kind: 'refit' };
  for (const id of next.nodes.keys()) if (!prev.nodes.has(id)) return { kind: 'refit' };
  if (prev.edges.length !== next.edges.length) return { kind: 'refit' };
  for (let i = 0; i < next.edges.length; i++) if (prev.edges[i] !== next.edges[i]) return { kind: 'refit' };

  // Only cards that OPENED are candidates. A card that closed is deliberately
  // ignored rather than counted: under selection-driven expansion one closes
  // on almost every change, and counting it would make "more than one card
  // changed" the normal case and leave the viewport following nothing.
  const opened: string[] = [];
  for (const [id, bits] of next.nodes) {
    const before = prev.nodes.get(id) ?? '';
    if (bits.charAt(0) === '1' && before.charAt(0) !== '1') opened.push(id);
  }
  return { kind: 'in-place', toggledId: opened.length === 1 ? opened[0] : null };
}

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Whether a flow-space rect is fully inside the visible pane. */
export function isRectInView(
  rect: Rect,
  viewport: { x: number; y: number; zoom: number },
  pane: { width: number; height: number },
): boolean {
  const left = rect.x * viewport.zoom + viewport.x;
  const top = rect.y * viewport.zoom + viewport.y;
  const right = left + rect.width * viewport.zoom;
  const bottom = top + rect.height * viewport.zoom;
  return left >= 0 && top >= 0 && right <= pane.width && bottom <= pane.height;
}

/**
 * Whether a pod stays on the map while the Traffic filter is on. The filter
 * hides pods that have no flows, but a pod with compute gauges (or an
 * active contention edge) is still worth a card: the kguardian namespace
 * itself, or any excluded namespace, has no traffic by design yet its CPU
 * and memory matter.
 */
export function keepOnMap<C>(
  pod: { id: string; traffic?: readonly unknown[] | null; compute?: C },
  showTraffic: boolean,
  contentionIds: ReadonlySet<string> | null,
  hasGauges: (compute: C | undefined) => boolean,
): boolean {
  if (!showTraffic) return true;
  if (pod.traffic && pod.traffic.length > 0) return true;
  if (contentionIds?.has(pod.id)) return true;
  return hasGauges(pod.compute);
}

/**
 * Combine the intent already waiting for a layout that has not landed with
 * the intent of a newer signature change. A pending `refit` is sticky: a
 * gauge tick that flips the compute bit on every card while a namespace
 * switch's ELK run is in flight must not downgrade that switch to "in
 * place", or the new namespace would never be fitted. `null` means the last
 * intent was consumed (acted on), so the newer one stands on its own.
 */
export function mergeLayoutIntent(pending: LayoutIntent | null, next: LayoutIntent): LayoutIntent {
  if (pending?.kind === 'refit') return pending;
  return next;
}
