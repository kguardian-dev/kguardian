import type { PodNodeData } from '../types';
import { isDaemonSetOrHostNetworkPod } from '../utils/daemonSetPeers';

/** What PodNode receives as `data`: the graph node plus the layout extras. */
export type PodNodeRenderData = PodNodeData & {
  layoutDirection?: 'LR' | 'TB';
  onBuildPolicy?: (pod: PodNodeData) => void;
};

/** Total syscalls across the comma-separated records — what the card shows. */
export function countSyscalls(data: Pick<PodNodeData, 'syscalls'>): number {
  return (
    data.syscalls?.reduce((total, record) => total + record.syscalls.split(',').filter((s) => s.trim()).length, 0) ?? 0
  );
}

/** The pods the card draws from: the identity group, or the primary pod alone. */
export function cardPods(data: Pick<PodNodeData, 'pod' | 'pods'>) {
  return data.pods && data.pods.length > 0 ? data.pods : [data.pod];
}

/**
 * THE list of what makes a PodNode re-render.
 *
 * PodNode is `React.memo`'d with a custom comparator because the graph
 * re-renders on every 5 s poll and usePodData hands back fresh objects each
 * time; comparing whole objects would re-render every card every poll. The
 * cost of that optimisation is that a field the card renders but the
 * comparator ignores silently stops updating on poll.
 *
 * So: every `data.<field>` that PodNode.tsx reads must appear here, keyed by
 * that field name, with a probe returning a cheap value that changes exactly
 * when the rendered output would (a primitive or a stable reference), OR in
 * POD_NODE_MEMO_IGNORED with the reason. podNodeMemo.test.ts scans PodNode.tsx
 * and fails when a read field is in neither — so adding a security badge
 * field means adding one line here, and forgetting it is a test failure
 * rather than a badge that never refreshes.
 */
export const POD_NODE_MEMO_KEYS: Readonly<Record<string, (d: PodNodeRenderData) => unknown>> = {
  id: (d) => d.id,
  label: (d) => d.label,
  // Name fallback when there is no label.
  pod: (d) => `${d.pod.pod_identity ?? ''}|${d.pod.pod_name}`,
  // Replica/IP count and the DaemonSet/host-network spine colour.
  pods: (d) => `${d.pods?.length ?? 1}|${cardPods(d).some(isDaemonSetOrHostNetworkPod)}`,
  tooltip: (d) => d.tooltip,
  externalNamespace: (d) => d.externalNamespace,
  isExpanded: (d) => d.isExpanded,
  isExternal: (d) => d.isExternal,
  layoutDirection: (d) => d.layoutDirection,
  traffic: (d) => d.traffic?.length ?? 0,
  // The rendered count, not the record count: records grow in place.
  syscalls: (d) => countSyscalls(d),
  // A new compute object arrives with every poll; identity is the cheapest
  // correct signal (usePodData builds a fresh one per gauged pod).
  compute: (d) => d.compute,
  // Lens badge: every field renders (text on the card, label as tooltip).
  lensBadge: (d) => (d.lensBadge ? `${d.lensBadge.lens}|${d.lensBadge.tone}|${d.lensBadge.text}|${d.lensBadge.label}` : undefined),
};

/** Fields PodNode reads that deliberately do NOT trigger a re-render. */
export const POD_NODE_MEMO_IGNORED: Readonly<Record<string, string>> = {
  onBuildPolicy:
    'Handler, not rendered state. App recreates it every render; comparing it would re-render every card on every App render.',
};

/** React.memo comparator for PodNode: true = props equal, skip the render. */
export function podNodePropsEqual(
  prev: { data: PodNodeRenderData; selected?: boolean },
  next: { data: PodNodeRenderData; selected?: boolean },
): boolean {
  if (prev.selected !== next.selected) return false;
  for (const probe of Object.values(POD_NODE_MEMO_KEYS)) {
    if (!Object.is(probe(prev.data), probe(next.data))) return false;
  }
  return true;
}
