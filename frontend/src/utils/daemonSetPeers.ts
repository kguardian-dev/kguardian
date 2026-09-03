import type { PodInfo, PodNodeData } from '../types';

// "DaemonSets" map toggle.
//
// Since the controller began recording pod→node-IP traffic (#1431), almost
// every pod in every namespace has node-exporter, the CNI agent, CSI node
// plugins and friends as peers. They are real traffic — the policy
// generators MUST keep them — but on the map they are noise that hides the
// workload-to-workload picture, so they are hidden by default. Only external
// (cross-namespace) peers are ever hidden: the selected namespace's own
// workloads always render, as does the focused or selected node.

/** A pod that belongs to a DaemonSet or shares the node's network. */
export function isDaemonSetOrHostNetworkPod(p: PodInfo | undefined | null): boolean {
  if (!p) return false;
  return p.workload_kind === 'DaemonSet' || p.host_network === true;
}

/**
 * Whether a graph node is a DaemonSet / host-network PEER. In-namespace
 * workloads (`isExternal` false), the Internet node and Service nodes with
 * synthetic member pods never qualify.
 */
export function isDaemonSetPeer(node: PodNodeData): boolean {
  if (!node.isExternal) return false;
  const members = node.pods && node.pods.length > 0 ? node.pods : [node.pod];
  return members.some(isDaemonSetOrHostNetworkPod);
}

export interface DaemonSetPartition {
  visible: PodNodeData[];
  hidden: PodNodeData[];
}

/**
 * Split external peers into the ones to render and the ones the toggle
 * hides. `focusedId` / `selectedId` are never hidden: hiding the node the
 * user just focused or clicked would make the map contradict the URL.
 */
export function partitionDaemonSetPeers(
  externalNodes: readonly PodNodeData[],
  opts: { show: boolean; focusedId: string | null; selectedId: string | null },
): DaemonSetPartition {
  if (opts.show) return { visible: [...externalNodes], hidden: [] };
  const visible: PodNodeData[] = [];
  const hidden: PodNodeData[] = [];
  for (const node of externalNodes) {
    const pinned = node.id === opts.focusedId || node.id === opts.selectedId;
    if (!pinned && isDaemonSetPeer(node)) hidden.push(node);
    else visible.push(node);
  }
  return { visible, hidden };
}

/**
 * A shared `?focus=` link pointing at a DaemonSet peer should reveal that
 * peer's whole class, not just the one node the pin exception keeps: flip the
 * toggle on. Returns true exactly when the caller should turn it on.
 */
export function shouldAutoShowDaemonSets(
  focusedId: string | null,
  externalNodes: readonly PodNodeData[],
  show: boolean,
): boolean {
  if (show || !focusedId) return false;
  return externalNodes.some((n) => n.id === focusedId && isDaemonSetPeer(n));
}
