// Host-network handling shared by the standard (networkPolicyGenerator) and
// Cilium (ciliumPolicyGenerator) policy builders.
//
// A pod with `spec.hostNetwork: true` has no netns of its own: its IP IS the
// node IP, and the CNI sees its traffic as node (host) identity, not pod
// identity. Two consequences for generated policy:
//
//  1. A PEER that resolves to a host-network pod cannot be matched by a
//     podSelector — the packets carry the node's identity. The standard
//     generator emits an ipBlock for the observed node IP instead; the Cilium
//     generator emits `fromEntities`/`toEntities: [host, remote-node]` (both,
//     because the peer may sit on the local node or a remote one).
//  2. A TARGET that is host-network cannot be selected at all by a namespaced
//     NetworkPolicy / CiliumNetworkPolicy. The policy is still emitted, with a
//     leading warning block, so the user is not handed a silently inert rule.
//
// Text here must stay byte-identical to llm-bridge and the advisor: the
// fixture tests compare the emitted comment lines.

import type { PodInfo, PodNodeData } from '../types';

/** `pod_obj.spec.nodeName` when the stored manifest carries it. */
export function specNodeName(pod: PodInfo): string | undefined {
  const spec = pod.pod_obj?.spec as { nodeName?: unknown } | undefined;
  return typeof spec?.nodeName === 'string' && spec.nodeName ? spec.nodeName : undefined;
}

/** Cilium entities that cover a host-network peer on any node. */
export const HOST_NETWORK_ENTITIES: readonly string[] = ['host', 'remote-node'];

/** Which policy kind is being explained — drives the selector wording. */
export type HostNetworkPolicyKind = 'standard' | 'cilium';

const SELECTOR_WORD: Record<HostNetworkPolicyKind, string> = {
  standard: 'podSelector',
  cilium: 'endpointSelector',
};

/**
 * The `# ...` line placed above a rule whose peer is a host-network pod.
 * `name` is the owning workload when known, else the pod name.
 */
export function hostNetworkPeerComment(
  kind: HostNetworkPolicyKind,
  namespace: string,
  name: string,
  node: string,
): string {
  return `host-network peer ${namespace}/${name} on node ${node} — ${SELECTOR_WORD[kind]} cannot match host traffic`;
}

/**
 * The rule comment for a Service whose backing pods are host-network. The
 * Service is named `<ns>/svc/<name>`; the node is the sorted, deduplicated
 * node list of those backends (a ClusterIP has no single node), falling back
 * to the observed IP. Mirrors the advisor's hostNetworkServiceComment.
 */
export function hostNetworkServiceComment(
  kind: HostNetworkPolicyKind,
  namespace: string,
  svcName: string,
  backends: readonly PodInfo[],
  peerIP: string,
): string {
  const nodes = Array.from(
    new Set(backends.map((p) => p.node_name || specNodeName(p) || '').filter((n) => n !== '')),
  ).sort();
  const node = nodes.length > 0 ? nodes.join(',') : peerIP;
  return `host-network peer ${namespace}/svc/${svcName} on node ${node} — ${SELECTOR_WORD[kind]} cannot match host traffic`;
}

/** `labels` carries every key/value of `selector`. */
export function labelsContain(labels: Record<string, string> | undefined, selector: Record<string, string>): boolean {
  if (!labels) return false;
  return Object.entries(selector).every(([k, v]) => labels[k] === v);
}

/**
 * The host-network pods backing a Service: alive pods in the Service's
 * namespace whose labels contain the whole selector, sorted by name. Empty
 * when the Service has no selector, no such pods, or NONE of them is
 * host-network. `pods` null means the listing failed — treated as unknown,
 * i.e. the pre-existing podSelector rendering.
 */
export function hostNetworkServiceBackends(
  pods: readonly PodInfo[] | null,
  svcNamespace: string | undefined,
  selector: Record<string, string> | undefined,
): PodInfo[] {
  if (!pods || !svcNamespace || !selector || Object.keys(selector).length === 0) return [];
  return pods
    .filter((p) => !p.is_dead && p.pod_namespace === svcNamespace && p.host_network === true)
    .filter((p) => labelsContain(p.pod_obj?.metadata?.labels, selector))
    .sort((a, b) => (a.pod_name < b.pod_name ? -1 : a.pod_name > b.pod_name ? 1 : 0));
}

/**
 * Leading warning block for a policy whose TARGET workload is host-network.
 * Line breaks are fixed (not re-flowed) so the three generators emit the
 * same bytes.
 */
export function hostNetworkTargetWarning(kind: HostNetworkPolicyKind, namespace: string, workload: string): string[] {
  const selector = kind === 'cilium' ? 'CiliumNetworkPolicy endpointSelector' : 'NetworkPolicy podSelector';
  return [
    `WARNING: ${namespace}/${workload} runs with hostNetwork: true. A ${selector} cannot select`,
    'host-network pods; this policy will have no effect. Use a CiliumClusterwideNetworkPolicy',
    'with a nodeSelector (host firewall) instead.',
  ];
}

/** The name a host-network target is reported under: its workload when known. */
export function hostNetworkTargetName(pod: PodNodeData): string {
  return pod.pod.workload_name || pod.pod.pod_identity || pod.pod.pod_name;
}

/**
 * Whether the policy target runs with hostNetwork. An identity group may hold
 * several pods; any one of them being host-network means the podSelector is
 * inert for it. null/absent (old broker) is NOT host-network.
 *
 * The group-wide check is a frontend-only notion (advisor/llm-bridge take a
 * single pod): mid-rollout, when a workload's hostNetwork flag has flipped and
 * old and new pods coexist, the warning must still fire rather than silently
 * produce a policy that is ineffective for half the group.
 */
export function isHostNetworkTarget(pod: PodNodeData): boolean {
  if (pod.pod.host_network === true) return true;
  return Array.isArray(pod.pods) && pod.pods.some((p) => p?.host_network === true);
}

/** Render a list of comment lines as YAML `# ` lines at the given indent. */
export function yamlComments(lines: readonly string[] | undefined, indent = ''): string[] {
  if (!lines || lines.length === 0) return [];
  return lines.map((l) => `${indent}# ${l}`);
}
