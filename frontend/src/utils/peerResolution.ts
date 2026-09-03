// Peer attribution for traffic rows — shared by the map (NetworkGraph,
// DataTable) and both policy generators.
//
// A traffic row records only the peer's IP, and pod IPs are recycled
// constantly (hourly volsync Jobs, migration Jobs — one IP on cluster-00 had
// 50+ dead owners). Looking the IP up at READ time therefore attributes old
// flows to whichever pod holds the IP NOW: `cmangos-database` had ingress
// rows from 10.244.12.199 dated May and July; `autobrr` took that IP on
// 2026-08-04 and the map drew autobrr → cmangos-database.
//
// Two rules fix this, in order of preference:
//
//  1. Stored identity wins. Since v4 the broker resolves the peer when the
//     row is ingested and persists it on the row (`peer_kind`, `peer_name`,
//     ...). Like Cilium Hubble's flow.proto Endpoint, that identity is
//     stamped at capture time and never recomputed from the IP.
//  2. By-IP fallback is guarded by the flow time. For a row with no stored
//     peer (legacy rows; the broker could not resolve it), a pod may only be
//     chosen if its start is KNOWN and not after the flow — a pod that did
//     not exist yet cannot have been the peer, and a record with no
//     `started_at` is a ghost or a Pending pod (every live pod gets its
//     start within a minute of the broker upgrade), which on cluster-00
//     absorbed months of old flows. When the guard excludes every candidate
//     the peer is "unattributed": a former holder of the IP the cluster no
//     longer knows. It renders as an IP node / ipBlock and never as a pod
//     selector.
//
// The guard runs here, client-side, regardless of whether the broker also
// applies it (`GET /pod/ip/{ip}?at=`): a broker predating `?at=` returns
// the current holder for any `at`, and the frontend must still not draw it.
//
// Precedence among surviving candidates mirrors the broker's resolver
// (scratchpad/broker-api-v4.md): alive before dead, then newest
// `started_at`, then newest record, then `<ns>/<name>`. The same algorithm
// runs in llm-bridge (`resolvePeerRow`) and the advisor
// (`pkg/network/peer.go`); the goldens in test/fixtures/generators/
// networkpolicy pin all three.

import type { NetworkTraffic, PodInfo, ServiceInfo } from '../types';

/** Tooltip for the map node that aggregates guarded-out peers. */
export const UNATTRIBUTED_PEER_TOOLTIP = 'former holder of this IP; no live pod matched at flow time';

/** `externalNamespace` of the map's Unattributed node (like 'internet'). */
export const UNATTRIBUTED_NAMESPACE = 'unattributed';

/** Label of the map's Unattributed node. */
export const UNATTRIBUTED_LABEL = 'Unattributed';

/**
 * Broker timestamps are naive UTC (`2026-08-04T09:12:41[.ffffff]`, no zone).
 * `Date.parse` would read a naive ISO string as LOCAL time, so a zone-less
 * value is pinned to UTC before parsing. RFC3339 input (with `Z` or an
 * offset) is parsed as-is. Returns epoch ms, or null when absent/unparseable.
 */
export function parseBrokerTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const s = value.trim();
  if (s === '') return null;
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(s);
  const t = Date.parse(hasZone ? s : `${s}Z`);
  return Number.isFinite(t) ? t : null;
}

/** The row carries a broker-stamped peer identity. */
export function hasStoredPeer(row: Pick<NetworkTraffic, 'peer_kind'>): boolean {
  return typeof row.peer_kind === 'string' && row.peer_kind !== '';
}

/**
 * The start-time guard. A pod may be the peer of a flow only when its
 * `started_at` is KNOWN and not later than the flow time. An unknown start
 * (NULL/absent) or an unparseable flow time disqualifies: there is nothing
 * to prove the pod existed when the flow happened.
 */
export function podEligibleAt(pod: Pick<PodInfo, 'started_at'>, flowTime: number | null): boolean {
  if (flowTime === null) return false;
  const started = parseBrokerTime(pod.started_at);
  return started !== null && started <= flowTime;
}

/** Every IP a pod record holds: `pod_ip` plus the dual-stack `pod_ips`. */
export function podAddresses(pod: PodInfo): string[] {
  const ips = new Set<string>();
  if (pod.pod_ip) ips.add(pod.pod_ip);
  if (Array.isArray(pod.pod_ips)) for (const ip of pod.pod_ips) if (ip) ips.add(ip);
  return Array.from(ips);
}

/** Lookup tables built once per pod/service listing. */
export interface PeerIndex {
  /** Every record (alive and dead) that holds the IP, before the guard. */
  podsByIp: Map<string, PodInfo[]>;
  /** By pod name — the broker keys `pod_details` on the name alone. */
  podsByName: Map<string, PodInfo>;
  /** By `<namespace>/<name>`. */
  podsByNsName: Map<string, PodInfo>;
  servicesByIp: Map<string, ServiceInfo>;
  servicesByNsName: Map<string, ServiceInfo>;
  pods: readonly PodInfo[];
}

export function buildPeerIndex(pods: readonly PodInfo[] | null | undefined, services: readonly ServiceInfo[] = []): PeerIndex {
  const index: PeerIndex = {
    podsByIp: new Map(),
    podsByName: new Map(),
    podsByNsName: new Map(),
    servicesByIp: new Map(),
    servicesByNsName: new Map(),
    pods: pods ?? [],
  };
  for (const pod of index.pods) {
    if (!pod?.pod_name) continue;
    for (const ip of podAddresses(pod)) {
      const list = index.podsByIp.get(ip);
      if (list) list.push(pod); else index.podsByIp.set(ip, [pod]);
    }
    index.podsByName.set(pod.pod_name, pod);
    index.podsByNsName.set(`${pod.pod_namespace ?? ''}/${pod.pod_name}`, pod);
  }
  for (const svc of services) {
    if (svc.svc_ip) index.servicesByIp.set(svc.svc_ip, svc);
    if (svc.svc_name) index.servicesByNsName.set(`${svc.svc_namespace ?? ''}/${svc.svc_name}`, svc);
  }
  return index;
}

/**
 * Order candidates the way the broker does: alive first; then newest
 * `started_at` (unknown last — such records never pass the guard, this only
 * keeps the order total); then newest record `time_stamp`; then
 * `<ns>/<name>`.
 */
export function rankPods(pods: readonly PodInfo[]): PodInfo[] {
  return [...pods].sort((a, b) => {
    if (a.is_dead !== b.is_dead) return a.is_dead ? 1 : -1;
    const sa = parseBrokerTime(a.started_at);
    const sb = parseBrokerTime(b.started_at);
    if (sa !== sb) {
      if (sa === null) return 1;
      if (sb === null) return -1;
      return sb - sa;
    }
    const ta = parseBrokerTime(a.time_stamp);
    const tb = parseBrokerTime(b.time_stamp);
    if (ta !== tb) {
      if (ta === null) return 1;
      if (tb === null) return -1;
      return tb - ta;
    }
    const na = `${a.pod_namespace ?? ''}/${a.pod_name}`;
    const nb = `${b.pod_namespace ?? ''}/${b.pod_name}`;
    return na < nb ? -1 : na > nb ? 1 : 0;
  });
}

export interface ByIpSelection {
  /** The chosen pod, or null when nothing survives the guard. */
  pod: PodInfo | null;
  /** True when candidates existed but the guard excluded every one. */
  guardedOut: boolean;
}

/**
 * Pick the pod that held an IP at `flowTime` from the records that hold it
 * now or held it once: only candidates with a known start not after the
 * flow qualify (`podEligibleAt`); none ⇒ guarded out.
 */
export function selectPodByIp(candidates: readonly PodInfo[] | undefined, flowTime: number | null): ByIpSelection {
  if (!candidates || candidates.length === 0) return { pod: null, guardedOut: false };
  const eligible = candidates.filter((p) => podEligibleAt(p, flowTime));
  if (eligible.length === 0) return { pod: null, guardedOut: true };
  return { pod: rankPods(eligible)[0], guardedOut: false };
}

/** A pod record synthesised from a row's stored peer fields. */
export type PlaceholderPod = PodInfo & { placeholder: true };

/**
 * Stand-in record for a stored peer whose `pod_details` row is gone
 * (retention pruned it) or whose uid no longer matches. It keeps the stored
 * identity for inspection but is flagged so every consumer — map, DataTable
 * and both generators — renders it as UNATTRIBUTED (no labels, no node of
 * its own, never a selector).
 */
export function placeholderPod(row: NetworkTraffic): PlaceholderPod {
  return {
    pod_name: row.peer_name ?? '',
    pod_ip: row.traffic_in_out_ip ?? '',
    pod_namespace: row.peer_namespace ?? null,
    time_stamp: row.time_stamp,
    node_name: '',
    is_dead: true,
    pod_identity: null,
    workload_selector_labels: null,
    workload_kind: row.peer_workload_kind ?? null,
    workload_name: row.peer_workload_name ?? null,
    host_network: row.peer_kind === 'node' ? true : null,
    started_at: null,
    placeholder: true,
  };
}

export function isPlaceholderPod(pod: PodInfo): pod is PlaceholderPod {
  return (pod as PlaceholderPod).placeholder === true;
}

export type PeerResolution =
  /** A pod-network pod (`peer_kind` pod, or the guarded by-IP choice). */
  | { kind: 'pod'; pod: PodInfo; stored: boolean }
  /** A host-network pod: the IP is a node IP (`peer_kind` node, or a by-IP
   *  choice whose record says host_network). */
  | { kind: 'node'; pod: PodInfo; stored: boolean }
  /** A Service ClusterIP the broker stamped. `svc` is the current Service
   *  of that namespace/name when the listing has it WITH a selector; null
   *  means the Service is gone or a recycled ClusterIP now names another
   *  Service — consumers render that as unattributed. */
  | { kind: 'service'; namespace: string | null; name: string | null; svc: ServiceInfo | null; stored: true }
  /** No stored peer and the guard excluded every pod that ever held the IP. */
  | { kind: 'unattributed'; ip: string; at: string }
  /** No stored peer, no pod ever held the IP: the caller's pre-v4 path
   *  (Service by IP, else external). */
  | { kind: 'unknown' };

/** `pod_obj.metadata.uid` when the stored manifest carries it. */
export function podUid(pod: PodInfo): string | undefined {
  const uid = pod.pod_obj?.metadata?.uid;
  return typeof uid === 'string' && uid !== '' ? uid : undefined;
}

/** `service_spec.spec.selector` when non-empty. */
export function serviceSelector(svc: ServiceInfo): Record<string, string> | undefined {
  const spec = (svc.service_spec as Record<string, unknown> | undefined)?.spec as Record<string, unknown> | undefined;
  const selector = spec?.selector as Record<string, string> | undefined;
  return selector && Object.keys(selector).length > 0 ? selector : undefined;
}

/**
 * Attribute one traffic row. Stored identity is used verbatim when present
 * (`peer_kind` pod/node/service) — the IP is never looked up for it;
 * otherwise the by-IP fallback runs under the start-time guard.
 *
 * A stored pod is matched in the listing by (namespace, name); when both
 * the record and the row carry a uid they must agree. No match ⇒ a
 * placeholder (see `placeholderPod`). A stored Service must still exist
 * under that namespace/name with a selector, else `svc` is null.
 */
export function resolvePeer(row: NetworkTraffic, index: PeerIndex): PeerResolution {
  const ip = row.traffic_in_out_ip;

  if (hasStoredPeer(row)) {
    const kind = row.peer_kind;
    if ((kind === 'pod' || kind === 'node') && row.peer_name) {
      const record = index.podsByNsName.get(`${row.peer_namespace ?? ''}/${row.peer_name}`);
      const uid = record ? podUid(record) : undefined;
      const uidMatches = !record || !uid || !row.peer_uid || uid === row.peer_uid;
      const pod = record && uidMatches ? record : placeholderPod(row);
      return { kind, pod, stored: true };
    }
    if (kind === 'service') {
      const svc = row.peer_name ? index.servicesByNsName.get(`${row.peer_namespace ?? ''}/${row.peer_name}`) : undefined;
      return {
        kind: 'service',
        namespace: row.peer_namespace ?? null,
        name: row.peer_name ?? null,
        svc: svc && serviceSelector(svc) ? svc : null,
        stored: true,
      };
    }
    // Unknown peer_kind from a newer broker, or a stored kind without a
    // name: fall through to the guarded by-IP path.
  }

  if (!ip) return { kind: 'unknown' };
  const { pod, guardedOut } = selectPodByIp(index.podsByIp.get(ip), parseBrokerTime(row.time_stamp));
  if (pod) return { kind: pod.host_network === true ? 'node' : 'pod', pod, stored: false };
  if (guardedOut) return { kind: 'unattributed', ip, at: row.time_stamp };
  return { kind: 'unknown' };
}

/**
 * Stable key naming the peer a row resolved to, independent of the IP: two
 * rows from the same IP months apart resolve to different keys when the IP
 * changed hands. `null` for the by-IP kinds (service / unknown), which the
 * callers keep keying on the IP as before.
 */
export function peerKey(peer: PeerResolution): string | null {
  switch (peer.kind) {
    case 'pod':
    case 'node':
      // A stored peer whose record is gone is rendered unattributed
      // everywhere (map and generators agree), so it keys like one.
      if (isPlaceholderPod(peer.pod)) return `unattributed:${peer.pod.pod_ip}`;
      return `pod:${peer.pod.pod_namespace ?? ''}/${peer.pod.pod_name}`;
    case 'unattributed':
      return `unattributed:${peer.ip}`;
    default:
      return null;
  }
}

/**
 * The name the map groups a peer pod under. Job/CronJob pods are grouped
 * under their owning workload (`peer_workload_name`) rather than by pod name
 * — every run of a CronJob is a new pod, and a node per run is noise.
 */
export function peerGroupIdentity(pod: PodInfo): string {
  const kind = pod.workload_kind ?? '';
  if ((kind === 'Job' || kind === 'CronJob') && pod.workload_name) return pod.workload_name;
  return pod.pod_identity || pod.workload_name || pod.pod_name;
}

/**
 * Selector labels for a peer pod: its workload selector labels, else its
 * pod labels. null when the record carries neither (or is a placeholder);
 * the caller must then emit an ipBlock, never a guessed selector.
 */
export function peerSelectorLabels(pod: PodInfo): Record<string, string> | null {
  if (pod.workload_selector_labels && Object.keys(pod.workload_selector_labels).length > 0) {
    return pod.workload_selector_labels;
  }
  const podLabels = pod.pod_obj?.metadata?.labels;
  if (podLabels && Object.keys(podLabels).length > 0) return podLabels;
  return null;
}
