import type { NetworkTraffic, PodInfo, ServiceInfo } from '../types';
import { apiClient } from '../services/api';
import { specNodeName } from './hostNetwork';
import {
  buildPeerIndex,
  isPlaceholderPod,
  peerSelectorLabels,
  podStartedAfter,
  parseBrokerTime,
  resolvePeer,
  serviceSelector,
  type PeerIndex,
} from './peerResolution';

export interface TrafficIdentity {
  podName?: string;
  podNamespace?: string;
  podLabels?: Record<string, string>;
  svcName?: string;
  svcNamespace?: string;
  svcSelector?: Record<string, string>;
  /** `pod.spec.hostNetwork` of the resolved pod. `true` means the peer IP is a
   *  NODE IP and no podSelector can match it; undefined when the broker did
   *  not report it (legacy) or the peer is a Service / external. */
  hostNetwork?: boolean;
  /** Node the resolved pod runs on — used only to annotate host-network peers. */
  nodeName?: string;
  /** Owning workload name (Deployment/DaemonSet/...) when the broker knows it. */
  workloadName?: string;
  /** Identity came from the row's stored `peer_*` fields (resolved by the
   *  broker at ingest), not from a by-IP lookup. */
  stored?: boolean;
  /** No pod may be selected for this row: the start-time guard excluded
   *  every pod that ever held the IP (the flow predates the current holder),
   *  or the stored peer is gone from the broker. Rendered as an ipBlock
   *  with the `unattributed peer` comment, never as a selector. `at` is the
   *  row's `time_stamp` verbatim. */
  unattributed?: { ip: string; at: string };
  isExternal: boolean;
}

function podIdentityFromRecord(podInfo: PodInfo): TrafficIdentity {
  return {
    podName: podInfo.pod_name,
    podNamespace: podInfo.pod_namespace || undefined,
    podLabels: peerSelectorLabels(podInfo) ?? undefined,
    hostNetwork: typeof podInfo.host_network === 'boolean' ? podInfo.host_network : undefined,
    nodeName: podInfo.node_name || specNodeName(podInfo) || undefined,
    workloadName: podInfo.workload_name || undefined,
    isExternal: false,
  };
}

function serviceIdentity(serviceInfo: ServiceInfo): TrafficIdentity {
  return {
    svcName: serviceInfo.svc_name ?? undefined,
    svcNamespace: serviceInfo.svc_namespace || undefined,
    svcSelector: serviceSelector(serviceInfo),
    isExternal: false,
  };
}

/**
 * By-IP resolution against the broker, following the advisor's priority:
 * Service ClusterIP, then pod, then external.
 *
 * `at` (a row's `time_stamp`) is passed to the broker as `?at=` so a broker
 * that supports it excludes pods started after the flow — and the same guard
 * is applied here on the returned record, because a broker predating `?at=`
 * ignores the parameter and returns the current holder. A guarded-out
 * result is `{ isExternal: true, unattributed }`.
 */
export async function resolveTrafficIdentity(ip: string, at?: string): Promise<TrafficIdentity> {
  if (!ip) {
    return { isExternal: true };
  }

  // Priority 1: Try to get service info from API
  try {
    const serviceInfo = await apiClient.getServiceByIP(ip);
    if (serviceInfo && serviceInfo.svc_name) {
      return serviceIdentity(serviceInfo);
    }
  } catch {
    // Service lookup failed, continue to pod lookup
  }

  // Priority 2: Try to get pod info from API (checks all namespaces)
  try {
    const podInfo = await apiClient.getPodDetailsByIP(ip, at);
    if (podInfo && podInfo.pod_name) {
      if (at !== undefined && podStartedAfter(podInfo, parseBrokerTime(at))) {
        return { isExternal: true, unattributed: { ip, at } };
      }
      return podIdentityFromRecord(podInfo);
    }
  } catch {
    // Pod lookup failed, continue to external
  }

  // Priority 3: External traffic
  return { isExternal: true };
}

/**
 * Per-row identity resolution for a policy generation.
 *
 * One `/pod/info` listing is fetched up front and every row is attributed
 * against it (utils/peerResolution): stored `peer_*` first, then the guarded
 * by-IP fallback. Service ClusterIPs are still looked up per IP
 * (`/svc/ip`), cached. When the listing is unavailable the resolver degrades
 * to `resolveTrafficIdentity(ip, row.time_stamp)` per distinct (ip, time),
 * which still applies the guard on whatever the broker returns.
 */
export interface RowIdentityResolver {
  resolve(row: NetworkTraffic): Promise<TrafficIdentity>;
  /** The listing the rows were attributed against; null when it failed. */
  pods: PodInfo[] | null;
  index: PeerIndex | null;
}

export async function createRowIdentityResolver(): Promise<RowIdentityResolver> {
  let pods: PodInfo[] | null;
  try {
    const listing = await apiClient.getAllPods();
    pods = Array.isArray(listing) && listing.length > 0 ? listing : null;
  } catch {
    pods = null;
  }
  const index = pods ? buildPeerIndex(pods) : null;

  const serviceByIp = new Map<string, Promise<ServiceInfo | null>>();
  const lookupService = (ip: string): Promise<ServiceInfo | null> => {
    let p = serviceByIp.get(ip);
    if (!p) {
      p = apiClient.getServiceByIP(ip).catch(() => null);
      serviceByIp.set(ip, p);
    }
    return p;
  };

  const byIpAt = new Map<string, Promise<TrafficIdentity>>();
  const lookupByIpAt = (ip: string, at: string): Promise<TrafficIdentity> => {
    const key = `${ip}@${at}`;
    let p = byIpAt.get(key);
    if (!p) {
      p = resolveTrafficIdentity(ip, at);
      byIpAt.set(key, p);
    }
    return p;
  };

  const resolve = async (row: NetworkTraffic): Promise<TrafficIdentity> => {
    const ip = row.traffic_in_out_ip;
    if (!ip) return { isExternal: true };

    if (!index) {
      // No listing: the broker does the by-IP work, guarded here too.
      return lookupByIpAt(ip, row.time_stamp);
    }

    const peer = resolvePeer(row, index);
    switch (peer.kind) {
      case 'pod':
      case 'node': {
        // A stored peer that is gone from the broker (or whose uid changed)
        // has nothing to select: unattributed, never re-resolved by IP.
        if (isPlaceholderPod(peer.pod)) return { isExternal: true, unattributed: { ip, at: row.time_stamp } };
        const identity = podIdentityFromRecord(peer.pod);
        if (peer.kind === 'node' && identity.hostNetwork === undefined) identity.hostNetwork = true;
        if (peer.stored) identity.stored = true;
        return identity;
      }
      case 'service': {
        // The Service of that namespace/name must still front this
        // ClusterIP with a selector (`/svc/ip`; the listing has no
        // Services). A different name on the IP means the ClusterIP was
        // recycled; gone or selector-less ⇒ unattributed.
        const svc = await lookupService(ip);
        const same = svc && svc.svc_name === peer.name && (svc.svc_namespace || undefined) === (peer.namespace || undefined);
        if (!same || !svc || !serviceSelector(svc)) return { isExternal: true, unattributed: { ip, at: row.time_stamp } };
        return { ...serviceIdentity(svc), stored: true };
      }
      case 'unattributed':
        return { isExternal: true, unattributed: { ip: peer.ip, at: peer.at } };
      case 'unknown': {
        // No pod ever held the IP: Service ClusterIP, else external.
        const svc = await lookupService(ip);
        return svc && svc.svc_name ? serviceIdentity(svc) : { isExternal: true };
      }
    }
  };

  return { resolve, pods, index };
}
