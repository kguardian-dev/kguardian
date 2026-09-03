// External-peer nodes for the map, built from per-row peer attribution.
//
// Pure so it can be tested without ReactFlow/ELK. NetworkGraph feeds it the
// in-namespace nodes, the Service listing and the per-row resolutions from
// utils/peerResolution and renders whatever comes back.
//
// The one rule this file exists to enforce: a Service is NEVER derived from
// a raw peer IP. A row joins a Service node only when resolvePeer accepted
// its peer (a stored identity, or a by-IP candidate that passed the
// start-time guard) AND that pod is a backend of the Service, or when the
// row's peer IS the ClusterIP. A row resolvePeer left unattributed stays
// unattributed even if a backend of some Service holds the IP today — that
// was exactly the autobrr → cmangos-database ghost edge on cluster-00.

import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';
import {
  UNATTRIBUTED_LABEL,
  UNATTRIBUTED_NAMESPACE,
  UNATTRIBUTED_PEER_TOOLTIP,
  isPlaceholderPod,
  peerGroupIdentity,
  peerKey,
  type PeerResolution,
} from './peerResolution';

export interface ExternalNodesInput {
  /** In-namespace nodes (their traffic rows are what gets attributed). */
  pods: readonly PodNodeData[];
  services: readonly ServiceInfo[];
  /** Per-row resolution (utils/peerResolution `resolvePeer`). */
  rowPeers: ReadonlyMap<NetworkTraffic, PeerResolution>;
  /** In-namespace node by pod name — a peer that is local is an edge, not an external node. */
  localPodByName: ReadonlyMap<string, PodNodeData>;
  /** ClusterIP → in-namespace node the Service selects (an edge, not an external node). */
  svcIpToLocalPod: ReadonlyMap<string, PodNodeData>;
  /** Backing pod NAME → ClusterIP of the Service selecting it. */
  podNameToSvcIp: ReadonlyMap<string, string>;
  /** Current pod record by IP — only to decorate synthetic Service members. */
  ipToAllPods: ReadonlyMap<string, PodInfo>;
}

/** `svc:<ns>/<name>` — the peer key a Service node answers for. */
export const serviceKey = (svc: ServiceInfo): string => `svc:${svc.svc_namespace ?? ''}/${svc.svc_name ?? svc.svc_ip}`;

export function buildExternalNodes(input: ExternalNodesInput): PodNodeData[] {
  const { pods, services, rowPeers, localPodByName, svcIpToLocalPod, podNameToSvcIp, ipToAllPods } = input;

  const svcByIp = new Map<string, ServiceInfo>();
  services.forEach((svc) => { if (svc.svc_ip) svcByIp.set(svc.svc_ip, svc); });

  // Step 1: classify each row by its RESOLVED peer. Entries are keyed by the
  // peer key (pod, Service, unattributed) or, for a truly unknown IP, by the
  // IP — so rows from one IP that changed hands land in different entries.
  interface Entry {
    podInfo: PodInfo | null;
    svc: ServiceInfo | null;
    ip: string;
    stored: boolean;
    unattributed: boolean;
    ingressTraffic: NetworkTraffic[];
    egressTraffic: NetworkTraffic[];
  }
  const entries = new Map<string, Entry>();
  const entry = (key: string, init: Omit<Entry, 'ingressTraffic' | 'egressTraffic'>): Entry => {
    let e = entries.get(key);
    if (!e) {
      e = { ...init, ingressTraffic: [], egressTraffic: [] };
      entries.set(key, e);
    }
    return e;
  };

  pods.forEach((pod) => {
    pod.traffic?.forEach((traffic) => {
      const remoteIp = traffic.traffic_in_out_ip;
      if (!remoteIp) return;
      const peer = rowPeers.get(traffic) ?? { kind: 'unknown' as const };

      let e: Entry;
      if ((peer.kind === 'pod' || peer.kind === 'node') && !isPlaceholderPod(peer.pod)) {
        // In-namespace peer: an edge, not an external node.
        if (localPodByName.has(peer.pod.pod_name)) return;
        e = entry(peerKey(peer)!, { podInfo: peer.pod, svc: null, ip: remoteIp, stored: peer.stored, unattributed: false });
      } else if (peer.kind === 'service' && peer.svc) {
        // The row's peer IS a ClusterIP (stored, or a by-IP ClusterIP match).
        const svcIp = peer.svc.svc_ip;
        if (svcIpToLocalPod.has(svcIp)) return;
        e = entry(serviceKey(peer.svc), { podInfo: null, svc: peer.svc, ip: svcIp, stored: peer.stored, unattributed: false });
      } else if (peer.kind === 'unknown') {
        // No pod ever held the IP and it is no ClusterIP: Internet.
        e = entry(`ip:${remoteIp}`, { podInfo: null, svc: null, ip: remoteIp, stored: false, unattributed: false });
      } else {
        // Guarded out, a stored pod whose record is gone, or a stored Service
        // that no longer fronts the IP: the Unattributed node — the same peer
        // the generators render as an ipBlock. Never re-derived from the IP.
        e = entry(`unattributed:${remoteIp}`, { podInfo: null, svc: null, ip: remoteIp, stored: false, unattributed: true });
      }

      const trafficType = traffic.traffic_type?.toLowerCase();
      if (trafficType === 'ingress') e.ingressTraffic.push(traffic);
      else if (trafficType === 'egress') e.egressTraffic.push(traffic);
    });
  });

  // Step 2: merge ACCEPTED pod peers that back a Service into that Service's
  // entry, so curl→ClusterIP and curl→backing-pod-IP produce one node (and
  // one edge). Matched by pod NAME — the pod resolvePeer chose — never by IP.
  const mergedBackingIps = new Map<string, string[]>(); // svc key → [backing IP, ...]
  const mergedPeerKeys = new Map<string, string[]>(); // svc key → [pod peer key, ...]
  const toMerge: Array<[string, ServiceInfo]> = [];
  entries.forEach((e, key) => {
    if (!e.podInfo) return;
    const svcIp = podNameToSvcIp.get(e.podInfo.pod_name);
    const svc = svcIp ? svcByIp.get(svcIp) : undefined;
    if (svc) toMerge.push([key, svc]);
  });
  toMerge.forEach(([key, svc]) => {
    const e = entries.get(key)!;
    const target = entry(serviceKey(svc), { podInfo: null, svc, ip: svc.svc_ip, stored: false, unattributed: false });
    target.ingressTraffic.push(...e.ingressTraffic);
    target.egressTraffic.push(...e.egressTraffic);
    entries.delete(key);
    const sk = serviceKey(svc);
    if (!mergedBackingIps.has(sk)) mergedBackingIps.set(sk, []);
    mergedBackingIps.get(sk)!.push(e.ip);
    if (!mergedPeerKeys.has(sk)) mergedPeerKeys.set(sk, []);
    mergedPeerKeys.get(sk)!.push(key);
  });

  // Step 3: group by identity, tracking direction-specific traffic
  interface IdentityGroup {
    memberPods: PodInfo[];
    peerKeys: Set<string>;
    ingressTraffic: NetworkTraffic[];
    egressTraffic: NetworkTraffic[];
  }
  const identityMap = new Map<string, IdentityGroup>();
  const group = (key: string): IdentityGroup => {
    let g = identityMap.get(key);
    if (!g) {
      g = { memberPods: [], peerKeys: new Set(), ingressTraffic: [], egressTraffic: [] };
      identityMap.set(key, g);
    }
    return g;
  };
  const internetEntries: { pod: PodInfo; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];
  const unattributedEntries: { pod: PodInfo; peerKey: string; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];

  entries.forEach((ext, entryKey) => {
    if (ext.unattributed) {
      unattributedEntries.push({
        pod: { pod_name: ext.ip, pod_ip: ext.ip, pod_namespace: UNATTRIBUTED_NAMESPACE, time_stamp: '', node_name: '', is_dead: false },
        peerKey: entryKey,
        ingressTraffic: ext.ingressTraffic,
        egressTraffic: ext.egressTraffic,
      });
      return;
    }

    if (ext.svc) {
      const svc = ext.svc;
      const ns = svc.svc_namespace || 'unknown';
      const name = svc.svc_name || ext.ip;
      const g = group(`external-svc-${ns}-${name}`);
      g.peerKeys.add(entryKey);
      mergedPeerKeys.get(entryKey)?.forEach((k) => g.peerKeys.add(k));
      const backingIps = mergedBackingIps.get(entryKey) || [];
      if (backingIps.length > 0) {
        // Use only the real backing pod IPs so the pod count reflects actual pods.
        // The service ClusterIP is a virtual IP and should not count as a pod.
        backingIps.forEach((backingIp) => {
          // Carry the backing pod's workload facts onto the synthetic member so
          // the DaemonSets toggle can recognise a Service fronting a DaemonSet or
          // host-network pods (node-exporter, CSI node plugins, ...).
          const known = ipToAllPods.get(backingIp);
          g.memberPods.push({
            pod_name: name,
            pod_ip: backingIp,
            pod_namespace: ns,
            pod_identity: name,
            time_stamp: '',
            node_name: known?.node_name ?? '',
            is_dead: false,
            workload_kind: known?.workload_kind ?? null,
            workload_name: known?.workload_name ?? null,
            host_network: known?.host_network ?? null,
          });
        });
      } else if (ext.ip) {
        // No backing pods known — the ClusterIP stands in so the node still renders.
        g.memberPods.push({ pod_name: name, pod_ip: ext.ip, pod_namespace: ns, pod_identity: name, time_stamp: '', node_name: '', is_dead: false });
      }
      g.ingressTraffic.push(...ext.ingressTraffic);
      g.egressTraffic.push(...ext.egressTraffic);
      return;
    }

    // Cross-namespace pod — grouped by identity (Job/CronJob pods under
    // their workload). A peer the broker stamped on the row renders even
    // when that pod is dead now: the identity was captured when the flow
    // happened, and a finished Job is a real peer a policy must allow.
    if (ext.podInfo && (ext.stored || !ext.podInfo.is_dead)) {
      const ns = ext.podInfo.pod_namespace || 'unknown';
      const g = group(`external-${ns}-${peerGroupIdentity(ext.podInfo)}`);
      g.memberPods.push(ext.podInfo);
      g.peerKeys.add(entryKey);
      g.ingressTraffic.push(...ext.ingressTraffic);
      g.egressTraffic.push(...ext.egressTraffic);
      return;
    }

    // Dead pod chosen by IP — legacy history; skip entirely
    if (ext.podInfo && ext.podInfo.is_dead) return;

    // Truly external IP — aggregate into "Internet"
    internetEntries.push({
      pod: { pod_name: ext.ip, pod_ip: ext.ip, pod_namespace: 'internet', time_stamp: '', node_name: '', is_dead: false },
      ingressTraffic: ext.ingressTraffic,
      egressTraffic: ext.egressTraffic,
    });
  });

  // Step 4: directional nodes — ingress (-in) and egress (-out)
  const out: PodNodeData[] = [];
  const addDirectionalNodes = (
    key: string,
    label: string,
    memberPods: PodInfo[],
    ingressTraffic: NetworkTraffic[],
    egressTraffic: NetworkTraffic[],
    externalNamespace: string,
    extra: Pick<PodNodeData, 'peerKeys' | 'tooltip'> = {},
  ) => {
    const primary = memberPods[0];
    const base = { label, pod: primary, pods: memberPods, isExpanded: false, isExternal: true, externalNamespace, ...extra };
    if (ingressTraffic.length > 0) out.push({ id: `${key}-in`, traffic: ingressTraffic, ...base });
    if (egressTraffic.length > 0) out.push({ id: `${key}-out`, traffic: egressTraffic, ...base });
  };

  identityMap.forEach((g, key) => {
    const primary = g.memberPods[0];
    addDirectionalNodes(
      key,
      key.startsWith('external-svc-') ? primary.pod_identity || primary.pod_name : peerGroupIdentity(primary),
      g.memberPods, g.ingressTraffic, g.egressTraffic, primary.pod_namespace || 'unknown',
      { peerKeys: Array.from(g.peerKeys) },
    );
  });

  if (unattributedEntries.length > 0) {
    addDirectionalNodes(
      'external-unattributed', UNATTRIBUTED_LABEL,
      unattributedEntries.map((e) => e.pod),
      unattributedEntries.flatMap((e) => e.ingressTraffic),
      unattributedEntries.flatMap((e) => e.egressTraffic),
      UNATTRIBUTED_NAMESPACE,
      { peerKeys: unattributedEntries.map((e) => e.peerKey), tooltip: UNATTRIBUTED_PEER_TOOLTIP },
    );
  }

  if (internetEntries.length > 0) {
    addDirectionalNodes(
      'external-internet', 'Internet',
      internetEntries.map((e) => e.pod),
      internetEntries.flatMap((e) => e.ingressTraffic),
      internetEntries.flatMap((e) => e.egressTraffic),
      'internet',
      { peerKeys: internetEntries.map((e) => `ip:${e.pod.pod_ip}`) },
    );
  }

  return out;
}

/**
 * The map node a row's peer connects to: the local node by pod NAME, else
 * the external node answering for the row's peer key. Nothing is looked up
 * by IP. `byKey` is the direction-specific index of external nodes' `peerKeys`.
 */
export function remoteNodeForRow(
  traffic: NetworkTraffic,
  rowPeers: ReadonlyMap<NetworkTraffic, PeerResolution>,
  localPodByName: ReadonlyMap<string, PodNodeData>,
  svcIpToLocalPod: ReadonlyMap<string, PodNodeData>,
  byKey: ReadonlyMap<string, PodNodeData>,
): PodNodeData | undefined {
  const remoteIp = traffic.traffic_in_out_ip;
  if (!remoteIp) return undefined;
  const peer = rowPeers.get(traffic) ?? { kind: 'unknown' as const };
  switch (peer.kind) {
    case 'pod':
    case 'node':
      if (isPlaceholderPod(peer.pod)) return byKey.get(`unattributed:${remoteIp}`);
      return localPodByName.get(peer.pod.pod_name) || byKey.get(peerKey(peer)!);
    case 'service':
      if (!peer.svc) return byKey.get(`unattributed:${remoteIp}`);
      return svcIpToLocalPod.get(peer.svc.svc_ip) || byKey.get(serviceKey(peer.svc));
    case 'unattributed':
      return byKey.get(`unattributed:${remoteIp}`);
    case 'unknown':
      return byKey.get(`ip:${remoteIp}`);
  }
}
