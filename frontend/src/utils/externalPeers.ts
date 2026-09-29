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
import { isPrivateAddress } from './ipCidr';
import {
  PRIVATE_LABEL,
  PRIVATE_NAMESPACE,
  PRIVATE_PEER_TOOLTIP,
  UNATTRIBUTED_LABEL,
  UNATTRIBUTED_NAMESPACE,
  UNATTRIBUTED_PEER_TOOLTIP,
  SERVICE_LOOKUP_FAILED_TOOLTIP,
  isPlaceholderPod,
  peerGroupIdentity,
  peerKey,
  rankPods,
  workloadKey,
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
  /** In-namespace node by `workloadKey` of its members (`localWorkloadIndex`) — how a
   *  stored peer whose record is gone still finds its local card. */
  localPodByWorkload: ReadonlyMap<string, PodNodeData>;
  /** ClusterIP → in-namespace node the Service selects (an edge, not an external node). */
  svcIpToLocalPod: ReadonlyMap<string, PodNodeData>;
  /** Backing pod NAME → ClusterIP of the Service selecting it. */
  podNameToSvcIp: ReadonlyMap<string, string>;
}

/** `svc:<ns>/<name>` — the peer key a Service node answers for. */
export const serviceKey = (svc: ServiceInfo): string => `svc:${svc.svc_namespace ?? ''}/${svc.svc_name ?? svc.svc_ip}`;

/** In-namespace node by the `workloadKey` of any of its member pods. */
export function localWorkloadIndex(pods: readonly PodNodeData[]): Map<string, PodNodeData> {
  const map = new Map<string, PodNodeData>();
  pods.forEach((node) => {
    [node.pod, ...(node.pods ?? [])].forEach((p) => {
      const key = workloadKey(p);
      if (key && !map.has(key)) map.set(key, node);
    });
  });
  return map;
}

/**
 * The in-namespace node a peer pod belongs to, or undefined when it is a
 * cross-namespace peer: by pod NAME in the same namespace (a StatefulSet slot
 * keeps its name across restarts, so a superseded record still lands on its
 * card), else by the stored workload (a pruned replica of a local Deployment).
 */
export function localNodeForPeer(
  pod: PodInfo,
  localPodByName: ReadonlyMap<string, PodNodeData>,
  localPodByWorkload: ReadonlyMap<string, PodNodeData>,
): PodNodeData | undefined {
  const byName = localPodByName.get(pod.pod_name);
  if (byName && byName.pod.pod_namespace === pod.pod_namespace) return byName;
  const key = workloadKey(pod);
  return key ? localPodByWorkload.get(key) : undefined;
}

/** The Unattributed node's tooltip: what its addresses are (former holders, failed Service lookups, or both). */
function unattributedTooltip(lookupFailed: readonly boolean[]): string {
  if (lookupFailed.every(Boolean)) return SERVICE_LOOKUP_FAILED_TOOLTIP;
  if (!lookupFailed.some(Boolean)) return UNATTRIBUTED_PEER_TOOLTIP;
  return `${UNATTRIBUTED_PEER_TOOLTIP}; for some addresses: ${SERVICE_LOOKUP_FAILED_TOOLTIP}`;
}

export function buildExternalNodes(input: ExternalNodesInput): PodNodeData[] {
  const { pods, services, rowPeers, localPodByName, localPodByWorkload, svcIpToLocalPod, podNameToSvcIp } = input;

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
    /** Unattributed because the Service lookup failed (no pod ever held the IP), not a former holder. */
    lookupFailed?: boolean;
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
      if (peer.kind === 'pod' || peer.kind === 'node') {
        // In-namespace peer: an edge, not an external node. A stored peer
        // whose record is gone (placeholder) keeps its stored identity and is
        // routed the same way — it is a former replica, not a bare IP.
        if (localNodeForPeer(peer.pod, localPodByName, localPodByWorkload)) return;
        e = entry(peerKey(peer)!, { podInfo: peer.pod, svc: null, ip: remoteIp, stored: peer.stored, unattributed: false });
      } else if (peer.kind === 'service' && peer.svc) {
        // The row's peer IS a ClusterIP (stored, or a by-IP ClusterIP match).
        // A stored Service that has no ClusterIP any more (headless,
        // ExternalName) keeps the observed address so its card still renders.
        const svcIp = peer.svc.svc_ip;
        if (svcIp && svcIpToLocalPod.has(svcIp)) return;
        e = entry(serviceKey(peer.svc), { podInfo: null, svc: peer.svc, ip: svcIp || remoteIp, stored: peer.stored, unattributed: false });
      } else if (peer.kind === 'unknown') {
        // No pod ever held the IP and it is no ClusterIP: Internet, or a
        // private address the cluster has no record of (split in step 3).
        e = entry(`ip:${remoteIp}`, { podInfo: null, svc: null, ip: remoteIp, stored: false, unattributed: false });
      } else {
        // Guarded out, a stored Service that no longer fronts the IP, or a
        // failed Service lookup: the Unattributed node — the same peer the
        // generators render as an ipBlock. Never re-derived from the IP.
        const lookupFailed = peer.kind === 'unattributed' && peer.reason === 'service-lookup-failed';
        e = entry(`unattributed:${remoteIp}`, { podInfo: null, svc: null, ip: remoteIp, stored: false, unattributed: true, lookupFailed });
        // A lookup-failed entry is one whose every row failed the lookup.
        if (!lookupFailed) e.lookupFailed = false;
      }

      const trafficType = traffic.traffic_type?.toLowerCase();
      if (trafficType === 'ingress') e.ingressTraffic.push(traffic);
      else if (trafficType === 'egress') e.egressTraffic.push(traffic);
    });
  });

  // Step 2: merge ACCEPTED pod peers that back a Service into that Service's
  // entry, so curl→ClusterIP and curl→backing-pod-IP produce one node (and
  // one edge). Matched by pod NAME — the pod resolvePeer chose — never by IP.
  const mergedBackingPods = new Map<string, PodInfo[]>(); // svc key → [resolved backing pod, ...]
  const mergedPeerKeys = new Map<string, string[]>(); // svc key → [pod peer key, ...]
  const merge = (key: string, svc: ServiceInfo, backing: PodInfo) => {
    const e = entries.get(key)!;
    const target = entry(serviceKey(svc), { podInfo: null, svc, ip: svc.svc_ip, stored: false, unattributed: false });
    target.ingressTraffic.push(...e.ingressTraffic);
    target.egressTraffic.push(...e.egressTraffic);
    entries.delete(key);
    const sk = serviceKey(svc);
    if (!mergedBackingPods.has(sk)) mergedBackingPods.set(sk, []);
    mergedBackingPods.get(sk)!.push(backing);
    if (!mergedPeerKeys.has(sk)) mergedPeerKeys.set(sk, []);
    mergedPeerKeys.get(sk)!.push(key);
  };
  const byName: Array<[string, ServiceInfo, PodInfo]> = [];
  const unmatchedPlaceholders: Array<[string, PodInfo]> = [];
  const svcByWorkload = new Map<string, ServiceInfo>();
  entries.forEach((e, key) => {
    const backing = e.podInfo;
    if (!backing) return;
    const svcIp = podNameToSvcIp.get(backing.pod_name);
    const candidate = svcIp ? svcByIp.get(svcIp) : undefined;
    // podNameToSvcIp is keyed by name alone; a Service only selects pods in
    // its own namespace.
    const svc = candidate && (candidate.svc_namespace ?? '') === (backing.pod_namespace ?? '') ? candidate : undefined;
    if (svc) {
      byName.push([key, svc, backing]);
      const wk = workloadKey(backing);
      if (wk && !svcByWorkload.has(wk)) svcByWorkload.set(wk, svc);
    } else if (isPlaceholderPod(backing)) {
      unmatchedPlaceholders.push([key, backing]);
    }
  });
  byName.forEach(([key, svc, backing]) => merge(key, svc, backing));
  // A gone record has no labels to match a selector; it follows the Service
  // its siblings (same stored workload) were matched to.
  unmatchedPlaceholders.forEach(([key, backing]) => {
    const wk = workloadKey(backing);
    const svc = wk ? svcByWorkload.get(wk) : undefined;
    if (svc) merge(key, svc, backing);
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
  const privateEntries: typeof internetEntries = [];
  const unattributedEntries: { pod: PodInfo; peerKey: string; lookupFailed: boolean; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];
  const placeholderEntries: Array<[string, Entry]> = [];
  const groupByWorkload = new Map<string, string>(); // workloadKey → identity group key

  entries.forEach((ext, entryKey) => {
    if (ext.unattributed) {
      unattributedEntries.push({
        pod: { pod_name: ext.ip, pod_ip: ext.ip, pod_namespace: UNATTRIBUTED_NAMESPACE, time_stamp: '', node_name: '', is_dead: false },
        peerKey: entryKey,
        lookupFailed: ext.lookupFailed === true,
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
      const backingPods = mergedBackingPods.get(entryKey) || [];
      // Members are the LIVE backing pods, so the badge counts endpoints, not
      // every record within the dead-pod window. Dead and superseded backing
      // pods keep their traffic on the card without inflating the count.
      const alive = backingPods.filter((p) => !p.is_dead);
      if (alive.length > 0) {
        alive.forEach((backing) => {
          // Carry the backing pod's workload facts onto the synthetic member so
          // the DaemonSets toggle can recognise a Service fronting a DaemonSet or
          // host-network pods (node-exporter, CSI node plugins, ...).
          //
          // Taken from the pod `resolvePeer` attributed to the flow, never from
          // an IP → pod map: pod_details keeps every pod that ever held an
          // address, so a by-IP lookup lands on an arbitrary former holder — on
          // EKS a dead node agent — and a Deployment-backed Service rendered
          // (and hid) as a DaemonSet peer (#1565).
          g.memberPods.push({
            pod_name: name,
            pod_ip: backing.pod_ip,
            pod_namespace: ns,
            pod_identity: name,
            time_stamp: '',
            node_name: backing.node_name ?? '',
            is_dead: false,
            workload_kind: backing.workload_kind ?? null,
            workload_name: backing.workload_name ?? null,
            host_network: backing.host_network ?? null,
          });
        });
      } else if (ext.ip) {
        // No live backing pod known — the ClusterIP stands in so the node still
        // renders, with the newest backing pod's workload facts (if any) so a
        // Service fronting a DaemonSet still reads as one.
        const facts = rankPods(backingPods)[0];
        g.memberPods.push({
          pod_name: name, pod_ip: ext.ip, pod_namespace: ns, pod_identity: name, time_stamp: '', node_name: '', is_dead: false,
          ...(facts ? { workload_kind: facts.workload_kind ?? null, workload_name: facts.workload_name ?? null, host_network: facts.host_network ?? null } : {}),
        });
      }
      g.ingressTraffic.push(...ext.ingressTraffic);
      g.egressTraffic.push(...ext.egressTraffic);
      return;
    }

    // A stored peer whose record is gone: grouped after the real records
    // below, so it can join its siblings' card.
    if (ext.podInfo && isPlaceholderPod(ext.podInfo)) {
      placeholderEntries.push([entryKey, ext]);
      return;
    }

    // Cross-namespace pod — grouped by identity (Job/CronJob pods under
    // their workload). A peer the broker stamped on the row renders even
    // when that pod is dead now: the identity was captured when the flow
    // happened, and a finished Job is a real peer a policy must allow.
    if (ext.podInfo && (ext.stored || !ext.podInfo.is_dead)) {
      const ns = ext.podInfo.pod_namespace || 'unknown';
      const key = `external-${ns}-${peerGroupIdentity(ext.podInfo)}`;
      const g = group(key);
      const wk = workloadKey(ext.podInfo);
      if (wk && !groupByWorkload.has(wk)) groupByWorkload.set(wk, key);
      g.memberPods.push(ext.podInfo);
      g.peerKeys.add(entryKey);
      g.ingressTraffic.push(...ext.ingressTraffic);
      g.egressTraffic.push(...ext.egressTraffic);
      return;
    }

    // Dead pod chosen by IP — legacy history; skip entirely
    if (ext.podInfo && ext.podInfo.is_dead) return;

    // Truly external IP — aggregate into "Internet", or into "Private network"
    // when the address cannot be routed on the Internet (a VPC address the
    // cluster holds no record of: a node that left, a load balancer, a VPN).
    const isPrivate = isPrivateAddress(ext.ip);
    (isPrivate ? privateEntries : internetEntries).push({
      pod: { pod_name: ext.ip, pod_ip: ext.ip, pod_namespace: isPrivate ? PRIVATE_NAMESPACE : 'internet', time_stamp: '', node_name: '', is_dead: false },
      ingressTraffic: ext.ingressTraffic,
      egressTraffic: ext.egressTraffic,
    });
  });

  // A gone record joins the card of its live siblings (same stored workload;
  // the map groups by pod_identity, which the row does not carry), else a card
  // named after the stored workload. It is not counted as a pod: only when it
  // is the sole member does it stand in so the card renders.
  placeholderEntries.forEach(([entryKey, ext]) => {
    const p = ext.podInfo!;
    const ns = p.pod_namespace || 'unknown';
    const wk = workloadKey(p);
    const g = group((wk && groupByWorkload.get(wk)) || `external-${ns}-${peerGroupIdentity(p)}`);
    if (g.memberPods.length === 0) g.memberPods.push(p);
    g.peerKeys.add(entryKey);
    g.ingressTraffic.push(...ext.ingressTraffic);
    g.egressTraffic.push(...ext.egressTraffic);
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
    if (!primary) return;
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
      { peerKeys: unattributedEntries.map((e) => e.peerKey), tooltip: unattributedTooltip(unattributedEntries.map((e) => e.lookupFailed)) },
    );
  }

  if (privateEntries.length > 0) {
    addDirectionalNodes(
      'external-private', PRIVATE_LABEL,
      privateEntries.map((e) => e.pod),
      privateEntries.flatMap((e) => e.ingressTraffic),
      privateEntries.flatMap((e) => e.egressTraffic),
      PRIVATE_NAMESPACE,
      { peerKeys: privateEntries.map((e) => `ip:${e.pod.pod_ip}`), tooltip: PRIVATE_PEER_TOOLTIP },
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
 * The map node a row's peer connects to: the local node by pod NAME or
 * stored workload, else the external node answering for the row's peer key.
 * Nothing is looked up by IP. `byKey` is the direction-specific index of
 * external nodes' `peerKeys`.
 */
export function remoteNodeForRow(
  traffic: NetworkTraffic,
  rowPeers: ReadonlyMap<NetworkTraffic, PeerResolution>,
  localPodByName: ReadonlyMap<string, PodNodeData>,
  svcIpToLocalPod: ReadonlyMap<string, PodNodeData>,
  byKey: ReadonlyMap<string, PodNodeData>,
  localPodByWorkload: ReadonlyMap<string, PodNodeData>,
): PodNodeData | undefined {
  const remoteIp = traffic.traffic_in_out_ip;
  if (!remoteIp) return undefined;
  const peer = rowPeers.get(traffic) ?? { kind: 'unknown' as const };
  switch (peer.kind) {
    case 'pod':
    case 'node':
      return localNodeForPeer(peer.pod, localPodByName, localPodByWorkload) || byKey.get(peerKey(peer)!);
    case 'service':
      if (!peer.svc) return byKey.get(`unattributed:${remoteIp}`);
      return svcIpToLocalPod.get(peer.svc.svc_ip) || byKey.get(serviceKey(peer.svc));
    case 'unattributed':
      return byKey.get(`unattributed:${remoteIp}`);
    case 'unknown':
      return byKey.get(`ip:${remoteIp}`);
  }
}
