import React, { useCallback, useMemo, useEffect, useState } from 'react';
import ReactFlow, {
  Controls,
  useNodesState,
  useEdgesState,
  MarkerType,
  useReactFlow,
  ReactFlowProvider,
  Panel,
} from 'reactflow';
import type { Node, Edge } from 'reactflow';
import 'reactflow/dist/style.css';
import ELK from 'elkjs/lib/elk.bundled.js';
import { Eye, EyeOff, Activity, ShieldAlert, Server, Crosshair, X, ArrowRight, ArrowDown } from 'lucide-react';
import PodNode from './PodNode';
import { shouldExitFocus } from '../utils/graphFocus';
import {
  UNATTRIBUTED_LABEL,
  UNATTRIBUTED_NAMESPACE,
  UNATTRIBUTED_PEER_TOOLTIP,
  buildPeerIndex,
  peerGroupIdentity,
  peerKey,
  resolvePeer,
  type PeerResolution,
} from '../utils/peerResolution';
import type { PodNodeData, PodInfo, ServiceInfo, NetworkTraffic } from '../types';
import { UI_TIMING } from '../constants/ui';

const elk = new ELK();

// Estimated node dimensions for ELK layout
const NODE_WIDTH = 240;
const NODE_HEIGHT = 100;

interface NetworkGraphProps {
  pods: PodNodeData[];
  allPodsLookup: PodInfo[];
  services: ServiceInfo[];
  showExternalNodes: boolean;
  onToggleExternalNodes: () => void;
  showTraffic: boolean;
  onToggleTraffic: () => void;
  layoutDirection: 'LR' | 'TB';
  onToggleLayoutDirection: () => void;
  onPodToggle: (podId: string) => void;
  onPodSelect: (pod: PodNodeData | null) => void;
  selectedPodId: string | null;
  onBuildPolicy?: (pod: PodNodeData) => void;
  /** Focused node (URL `?focus=`), or null. Controlled by the caller so a
   *  focused view is shareable; the graph reports every change back. */
  focusedNodeId: string | null;
  onFocusChange: (id: string | null) => void;
}

// Define nodeTypes outside component to prevent recreation
const nodeTypes = {
  podNode: PodNode,
} as const;

// Noop toggle for external nodes (they don't expand)
const noopToggle = () => {};

const NetworkGraphInner: React.FC<NetworkGraphProps> = ({
  pods,
  allPodsLookup,
  services,
  showExternalNodes,
  onToggleExternalNodes,
  showTraffic,
  onToggleTraffic,
  layoutDirection,
  onToggleLayoutDirection,
  onPodToggle,
  onPodSelect,
  selectedPodId,
  onBuildPolicy,
  focusedNodeId,
  onFocusChange,
}) => {
  const { fitView } = useReactFlow();

  // Focus mode: isolate a node + its direct upstream/downstream, hide the rest,
  // and re-lay-out the subset. Toggling the same node (or Esc / the pill) exits.
  // The focused id lives in the URL hash (see App) so the view is shareable.
  const setFocusedNodeId = onFocusChange;
  const onFocus = useCallback(
    (id: string) => onFocusChange(focusedNodeId === id ? null : id),
    [onFocusChange, focusedNodeId],
  );

  // Build IP-to-PodInfo lookup from allPodsLookup for cross-namespace resolution
  const ipToAllPodsMap = useMemo(() => {
    const map = new Map<string, PodInfo>();
    allPodsLookup.forEach((pod) => {
      if (pod.pod_ip) {
        map.set(pod.pod_ip, pod);
      }
    });
    return map;
  }, [allPodsLookup]);

  // Peer attribution per traffic ROW (utils/peerResolution): the row's
  // stored peer_* identity first, else a by-IP lookup guarded by the flow
  // time. Pod IPs are recycled, so this — not an IP → pod map — decides
  // which node a flow connects to. Shared by externalNodes and initialEdges.
  const peerIndex = useMemo(() => buildPeerIndex(allPodsLookup, services), [allPodsLookup, services]);
  const rowPeers = useMemo(() => {
    const map = new Map<NetworkTraffic, PeerResolution>();
    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        if (traffic.traffic_in_out_ip) map.set(traffic, resolvePeer(traffic, peerIndex));
      });
    });
    return map;
  }, [pods, peerIndex]);

  // Build name-to-PodNodeData lookup for in-namespace pods (a resolved peer
  // is matched to its node by NAME, never by IP)
  const localPodByName = useMemo(() => {
    const map = new Map<string, PodNodeData>();
    pods.forEach((pod) => {
      map.set(pod.pod.pod_name, pod);
      pod.pods?.forEach((p) => map.set(p.pod_name, pod));
    });
    return map;
  }, [pods]);

  // Build IP-to-PodNodeData lookup for in-namespace pods
  const ipToLocalPodMap = useMemo(() => {
    const map = new Map<string, PodNodeData>();
    pods.forEach((pod) => {
      if (pod.pod.pod_ip) {
        map.set(pod.pod.pod_ip, pod);
      }
      pod.pods?.forEach((p) => {
        if (p.pod_ip) {
          map.set(p.pod_ip, pod);
        }
      });
    });
    return map;
  }, [pods]);

  // Build service ClusterIP → local PodNodeData map by matching selectors
  const svcIpToLocalPodMap = useMemo(() => {
    const map = new Map<string, PodNodeData>();
    if (!services.length) return map;

    services.forEach((svc) => {
      if (!svc.svc_ip) return;

      // Extract selector from the service spec
      const selector = (svc.service_spec as Record<string, unknown>)?.spec as
        Record<string, unknown> | undefined;
      const selectorLabels = selector?.selector as Record<string, string> | undefined;
      if (!selectorLabels || Object.keys(selectorLabels).length === 0) return;

      // Find a local pod whose workload_selector_labels match the service selector
      for (const pod of pods) {
        const podLabels = pod.pod.workload_selector_labels;
        if (!podLabels) continue;

        const matches = Object.entries(selectorLabels).every(
          ([k, v]) => podLabels[k] === v
        );
        if (matches) {
          map.set(svc.svc_ip, pod);
          break;
        }
      }
    });

    return map;
  }, [services, pods]);

  // Map backing pod IP → service ClusterIP, for cross-namespace deduplication.
  // Shared between externalNodes (traffic merge) and initialEdges (edge resolution).
  const podIpToSvcIp = useMemo(() => {
    const map = new Map<string, string>();
    services.forEach((svc) => {
      if (!svc.svc_ip) return;
      const svcSpec = (svc.service_spec as Record<string, unknown>)?.spec as Record<string, unknown> | undefined;
      const selectorLabels = svcSpec?.selector as Record<string, string> | undefined;
      if (!selectorLabels || Object.keys(selectorLabels).length === 0) return;
      allPodsLookup.forEach((pod) => {
        if (!pod.pod_ip || !pod.workload_selector_labels) return;
        if (Object.entries(selectorLabels).every(([k, v]) => pod.workload_selector_labels![k] === v)) {
          map.set(pod.pod_ip, svc.svc_ip!);
        }
      });
    });
    return map;
  }, [services, allPodsLookup]);

  // Map backing pod NAME → service ClusterIP, for peers resolved to a pod
  // record (the by-IP map above is ambiguous once an IP has changed hands).
  const podNameToSvcIp = useMemo(() => {
    const map = new Map<string, string>();
    services.forEach((svc) => {
      if (!svc.svc_ip) return;
      const svcSpec = (svc.service_spec as Record<string, unknown>)?.spec as Record<string, unknown> | undefined;
      const selectorLabels = svcSpec?.selector as Record<string, string> | undefined;
      if (!selectorLabels || Object.keys(selectorLabels).length === 0) return;
      allPodsLookup.forEach((pod) => {
        if (!pod.workload_selector_labels || pod.pod_namespace !== svc.svc_namespace) return;
        if (Object.entries(selectorLabels).every(([k, v]) => pod.workload_selector_labels![k] === v)) {
          map.set(pod.pod_name, svc.svc_ip!);
        }
      });
    });
    return map;
  }, [services, allPodsLookup]);

  // Discover external endpoints from traffic data, split by direction
  // Ingress sources (-in suffix) go on the left, egress destinations (-out suffix) on the right
  const externalNodes = useMemo(() => {
    if (!showExternalNodes || !showTraffic) return [];

    // Step 1: Classify each external peer's traffic by direction. Entries are
    // keyed by the RESOLVED peer (utils/peerResolution `peerKey`) when a row
    // attributes to a pod or is guarded out, and by IP otherwise — so rows
    // from one IP that changed hands land in different entries.
    const externalIpData = new Map<string, {
      podInfo: PodInfo | null;
      ip: string;
      // podInfo came from the row's stored peer_* fields
      stored: boolean;
      // the guard excluded every pod that ever held the IP
      unattributed: boolean;
      ingressTraffic: NetworkTraffic[];
      egressTraffic: NetworkTraffic[];
    }>();

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        const remoteIp = traffic.traffic_in_out_ip;
        if (!remoteIp) return;
        const peer = rowPeers.get(traffic) ?? { kind: 'unknown' as const };

        let entryKey: string;
        let entryIp = remoteIp;
        let podInfo: PodInfo | null = null;
        let stored = false;
        let unattributed = false;
        if (peer.kind === 'pod' || peer.kind === 'node') {
          // In-namespace peer: an edge, not an external node.
          if (localPodByName.has(peer.pod.pod_name)) return;
          podInfo = peer.pod;
          stored = peer.stored;
          entryKey = peerKey(peer)!;
        } else if (peer.kind === 'unattributed' || (peer.kind === 'service' && !peer.svc)) {
          // Guarded out, or a stored Service that no longer fronts this IP.
          unattributed = true;
          entryKey = `unattributed:${remoteIp}`;
        } else {
          // Service / unknown: the pre-v4 by-IP path, on the canonical ClusterIP.
          if (peer.kind === 'service' && peer.svc?.svc_ip) entryIp = peer.svc.svc_ip;
          if (ipToLocalPodMap.has(entryIp)) return;
          if (svcIpToLocalPodMap.has(entryIp)) return;
          entryKey = entryIp;
        }

        if (!externalIpData.has(entryKey)) {
          externalIpData.set(entryKey, {
            podInfo,
            ip: entryIp,
            stored,
            unattributed,
            ingressTraffic: [],
            egressTraffic: [],
          });
        }
        const entry = externalIpData.get(entryKey)!;
        const trafficType = traffic.traffic_type?.toLowerCase();
        if (trafficType === 'ingress') {
          entry.ingressTraffic.push(traffic);
        } else if (trafficType === 'egress') {
          entry.egressTraffic.push(traffic);
        }
      });
    });

    // Step 2: Build service IP lookup
    const svcIpLookup = new Map<string, ServiceInfo>();
    services.forEach((svc) => {
      if (svc.svc_ip) svcIpLookup.set(svc.svc_ip, svc);
    });

    // Step 2b: Merge backing pod IP entries into their service IP entry so that
    // curl→serviceIP and curl→podIP produce a single external node (and single edge)
    // Track which backing pod IPs were merged into each service IP so we can
    // include them in the external node's pods array for edge resolution.
    const mergedBackingIps = new Map<string, string[]>(); // svcIp → [podIp, ...]
    const mergedPeerKeys = new Map<string, string[]>(); // svcIp → [peer key, ...] (edge resolution)
    const podIpsToMerge: Array<[string, string]> = [];
    externalIpData.forEach((entry, key) => {
      if (entry.unattributed) return;
      // A resolved pod record is matched to its Service by name; a bare IP
      // entry by IP, as before.
      const svcIp = entry.podInfo ? podNameToSvcIp.get(entry.podInfo.pod_name) : podIpToSvcIp.get(key);
      if (svcIp && svcIpLookup.has(svcIp)) podIpsToMerge.push([key, svcIp]);
    });
    podIpsToMerge.forEach(([key, svcIp]) => {
      const entry = externalIpData.get(key)!;
      if (!externalIpData.has(svcIp)) {
        externalIpData.set(svcIp, { podInfo: null, ip: svcIp, stored: false, unattributed: false, ingressTraffic: [], egressTraffic: [] });
      }
      const svcEntry = externalIpData.get(svcIp)!;
      svcEntry.ingressTraffic.push(...entry.ingressTraffic);
      svcEntry.egressTraffic.push(...entry.egressTraffic);
      externalIpData.delete(key);
      if (!mergedBackingIps.has(svcIp)) mergedBackingIps.set(svcIp, []);
      mergedBackingIps.get(svcIp)!.push(entry.ip);
      if (entry.podInfo) {
        if (!mergedPeerKeys.has(svcIp)) mergedPeerKeys.set(svcIp, []);
        mergedPeerKeys.get(svcIp)!.push(key);
      }
    });

    // Step 3: Group by identity, tracking direction-specific traffic
    interface IdentityGroup {
      memberPods: PodInfo[];
      // peer keys the group answers for (edge resolution)
      peerKeys: Set<string>;
      ingressTraffic: NetworkTraffic[];
      egressTraffic: NetworkTraffic[];
    }

    const identityMap = new Map<string, IdentityGroup>();
    const internetEntries: { pod: PodInfo; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];
    const unattributedEntries: { pod: PodInfo; peerKey: string; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];

    externalIpData.forEach((ext, entryKey) => {
      // Guarded-out peer: the flow predates every pod that ever held the
      // IP. Aggregated into one "Unattributed" node (like "Internet").
      if (ext.unattributed) {
        unattributedEntries.push({
          pod: { pod_name: ext.ip, pod_ip: ext.ip, pod_namespace: UNATTRIBUTED_NAMESPACE, time_stamp: '', node_name: '', is_dead: false },
          peerKey: entryKey,
          ingressTraffic: ext.ingressTraffic,
          egressTraffic: ext.egressTraffic,
        });
        return;
      }

      // First check service IPs (takes priority regardless of podInfo)
      const svc = svcIpLookup.get(ext.ip);
      if (svc) {
        const ns = svc.svc_namespace || 'unknown';
        const name = svc.svc_name || ext.ip;
        const key = `external-svc-${ns}-${name}`;
        if (!identityMap.has(key)) {
          identityMap.set(key, { memberPods: [], peerKeys: new Set(), ingressTraffic: [], egressTraffic: [] });
        }
        const group = identityMap.get(key)!;
        mergedPeerKeys.get(ext.ip)?.forEach((k) => group.peerKeys.add(k));
        const backingIps = mergedBackingIps.get(ext.ip) || [];
        if (backingIps.length > 0) {
          // Use only the real backing pod IPs so the pod count reflects actual pods.
          // The service ClusterIP is a virtual IP and should not count as a pod.
          // Edge resolution for "→ service ClusterIP" traffic is handled in the edge
          // building step by indexing the canonical service IP from each backing pod IP.
          backingIps.forEach((backingIp) => {
            // Carry the backing pod's workload facts onto the synthetic member so
            // the DaemonSets toggle can recognise a Service fronting a DaemonSet or
            // host-network pods (node-exporter, CSI node plugins, ...).
            const known = ipToAllPodsMap.get(backingIp);
            group.memberPods.push({
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
        } else {
          // No backing pods known — use the service ClusterIP as a placeholder so the
          // node is still displayed and edges for "→ service ClusterIP" traffic resolve.
          if (ext.ip) {
            group.memberPods.push({
              pod_name: name,
              pod_ip: ext.ip,
              pod_namespace: ns,
              pod_identity: name,
              time_stamp: '',
              node_name: '',
              is_dead: false,
            });
          }
        }
        group.ingressTraffic.push(...ext.ingressTraffic);
        group.egressTraffic.push(...ext.egressTraffic);
        return;
      }

      // Cross-namespace pod — grouped by identity (Job/CronJob pods under
      // their workload). A peer the broker stamped on the row renders even
      // when that pod is dead now: the identity was captured when the flow
      // happened, and a finished Job is a real peer a policy must allow.
      if (ext.podInfo && (ext.stored || !ext.podInfo.is_dead)) {
        const identity = peerGroupIdentity(ext.podInfo);
        const ns = ext.podInfo.pod_namespace || 'unknown';
        const key = `external-${ns}-${identity}`;
        if (!identityMap.has(key)) {
          identityMap.set(key, { memberPods: [], peerKeys: new Set(), ingressTraffic: [], egressTraffic: [] });
        }
        const group = identityMap.get(key)!;
        group.memberPods.push(ext.podInfo);
        group.peerKeys.add(entryKey);
        group.ingressTraffic.push(...ext.ingressTraffic);
        group.egressTraffic.push(...ext.egressTraffic);
        return;
      }

      // Dead pod chosen by IP — legacy history; skip entirely
      if (ext.podInfo && ext.podInfo.is_dead) {
        return;
      }

      // Truly external IP (not matching any cluster pod or service) — aggregate into "Internet" node
      internetEntries.push({
        pod: {
          pod_name: ext.ip,
          pod_ip: ext.ip,
          pod_namespace: 'internet',
          time_stamp: '',
          node_name: '',
          is_dead: false,
        },
        ingressTraffic: ext.ingressTraffic,
        egressTraffic: ext.egressTraffic,
      });
    });

    // Step 4: Create directional nodes — separate ingress (-in) and egress (-out) nodes
    const externalPodNodes: PodNodeData[] = [];

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
      if (ingressTraffic.length > 0) {
        externalPodNodes.push({
          id: `${key}-in`,
          label,
          pod: primary,
          pods: memberPods,
          traffic: ingressTraffic,
          isExpanded: false,
          isExternal: true,
          externalNamespace,
          ...extra,
        });
      }
      if (egressTraffic.length > 0) {
        externalPodNodes.push({
          id: `${key}-out`,
          label,
          pod: primary,
          pods: memberPods,
          traffic: egressTraffic,
          isExpanded: false,
          isExternal: true,
          externalNamespace,
          ...extra,
        });
      }
    };

    identityMap.forEach((group, key) => {
      const primary = group.memberPods[0];
      addDirectionalNodes(
        key,
        key.startsWith('external-svc-') ? primary.pod_identity || primary.pod_name : peerGroupIdentity(primary),
        group.memberPods,
        group.ingressTraffic,
        group.egressTraffic,
        primary.pod_namespace || 'unknown',
        { peerKeys: Array.from(group.peerKeys) },
      );
    });

    // Aggregate guarded-out peers into a single "Unattributed" node
    if (unattributedEntries.length > 0) {
      addDirectionalNodes(
        'external-unattributed',
        UNATTRIBUTED_LABEL,
        unattributedEntries.map((e) => e.pod),
        unattributedEntries.flatMap((e) => e.ingressTraffic),
        unattributedEntries.flatMap((e) => e.egressTraffic),
        UNATTRIBUTED_NAMESPACE,
        { peerKeys: unattributedEntries.map((e) => e.peerKey), tooltip: UNATTRIBUTED_PEER_TOOLTIP },
      );
    }

    // Aggregate all unknown IPs into a single "Internet" node
    if (internetEntries.length > 0) {
      const internetPods: PodInfo[] = [];
      const internetIngress: NetworkTraffic[] = [];
      const internetEgress: NetworkTraffic[] = [];
      internetEntries.forEach((entry) => {
        internetPods.push(entry.pod);
        internetIngress.push(...entry.ingressTraffic);
        internetEgress.push(...entry.egressTraffic);
      });
      addDirectionalNodes(
        'external-internet',
        'Internet',
        internetPods,
        internetIngress,
        internetEgress,
        'internet',
      );
    }

    return externalPodNodes;
  }, [pods, showExternalNodes, showTraffic, ipToLocalPodMap, ipToAllPodsMap, svcIpToLocalPodMap, services, podIpToSvcIp, podNameToSvcIp, rowPeers, localPodByName]);

  // Combine in-namespace and external pods for rendering
  // When traffic is enabled, hide local pods that have no traffic
  const allDisplayPods = useMemo(() => {
    const visiblePods = showTraffic
      ? pods.filter((pod) => pod.traffic && pod.traffic.length > 0)
      : pods;
    return [...visiblePods, ...externalNodes];
  }, [pods, externalNodes, showTraffic]);

  // Focus is only meaningful while the focused node exists in the current
  // node set. Switching namespace (or the pod being deleted) used to leave
  // the stale focus filtering EVERYTHING out — an empty graph with the
  // focus pill still up. Self-heal instead of threading the namespace down:
  // any change that removes the focused node exits focus mode (and drops the
  // URL param) — but only once nodes have loaded, so a shared `?focus=` link
  // survives the initial fetch (utils/graphFocus).
  useEffect(() => {
    if (shouldExitFocus(focusedNodeId, allDisplayPods.map((p) => p.id), pods.length > 0)) {
      onFocusChange(null);
    }
  }, [focusedNodeId, allDisplayPods, pods.length, onFocusChange]);

  // Build React Flow nodes with placeholder positions (ELK will reposition)
  const baseNodes: Node[] = useMemo(() => {
    return allDisplayPods.map((pod) => {
      const isExternal = pod.isExternal || false;
      return {
        id: pod.id,
        type: 'podNode',
        position: { x: 0, y: 0 },
        data: {
          ...pod,
          layoutDirection,
          onToggle: isExternal ? noopToggle : onPodToggle,
          onBuildPolicy: isExternal ? undefined : onBuildPolicy,
          onFocus,
          isFocused: pod.id === focusedNodeId,
        },
        selected: pod.id === selectedPodId,
      };
    });
  }, [allDisplayPods, onPodToggle, selectedPodId, onBuildPolicy, layoutDirection, onFocus, focusedNodeId]);

  // Track ELK-computed node positions
  const [elkPositions, setElkPositions] = useState<Map<string, { x: number; y: number }>>(new Map());

  // Well-known port to service name mapping
  const wellKnownPorts: Record<string, string> = useMemo(() => ({
    '53': 'DNS',
    '80': 'HTTP',
    '443': 'HTTPS',
    '6443': 'K8s API',
  }), []);

  // Generate edges from network traffic data
  const initialEdges: Edge[] = useMemo(() => {
    if (!showTraffic) return [];

    const edges: Edge[] = [];
    const edgeMap = new Map<string, {
      count: number;
      isExternal: boolean;
      ports: Map<string, number>;
      protocols: Set<string>;
      dropCount: number;
    }>();

    // Build direction-specific lookups for external nodes: by resolved peer
    // key (pod / unattributed peers) and by IP (Service, Internet).
    const ingressExternalIpMap = new Map<string, PodNodeData>();
    const egressExternalIpMap = new Map<string, PodNodeData>();
    const ingressExternalByKey = new Map<string, PodNodeData>();
    const egressExternalByKey = new Map<string, PodNodeData>();
    allDisplayPods.forEach((pod) => {
      if (!pod.isExternal) return;
      const isInNode = pod.id.endsWith('-in');
      const isOutNode = pod.id.endsWith('-out');
      pod.peerKeys?.forEach((k) => {
        if (isInNode) ingressExternalByKey.set(k, pod);
        if (isOutNode) egressExternalByKey.set(k, pod);
      });
      pod.pods?.forEach((p) => {
        if (p.pod_ip) {
          if (isInNode) ingressExternalIpMap.set(p.pod_ip, pod);
          if (isOutNode) egressExternalIpMap.set(p.pod_ip, pod);
          // Also index the canonical service ClusterIP for this backing pod IP so that
          // traffic recorded against the service IP (not the pod IP directly) still
          // resolves to this external node — e.g. when a pod curls via the ClusterIP
          // first and then later directly to the backing pod IP.
          const svcIp = podIpToSvcIp.get(p.pod_ip);
          if (svcIp) {
            if (isInNode) ingressExternalIpMap.set(svcIp, pod);
            if (isOutNode) egressExternalIpMap.set(svcIp, pod);
          }
        }
      });
    });

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        let sourcePod: PodNodeData | undefined;
        let destPod: PodNodeData | undefined;
        const remoteIp = traffic.traffic_in_out_ip;

        // The row's attributed peer (utils/peerResolution). A pod peer is
        // matched to its node by NAME (local) or peer key (external) — never
        // by IP, which may have changed hands since the flow. A guarded-out
        // peer resolves to the Unattributed node. Service/unknown peers keep
        // the by-IP path, canonicalised to the Service ClusterIP.
        const peer = remoteIp ? rowPeers.get(traffic) : undefined;
        const key = peer ? peerKey(peer) : null;
        const resolveRemote = (byKey: Map<string, PodNodeData>, byIp: Map<string, PodNodeData>): PodNodeData | undefined => {
          if (!remoteIp) return undefined;
          if (key && peer && (peer.kind === 'pod' || peer.kind === 'node')) {
            // Local node by name, else the external node answering for this
            // peer key (a Service node when the pod was merged into it).
            return localPodByName.get(peer.pod.pod_name) || byKey.get(key);
          }
          if (key) return byKey.get(key);
          if (peer?.kind === 'service' && !peer.svc) return byKey.get(`unattributed:${remoteIp}`);
          const ip = peer?.kind === 'service' && peer.svc?.svc_ip ? peer.svc.svc_ip : remoteIp;
          const canonicalIp = podIpToSvcIp.get(ip) ?? ip;
          return ipToLocalPodMap.get(ip) || svcIpToLocalPodMap.get(ip) || byIp.get(ip) || byIp.get(canonicalIp);
        };

        const trafficType = traffic.traffic_type?.toLowerCase();
        if (trafficType === 'egress') {
          sourcePod = pod;
          // Egress: remote IP is the destination → local pod, service IP, or egress-external node.
          destPod = resolveRemote(egressExternalByKey, egressExternalIpMap);
        } else if (trafficType === 'ingress') {
          // Ingress: remote IP is the source → local pod, service IP, or ingress-external node.
          sourcePod = resolveRemote(ingressExternalByKey, ingressExternalIpMap);
          destPod = pod;
        }

        if (sourcePod && destPod && sourcePod.id !== destPod.id) {
          const edgeKey = `${sourcePod.id}::${destPod.id}`;
          const isExternalEdge = !!(sourcePod.isExternal || destPod.isExternal);
          if (!edgeMap.has(edgeKey)) {
            edgeMap.set(edgeKey, {
              count: 0,
              isExternal: isExternalEdge,
              ports: new Map(),
              protocols: new Set(),
              dropCount: 0,
            });
          }
          const entry = edgeMap.get(edgeKey)!;
          entry.count++;

          const port = traffic.traffic_in_out_port;
          if (port && port !== '0') {
            entry.ports.set(port, (entry.ports.get(port) ?? 0) + 1);
          }

          if (traffic.ip_protocol) {
            entry.protocols.add(traffic.ip_protocol.toUpperCase());
          }

          if (traffic.decision?.toUpperCase() === 'DROP') {
            entry.dropCount++;
          }
        }
      });
    });

    edgeMap.forEach((edgeData, key) => {
      const [source, target] = key.split('::');
      const { count, isExternal, ports, protocols, dropCount } = edgeData;

      // Trust-state edge coloring (kguardian brand): denied flows are the single
      // most important signal for a runtime-security operator, so they get the
      // error red + a bolder stroke; egress-to-external is warm amber (dashed);
      // trusted in-cluster traffic is the brand indigo (was an off-brand #3B82F6).
      const isDrop = dropCount > 0;
      const strokeColor = isDrop ? '#EF4444' : isExternal ? '#F59E0B' : '#4E3AD9';

      // Build semantic label from port/protocol data
      let label: string;
      if (ports.size > 0) {
        // Find the top port (highest traffic count)
        let topPort = '';
        let topCount = 0;
        ports.forEach((c, p) => {
          if (c > topCount) {
            topPort = p;
            topCount = c;
          }
        });

        // Use well-known name if available, otherwise port/protocol
        const proto = protocols.size === 1 ? [...protocols][0] : 'TCP';
        const serviceName = wellKnownPorts[topPort];
        label = serviceName ?? `${topPort}/${proto}`;

        // Show additional port count if multiple ports
        if (ports.size > 1) {
          label += ` +${ports.size - 1}`;
        }
      } else if (protocols.size > 0) {
        label = [...protocols].join('/');
      } else {
        label = `${count}`;
      }

      // Append drop indicator
      if (dropCount > 0) {
        label += ` (${dropCount} drop${dropCount > 1 ? 's' : ''})`;
      }

      edges.push({
        id: key,
        source,
        target,
        animated: true,
        style: {
          stroke: strokeColor,
          strokeWidth: isDrop ? Math.min(count / 2 + 2.5, 5) : Math.min(count / 2 + 1, 4),
          strokeDasharray: isExternal && !isDrop ? '5 5' : undefined,
        },
        label,
        labelStyle: {
          fill: isDrop ? '#EF4444' : 'var(--theme-text-secondary)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          fontWeight: isDrop ? 600 : 400,
        },
        labelBgStyle: {
          fill: 'var(--theme-bg-card)',
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
        },
      });
    });

    return edges;
  }, [pods, allDisplayPods, ipToLocalPodMap, svcIpToLocalPodMap, showTraffic, wellKnownPorts, podIpToSvcIp, rowPeers, localPodByName]);

  // Focus filter: the focused node + everything one hop up/downstream. Applied
  // before ELK so the isolated subset gets its own clean layout.
  const focusNeighborhood = useMemo(() => {
    if (!focusedNodeId) return null;
    const ids = new Set<string>([focusedNodeId]);
    for (const e of initialEdges) {
      if (e.source === focusedNodeId) ids.add(e.target);
      if (e.target === focusedNodeId) ids.add(e.source);
    }
    return ids;
  }, [focusedNodeId, initialEdges]);

  const displayNodes: Node[] = useMemo(
    () => (focusNeighborhood ? baseNodes.filter((n) => focusNeighborhood.has(n.id)) : baseNodes),
    [baseNodes, focusNeighborhood],
  );
  const displayEdges: Edge[] = useMemo(
    () => (focusNeighborhood
      ? initialEdges.filter((e) => focusNeighborhood.has(e.source) && focusNeighborhood.has(e.target))
      : initialEdges),
    [initialEdges, focusNeighborhood],
  );

  const focusedLabel = useMemo(
    () => (focusedNodeId ? allDisplayPods.find((p) => p.id === focusedNodeId)?.label ?? 'node' : null),
    [focusedNodeId, allDisplayPods],
  );

  // Run ELK layout whenever nodes or edges change
  useEffect(() => {
    if (displayNodes.length === 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setElkPositions(new Map());
      return;
    }

    // Only include edges whose source and target exist in the current node set
    const nodeIds = new Set(displayNodes.map((n) => n.id));
    const validEdges = displayEdges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    // Build ELK graph from current nodes and edges
    const elkGraph = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': layoutDirection === 'TB' ? 'DOWN' : 'RIGHT',
        'elk.spacing.nodeNode': '80',
        'elk.layered.spacing.nodeNodeBetweenLayers': '120',
        'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
        'elk.separateConnectedComponents': 'true',
        'elk.spacing.componentComponent': '100',
      },
      children: displayNodes.map((node) => {
        const isIn = node.id.endsWith('-in');
        const isOut = node.id.endsWith('-out');
        const isInternet = node.id.startsWith('external-internet-');
        const layerOpts: Record<string, string> = {};
        if (isIn) {
          layerOpts['elk.layered.layerConstraint'] = 'FIRST';
          if (isInternet) layerOpts['elk.layered.priority.direction'] = '100';
        } else if (isOut) {
          layerOpts['elk.layered.layerConstraint'] = 'LAST';
          if (isInternet) layerOpts['elk.layered.priority.direction'] = '100';
        }
        return {
          id: node.id,
          width: NODE_WIDTH,
          height: NODE_HEIGHT,
          ...(Object.keys(layerOpts).length > 0 ? { layoutOptions: layerOpts } : {}),
        };
      }),
      edges: validEdges.map((edge) => ({
        id: edge.id,
        sources: [edge.source],
        targets: [edge.target],
      })),
    };

    elk.layout(elkGraph).then((layoutResult) => {
      const positions = new Map<string, { x: number; y: number }>();
      layoutResult.children?.forEach((child) => {
        positions.set(child.id, { x: child.x ?? 0, y: child.y ?? 0 });
      });

      // Ensure Internet nodes sit at the absolute graph extremes
      const isHorizontal = layoutDirection !== 'TB';
      const axis = isHorizontal ? 'x' : 'y';
      const margin = 120;

      let minPos = Infinity;
      let maxPos = -Infinity;
      positions.forEach((pos, id) => {
        if (id.startsWith('external-internet-')) return;
        const v = pos[axis];
        if (v < minPos) minPos = v;
        if (v > maxPos) maxPos = v;
      });

      if (minPos !== Infinity) {
        positions.forEach((pos, id) => {
          if (!id.startsWith('external-internet-')) return;
          if (id.endsWith('-in')) {
            pos[axis] = minPos - margin - NODE_WIDTH;
          } else if (id.endsWith('-out')) {
            pos[axis] = maxPos + margin + NODE_WIDTH;
          }
        });
      }

      setElkPositions(positions);
    }).catch((err) => {
      // Fallback: simple grid layout if ELK fails
      console.error('ELK layout error, using fallback grid:', err);
      const positions = new Map<string, { x: number; y: number }>();
      const cols = Math.ceil(Math.sqrt(displayNodes.length));
      displayNodes.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions.set(node.id, {
          x: col * (NODE_WIDTH + 80),
          y: row * (NODE_HEIGHT + 80),
        });
      });
      setElkPositions(positions);
    });
  }, [displayNodes, displayEdges, layoutDirection]);

  // Merge ELK positions into nodes — hide nodes until ELK has run for the current set
  const positionedNodes: Node[] = useMemo(() => {
    // Check if ELK has computed positions for these specific nodes
    const hasPositions = displayNodes.length > 0 && displayNodes.some((n) => elkPositions.has(n.id));
    if (!hasPositions) return [];
    return displayNodes.map((node) => ({
      ...node,
      position: elkPositions.get(node.id) ?? { x: -9999, y: -9999 },
    }));
  }, [displayNodes, elkPositions]);

  const [nodes, setNodes, onNodesChange] = useNodesState(positionedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Force-replace nodes when ELK positions or data changes.
  // Using a function updater that ignores previous state ensures React Flow
  // doesn't merge stale dragged positions with new layout positions.
  useEffect(() => {
    setNodes(positionedNodes);
  }, [positionedNodes, setNodes]);

  // Update edges when traffic changes
  useEffect(() => {
    setEdges(displayEdges);
  }, [displayEdges, setEdges]);

  // Esc exits focus mode.
  useEffect(() => {
    if (!focusedNodeId) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setFocusedNodeId(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [focusedNodeId]);

  // Auto-fit view after ELK layout completes
  useEffect(() => {
    if (elkPositions.size > 0) {
      setTimeout(() => {
        fitView({ padding: 0.2, duration: UI_TIMING.FIT_VIEW_DURATION });
      }, UI_TIMING.FIT_VIEW_DELAY);
    }
  }, [elkPositions, fitView]);

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      const pod = allDisplayPods.find((p) => p.id === node.id);
      onPodSelect(pod || null);
    },
    [allDisplayPods, onPodSelect]
  );

  const onPaneClick = useCallback(() => {
    onPodSelect(null);
  }, [onPodSelect]);

  const externalCount = externalNodes.length;

  // Compute namespace-level summary stats for the Security Summary Panel
  const summaryStats = useMemo(() => {
    let totalFlows = 0;
    let totalDrops = 0;

    pods.forEach((pod) => {
      totalFlows += pod.traffic?.length || 0;
      pod.traffic?.forEach((t) => {
        if (t.decision?.toUpperCase() === 'DROP') totalDrops++;
      });
    });

    return { podCount: pods.length, totalFlows, totalDrops };
  }, [pods]);

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodesConnectable={false}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        fitView
        attributionPosition="bottom-right"
      >
        <Controls className="bg-hubble-card border-hubble-border" />

        {/* Focus pill — shown while a node's neighborhood is isolated */}
        {focusedNodeId && (
          <Panel position="top-center">
            <div className="flex items-center gap-2 pl-3 pr-1.5 py-1.5 rounded-full bg-hubble-accent/15 border border-hubble-accent/40 backdrop-blur-sm text-xs">
              <Crosshair className="w-3.5 h-3.5 text-hubble-accent shrink-0" />
              <span className="text-primary">
                Focused on <span className="font-semibold">{focusedLabel}</span>
              </span>
              <button
                onClick={() => setFocusedNodeId(null)}
                className="flex items-center gap-1 pl-2 pr-2 py-0.5 rounded-full text-secondary hover:text-primary hover:bg-hubble-hover transition-colors"
                title="Show all nodes (Esc)"
              >
                <X className="w-3 h-3" />
                Show all
              </button>
            </div>
          </Panel>
        )}

        {/* Security Summary Panel */}
        <Panel position="top-left">
          <div className="flex items-center gap-3 px-3 py-2 rounded-surface bg-hubble-card/90 border border-hubble-border backdrop-blur-sm text-xs">
            <div className="flex items-center gap-1.5 text-secondary" title="Total workload identities in the current namespace">
              <Server className="w-3.5 h-3.5 text-hubble-accent" />
              <span className="font-medium font-mono tabular-nums">{summaryStats.podCount}</span>
            </div>
            <div className="w-px h-4 bg-hubble-border" />
            <div className="flex items-center gap-1.5 text-secondary" title="Total observed network flows (ingress + egress) across all pods">
              <Activity className="w-3.5 h-3.5 text-hubble-accent" />
              <span className="font-medium font-mono tabular-nums">{summaryStats.totalFlows.toLocaleString()}</span>
            </div>
            <div className="w-px h-4 bg-hubble-border" />
            <div
              className={`flex items-center gap-1.5 ${summaryStats.totalDrops > 0 ? 'text-hubble-error' : 'text-secondary'}`}
              title={`Packets denied by network policy${summaryStats.totalDrops > 0 ? ' — review your policies for misconfigurations' : ''}`}
            >
              <ShieldAlert className={`w-3.5 h-3.5 ${summaryStats.totalDrops > 0 ? 'text-hubble-error' : 'text-secondary'}`} />
              <span className="font-medium font-mono tabular-nums">{summaryStats.totalDrops}</span>
            </div>
          </div>
        </Panel>

        {/* Edge legend — decode the trust-state colors */}
        {showTraffic && (
          <Panel position="bottom-left">
            <div className="flex items-center gap-3 px-3 py-1.5 rounded-surface bg-hubble-card/90 border border-hubble-border backdrop-blur-sm text-[11px] text-secondary">
              <span className="flex items-center gap-1.5"><span className="w-3.5 h-0.5 rounded-full" style={{ background: '#4E3AD9' }} />Trusted</span>
              <span className="flex items-center gap-1.5"><span className="w-3.5 h-0 border-t-2 border-dashed" style={{ borderColor: '#F59E0B' }} />Egress</span>
              <span className="flex items-center gap-1.5"><span className="w-3.5 h-[3px] rounded-full" style={{ background: '#EF4444' }} />Denied</span>
            </div>
          </Panel>
        )}

        {/* Graph controls */}
        <Panel position="top-right">
          <div className="flex gap-2">
            <button
              onClick={onToggleTraffic}
              className={`flex items-center gap-2 h-8 px-3 rounded-control border text-xs font-medium transition-colors ${
                showTraffic
                  ? 'bg-hubble-accent/15 border-hubble-accent/50 text-hubble-accent hover:bg-hubble-accent/25'
                  : 'bg-hubble-card border-hubble-border text-tertiary hover:border-hubble-border-strong hover:text-secondary'
              }`}
              title={showTraffic ? 'Hide traffic edges' : 'Show traffic edges'}
            >
              {showTraffic ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
              Traffic
            </button>
            {showTraffic && (
              <button
                onClick={onToggleExternalNodes}
                className={`flex items-center gap-2 h-8 px-3 rounded-control border text-xs font-medium transition-colors ${
                  showExternalNodes
                    ? 'bg-hubble-warning/15 border-hubble-warning/50 text-hubble-warning hover:bg-hubble-warning/25'
                    : 'bg-hubble-card border-hubble-border text-tertiary hover:border-hubble-border-strong hover:text-secondary'
                }`}
                title={showExternalNodes ? 'Hide external namespace nodes' : 'Show external namespace nodes'}
              >
                {showExternalNodes ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
                External{externalCount > 0 ? ` (${externalCount})` : ''}
              </button>
            )}
            {showTraffic && (
              <button
                onClick={onToggleLayoutDirection}
                className="flex items-center gap-2 h-8 px-3 rounded-control border text-xs font-medium transition-colors
                           bg-hubble-card border-hubble-border text-secondary hover:border-hubble-border-strong hover:text-primary"
                title={`Switch to ${layoutDirection === 'LR' ? 'vertical' : 'horizontal'} layout`}
              >
                {layoutDirection === 'LR' ? <ArrowRight className="w-3.5 h-3.5" /> : <ArrowDown className="w-3.5 h-3.5" />}
                Layout
              </button>
            )}
          </div>
        </Panel>
      </ReactFlow>
    </div>
  );
};

// Wrapper component to provide ReactFlow context
const NetworkGraph: React.FC<NetworkGraphProps> = (props) => {
  return (
    <ReactFlowProvider>
      <NetworkGraphInner {...props} />
    </ReactFlowProvider>
  );
};

export default NetworkGraph;
