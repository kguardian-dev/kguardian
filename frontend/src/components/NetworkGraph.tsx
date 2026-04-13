import React, { useCallback, useMemo, useEffect, useState } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  MarkerType,
  useReactFlow,
  ReactFlowProvider,
  Panel,
} from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import ELK from 'elkjs/lib/elk.bundled.js';
import { Eye, EyeOff, Activity, ShieldAlert, Server } from 'lucide-react';
import PodNode from './PodNode';
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
}) => {
  const { fitView } = useReactFlow();

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

  // Discover external endpoints from traffic data, split by direction
  // Ingress sources (-in suffix) go on the left, egress destinations (-out suffix) on the right
  const externalNodes = useMemo(() => {
    if (!showExternalNodes || !showTraffic) return [];

    // Step 1: Classify each external IP's traffic by direction
    const externalIpData = new Map<string, {
      podInfo: PodInfo | null;
      ip: string;
      ingressTraffic: NetworkTraffic[];
      egressTraffic: NetworkTraffic[];
    }>();

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        const remoteIp = traffic.traffic_in_out_ip;
        if (!remoteIp) return;
        if (ipToLocalPodMap.has(remoteIp)) return;
        if (svcIpToLocalPodMap.has(remoteIp)) return;

        if (!externalIpData.has(remoteIp)) {
          externalIpData.set(remoteIp, {
            podInfo: ipToAllPodsMap.get(remoteIp) || null,
            ip: remoteIp,
            ingressTraffic: [],
            egressTraffic: [],
          });
        }
        const entry = externalIpData.get(remoteIp)!;
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
    const podIpsToMerge: Array<[string, string]> = [];
    externalIpData.forEach((_entry, ip) => {
      const svcIp = podIpToSvcIp.get(ip);
      if (svcIp && svcIpLookup.has(svcIp)) podIpsToMerge.push([ip, svcIp]);
    });
    podIpsToMerge.forEach(([podIp, svcIp]) => {
      const entry = externalIpData.get(podIp)!;
      if (!externalIpData.has(svcIp)) {
        externalIpData.set(svcIp, { podInfo: null, ip: svcIp, ingressTraffic: [], egressTraffic: [] });
      }
      const svcEntry = externalIpData.get(svcIp)!;
      svcEntry.ingressTraffic.push(...entry.ingressTraffic);
      svcEntry.egressTraffic.push(...entry.egressTraffic);
      externalIpData.delete(podIp);
      if (!mergedBackingIps.has(svcIp)) mergedBackingIps.set(svcIp, []);
      mergedBackingIps.get(svcIp)!.push(podIp);
    });

    // Step 3: Group by identity, tracking direction-specific traffic
    interface IdentityGroup {
      memberPods: PodInfo[];
      ingressTraffic: NetworkTraffic[];
      egressTraffic: NetworkTraffic[];
    }

    const identityMap = new Map<string, IdentityGroup>();
    const internetEntries: { pod: PodInfo; ingressTraffic: NetworkTraffic[]; egressTraffic: NetworkTraffic[] }[] = [];

    externalIpData.forEach((ext) => {
      // First check service IPs (takes priority regardless of podInfo)
      const svc = svcIpLookup.get(ext.ip);
      if (svc) {
        const ns = svc.svc_namespace || 'unknown';
        const name = svc.svc_name || ext.ip;
        const key = `external-svc-${ns}-${name}`;
        if (!identityMap.has(key)) {
          identityMap.set(key, { memberPods: [], ingressTraffic: [], egressTraffic: [] });
        }
        const group = identityMap.get(key)!;
        const backingIps = mergedBackingIps.get(ext.ip) || [];
        if (backingIps.length > 0) {
          // Use only the real backing pod IPs so the pod count reflects actual pods.
          // The service ClusterIP is a virtual IP and should not count as a pod.
          // Edge resolution for "→ service ClusterIP" traffic is handled in the edge
          // building step by indexing the canonical service IP from each backing pod IP.
          backingIps.forEach((backingIp) => {
            group.memberPods.push({
              pod_name: name,
              pod_ip: backingIp,
              pod_namespace: ns,
              pod_identity: name,
              time_stamp: '',
              node_name: '',
              is_dead: false,
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

      // Cross-namespace pod (not dead) — use pod_identity if available, fall back to pod_name
      // for standalone pods created without a Deployment/ReplicaSet (pod_identity is null)
      if (ext.podInfo && !ext.podInfo.is_dead) {
        const identity = ext.podInfo.pod_identity || ext.podInfo.pod_name;
        const ns = ext.podInfo.pod_namespace || 'unknown';
        const key = `external-${ns}-${identity}`;
        if (!identityMap.has(key)) {
          identityMap.set(key, { memberPods: [], ingressTraffic: [], egressTraffic: [] });
        }
        const group = identityMap.get(key)!;
        group.memberPods.push(ext.podInfo);
        group.ingressTraffic.push(...ext.ingressTraffic);
        group.egressTraffic.push(...ext.egressTraffic);
        return;
      }

      // Dead pod — IP belonged to a pod that no longer exists; skip entirely
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
        });
      }
    };

    identityMap.forEach((group, key) => {
      const primary = group.memberPods[0];
      addDirectionalNodes(
        key,
        primary.pod_identity || primary.pod_name,
        group.memberPods,
        group.ingressTraffic,
        group.egressTraffic,
        primary.pod_namespace || 'unknown',
      );
    });

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
  }, [pods, showExternalNodes, showTraffic, ipToLocalPodMap, ipToAllPodsMap, svcIpToLocalPodMap, services, podIpToSvcIp]);

  // Combine in-namespace and external pods for rendering
  // When traffic is enabled, hide local pods that have no traffic
  const allDisplayPods = useMemo(() => {
    const visiblePods = showTraffic
      ? pods.filter((pod) => pod.traffic && pod.traffic.length > 0)
      : pods;
    return [...visiblePods, ...externalNodes];
  }, [pods, externalNodes, showTraffic]);

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
        },
        selected: pod.id === selectedPodId,
      };
    });
  }, [allDisplayPods, onPodToggle, selectedPodId, onBuildPolicy, layoutDirection]);

  // Track ELK-computed node positions
  const [elkPositions, setElkPositions] = useState<Map<string, { x: number; y: number }>>(new Map());

  // Track whether ELK layout is being computed
  const [isLayoutLoading, setIsLayoutLoading] = useState(false);

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

    // Build direction-specific IP lookups for external nodes
    const ingressExternalIpMap = new Map<string, PodNodeData>();
    const egressExternalIpMap = new Map<string, PodNodeData>();
    allDisplayPods.forEach((pod) => {
      if (!pod.isExternal) return;
      const isInNode = pod.id.endsWith('-in');
      const isOutNode = pod.id.endsWith('-out');
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

        const trafficType = traffic.traffic_type?.toLowerCase();
        if (trafficType === 'egress') {
          sourcePod = pod;
          // Egress: remote IP is the destination → resolve to local pod, service IP, or egress-external node.
          // If the remote IP is a backing pod IP for a cross-namespace service, resolve via the service ClusterIP
          // so that curl→serviceIP and curl→podIP collapse to the same external node.
          if (remoteIp) {
            const canonicalIp = podIpToSvcIp.get(remoteIp) ?? remoteIp;
            destPod = ipToLocalPodMap.get(remoteIp)
              || svcIpToLocalPodMap.get(remoteIp)
              || egressExternalIpMap.get(remoteIp)
              || egressExternalIpMap.get(canonicalIp);
          }
        } else if (trafficType === 'ingress') {
          // Ingress: remote IP is the source → resolve to local pod, service IP, or ingress-external node.
          // If the remote IP is a backing pod IP, also check the canonical service ClusterIP
          // (mirrors the egress canonicalization logic).
          if (remoteIp) {
            const canonicalIp = podIpToSvcIp.get(remoteIp) ?? remoteIp;
            sourcePod = ipToLocalPodMap.get(remoteIp)
              || svcIpToLocalPodMap.get(remoteIp)
              || ingressExternalIpMap.get(remoteIp)
              || ingressExternalIpMap.get(canonicalIp);
          }
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

      // Determine stroke color: red for drops, amber for external, blue for internal
      const strokeColor = dropCount > 0 ? '#EF4444' : isExternal ? '#F59E0B' : '#3B82F6';

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
          strokeWidth: Math.min(count / 2 + 1, 4),
          strokeDasharray: isExternal ? '5 5' : undefined,
        },
        label,
        labelStyle: {
          fill: 'var(--theme-text-secondary)',
          fontSize: 11,
          fontFamily: 'monospace',
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
  }, [pods, allDisplayPods, ipToLocalPodMap, svcIpToLocalPodMap, showTraffic, wellKnownPorts, podIpToSvcIp]);

  // Run ELK layout whenever nodes or edges change
  useEffect(() => {
    if (baseNodes.length === 0) {
      setElkPositions(new Map());
      return;
    }

    setIsLayoutLoading(true);

    // Only include edges whose source and target exist in the current node set
    const nodeIds = new Set(baseNodes.map((n) => n.id));
    const validEdges = initialEdges.filter(
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
      children: baseNodes.map((node) => {
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
      setIsLayoutLoading(false);
    }).catch((err) => {
      // Fallback: simple grid layout if ELK fails
      console.error('ELK layout error, using fallback grid:', err);
      const positions = new Map<string, { x: number; y: number }>();
      const cols = Math.ceil(Math.sqrt(baseNodes.length));
      baseNodes.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions.set(node.id, {
          x: col * (NODE_WIDTH + 80),
          y: row * (NODE_HEIGHT + 80),
        });
      });
      setElkPositions(positions);
      setIsLayoutLoading(false);
    });
  }, [baseNodes, initialEdges, layoutDirection]);

  // Merge ELK positions into nodes — hide nodes until ELK has run for the current set
  const positionedNodes: Node[] = useMemo(() => {
    // Check if ELK has computed positions for these specific nodes
    const hasPositions = baseNodes.length > 0 && baseNodes.some((n) => elkPositions.has(n.id));
    if (!hasPositions) return [];
    return baseNodes.map((node) => ({
      ...node,
      position: elkPositions.get(node.id) ?? { x: -9999, y: -9999 },
    }));
  }, [baseNodes, elkPositions]);

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
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

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
    <div className="w-full h-full relative">
      {isLayoutLoading && (
        <div className="absolute inset-0 z-10 flex items-center justify-center pointer-events-none">
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-hubble-card/90 border border-hubble-border backdrop-blur-sm text-xs text-secondary">
            <span
              className="inline-block w-3 h-3 rounded-full border-2 border-hubble-accent border-t-transparent animate-spin"
              aria-hidden="true"
            />
            Computing layout...
          </div>
        </div>
      )}
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
        <Background
          variant={BackgroundVariant.Dots}
          gap={16}
          size={1}
          color="var(--theme-border)"
        />

        {/* Security Summary Panel */}
        <Panel position="top-left">
          <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-hubble-card/90 border border-hubble-border backdrop-blur-sm text-xs">
            <div className="flex items-center gap-1.5 text-secondary" title="Total workload identities in the current namespace">
              <Server className="w-3.5 h-3.5 text-hubble-accent" />
              <span className="font-medium">{summaryStats.podCount}</span>
            </div>
            <div className="w-px h-4 bg-hubble-border" />
            <div className="flex items-center gap-1.5 text-secondary" title="Total observed network flows (ingress + egress) across all pods">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              <span className="font-medium">{summaryStats.totalFlows.toLocaleString()}</span>
            </div>
            <div className="w-px h-4 bg-hubble-border" />
            <div
              className={`flex items-center gap-1.5 ${summaryStats.totalDrops > 0 ? 'text-red-400' : 'text-secondary'}`}
              title={`Packets denied by network policy${summaryStats.totalDrops > 0 ? ' — review your policies for misconfigurations' : ''}`}
            >
              <ShieldAlert className={`w-3.5 h-3.5 ${summaryStats.totalDrops > 0 ? 'text-red-400' : 'text-secondary'}`} />
              <span className="font-medium">{summaryStats.totalDrops}</span>
            </div>
          </div>
        </Panel>

        {/* Graph controls */}
        <Panel position="top-right">
          <div className="flex gap-2">
            <button
              onClick={onToggleTraffic}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all ${
                showTraffic
                  ? 'bg-blue-500/20 border-blue-500/50 text-blue-400 hover:bg-blue-500/30'
                  : 'bg-hubble-card border-hubble-border text-tertiary hover:border-hubble-accent'
              }`}
              title={showTraffic ? 'Hide traffic edges' : 'Show traffic edges'}
            >
              {showTraffic ? (
                <Eye className="w-3.5 h-3.5" />
              ) : (
                <EyeOff className="w-3.5 h-3.5" />
              )}
              Traffic
            </button>
            {showTraffic && (
              <button
                onClick={onToggleExternalNodes}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all ${
                  showExternalNodes
                    ? 'bg-amber-500/20 border-amber-500/50 text-amber-400 hover:bg-amber-500/30'
                    : 'bg-hubble-card border-hubble-border text-tertiary hover:border-hubble-accent'
                }`}
                title={showExternalNodes ? 'Hide external namespace nodes' : 'Show external namespace nodes'}
              >
                {showExternalNodes ? (
                  <Eye className="w-3.5 h-3.5" />
                ) : (
                  <EyeOff className="w-3.5 h-3.5" />
                )}
                External{externalCount > 0 ? ` (${externalCount})` : ''}
              </button>
            )}
            {showTraffic && (
              <button
                onClick={onToggleLayoutDirection}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all
                           bg-hubble-card border-hubble-border text-secondary hover:border-hubble-accent"
                title={`Switch to ${layoutDirection === 'LR' ? 'vertical' : 'horizontal'} layout`}
              >
                Layout: {layoutDirection === 'LR' ? '\u2192' : '\u2193'}
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
