import React, { useCallback, useMemo, useEffect } from 'react';
import ReactFlow, {
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  MarkerType,
  useReactFlow,
  ReactFlowProvider,
  Panel,
} from 'reactflow';
import type { Node, Edge } from 'reactflow';
import 'reactflow/dist/style.css';
import { Eye, EyeOff } from 'lucide-react';
import PodNode from './PodNode';
import type { PodNodeData, PodInfo, ServiceInfo } from '../types';
import { UI_TIMING } from '../constants/ui';

interface NetworkGraphProps {
  pods: PodNodeData[];
  allPodsLookup: PodInfo[];
  services: ServiceInfo[];
  showExternalNodes: boolean;
  onToggleExternalNodes: () => void;
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

  // Discover external endpoints from traffic data
  const externalNodes = useMemo(() => {
    if (!showExternalNodes) return [];

    const externalMap = new Map<string, {
      podInfo: PodInfo | null;
      trafficCount: number;
      ip: string;
    }>();

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        const remoteIp = traffic.traffic_in_out_ip;
        if (!remoteIp) return;

        // Skip if this IP belongs to an in-namespace pod
        if (ipToLocalPodMap.has(remoteIp)) return;

        // Skip if this IP is a service ClusterIP that resolves to a local pod
        if (svcIpToLocalPodMap.has(remoteIp)) return;

        // This is an external IP - either cross-namespace pod or unknown
        if (!externalMap.has(remoteIp)) {
          const remotePod = ipToAllPodsMap.get(remoteIp) || null;
          externalMap.set(remoteIp, {
            podInfo: remotePod,
            trafficCount: 0,
            ip: remoteIp,
          });
        }
        externalMap.get(remoteIp)!.trafficCount++;
      });
    });

    // Build service IP lookup for classifying external IPs
    const svcIpLookup = new Map<string, ServiceInfo>();
    services.forEach((svc) => {
      if (svc.svc_ip) svcIpLookup.set(svc.svc_ip, svc);
    });

    // Group cross-namespace pods by identity, aggregate unknown IPs into one node
    const identityMap = new Map<string, {
      pods: PodInfo[];
      trafficCount: number;
      ip: string;
    }>();
    let internetTrafficCount = 0;
    const internetIps: PodInfo[] = [];

    externalMap.forEach((ext) => {
      if (ext.podInfo) {
        const identity = ext.podInfo.pod_identity || ext.podInfo.pod_name;
        const ns = ext.podInfo.pod_namespace || 'unknown';
        const key = `external-${ns}-${identity}`;
        if (!identityMap.has(key)) {
          identityMap.set(key, { pods: [], trafficCount: 0, ip: ext.ip });
        }
        const group = identityMap.get(key)!;
        group.pods.push(ext.podInfo);
        group.trafficCount += ext.trafficCount;
      } else {
        // Check if this IP is a known service ClusterIP
        const svc = svcIpLookup.get(ext.ip);
        if (svc) {
          // Show as a named service node instead of raw IP
          const ns = svc.svc_namespace || 'unknown';
          const name = svc.svc_name || ext.ip;
          const key = `external-svc-${ns}-${name}`;
          if (!identityMap.has(key)) {
            identityMap.set(key, { pods: [], trafficCount: 0, ip: ext.ip });
          }
          const group = identityMap.get(key)!;
          group.pods.push({
            pod_name: name,
            pod_ip: ext.ip,
            pod_namespace: ns,
            pod_identity: name,
            time_stamp: '',
            node_name: '',
            is_dead: false,
          });
          group.trafficCount += ext.trafficCount;
        } else {
          // Unknown external IP — aggregate into single Internet node
          internetTrafficCount += ext.trafficCount;
          internetIps.push({
            pod_name: ext.ip,
            pod_ip: ext.ip,
            pod_namespace: 'internet',
            time_stamp: '',
            node_name: '',
            is_dead: false,
          });
        }
      }
    });

    // Convert to PodNodeData for rendering
    const externalPodNodes: PodNodeData[] = [];
    identityMap.forEach((group, key) => {
      const primary = group.pods[0];
      externalPodNodes.push({
        id: key,
        label: primary.pod_identity || primary.pod_name,
        pod: primary,
        pods: group.pods,
        traffic: [],
        isExpanded: false,
        isExternal: true,
        externalNamespace: primary.pod_namespace || 'unknown',
      });
    });

    // Add single aggregated Internet node for all unknown external IPs
    if (internetIps.length > 0) {
      externalPodNodes.push({
        id: 'external-internet',
        label: `Internet (${internetIps.length} IPs)`,
        pod: {
          pod_name: 'Internet',
          pod_ip: internetIps[0].pod_ip,
          pod_namespace: 'internet',
          time_stamp: '',
          node_name: '',
          is_dead: false,
        },
        pods: internetIps,
        traffic: [],
        isExpanded: false,
        isExternal: true,
        externalNamespace: 'internet',
      });
    }

    return externalPodNodes;
  }, [pods, showExternalNodes, ipToLocalPodMap, ipToAllPodsMap, svcIpToLocalPodMap, services]);

  // Combine in-namespace and external pods for rendering
  const allDisplayPods = useMemo(() => {
    return [...pods, ...externalNodes];
  }, [pods, externalNodes]);

  // Convert pod data to React Flow nodes
  const initialNodes: Node[] = useMemo(() => {
    const localCount = pods.length;

    return allDisplayPods.map((pod, index) => {
      const isExternal = pod.isExternal || false;
      // Local pods in a grid on the left, external pods on the right
      const position = isExternal
        ? {
            x: 100 + (localCount > 0 ? Math.ceil(localCount / Math.min(localCount, 3)) : 1) * 300 + 200,
            y: 100 + (index - localCount) * 160,
          }
        : {
            x: 100 + (index % 3) * 300,
            y: 100 + Math.floor(index / 3) * 200,
          };

      return {
        id: pod.id,
        type: 'podNode',
        position,
        data: {
          ...pod,
          onToggle: isExternal ? noopToggle : onPodToggle,
          onBuildPolicy: isExternal ? undefined : onBuildPolicy,
        },
        selected: pod.id === selectedPodId,
      };
    });
  }, [allDisplayPods, pods.length, onPodToggle, selectedPodId, onBuildPolicy]);

  // Generate edges from network traffic data
  const initialEdges: Edge[] = useMemo(() => {
    const edges: Edge[] = [];
    const edgeMap = new Map<string, { count: number; isExternal: boolean }>();

    // Build combined IP lookup: local pods + external nodes + service ClusterIPs
    const ipToNodeMap = new Map<string, PodNodeData>();
    allDisplayPods.forEach((pod) => {
      if (pod.pod.pod_ip) {
        ipToNodeMap.set(pod.pod.pod_ip, pod);
      }
      pod.pods?.forEach((p) => {
        if (p.pod_ip) {
          ipToNodeMap.set(p.pod_ip, pod);
        }
      });
    });

    // Add service ClusterIPs that resolve to local pods
    svcIpToLocalPodMap.forEach((pod, svcIp) => {
      if (!ipToNodeMap.has(svcIp)) {
        ipToNodeMap.set(svcIp, pod);
      }
    });

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        let sourcePod: PodNodeData | undefined;
        let destPod: PodNodeData | undefined;

        if (traffic.traffic_type === 'egress') {
          sourcePod = pod;
          destPod = traffic.traffic_in_out_ip ? ipToNodeMap.get(traffic.traffic_in_out_ip) : undefined;
        } else if (traffic.traffic_type === 'ingress') {
          sourcePod = traffic.traffic_in_out_ip ? ipToNodeMap.get(traffic.traffic_in_out_ip) : undefined;
          destPod = pod;
        }

        if (sourcePod && destPod && sourcePod.id !== destPod.id) {
          const edgeKey = `${sourcePod.id}::${destPod.id}`;
          const isExternalEdge = !!(sourcePod.isExternal || destPod.isExternal);
          if (!edgeMap.has(edgeKey)) {
            edgeMap.set(edgeKey, { count: 0, isExternal: isExternalEdge });
          }
          edgeMap.get(edgeKey)!.count++;
        }
      });
    });

    edgeMap.forEach(({ count, isExternal }, key) => {
      const [source, target] = key.split('::');
      const strokeColor = isExternal ? '#F59E0B' : '#3B82F6';
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
        label: `${count}`,
        labelStyle: {
          fill: 'var(--theme-text-secondary)',
          fontSize: 12,
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
  }, [pods, allDisplayPods, svcIpToLocalPodMap]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update nodes when pods or selectedPodId changes
  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  // Update edges when traffic changes
  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  // Auto-fit view when pods data changes (namespace load)
  useEffect(() => {
    if (initialNodes.length > 0) {
      setTimeout(() => {
        fitView({ padding: 0.2, duration: UI_TIMING.FIT_VIEW_DURATION });
      }, UI_TIMING.FIT_VIEW_DELAY);
    }
  }, [initialNodes.length, fitView]);

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
        <Background
          variant={BackgroundVariant.Dots}
          gap={16}
          size={1}
          color="var(--theme-border)"
        />

        {/* External nodes toggle */}
        <Panel position="top-right">
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
