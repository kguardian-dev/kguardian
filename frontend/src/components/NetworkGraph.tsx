import React, { useCallback, useMemo, useEffect } from 'react';
import ReactFlow, {
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  addEdge,
  MarkerType,
  useReactFlow,
  ReactFlowProvider,
} from 'reactflow';
import type { Node, Edge, Connection } from 'reactflow';
import 'reactflow/dist/style.css';
import PodNode from './PodNode';
import type { PodNodeData } from '../types';
import { UI_TIMING } from '../constants/ui';

interface NetworkGraphProps {
  pods: PodNodeData[];
  onPodToggle: (podId: string) => void;
  onPodSelect: (pod: PodNodeData | null) => void;
  selectedPodId: string | null;
  onBuildPolicy?: (pod: PodNodeData) => void;
}

// Define nodeTypes outside component to prevent recreation
const nodeTypes = {
  podNode: PodNode,
} as const;

const NetworkGraphInner: React.FC<NetworkGraphProps> = ({
  pods,
  onPodToggle,
  onPodSelect,
  selectedPodId,
  onBuildPolicy,
}) => {
  const { fitView } = useReactFlow();
  // Convert pod data to React Flow nodes
  const initialNodes: Node[] = useMemo(() => {
    return pods.map((pod, index) => ({
      id: pod.id,
      type: 'podNode',
      position: {
        x: 100 + (index % 3) * 300,
        y: 100 + Math.floor(index / 3) * 200,
      },
      data: {
        ...pod,
        onToggle: onPodToggle,
        onBuildPolicy,
      },
      selected: pod.id === selectedPodId,
    }));
  }, [pods, onPodToggle, selectedPodId, onBuildPolicy]);

  // Generate edges from network traffic data
  const initialEdges: Edge[] = useMemo(() => {
    const edges: Edge[] = [];
    const edgeMap = new Map<string, number>();

    // Create IP to pod lookup map for O(1) access
    // Using IP for now since traffic records use traffic_in_out_ip
    // This maps IPs to their pod identities (handles multiple replicas)
    const ipToPodMap = new Map<string, PodNodeData>();
    pods.forEach((pod) => {
      // Map primary pod IP
      if (pod.pod.pod_ip) {
        ipToPodMap.set(pod.pod.pod_ip, pod);
      }
      // Map all replica IPs to the same identity
      pod.pods?.forEach((p) => {
        if (p.pod_ip) {
          ipToPodMap.set(p.pod_ip, pod);
        }
      });
    });

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        // Find the other pod based on traffic direction
        let sourcePod, destPod;

        if (traffic.traffic_type === 'egress') {
          // Pod is source, traffic_in_out_ip is destination
          sourcePod = pod;
          destPod = traffic.traffic_in_out_ip ? ipToPodMap.get(traffic.traffic_in_out_ip) : undefined;
        } else if (traffic.traffic_type === 'ingress') {
          // Pod is destination, traffic_in_out_ip is source
          sourcePod = traffic.traffic_in_out_ip ? ipToPodMap.get(traffic.traffic_in_out_ip) : undefined;
          destPod = pod;
        }

        if (sourcePod && destPod && sourcePod.id !== destPod.id) {
          const edgeKey = `${sourcePod.id}-${destPod.id}`;
          edgeMap.set(edgeKey, (edgeMap.get(edgeKey) || 0) + 1);
        }
      });
    });

    // Create edges with traffic count
    edgeMap.forEach((count, key) => {
      const [source, target] = key.split('-');
      edges.push({
        id: key,
        source,
        target,
        animated: true,
        style: {
          stroke: '#3B82F6',
          strokeWidth: Math.min(count / 2 + 1, 4),
        },
        label: `${count}`,
        labelStyle: {
          fill: '#9CA3AF',
          fontSize: 12,
        },
        labelBgStyle: {
          fill: '#1A2332',
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#3B82F6',
        },
      });
    });

    return edges;
  }, [pods]);

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
    if (nodes.length > 0) {
      // Small delay to ensure nodes are rendered before fitting
      setTimeout(() => {
        fitView({ padding: 0.2, duration: UI_TIMING.FIT_VIEW_DURATION });
      }, UI_TIMING.FIT_VIEW_DELAY);
    }
  }, [nodes, fitView]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      const pod = pods.find((p) => p.id === node.id);
      onPodSelect(pod || null);
    },
    [pods, onPodSelect]
  );

  const onPaneClick = useCallback(() => {
    onPodSelect(null);
  }, [onPodSelect]);

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={onNodeClick}
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
          color="#2A3647"
        />
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
