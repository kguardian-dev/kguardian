import React, { useCallback, useMemo } from 'react';
import ReactFlow, {
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  addEdge,
  MarkerType,
} from 'reactflow';
import type { Node, Edge, Connection } from 'reactflow';
import 'reactflow/dist/style.css';
import PodNode from './PodNode';
import type { PodNodeData } from '../types';

interface NetworkGraphProps {
  pods: PodNodeData[];
  onPodToggle: (podId: string) => void;
  onPodSelect: (pod: PodNodeData | null) => void;
  selectedPodId: string | null;
}

const nodeTypes = {
  podNode: PodNode,
};

const NetworkGraph: React.FC<NetworkGraphProps> = ({
  pods,
  onPodToggle,
  onPodSelect,
  selectedPodId,
}) => {
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
      },
      selected: pod.id === selectedPodId,
    }));
  }, [pods, onPodToggle, selectedPodId]);

  // Generate edges from network traffic data
  const initialEdges: Edge[] = useMemo(() => {
    const edges: Edge[] = [];
    const edgeMap = new Map<string, number>();

    pods.forEach((pod) => {
      pod.traffic?.forEach((traffic) => {
        // Traffic has pod_ip and traffic_in_out_ip
        // Find the other pod based on traffic direction
        let sourcePod, destPod;

        if (traffic.traffic_type === 'egress') {
          // Pod is source, traffic_in_out_ip is destination
          sourcePod = pod;
          destPod = pods.find((p) => p.pod.pod_ip === traffic.traffic_in_out_ip);
        } else if (traffic.traffic_type === 'ingress') {
          // Pod is destination, traffic_in_out_ip is source
          sourcePod = pods.find((p) => p.pod.pod_ip === traffic.traffic_in_out_ip);
          destPod = pod;
        }

        if (sourcePod && destPod && sourcePod.id !== destPod.id) {
          const edgeKey = `${sourcePod.id}-${destPod.id}`;
          const count = (edgeMap.get(edgeKey) || 0) + 1;
          edgeMap.set(edgeKey, count);
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
  React.useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  // Update edges when traffic changes
  React.useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

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

export default NetworkGraph;
