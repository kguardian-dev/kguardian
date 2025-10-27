import React from 'react';
import { Handle, Position } from 'reactflow';
import { ChevronDown, ChevronRight, Network, Server } from 'lucide-react';
import type { PodNodeData } from '../types';

interface PodNodeProps {
  data: PodNodeData & { onToggle: (id: string) => void };
  selected?: boolean;
}

const PodNode: React.FC<PodNodeProps> = ({ data, selected }) => {
  const trafficCount = data.traffic?.length || 0;

  // Count total syscalls from comma-separated strings
  const syscallCount = data.syscalls?.reduce((total, syscallRecord) => {
    const syscalls = syscallRecord.syscalls.split(',').filter(s => s.trim());
    return total + syscalls.length;
  }, 0) || 0;

  return (
    <div
      className={`
        px-4 py-3 rounded-lg border-2 transition-all min-w-[200px]
        ${
          selected
            ? 'border-hubble-accent bg-hubble-card shadow-lg shadow-hubble-accent/20'
            : 'border-hubble-border bg-hubble-card hover:border-hubble-accent/50'
        }
      `}
    >
      <Handle type="target" position={Position.Left} />

      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 flex-1">
          <button
            onClick={() => data.onToggle(data.id)}
            className="text-hubble-accent hover:text-blue-400 transition-colors"
          >
            {data.isExpanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>

          <Server className="w-5 h-5 text-hubble-accent" />

          <div className="flex-1">
            <div className="font-semibold text-sm text-gray-100">
              {data.label}
            </div>
            <div className="text-xs text-gray-400">
              {data.pod.pod_namespace}
            </div>
          </div>
        </div>
      </div>

      {data.isExpanded && (
        <div className="mt-3 pt-3 border-t border-hubble-border space-y-2">
          <div className="text-xs text-gray-400">
            <div className="flex items-center gap-1">
              <span className="font-mono">{data.pod.pod_ip}</span>
            </div>
          </div>

          <div className="flex gap-3 text-xs">
            <div className="flex items-center gap-1">
              <Network className="w-3 h-3 text-hubble-success" />
              <span className="text-gray-300">
                {trafficCount} connections
              </span>
            </div>

            {syscallCount > 0 && (
              <div className="flex items-center gap-1">
                <span className="text-gray-300">
                  {syscallCount} syscalls
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      <Handle type="source" position={Position.Right} />
    </div>
  );
};

export default PodNode;
