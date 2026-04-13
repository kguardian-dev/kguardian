import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { ChevronDown, ChevronRight, Network, Server, Globe, FileCode } from 'lucide-react';
import type { PodNodeData } from '../types';

interface PodNodeProps {
  data: PodNodeData & {
    layoutDirection?: 'LR' | 'TB';
    onToggle: (id: string) => void;
    onBuildPolicy?: (pod: PodNodeData) => void;
  };
  selected?: boolean;
}

const PodNode: React.FC<PodNodeProps> = React.memo(({ data, selected }) => {
  const trafficCount = data.traffic?.length || 0;
  const identityName = data.label || data.pod.pod_identity || data.pod.pod_name;
  const podCount = data.pods?.length || 1;
  const isExternal = data.isExternal ?? false;
  const isTB = data.layoutDirection === 'TB';
  const targetPosition = isTB ? Position.Top : Position.Left;
  const sourcePosition = isTB ? Position.Bottom : Position.Right;

  // Count total syscalls from comma-separated strings
  const syscallCount = data.syscalls?.reduce((total, syscallRecord) => {
    const syscalls = syscallRecord.syscalls.split(',').filter(s => s.trim());
    return total + syscalls.length;
  }, 0) || 0;

  const IconComponent = isExternal ? Globe : Server;
  const accentColor = isExternal ? 'text-amber-500' : 'text-hubble-accent';

  const borderClasses = isExternal
    ? selected
      ? 'border-amber-500 bg-hubble-card shadow-lg shadow-amber-500/20'
      : 'border-amber-500/40 bg-hubble-card hover:border-amber-500/60'
    : selected
      ? 'border-hubble-accent bg-hubble-card shadow-lg shadow-hubble-accent/20'
      : 'border-hubble-border bg-hubble-card hover:border-hubble-accent/50';

  return (
    <div
      className={`
        px-4 py-3 rounded-lg border-2 transition-all min-w-[200px]
        ${borderClasses}
      `}
    >
      <Handle type="target" position={targetPosition} />

      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 flex-1">
          <button
            onClick={() => data.onToggle(data.id)}
            className={`${accentColor} hover:opacity-75 transition-colors`}
          >
            {data.isExpanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>

          <IconComponent className={`w-5 h-5 ${accentColor}`} />

          <div className="flex-1">
            <div className="font-semibold text-sm text-primary">
              {identityName}
            </div>
            {data.externalNamespace && data.externalNamespace !== 'internet' && data.externalNamespace !== 'cluster' && (
              <div className="text-xs text-tertiary">
                ns: {data.externalNamespace}
              </div>
            )}
            {podCount > 1 && (
              <div className="text-xs text-tertiary">
                {podCount} {isExternal ? ((data.externalNamespace === 'internet' || data.externalNamespace === 'cluster') ? 'IPs' : 'pods') : 'replicas'}
              </div>
            )}
          </div>
        </div>
      </div>

      {data.isExpanded && (
        <div className="mt-3 pt-3 border-t border-hubble-border space-y-2">
          {trafficCount === 0 && syscallCount === 0 ? (
            <div className="text-xs text-tertiary italic">
              No traffic or syscalls recorded yet
            </div>
          ) : (
            <div className="flex gap-3 text-xs">
              <div className="flex items-center gap-1">
                <Network className="w-3 h-3 text-hubble-success" />
                <span className="text-secondary">
                  {trafficCount} connections
                </span>
              </div>

              {syscallCount > 0 && (
                <div className="flex items-center gap-1">
                  <span className="text-secondary">
                    {syscallCount} syscalls
                  </span>
                </div>
              )}
            </div>
          )}

          {!isExternal && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                data.onBuildPolicy?.(data);
              }}
              className="w-full mt-2 px-3 py-1.5 bg-hubble-success/10 border border-hubble-success/30
                         rounded text-hubble-success hover:bg-hubble-success/20 hover:border-hubble-success
                         transition-all flex items-center justify-center gap-2 text-xs font-medium"
              title="Build Network Policy"
            >
              <FileCode className="w-3 h-3" />
              Build Policy
            </button>
          )}
        </div>
      )}

      <Handle type="source" position={sourcePosition} />
    </div>
  );
}, (prevProps, nextProps) => {
  // Custom comparison function for React.memo
  // Only re-render if these specific props change
  return (
    prevProps.data.id === nextProps.data.id &&
    prevProps.data.isExpanded === nextProps.data.isExpanded &&
    prevProps.selected === nextProps.selected &&
    prevProps.data.traffic?.length === nextProps.data.traffic?.length &&
    prevProps.data.syscalls?.length === nextProps.data.syscalls?.length &&
    prevProps.data.isExternal === nextProps.data.isExternal &&
    prevProps.data.layoutDirection === nextProps.data.layoutDirection
  );
});

export default PodNode;
