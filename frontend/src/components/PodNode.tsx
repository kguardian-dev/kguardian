import React from 'react';
import { Handle, Position } from 'reactflow';
import { ChevronDown, ChevronRight, Network, Server, Globe, FileCode, Crosshair } from 'lucide-react';
import { isDaemonSetOrHostNetworkPod } from '../utils/daemonSetPeers';
import type { PodNodeData } from '../types';
import { Button } from './ui/Button';

interface PodNodeProps {
  data: PodNodeData & {
    layoutDirection?: 'LR' | 'TB';
    onToggle: (id: string) => void;
    onBuildPolicy?: (pod: PodNodeData) => void;
    onFocus?: (id: string) => void;
    isFocused?: boolean;
  };
  selected?: boolean;
}

// Pseudo-namespaces of the nodes that aggregate bare IPs rather than pods.
const AGGREGATE_NAMESPACES = new Set(['internet', 'cluster', 'unattributed']);

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
  // DaemonSet / host-network peers (see utils/daemonSetPeers) take the same
  // teal as their toolbar toggle and their edges — colour alone carries the
  // association, no tag text on the card.
  const daemonSetPeer = isExternal && (data.pods && data.pods.length > 0 ? data.pods : [data.pod]).some(isDaemonSetOrHostNetworkPod);
  // Trust state → accent: external endpoints = warning amber, in-cluster
  // workloads = brand indigo, DaemonSet/host-network peers = teal. Encoded as
  // a left spine rather than a full tinted border (elevation + a spine reads
  // authored; a rounded tint box reads generic).
  const accentColor = daemonSetPeer ? 'text-hubble-info' : isExternal ? 'text-hubble-warning' : 'text-hubble-accent';
  const spineColor = daemonSetPeer ? 'border-l-hubble-info' : isExternal ? 'border-l-hubble-warning' : 'border-l-hubble-accent';

  const borderClasses = selected
    ? `border-hubble-border-strong ring-1 ring-hubble-accent/60 shadow-lg`
    : `border-hubble-border hover:border-hubble-border-strong`;

  return (
    <div
      className={`
        relative px-4 py-3 rounded-surface bg-hubble-card border border-l-[3px] ${spineColor}
        transition-colors min-w-[200px] max-w-[264px]
        ${borderClasses}
      `}
    >
      <Handle type="target" position={targetPosition} />

      <div className="flex items-start justify-between gap-2">
        {/* min-w-0 is load-bearing: without it this flex level's automatic
            minimum is the full nowrap width of a long pod/service name, the
            row overflows the card, and the focus button renders out on the
            graph canvas. Truncation only works when every nested flex level
            may shrink. */}
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {/* External endpoints aggregate traffic only — they have no syscalls
              or policy to reveal (their toggle is a no-op), so no expander. */}
          {!isExternal && (
            <button
              onClick={() => data.onToggle(data.id)}
              className={`${accentColor} hover:opacity-75 transition-colors`}
              aria-label={data.isExpanded ? 'Collapse' : 'Expand'}
            >
              {data.isExpanded ? (
                <ChevronDown className="w-4 h-4" />
              ) : (
                <ChevronRight className="w-4 h-4" />
              )}
            </button>
          )}

          <IconComponent className={`w-5 h-5 ${accentColor}`} />

          <div className="flex-1 min-w-0">
            <div className="font-semibold text-sm text-primary truncate" title={data.tooltip ?? identityName}>
              {identityName}
            </div>
            {data.externalNamespace && !AGGREGATE_NAMESPACES.has(data.externalNamespace) && (
              <div className="text-xs text-tertiary truncate" title={data.externalNamespace}>
                ns: {data.externalNamespace}
              </div>
            )}

            {podCount > 1 && (
              <div className="text-xs text-tertiary">
                {podCount} {isExternal ? (AGGREGATE_NAMESPACES.has(data.externalNamespace ?? '') ? 'IPs' : 'pods') : 'replicas'}
              </div>
            )}
          </div>
        </div>

        {data.onFocus && (
          <button
            onClick={(e) => { e.stopPropagation(); data.onFocus?.(data.id); }}
            className={`shrink-0 p-1 rounded transition-colors ${
              data.isFocused
                ? 'text-hubble-accent bg-hubble-accent/15'
                : 'text-tertiary hover:text-primary hover:bg-hubble-hover'
            }`}
            title={data.isFocused ? 'Exit focus' : 'Focus on this node’s connections'}
            aria-label={data.isFocused ? 'Exit focus' : 'Focus on connections'}
          >
            <Crosshair className="w-3.5 h-3.5" />
          </button>
        )}
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
            <Button
              variant="success"
              size="sm"
              leftIcon={FileCode}
              className="w-full mt-2"
              onClick={(e) => {
                e.stopPropagation();
                data.onBuildPolicy?.(data);
              }}
              title="Build Network Policy"
            >
              Build Policy
            </Button>
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
    prevProps.data.isFocused === nextProps.data.isFocused &&
    prevProps.selected === nextProps.selected &&
    prevProps.data.traffic?.length === nextProps.data.traffic?.length &&
    prevProps.data.syscalls?.length === nextProps.data.syscalls?.length &&
    prevProps.data.isExternal === nextProps.data.isExternal &&
    prevProps.data.layoutDirection === nextProps.data.layoutDirection
  );
});

export default PodNode;
