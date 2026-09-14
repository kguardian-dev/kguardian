import React from 'react';
import { Handle, Position } from 'reactflow';
import { ChevronDown, ChevronRight, Network, Server, Globe, FileCode, Crosshair, Cpu, MemoryStick, Zap, Gauge } from 'lucide-react';
import { isDaemonSetOrHostNetworkPod } from '../utils/daemonSetPeers';
import type { PodNodeData } from '../types';
import type { PodComputeData } from '../types/compute';
import { Button } from './ui/Button';
import { Sparkline } from './ui/Sparkline';
import {
  COMPUTE_DOT_CLASS,
  COMPUTE_HISTORY_WINDOW_LABEL,
  denominatorLabel,
  formatBytes,
  formatMillicores,
  formatPercent,
  hasComputeGauges,
  culpritUsageLabel,
  starvedBy,
  statusTooltip,
  throttledFinding,
} from '../utils/compute';

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

/** Bar fill colour by how full the gauge is: past the denominator is an error. */
function gaugeFillClass(pct: number | null): string {
  if (pct === null) return 'bg-hubble-border';
  if (pct >= 100) return 'bg-hubble-error';
  if (pct >= 80) return 'bg-hubble-warning';
  return 'bg-hubble-accent';
}

const gaugeTitle = (label: string, value: string, pct: number | null, den: PodComputeData['cpuDenominator'], capacity: string) =>
  pct === null
    ? `${label} ${value} (${denominatorLabel(den)})`
    : `${label} ${value} — ${formatPercent(pct)} of ${capacity} ${denominatorLabel(den)}`;

/** Two-segment micro bar (CPU %, memory %) under the title. */
const ComputeMicroBar: React.FC<{ compute: PodComputeData }> = ({ compute }) => {
  const cpuTitle = gaugeTitle('CPU', formatMillicores(compute.cpuMillis), compute.cpuPct, compute.cpuDenominator, formatMillicores(compute.cpuCapacityMillis));
  const memTitle = gaugeTitle('Memory', formatBytes(compute.memBytes), compute.memPct, compute.memDenominator, formatBytes(compute.memCapacityBytes));
  const seg = (pct: number | null, title: string, testId: string) => (
    <div className="flex-1 h-1.5 rounded-full bg-hubble-border/60 overflow-hidden" title={title} role="img" aria-label={title} data-testid={testId}>
      <div
        className={`h-full rounded-full ${gaugeFillClass(pct)} transition-[width] duration-500`}
        style={{ width: `${pct === null ? 0 : Math.min(100, Math.max(0, pct))}%` }}
      />
    </div>
  );
  return (
    <div className="mt-1.5 flex items-center gap-1.5" data-testid="compute-microbar">
      <Cpu className="w-3 h-3 text-tertiary shrink-0" />
      {seg(compute.cpuPct, cpuTitle, 'compute-cpu-bar')}
      <MemoryStick className="w-3 h-3 text-tertiary shrink-0" />
      {seg(compute.memPct, memTitle, 'compute-mem-bar')}
    </div>
  );
};

/** Expanded-body sparklines + finding chips. */
const ComputeDetail: React.FC<{ compute: PodComputeData }> = ({ compute }) => {
  const starved = starvedBy(compute.findings);
  const throttled = throttledFinding(compute.findings);
  const culprit = starved?.culprit;
  const culpritLabel = culprit
    ? culprit.kind === 'pod' && culprit.pod_name
      ? `${culprit.namespace ?? ''}/${culprit.pod_name}`
      : culprit.ref
    : null;
  // The sparkline's ceiling is the same denominator as the micro bar when it
  // is the pod's own limit or request. Against NODE capacity (a request-less
  // pod on a 32-core node) that would flatten every line to the baseline, so
  // those auto-scale to the buffer's own maximum instead.
  const cpuMax = compute.cpuDenominator === 'node' ? null : compute.cpuCapacityMillis;
  const memMax = compute.memDenominator === 'node' ? null : compute.memCapacityBytes;
  return (
    <div className="space-y-2" data-testid="compute-detail">
      <div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-tertiary flex items-center gap-1"><Cpu className="w-3 h-3" />CPU</span>
          <span className="font-mono tabular-nums text-secondary">
            {formatMillicores(compute.cpuMillis)}
            {compute.cpuCapacityMillis !== null && (
              <span className="text-tertiary"> / {formatMillicores(compute.cpuCapacityMillis)} {denominatorLabel(compute.cpuDenominator)}</span>
            )}
          </span>
        </div>
        <Sparkline
          values={compute.sparkCpu}
          max={cpuMax}
          height={26}
          title={`CPU, ${COMPUTE_HISTORY_WINDOW_LABEL}`}
        />
      </div>
      <div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-tertiary flex items-center gap-1"><MemoryStick className="w-3 h-3" />Memory</span>
          <span className="font-mono tabular-nums text-secondary">
            {formatBytes(compute.memBytes)}
            {compute.memCapacityBytes !== null && (
              <span className="text-tertiary"> / {formatBytes(compute.memCapacityBytes)} {denominatorLabel(compute.memDenominator)}</span>
            )}
          </span>
        </div>
        <Sparkline
          values={compute.sparkMem}
          max={memMax}
          height={26}
          color="var(--color-hubble-info)"
          title={`Working set, ${COMPUTE_HISTORY_WINDOW_LABEL}`}
        />
      </div>
      {(starved || throttled) && (
        <div className="flex flex-wrap gap-1">
          {starved && culpritLabel && (
            <span
              className="inline-flex items-center gap-1 rounded-full border border-hubble-error/30 bg-hubble-error/15 text-hubble-error px-2 py-0.5 text-[10px] font-medium"
              title={culprit?.cpu_usage_millis === null ? `${starved.message} — ${culpritUsageLabel(null)}` : starved.message}
              data-testid="compute-starved-chip"
            >
              <Zap className="w-3 h-3" />
              Starved by {culpritLabel}
            </span>
          )}
          {throttled && (
            <span
              className="inline-flex items-center gap-1 rounded-full border border-hubble-warning/30 bg-hubble-warning/15 text-hubble-warning px-2 py-0.5 text-[10px] font-medium"
              title={throttled.message}
              data-testid="compute-throttled-chip"
            >
              <Gauge className="w-3 h-3" />
              Throttled {formatPercent(throttled.evidence.throttled_ratio * 100)}
            </span>
          )}
        </div>
      )}
    </div>
  );
};

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
  // Compute gauges (design D8). `compute` absent ⇒ the card is exactly the
  // pre-feature card; present without rows ⇒ just the muted dot + tooltip.
  const compute = data.compute;
  const gauged = compute !== undefined && hasComputeGauges(compute);
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
            <div className="flex items-center gap-1.5 min-w-0">
              {compute && (
                <span
                  className={`shrink-0 w-2 h-2 rounded-full ${COMPUTE_DOT_CLASS[compute.status]}`}
                  title={statusTooltip(compute.status, compute.findings, compute.probeDrops)}
                  role="img"
                  aria-label={statusTooltip(compute.status, compute.findings, compute.probeDrops)}
                  data-testid="compute-status-dot"
                  data-status={compute.status}
                />
              )}
              <div className="font-semibold text-sm text-primary truncate" title={data.tooltip ?? identityName}>
                {identityName}
              </div>
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
            {gauged && <ComputeMicroBar compute={compute} />}
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
          {gauged && <ComputeDetail compute={compute} />}
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
    prevProps.data.layoutDirection === nextProps.data.layoutDirection &&
    // A new compute object arrives with every 5 s poll; identity is the
    // cheapest correct signal (usePodData builds a fresh one per gauged pod).
    prevProps.data.compute === nextProps.data.compute
  );
});

export default PodNode;
