import React from 'react';
import { Handle, Position } from 'reactflow';
import { Network, Server, Globe, FileCode, Cpu, MemoryStick, Zap, Gauge } from 'lucide-react';
import { isDaemonSetOrHostNetworkPod } from '../utils/daemonSetPeers';
import { cardPods, countSyscalls, podNodePropsEqual, type PodNodeRenderData } from './podNodeMemo';
import type { PodComputeData } from '../types/compute';
import { Button } from './ui/Button';
import type { LensBadge } from '../types';
import { TIER_BADGE_CLASS } from '../utils/severity';
import { Sparkline } from './ui/Sparkline';
import {
  COMPUTE_DOT_CLASS,
  COMPUTE_HISTORY_WINDOW_LABEL,
  COMPUTE_SPARK_GAP_MS,
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
  data: PodNodeRenderData;
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

/** Map lens badge tones: tiers use the tier tokens, unknown is dashed and never reads as good. */
const LENS_TONE_CLASS: Record<LensBadge['tone'], string> = {
  p0: TIER_BADGE_CLASS.P0,
  p1: TIER_BADGE_CLASS.P1,
  risk: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  warn: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  good: 'bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30',
  neutral: 'bg-hubble-border/30 text-secondary border-hubble-border',
  unknown: 'text-tertiary border-dashed border-hubble-border-strong',
};

const LensBadgeChip: React.FC<{ badge: LensBadge }> = ({ badge }) => (
  <span
    className={`shrink-0 rounded border px-1 text-[10px] font-mono font-semibold leading-4 whitespace-nowrap ${LENS_TONE_CLASS[badge.tone]}`}
    title={badge.label}
    role="img"
    aria-label={badge.label}
    data-testid="lens-badge"
    data-lens={badge.lens}
    data-tone={badge.tone}
  >
    {badge.text}
  </span>
);

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
          points={compute.sparkCpu}
          from={compute.sparkWindow.from}
          to={compute.sparkWindow.to}
          gapMs={COMPUTE_SPARK_GAP_MS}
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
          points={compute.sparkMem}
          from={compute.sparkWindow.from}
          to={compute.sparkWindow.to}
          gapMs={COMPUTE_SPARK_GAP_MS}
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

  const syscallCount = countSyscalls(data);

  const IconComponent = isExternal ? Globe : Server;
  // Compute gauges (design D8). `compute` absent ⇒ the card is exactly the
  // pre-feature card; present without rows ⇒ just the muted dot + tooltip.
  const compute = data.compute;
  const lensBadge = data.lensBadge;
  const gauged = compute !== undefined && hasComputeGauges(compute);
  // DaemonSet / host-network peers (see utils/daemonSetPeers) take the same
  // teal as their toolbar toggle and their edges — colour alone carries the
  // association, no tag text on the card.
  const daemonSetPeer = isExternal && cardPods(data).some(isDaemonSetOrHostNetworkPod);
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
          {/* No expander control: selecting the card opens it (NetworkGraph
              derives `isExpanded` from the selection). The chevron that used
              to live here was a second, smaller target for the thing the
              whole card already did, and it made "selected" and "open" two
              states a card could disagree about. */}

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
              {lensBadge && <LensBadgeChip badge={lensBadge} />}
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

        {/* No focus control: selecting the card focuses it, the same click
            that opens it. The crosshair that used to live here was a third
            target on a card that already had two, and it let "selected" and
            "focused" drift apart. Esc still drops the focus and leaves the
            card open — see App's selectPod. */}
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
  // Re-render only when a rendered field changes. The field list, and the
  // test that keeps it complete, live in podNodeMemo.ts: add any new field
  // the card renders there, or it will not refresh on poll.
}, podNodePropsEqual);

export default PodNode;
