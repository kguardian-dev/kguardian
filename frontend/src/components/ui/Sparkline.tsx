// Hand-rolled SVG sparkline (design D8: no chart dependency). Draws the
// last N samples as a line with a soft fill, optionally against a capacity
// line so "how close to the limit" reads at a glance.

import { sparklineSegments } from '../../utils/sparkline';

export interface SparklineProps {
  /** Oldest → newest, one slot per bucket. `null` is a bucket with no
   *  sample: the line breaks there instead of being drawn across it. */
  values: readonly (number | null)[];
  /** Fixed y-axis maximum (e.g. the limit); default = max of values. */
  max?: number | null;
  width?: number;
  height?: number;
  /** CSS colour for the stroke; defaults to the accent token. */
  color?: string;
  className?: string;
  title?: string;
}

export function Sparkline({
  values,
  max,
  width = 200,
  height = 28,
  color = 'var(--color-hubble-accent)',
  className = '',
  title,
}: SparklineProps) {
  const dataMax = values.reduce<number>((m, v) => (v !== null && v > m ? v : m), 0);
  const yMax = max && max > 0 ? Math.max(max, dataMax) : dataMax || 1;
  const segments = sparklineSegments(values, width, height, yMax);
  const capY = max && max > 0 ? height - (Math.min(max, yMax) / yMax) * (height - 1) - 0.5 : null;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      preserveAspectRatio="none"
      className={className}
      role="img"
      aria-label={title}
      data-testid="sparkline"
    >
      {title && <title>{title}</title>}
      {capY !== null && (
        <line x1={0} x2={width} y1={capY} y2={capY} stroke="var(--theme-border-strong)" strokeDasharray="3 3" strokeWidth={1} />
      )}
      {segments.map((segment, i) => (
        // One pair per unbroken run: a single fill polygon across a gap would
        // shade minutes the pod never reported.
        <g key={i}>
          <path d={segment.area} fill={color} fillOpacity={0.12} stroke="none" />
          <path d={segment.d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        </g>
      ))}
    </svg>
  );
}
