// Path geometry for the hand-rolled SVG sparkline (components/ui/Sparkline).
// Pure, so the drawing can be asserted without rendering.

/** One unbroken run of values; gaps (`null`) split the line into several. */
export interface SparklineSegment {
  /** The line through the run. */
  d: string;
  /** The same run closed down to the baseline, for the soft fill. */
  area: string;
}

/**
 * Segments through `values`, one slot per value, oldest → newest. `max` is
 * the y-axis ceiling; values are clamped to [0, max].
 *
 * The series is always exactly as long as the window it draws (`denseSeries`
 * returns one slot per bucket, empty ones included), so there is no
 * right-alignment here: a short series would be a series of absolute-time
 * slots silently shifted along the axis.
 *
 * A `null` is a slot with no sample — a minute the pod reported nothing —
 * and BREAKS the line rather than being interpolated across: joining the
 * points either side would draw an outage as a straight run of usage that
 * never happened. A run of one draws a zero-length line, which the round
 * line cap renders as a dot, so an isolated minute is still visible.
 */
export function sparklineSegments(
  values: readonly (number | null)[],
  width: number,
  height: number,
  max: number,
): SparklineSegment[] {
  if (values.length === 0) return [];
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  const y = (v: number) => {
    const clamped = max > 0 ? Math.min(Math.max(v, 0), max) / max : 0;
    return height - clamped * (height - 1) - 0.5;
  };

  const segments: SparklineSegment[] = [];
  let run: { x: string; y: string }[] = [];
  const flush = () => {
    if (run.length === 0) return;
    const line = run.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
    const d = run.length === 1 ? `${line} L${run[0].x},${run[0].y}` : line;
    const bottom = height.toFixed(1);
    segments.push({ d, area: `${line} L${run[run.length - 1].x},${bottom} L${run[0].x},${bottom} Z` });
    run = [];
  };

  values.forEach((v, i) => {
    if (!Number.isFinite(v)) { // null, undefined and NaN alike: no sample
      flush();
      return;
    }
    run.push({ x: (i * step).toFixed(1), y: y(v as number).toFixed(1) });
  });
  flush();
  return segments;
}
