// Path geometry for the hand-rolled SVG sparkline (components/ui/Sparkline).
// Pure, so the drawing can be asserted without rendering.

/** A value and the instant it was observed. */
export interface SparklinePoint {
  at: number;
  value: number;
}

/** One unbroken run of points; a gap in time splits the line into several. */
export interface SparklineSegment {
  /** The line through the run. */
  d: string;
  /** The same run closed down to the baseline, for the soft fill. */
  area: string;
}

export interface SparklineGeometry {
  width: number;
  height: number;
  /** Y-axis ceiling; values are clamped to [0, max]. */
  max: number;
  /** Start and end of the span the chart covers, in the same clock as `at`. */
  from: number;
  to: number;
  /** Longer than this between two points and the line breaks. */
  gapMs: number;
}

/**
 * Segments through `points`, placed by TIME: x comes from each point's own
 * timestamp, not from its position in the array.
 *
 * That is what lets the series be as irregular as the data really is — 5 s
 * live samples on the right, minute-spaced seeded ones behind them, drifting
 * fold stamps, whole minutes missing — with no grid to fold them onto, and
 * without inventing a value, or a hole, for an instant nobody measured.
 *
 * Points further apart than `gapMs` are not joined: a line across them would
 * assert a measurement nobody took. A run of one draws a zero-length line,
 * which the round line cap renders as a dot, so a lone observation is still
 * visible. Anything outside [from, to] is not drawn.
 */
export function sparklineSegments(points: readonly SparklinePoint[], geometry: SparklineGeometry): SparklineSegment[] {
  const { width, height, max, from, to, gapMs } = geometry;
  const span = to - from;
  if (points.length === 0 || span <= 0) return [];
  const x = (at: number) => (((at - from) / span) * width).toFixed(1);
  const y = (v: number) => {
    const clamped = max > 0 ? Math.min(Math.max(v, 0), max) / max : 0;
    return (height - clamped * (height - 1) - 0.5).toFixed(1);
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

  let previous: number | null = null;
  for (const p of points) {
    if (!Number.isFinite(p.value) || !Number.isFinite(p.at)) continue;
    if (p.at < from || p.at > to) continue;
    if (previous !== null && p.at - previous > gapMs) flush();
    run.push({ x: x(p.at), y: y(p.value) });
    previous = p.at;
  }
  flush();
  return segments;
}
