import { describe, expect, test } from 'vitest';
import { sparklineSegments } from './sparkline';

// The chart places every point by its own timestamp, so an irregular series
// draws as irregular — and a stretch of time nobody measured draws as a gap
// rather than as a line across it.

const T0 = Date.parse('2026-09-14T10:00:00Z');
const W = 100;
const H = 10;
const geo = (over: Partial<Parameters<typeof sparklineSegments>[1]> = {}) => ({
  width: W, height: H, max: 10, from: T0, to: T0 + 600_000, gapMs: 150_000, ...over,
});
const at = (offsetMs: number, value: number) => ({ at: T0 + offsetMs, value });

describe('sparklineSegments', () => {
  test('x comes from the timestamp, not the position in the array', () => {
    // Three points over a ten-minute window: start, halfway, end.
    const [segment] = sparklineSegments([at(0, 10), at(300_000, 10), at(600_000, 10)], geo({ gapMs: 600_000 }));
    expect(segment.d).toBe('M0.0,0.5 L50.0,0.5 L100.0,0.5');
  });

  test('uneven spacing in time is uneven spacing on screen', () => {
    // Two points a minute apart, then one nine minutes later: the last leg
    // must be far longer than the first, which index-based plotting would
    // have drawn as three evenly spaced points.
    const [segment] = sparklineSegments([at(0, 10), at(60_000, 10), at(600_000, 10)], geo({ gapMs: 600_000 }));
    expect(segment.d).toBe('M0.0,0.5 L10.0,0.5 L100.0,0.5');
  });

  test('a stretch longer than gapMs breaks the line instead of spanning it', () => {
    const segments = sparklineSegments([at(0, 10), at(60_000, 10), at(400_000, 10), at(460_000, 10)], geo());
    expect(segments).toHaveLength(2);
    expect(segments[0].d).toBe('M0.0,0.5 L10.0,0.5');
    expect(segments[1].d).toBe('M66.7,0.5 L76.7,0.5');
  });

  test('dense samples inside the threshold stay one line', () => {
    // A 5 s live cadence: twelve points in a minute, all joined.
    const points = Array.from({ length: 12 }, (_, i) => at(i * 5_000, 10));
    expect(sparklineSegments(points, geo())).toHaveLength(1);
  });

  // Folds close on a sample count, not a clock boundary, so their stamps
  // creep forward. That irregularity must not read as an outage — the whole
  // reason three rounds of grid-alignment machinery existed.
  test('drifting minute stamps draw one unbroken line', () => {
    const points = Array.from({ length: 40 }, (_, i) => at(i * 62_000, 10));
    expect(sparklineSegments(points, geo({ to: T0 + 40 * 62_000 }))).toHaveLength(1);
  });

  test('each segment fills only under itself', () => {
    const segments = sparklineSegments([at(0, 10), at(400_000, 10)], geo());
    expect(segments[0].area).toBe('M0.0,0.5 L0.0,10.0 L0.0,10.0 Z');
    expect(segments[1].area).toBe('M66.7,0.5 L66.7,10.0 L66.7,10.0 Z');
  });

  test('a lone point draws a zero-length line, which the round cap shows as a dot', () => {
    const [segment] = sparklineSegments([at(300_000, 7)], geo());
    expect(segment.d).toBe('M50.0,3.2 L50.0,3.2'); // 7 of 10, in a 10px box
  });

  test('points outside the window, and unusable ones, are not drawn', () => {
    const segments = sparklineSegments(
      [at(-60_000, 10), at(700_000, 10), { at: T0 + 1, value: Number.NaN }, at(300_000, 10)],
      geo(),
    );
    expect(segments).toHaveLength(1);
    expect(segments[0].d).toBe('M50.0,0.5 L50.0,0.5'); // only the in-window point
  });

  test('values are clamped to [0, max]; an empty series or window draws nothing', () => {
    const [segment] = sparklineSegments([at(0, -5), at(600_000, 50)], geo({ gapMs: 600_000 }));
    expect(segment.d).toBe('M0.0,9.5 L100.0,0.5');
    expect(sparklineSegments([], geo())).toEqual([]);
    expect(sparklineSegments([at(0, 1)], geo({ to: T0 }))).toEqual([]);
  });
});
