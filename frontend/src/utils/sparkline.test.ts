import { describe, expect, test } from 'vitest';
import { sparklineSegments } from './sparkline';

// The series is one slot per minute with `null` for minutes nothing was
// sampled (utils/compute `denseSeries`). Drawing across those gaps would
// invent usage that never happened, so they break the line instead.

const W = 100;
const H = 10;

describe('sparklineSegments', () => {
  test('an unbroken series is one segment, right-aligned in its slots', () => {
    const segments = sparklineSegments([0, 5, 10], W, H, 10);
    expect(segments).toHaveLength(1);
    expect(segments[0].d.startsWith('M0.0,')).toBe(true);
    expect(segments[0].d.split('L')).toHaveLength(3); // M + two L
    expect(segments[0].area.endsWith('Z')).toBe(true);
  });

  test('one slot per value: the series spans the full width, never shifted', () => {
    const [segment] = sparklineSegments([10, 10], W, H, 10);
    expect(segment.d).toBe('M0.0,0.5 L100.0,0.5');
  });

  test('a gap splits the line, and neither piece spans it', () => {
    const segments = sparklineSegments([10, null, 10], W, H, 10);
    expect(segments).toHaveLength(2);
    expect(segments[0].d).toContain('M0.0,');
    expect(segments[1].d).toContain('M100.0,');
    // No segment joins the two sides: the middle x is in neither path.
    expect(segments.some((s) => s.d.includes('50.0'))).toBe(false);
  });

  test('each segment fills only under itself', () => {
    const segments = sparklineSegments([10, null, 10], W, H, 10);
    expect(segments[0].area).toBe('M0.0,0.5 L0.0,10.0 L0.0,10.0 Z');
    expect(segments[1].area).toBe('M100.0,0.5 L100.0,10.0 L100.0,10.0 Z');
  });

  test('a lone point draws a zero-length line, which the round cap shows as a dot', () => {
    const [segment] = sparklineSegments([null, 7, null], W, H, 10);
    expect(segment.d).toBe('M50.0,3.2 L50.0,3.2'); // 7 of 10, in a 10px box
  });

  test('leading and trailing gaps are not drawn', () => {
    expect(sparklineSegments([null, null], W, H, 10)).toEqual([]);
  });

  test('values are clamped to [0, max] and an empty series draws nothing', () => {
    const [segment] = sparklineSegments([-5, 50], W, H, 10);
    expect(segment.d).toBe('M0.0,9.5 L100.0,0.5');
    expect(sparklineSegments([], W, H, 10)).toEqual([]);
  });
});
