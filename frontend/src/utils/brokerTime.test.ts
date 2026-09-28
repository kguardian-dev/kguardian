import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { brokerTimeMs, formatBrokerTime } from './brokerTime';

// Broker rows carry naive UTC ("2026-09-28T12:57:04.215869"). Rendered with
// `new Date(s).toLocaleString()` an AEST browser showed 12:57 PM for an event
// that happened at 10:57 PM local: UTC digits in a local-looking format.

const NAIVE = '2026-09-28T12:57:04.215869';
const INSTANT = Date.UTC(2026, 8, 28, 12, 57, 4, 215);

describe('formatBrokerTime', () => {
  let tz: string | undefined;
  beforeEach(() => {
    tz = process.env.TZ;
    process.env.TZ = 'Australia/Sydney';
  });
  afterEach(() => {
    process.env.TZ = tz;
  });

  test('a naive broker timestamp is pinned to UTC, then shown in the local zone with its name', () => {
    const out = formatBrokerTime(NAIVE);
    // 12:57 UTC is 22:57 in Sydney on 28 Sep (AEST, +10; DST starts in October).
    expect(out).toMatch(/10:57:04|22:57:04/);
    expect(out).not.toMatch(/12:57:04/);
    expect(out).toMatch(/AEST|GMT\+10/);
    expect(out).toBe(new Date(INSTANT).toLocaleString(undefined, { timeZoneName: 'short' }));
  });

  test('an offset timestamp is honoured rather than re-pinned to UTC', () => {
    // 12:57:04+02:00 is 10:57:04Z, so 20:57:04 in Sydney.
    const out = formatBrokerTime('2026-09-28T12:57:04+02:00');
    expect(out).toMatch(/8:57:04|20:57:04/);
    expect(out).toBe(formatBrokerTime('2026-09-28T10:57:04Z'));
  });

  test('invalid or missing input never renders "Invalid Date"', () => {
    expect(formatBrokerTime('not-a-time')).toBe('not-a-time');
    expect(formatBrokerTime(null)).toBe('—');
    expect(formatBrokerTime(undefined)).toBe('—');
    expect(formatBrokerTime('  ')).toBe('—');
  });
});

describe('brokerTimeMs', () => {
  test('orders naive rows by their UTC instant and sinks unparseable ones', () => {
    expect(brokerTimeMs(NAIVE)).toBe(INSTANT);
    expect(brokerTimeMs('2026-09-28T12:57:04Z')).toBe(brokerTimeMs('2026-09-28T12:57:04'));
    expect(brokerTimeMs('2026-09-28T22:57:04+10:00')).toBe(brokerTimeMs('2026-09-28T12:57:04'));
    expect(brokerTimeMs('garbage')).toBe(0);
    expect(brokerTimeMs(null)).toBe(0);
  });
});
