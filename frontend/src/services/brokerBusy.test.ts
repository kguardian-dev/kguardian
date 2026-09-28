import { describe, expect, test } from 'vitest';
import { busyMessage, retryAfterMs } from './brokerBusy';

const budget = (needs: number, total: number) =>
  `broker read memory budget exhausted: this request needs ${needs} KiB of a ${total} KiB budget and waited 5000 ms without getting it. The request was REFUSED, not truncated — retry. Raise BROKER_READ_MEMORY_BUDGET_MB (and the container memory limit with it) if this is persistent.`;

describe('busyMessage', () => {
  test('a statement the database cancelled is the Broker\'s own message, never a read-budget shed', () => {
    const m = busyMessage('database busy: canceling statement due to statement timeout; retry after 5 s');
    expect(m).toBe('Database busy: canceling statement due to statement timeout; retry after 5 s.');
    expect(m).not.toMatch(/read budget|shedding/);
  });

  test('a read that needs the whole budget is told so, not "try again in a few seconds"', () => {
    const m = busyMessage(budget(262144, 262144));
    expect(m).toMatch(/whole read memory budget \(256 MiB\)/);
    expect(m).toContain('BROKER_READ_MEMORY_BUDGET_MB');
    expect(m).not.toMatch(/few seconds/);
  });

  test('a partial reservation is a transient shed, with its numbers', () => {
    expect(busyMessage(budget(51200, 262144))).toBe('The Broker is shedding reads right now (read budget: this read needs 50 MiB of 256 MiB). Try again in a few seconds.');
    expect(busyMessage(budget(512, 262144))).toMatch(/needs 512 KiB of 256 MiB/);
    expect(busyMessage('read memory budget exhausted')).toBe('The Broker is shedding reads right now (read budget). Try again in a few seconds.');
  });

  test('an unrecognised body is a plain 503 with the body quoted on one line, not a guess at the cause', () => {
    expect(busyMessage('')).toBe('The Broker is not taking this read right now (503). Try again in a few seconds.');
    expect(busyMessage('busy')).toBe('The Broker is not taking this read right now (503: busy). Try again in a few seconds.');
    const html = `<html>\n<body>\n${'upstream unavailable '.repeat(30)}</body></html>`;
    const m = busyMessage(html);
    expect(m).not.toContain('\n');
    expect(m.length).toBeLessThan(300);
    expect(m).toMatch(/…\)\. Try again/);
  });
});

describe('retryAfterMs', () => {
  test('delta-seconds, an HTTP-date, and absent or unreadable values', () => {
    expect(retryAfterMs(new Headers({ 'Retry-After': '5' }))).toBe(5000);
    expect(retryAfterMs(new Headers({ 'Retry-After': ' 1 ' }))).toBe(1000);
    const now = Date.parse('2026-09-29T10:00:00Z');
    expect(retryAfterMs(new Headers({ 'Retry-After': 'Tue, 29 Sep 2026 10:00:07 GMT' }), now)).toBe(7000);
    expect(retryAfterMs(new Headers({ 'Retry-After': 'Tue, 29 Sep 2026 09:59:00 GMT' }), now)).toBe(0);
    expect(retryAfterMs(new Headers())).toBeNull();
    expect(retryAfterMs(new Headers({ 'Retry-After': 'soon' }))).toBeNull();
  });
});
