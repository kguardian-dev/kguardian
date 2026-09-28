import { parseBrokerTime } from './peerResolution';

/**
 * Local rendering of a broker timestamp with a short zone name. Broker
 * times are naive UTC, and `new Date(s)` would read them as local time.
 */
export function formatBrokerTime(value: string | null | undefined): string {
  const t = parseBrokerTime(value);
  if (t === null) return value?.trim() ? value : '—';
  return new Date(t).toLocaleString(undefined, { timeZoneName: 'short' });
}

/** Epoch ms for ordering broker rows; an unparseable value sorts as oldest. */
export function brokerTimeMs(value: string | null | undefined): number {
  return parseBrokerTime(value) ?? 0;
}
