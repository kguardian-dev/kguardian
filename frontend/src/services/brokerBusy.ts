/**
 * A Broker 503 is one of two things: the read memory budget refused the
 * request (broker/src/read_budget.rs), or Postgres cancelled the statement
 * (statement or lock timeout, deadlock, serialization failure; the body
 * starts "database busy:"). Both carry `Retry-After`. The message follows
 * the body, so a statement timeout is never called a budget shed.
 */

const fmtKib = (kib: number) => (kib >= 1024 ? `${Math.round(kib / 1024)} MiB` : `${kib} KiB`);

/** Bodies from a proxy in front of the Broker can be long HTML; keep one line of it. */
const oneLine = (s: string, max = 200) => {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
};

export function busyMessage(body: string): string {
  const text = oneLine(body);
  if (/^database busy:/i.test(text)) {
    // The Broker's own words ("database busy: <cause>; retry after N s"), as a sentence.
    return `${text.charAt(0).toUpperCase()}${text.slice(1)}${/[.!?]$/.test(text) ? '' : '.'}`;
  }
  const m = /needs (\d+) KiB of a (\d+) KiB budget/.exec(text);
  if (m) {
    const needs = Number(m[1]);
    const total = Number(m[2]);
    if (needs >= total) {
      return `This read reserves the Broker's whole read memory budget (${fmtKib(total)}), so it is refused whenever any other read is in flight, and a retry asks for the whole budget again. Retry when the Broker is idle, or raise BROKER_READ_MEMORY_BUDGET_MB (and the container memory limit with it).`;
    }
    return `The Broker is shedding reads right now (read budget: this read needs ${fmtKib(needs)} of ${fmtKib(total)}). Try again in a few seconds.`;
  }
  if (/read memory budget/i.test(text)) return 'The Broker is shedding reads right now (read budget). Try again in a few seconds.';
  return `The Broker is not taking this read right now (503${text ? `: ${text}` : ''}). Try again in a few seconds.`;
}

/** `Retry-After` as milliseconds (delta-seconds or an HTTP-date); null when absent or unreadable. */
export function retryAfterMs(headers: Headers, now = Date.now()): number | null {
  const raw = headers.get('Retry-After');
  if (raw === null) return null;
  const v = raw.trim();
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : Math.max(0, t - now);
}
