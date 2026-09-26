/**
 * Every Broker read gives up after this long. A hanging request would
 * otherwise hold a skeleton on screen forever with no way to retry.
 */
export const READ_TIMEOUT_MS = 15_000;

/** An AbortSignal that fires after `ms` (AbortSignal.timeout where it exists). */
export function timeoutSignal(ms: number): AbortSignal {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
  const c = new AbortController();
  setTimeout(() => c.abort(new DOMException('The operation timed out.', 'TimeoutError')), ms);
  return c.signal;
}

/** The request was cut off by the timeout (or aborted) rather than failing on the network. */
export function isTimeout(err: unknown): boolean {
  return err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
}

export const timeoutMessage = (ms: number) => `The Broker did not answer within ${Math.round(ms / 1000)}s.`;
