/**
 * Every Broker read gives up after this long. A hanging request would
 * otherwise hold a skeleton on screen forever with no way to retry.
 */
export const READ_TIMEOUT_MS = 15_000;

/**
 * The Broker's default Postgres statement timeout (DB_STATEMENT_TIMEOUT_MS in
 * broker/src/main.rs). `/version` does not expose the configured value.
 */
export const BROKER_STATEMENT_TIMEOUT_MS = 30_000;

/**
 * Workload profile reads are computed live and can legitimately take most of
 * the statement timeout. Waiting a little past it lets the Broker's own
 * answer, or its timeout error, arrive instead of a client abort that leaves
 * the statement running and repeats every poll.
 */
export const PROFILE_READ_TIMEOUT_MS = BROKER_STATEMENT_TIMEOUT_MS + 5_000;

/**
 * The pod and Service listings are the heaviest responses the Broker builds
 * (72 MB of pods on a 43k-pod cluster) and can legitimately take most of its
 * statement timeout. Giving up at the default 10 s turned every slow listing
 * into a failure while the statement kept running server-side.
 */
export const LISTING_READ_TIMEOUT_MS = BROKER_STATEMENT_TIMEOUT_MS + 5_000;

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
