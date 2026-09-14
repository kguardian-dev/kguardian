// Bounded parallelism for the data hooks: usePodData fans out per-pod traffic
// and syscall reads, useComputeData fans out compute-history backfills, and
// neither may open an unbounded number of requests against the broker.

/**
 * Run `tasks` with at most `limit` in flight, resolving to their results in
 * task order.
 *
 * Fail-fast: the first failure stops new tasks from being started and is
 * re-thrown at once. Against a broker shedding reads, a large namespace
 * must cost about one wave of requests, not every task it could have queued
 * — and the caller is usually clearing a `loading` flag it should not hold
 * for the rest of the fan-out.
 *
 * A failing task's rejection is captured rather than left on the promise, so
 * abandoning its siblings cannot surface as unhandled rejections, and the
 * bookkeeping delete sits in a `finally`, so a rejected task cannot linger in
 * the in-flight set and wedge the limiter at `limit` forever.
 */
export async function withConcurrencyLimit<T>(tasks: readonly (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  const executing = new Set<Promise<void>>();
  const max = Math.max(1, Math.floor(limit));
  // A holder, not a plain `let`: assignments inside the task closures are
  // invisible to control-flow narrowing, which would type the throws below as
  // unreachable.
  const first: { failure?: { err: unknown } } = {};

  for (let i = 0; i < tasks.length; i++) {
    const index = i;
    const run = (async () => {
      try {
        results[index] = await tasks[index]();
      } catch (err) {
        first.failure ??= { err };
      }
    })();
    // `finally`, not `then`: equivalent only for as long as `run` swallows,
    // and the wedge this guards against — a rejected task never leaving the
    // set, so the limiter never drops below `limit` again — is worth keeping
    // impossible by construction rather than by a catch someone may move.
    const tracked: Promise<void> = run.finally(() => {
      executing.delete(tracked);
    });
    executing.add(tracked);
    if (executing.size >= max) await Promise.race(executing);
    if (first.failure) throw first.failure.err;
  }

  await Promise.all(executing);
  if (first.failure) throw first.failure.err;
  return results;
}
