import { useCallback, useEffect, useRef, useState } from 'react';
import { errorKind, profileApi, type ProfileApi } from '../services/profileApi';
import type { PostureStatus, ProfileDiff, VersionList, WorkloadListItem, WorkloadProfile } from '../types/profile';

/**
 * Keeps a request's result tied to the key it was made for: a response for
 * a workload the user has already navigated away from is dropped.
 */
function useLatest() {
  const seq = useRef(0);
  return useCallback(() => {
    const id = ++seq.current;
    return () => id === seq.current;
  }, []);
}

/** Longest wait between profile polls after consecutive failures. */
export const PROFILE_POLL_MAX_BACKOFF_MS = 300_000;

/**
 * Failures worth backing off for: the Broker is slow or struggling (timeout,
 * 5xx, shed read, network), and asking again in 30 s only adds load; or the
 * read was refused (401/403), which lasts until someone fixes the token or
 * its scope, so a fast poll only repeats the refusal. A 404 or 400 keeps the
 * plain poll: the workload may appear.
 */
function backsOff(err: unknown): boolean {
  const kind = errorKind(err);
  return kind === 'timeout' || kind === 'busy' || kind === 'error' || kind === 'auth';
}

/**
 * One workload's live profile. Reloads on key change and on the header
 * Refresh (`refreshTick`), and polls (the profile is computed live). A poll
 * that fails keeps the last good profile and surfaces the error beside it.
 * A poll is skipped while a read is still in flight, and after a transient
 * or auth failure the next poll waits twice as long per consecutive failure (up to
 * PROFILE_POLL_MAX_BACKOFF_MS); `reload` (the Retry button) resets that.
 */
export function useWorkloadProfile(ns: string, kind: string, name: string, refreshTick = 0, pollMs = 30_000, api: ProfileApi = profileApi) {
  const [profile, setProfile] = useState<WorkloadProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  const failures = useRef(0);
  const nextPollAt = useRef(0);
  const inflight = useRef(false);

  const load = useCallback(async () => {
    const current = begin();
    inflight.current = true;
    try {
      const p = await api.getProfile(ns, kind, name);
      if (!current()) return;
      failures.current = 0;
      nextPollAt.current = 0;
      setProfile(p);
      setError(null);
    } catch (err) {
      if (!current()) return;
      if (backsOff(err)) {
        failures.current += 1;
        nextPollAt.current = Date.now() + Math.min(pollMs * 2 ** failures.current, PROFILE_POLL_MAX_BACKOFF_MS);
      }
      setError(err);
    } finally {
      if (current()) {
        inflight.current = false;
        setLoading(false);
      }
    }
  }, [api, ns, kind, name, begin, pollMs]);

  useEffect(() => {
    // A different workload: forget the previous one before loading.
    /* eslint-disable react-hooks/set-state-in-effect -- reset + fetch on key change */
    setProfile(null);
    setError(null);
    setLoading(true);
    /* eslint-enable react-hooks/set-state-in-effect */
    failures.current = 0;
    nextPollAt.current = 0;
    void load();
    if (pollMs <= 0) return;
    const t = setInterval(() => {
      if (inflight.current || Date.now() < nextPollAt.current) return;
      void load();
    }, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const seenTick = useRef(refreshTick);
  useEffect(() => {
    if (seenTick.current === refreshTick) return;
    seenTick.current = refreshTick;
    failures.current = 0;
    nextPollAt.current = 0;
    void load();
  }, [refreshTick, load]);

  // The user asked: drop the back-off, and show the skeleton again while
  // there is no profile to keep on screen.
  const reload = useCallback(async () => {
    failures.current = 0;
    nextPollAt.current = 0;
    setLoading(true);
    await load();
  }, [load]);

  return { profile, loading, error, reload };
}

/**
 * Whole seconds since `active` last became true; 0 while inactive. For a
 * skeleton that should say how long it has been waiting.
 */
export function useElapsedSeconds(active: boolean): number {
  const [elapsed, setElapsed] = useState(0);
  // Reset on (de)activation during render, so a new wait never shows the previous one's count.
  const [wasActive, setWasActive] = useState(active);
  if (active !== wasActive) {
    setWasActive(active);
    setElapsed(0);
  }
  useEffect(() => {
    if (!active) return;
    const started = Date.now();
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(t);
  }, [active]);
  return active ? elapsed : 0;
}

/**
 * Version history, newest first, with "load older" paging. Another workload
 * empties the list until its own first page answers, and a page of the
 * previous workload's that answers late is dropped.
 */
export function useProfileVersions(ns: string, kind: string, name: string, refreshTick = 0, api: ProfileApi = profileApi) {
  const [data, setData] = useState<VersionList | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  // A first page in flight owns the sequence: a page-more issued meanwhile would supersede it and page the wrong list.
  const firstPageInFlight = useRef(false);

  const page = useCallback((before?: number) => api.listVersions(ns, kind, name, before === undefined ? {} : { before }), [api, ns, kind, name]);

  // The workload the versions in `data` belong to: another one's are no answer for this one.
  const dataFor = useRef(page);

  const load = useCallback(async () => {
    const current = begin();
    firstPageInFlight.current = true;
    setLoading(true);
    // A new first page supersedes any page-more in flight, whose own reset is skipped.
    setLoadingMore(false);
    if (dataFor.current !== page) {
      dataFor.current = page;
      setData(null);
      setError(null);
    }
    try {
      const v = await page();
      if (!current()) return;
      setData(v);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) {
        firstPageInFlight.current = false;
        setLoading(false);
      }
    }
  }, [page, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / key change
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!data?.nextBefore || firstPageInFlight.current) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const more = await page(data.nextBefore);
      if (!current()) return;
      setData((prev) => (prev ? { ...more, items: [...prev.items, ...more.items] } : more));
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [page, data, begin]);

  return { data, loading, loadingMore, error, reload: load, loadMore };
}

/**
 * The diff between two stored revisions (either may be omitted: broker
 * defaults). Another pair (or workload) clears the diff until its own
 * answers, so the pickers never name revisions above another pair's diff;
 * a Refresh of the same pair keeps it on screen meanwhile.
 */
export function useProfileDiff(ns: string, kind: string, name: string, from: number | undefined, to: number | undefined, enabled: boolean, api: ProfileApi = profileApi) {
  const [diff, setDiff] = useState<ProfileDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const read = useCallback(() => api.getDiff(ns, kind, name, { from, to }), [api, ns, kind, name, from, to]);

  // The pair the diff on screen answers.
  const diffFor = useRef(read);

  const load = useCallback(async () => {
    if (!enabled) return;
    const current = begin();
    setLoading(true);
    if (diffFor.current !== read) {
      diffFor.current = read;
      setDiff(null);
      setError(null);
    }
    try {
      const d = await read();
      if (!current()) return;
      setDiff(d);
      setError(null);
    } catch (err) {
      if (current()) {
        setDiff(null);
        setError(err);
      }
    } finally {
      if (current()) setLoading(false);
    }
  }, [read, enabled, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on selection change
    void load();
  }, [load]);

  return { diff, loading, error, reload: load };
}

/** Rows per `GET /workloads` page the Workloads table asks for (the Broker's maximum). */
export const POSTURE_PAGE_SIZE = 500;

/** Pages the Workloads table fetches on its own before offering Load more. */
export const POSTURE_AUTO_PAGES = 5;

/**
 * `GET /workloads` posture summaries for the Workloads table's posture
 * column, one server page at a time (the Broker orders by `(namespace,
 * kind, name)`; the table's `(namespace, name, kind)` is close enough that
 * a page covers the top of the table): the first page on load / scope or
 * filter change / refresh, further pages through `loadMore` (the table calls
 * it while rendered rows are uncovered, up to POSTURE_AUTO_PAGES, then the
 * user does). `pages` counts the pages fetched since the last first page.
 * `namespace`, `status` and `search` are server-side filters; a change to
 * any of them empties `byKey` until the new first page answers. `error` set
 * means the column is unavailable (older Broker, read budget); after a failed
 * first page `byKey` is empty. The rest of the table works.
 */
export function useWorkloadPostures(
  namespace: string | undefined,
  status: PostureStatus | undefined,
  /** Server-side, case-insensitive substring of the workload name. */
  search: string | undefined,
  refreshTick = 0,
  api: ProfileApi = profileApi,
  pageSize = POSTURE_PAGE_SIZE,
  enabled = true,
) {
  const [byKey, setByKey] = useState<Map<string, WorkloadListItem>>(new Map());
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [pages, setPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  // A first page in flight owns the sequence: a page-more issued meanwhile would supersede it and page the wrong list.
  const firstPageInFlight = useRef(false);

  const page = useCallback(
    (after: string | undefined) =>
      api.listWorkloads({ limit: pageSize, ...(namespace ? { namespace } : {}), ...(status ? { status } : {}), ...(search ? { search } : {}), after }),
    [api, namespace, status, search, pageSize],
  );

  // The query the rows in `byKey` answer. Rows for another scope or filter are
  // no answer for this one: under a posture filter they would list workloads
  // that do not have that posture.
  const rowsQuery = useRef(page);
  const clear = useCallback(() => {
    setByKey(new Map());
    setNextAfter(null);
    setPages(0);
  }, []);

  const load = useCallback(async () => {
    if (!enabled) return;
    const current = begin();
    firstPageInFlight.current = true;
    setLoading(true);
    // A new first page supersedes any page-more in flight, whose own reset is skipped.
    setLoadingMore(false);
    if (rowsQuery.current !== page) {
      rowsQuery.current = page;
      clear();
    }
    try {
      const p = await page(undefined);
      if (!current()) return;
      setByKey(new Map(p.items.map((i) => [`${i.namespace}/${i.kind}/${i.name}`, i])));
      setNextAfter(p.nextAfter);
      setPages(1);
      setError(null);
    } catch (err) {
      if (!current()) return;
      // A refresh that failed cannot vouch for the rows it was meant to replace.
      clear();
      setError(err);
    } finally {
      if (current()) {
        firstPageInFlight.current = false;
        setLoading(false);
      }
    }
  }, [page, begin, enabled, clear]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / scope or filter change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter || firstPageInFlight.current) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const p = await page(nextAfter);
      if (!current()) return;
      setByKey((prev) => {
        const next = new Map(prev);
        for (const i of p.items) next.set(`${i.namespace}/${i.kind}/${i.name}`, i);
        return next;
      });
      setNextAfter(p.nextAfter);
      setPages((n) => n + 1);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [nextAfter, page, begin]);

  return { byKey, loading, loadingMore, error, hasMore: nextAfter !== null, pages, loadMore };
}
