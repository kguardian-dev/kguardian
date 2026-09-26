import { useCallback, useEffect, useRef, useState } from 'react';
import { profileApi, type ProfileApi } from '../services/profileApi';
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

/**
 * One workload's live profile. Reloads on key change and on the header
 * Refresh (`refreshTick`), and polls (the profile is computed live). A poll
 * that fails keeps the last good profile and surfaces the error beside it.
 */
export function useWorkloadProfile(ns: string, kind: string, name: string, refreshTick = 0, pollMs = 30_000, api: ProfileApi = profileApi) {
  const [profile, setProfile] = useState<WorkloadProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const load = useCallback(async () => {
    const current = begin();
    try {
      const p = await api.getProfile(ns, kind, name);
      if (!current()) return;
      setProfile(p);
      setError(null);
    } catch (err) {
      if (!current()) return;
      setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, ns, kind, name, begin]);

  useEffect(() => {
    // A different workload: forget the previous one before loading.
    /* eslint-disable react-hooks/set-state-in-effect -- reset + fetch on key change */
    setProfile(null);
    setError(null);
    setLoading(true);
    /* eslint-enable react-hooks/set-state-in-effect */
    void load();
    if (pollMs <= 0) return;
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const seenTick = useRef(refreshTick);
  useEffect(() => {
    if (seenTick.current === refreshTick) return;
    seenTick.current = refreshTick;
    void load();
  }, [refreshTick, load]);

  return { profile, loading, error, reload: load };
}

/** Version history, newest first, with "load older" paging. */
export function useProfileVersions(ns: string, kind: string, name: string, refreshTick = 0, api: ProfileApi = profileApi) {
  const [data, setData] = useState<VersionList | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const load = useCallback(async () => {
    const current = begin();
    setLoading(true);
    try {
      const v = await api.listVersions(ns, kind, name);
      if (!current()) return;
      setData(v);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, ns, kind, name, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / key change
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!data?.nextBefore) return;
    setLoadingMore(true);
    try {
      const more = await api.listVersions(ns, kind, name, { before: data.nextBefore });
      setData((prev) => (prev ? { ...more, items: [...prev.items, ...more.items] } : more));
    } catch (err) {
      setError(err);
    } finally {
      setLoadingMore(false);
    }
  }, [api, ns, kind, name, data]);

  return { data, loading, loadingMore, error, reload: load, loadMore };
}

/** The diff between two stored revisions (either may be omitted: broker defaults). */
export function useProfileDiff(ns: string, kind: string, name: string, from: number | undefined, to: number | undefined, enabled: boolean, api: ProfileApi = profileApi) {
  const [diff, setDiff] = useState<ProfileDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const load = useCallback(async () => {
    if (!enabled) return;
    const current = begin();
    setLoading(true);
    try {
      const d = await api.getDiff(ns, kind, name, { from, to });
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
  }, [api, ns, kind, name, from, to, enabled, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on selection change
    void load();
  }, [load]);

  return { diff, loading, error, reload: load };
}

/** Rows per `GET /workloads` page the Workloads table asks for. */
export const POSTURE_PAGE_SIZE = 100;

/**
 * `GET /workloads` posture summaries for the Workloads table's posture
 * column, one server page at a time (same `(namespace, kind, name)` order
 * the table uses): the first page on load / scope change / refresh, more
 * only when the user asks (`loadMore`). `namespace` and `status` are
 * server-side filters. `error` set means the column is unavailable (older
 * Broker, read budget); the rest of the table works.
 */
export function useWorkloadPostures(
  namespace: string | undefined,
  status: PostureStatus | undefined,
  refreshTick = 0,
  api: ProfileApi = profileApi,
  pageSize = POSTURE_PAGE_SIZE,
  enabled = true,
) {
  const [byKey, setByKey] = useState<Map<string, WorkloadListItem>>(new Map());
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const page = useCallback(
    (after: string | undefined) => api.listWorkloads({ limit: pageSize, ...(namespace ? { namespace } : {}), ...(status ? { status } : {}), after }),
    [api, namespace, status, pageSize],
  );

  const load = useCallback(async () => {
    if (!enabled) return;
    const current = begin();
    setLoading(true);
    try {
      const p = await page(undefined);
      if (!current()) return;
      setByKey(new Map(p.items.map((i) => [`${i.namespace}/${i.kind}/${i.name}`, i])));
      setNextAfter(p.nextAfter);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [page, begin, enabled]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / scope or filter change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter) return;
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
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [nextAfter, page, begin]);

  return { byKey, loading, loadingMore, error, hasMore: nextAfter !== null, loadMore };
}
