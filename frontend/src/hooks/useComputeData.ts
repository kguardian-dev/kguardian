import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ComputeUnsupportedError, apiClient } from '../services/api';
import type { ComputeContainer, ComputeFinding, ComputeFindingsMeta, ComputeNode, ComputeSample } from '../types/compute';
import {
  COMPUTE_HISTORY_WINDOW_MINUTES,
  RingBuffer,
  appendSample,
  historySamples,
  needsSeed,
  podLevelSample,
  podNameKey,
  seedSamples,
} from '../utils/compute';

export const COMPUTE_POLL_MS = 5_000;
export const COMPUTE_FINDINGS_POLL_MS = 15_000;

/**
 * How long after a completed seed the same pod may be read again.
 *
 * Seeding is idempotent and re-runnable by design — that is what refills the
 * hole a hidden tab leaves — but an open card asks on every 5 s poll, so a
 * pod is read at most once a minute. `needsSeed` means the usual answer is
 * that there is nothing to fetch and no read happens at all.
 */
export const COMPUTE_SEED_COOLDOWN_MS = 60_000;

/**
 * First backoff after a failed seed, doubled per consecutive failure up to
 * COMPUTE_SEED_MAX_BACKOFF_MS.
 *
 * The broker sheds a read that does not fit its budget with `503` and a
 * `Retry-After` (broker/src/read_budget.rs) — explicitly retryable, so this
 * never gives up permanently; it just stops asking a struggling broker on
 * every poll.
 */
export const COMPUTE_SEED_RETRY_MS = 10_000;
export const COMPUTE_SEED_MAX_BACKOFF_MS = 300_000;

/**
 * Consecutive polls a pod may be missing from `/compute/latest` before its
 * buffer is dropped.
 *
 * A single absent poll is not a dead pod: retention prunes
 * `pod_compute_latest`, `LATEST_ROW_CAP` truncates a large namespace
 * alphabetically, a controller misses a heartbeat. Dropping on the first
 * miss costs an hour of seeded history and a fresh history read to rebuild
 * it, where tolerating a few polls costs nothing and still keeps a recycled
 * uid from inheriting the previous pod's series.
 */
export const COMPUTE_MISSED_POLLS_BEFORE_DROP = 3;

export interface UseComputeDataOptions {
  /** Latest-rows poll interval; ≤ 0 disables polling (fetch once). */
  pollMs?: number;
  /** Findings poll interval. */
  findingsPollMs?: number;
  /** Test hook: the API to call. */
  api?: Pick<typeof apiClient, 'getComputeLatest' | 'getComputeFindings' | 'getComputeNodes' | 'getComputeHistory'>;
}

export interface ComputeData {
  /** Live rows grouped by `pod_uid`. */
  containersByPodUid: Map<string, ComputeContainer[]>;
  /** The same rows grouped by `<namespace>/<pod_name>` — the join key when a
   *  PodInfo carries no uid (utils/compute `containersForNode`). */
  containersByPodName: Map<string, ComputeContainer[]>;
  nodesByName: Map<string, ComputeNode>;
  findings: ComputeFinding[];
  /** Truncation / history-disabled flags from the findings endpoint. */
  findingsMeta: ComputeFindingsMeta;
  /** The last hour of pod-level samples per `pod_uid`, each at the instant it
   *  was observed: seeded from `/compute/history` when a card is expanded,
   *  and appended to by the poll. */
  history: Map<string, RingBuffer<ComputeSample>>;
  /** False when the broker returned no node rows for the namespace (feature
   *  off, or a broker / controller predating it) or every node reports
   *  `compute_enabled=false`. Consumers render exactly as before then. */
  enabled: boolean;
  /** False once the broker answered 404/501 on a compute endpoint: an older
   *  broker. Both polls stop for this namespace session (they retry on the
   *  next namespace change, which is the only cheap "try again" signal). */
  supported: boolean;
  /** Last transient failure (network, 5xx). Cleared by the next good poll;
   *  polling continues. Never set for `unsupported`. */
  error: string | null;
  /** When the last successful `/compute/latest` landed. The sparklines end
   *  their window here rather than at a `Date.now()` read per card, so every
   *  chart in a render pass puts the same instant at the same x — and render
   *  stays pure. 0 before the first poll. */
  polledAt: number;
  /** Seed one pod's history now (the user expanded its card). Idempotent, and
   *  a no-op when a read is in flight or nothing new could be fetched. */
  seedPod: (uid: string) => void;
}

const NO_META: ComputeFindingsMeta = { truncated: false, victimsEvaluated: null, historyDisabled: false };

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The only live poll on the map (design D8): `GET /compute/latest` every
 * 5 s and `GET /compute/findings` every 15 s for the namespace, paused while
 * the tab is hidden and resumed (with an immediate refresh) when it is shown
 * again. Traffic and syscalls stay on manual refresh in usePodData.
 *
 * The per-pod series are samples at the instants they were observed, seeded
 * from `GET /compute/history/{pod_uid}` when a card is expanded and appended
 * to by the poll — so an expanded node opens on an hour of real trend instead
 * of an empty chart that fills while you watch.
 */
export function useComputeData(namespace: string, opts: UseComputeDataOptions = {}): ComputeData {
  const pollMs = opts.pollMs ?? COMPUTE_POLL_MS;
  const findingsPollMs = opts.findingsPollMs ?? COMPUTE_FINDINGS_POLL_MS;
  const api = opts.api ?? apiClient;

  const [containers, setContainers] = useState<ComputeContainer[]>([]);
  const [nodes, setNodes] = useState<ComputeNode[]>([]);
  const [findings, setFindings] = useState<ComputeFinding[]>([]);
  const [findingsMeta, setFindingsMeta] = useState<ComputeFindingsMeta>(NO_META);
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState(true);
  const [polledAt, setPolledAt] = useState(0);

  // Request generation: bumped on every namespace change. A response whose
  // generation is no longer current (the user switched namespace while it
  // was in flight) is discarded instead of landing on the new namespace.
  const generation = useRef(0);
  /** Generation whose one-shot /compute/nodes fetch has started (see loadNodes). */
  const nodesLoadedGen = useRef(-1);

  // Ring buffers live in a ref and are mutated in place on every poll; the
  // `history` state is a fresh Map over the same buffers per poll so a memo
  // keyed on it re-reads them. Reset on namespace change.
  const historyRef = useRef<Map<string, RingBuffer<ComputeSample>>>(new Map());
  const [history, setHistory] = useState<Map<string, RingBuffer<ComputeSample>>>(() => new Map());
  /** Per-pod seed bookkeeping: whether a read is in flight, how many have
   *  failed in a row, and the earliest time to try again. There is no
   *  permanent "seeded" latch — a series can always have a new hole worth
   *  filling, and `needsSeed` is what decides whether a read is worth making.
   *  An entry is dropped along with the pod's buffer. */
  const seedRef = useRef<Map<string, { inFlight: boolean; failures: number; nextAt: number; askedAt: number | null }>>(new Map());
  /** Consecutive polls each known pod has been missing from /compute/latest. */
  const missedPollsRef = useRef<Map<string, number>>(new Map());
  /** False once /compute/history answered 404/501: an optional endpoint this
   *  broker does not have. Deliberately NOT `supported`, which would stop
   *  the live polls and blank the map (see seedPod). */
  const historySupportedRef = useRef(true);
  /** Mirrors findingsMeta.historyDisabled: with history off, every seed read
   *  is charged a permit and comes back empty. */
  const historyDisabledRef = useRef(false);
  const inflightLatest = useRef(false);
  const inflightFindings = useRef(false);

  const hidden = () => typeof document !== 'undefined' && document.hidden;

  // One 404 is enough: stop polling and say so once, at debug — an older
  // broker is a supported configuration, not an error to log every 5 s.
  const markUnsupported = useCallback((err: ComputeUnsupportedError) => {
    setSupported((was) => {
      if (was) console.debug(`[compute] ${err.message}; compute polling stopped for this namespace`);
      return false;
    });
  }, []);

  /**
   * Seed one pod's sparkline from the broker's stored history, because the
   * user just opened its card.
   *
   * Seeding is on demand ONLY. The sparklines are the sole consumer of this
   * data (`ComputeDetail`, rendered under `isExpanded`); the collapsed card's
   * dot and micro bar read the newest sample, which comes from the 5 s poll
   * and which seeded points are never newer than. So seeding a namespace's
   * worth of pods eagerly would spend windowed range reads on charts that are
   * not on screen and cannot affect anything that is. One expansion, one
   * read.
   *
   * Idempotent: a pod already seeded, already being read, or out of attempts
   * issues nothing, so this can safely be called on every poll for every open
   * card. Fire-and-forget — nothing here may throw into the caller, and a
   * failure costs this pod its seeded history and nothing else.
   */
  const seedPod = useCallback((uid: string) => {
    const gen = generation.current;
    const state = seedRef.current;
    if (!historySupportedRef.current) return;
    // `retentionDays: 0`: the broker answers every history read with an empty
    // row set, after charging a read permit for it.
    if (historyDisabledRef.current) return;
    const pod = state.get(uid);
    const now = Date.now();
    if (pod?.inFlight || (pod && now < pod.nextAt)) return;
    // No buffer means the pod is not being tracked (it never reported, or it
    // stopped): there is nothing to seed.
    const buffer = historyRef.current.get(uid);
    if (!buffer) return;
    // `askedAt` is null until a read has succeeded, so a pod never asked
    // about, and one whose last read failed and fetched nothing, both ask.
    // After a success it is only the time since that read that can hold
    // anything new — which is what makes a paused tab recoverable without
    // asking forever about a gap the broker cannot fill.
    if (!needsSeed(buffer.values(), now, pod?.askedAt ?? null)) return;

    const entry = { inFlight: true, failures: pod?.failures ?? 0, nextAt: pod?.nextAt ?? 0, askedAt: pod?.askedAt ?? null };
    // Issued now: everything up to this instant is what the read will cover.
    const issuedAt = now;
    state.set(uid, entry);

    void (async () => {
      try {
        const rows = await api.getComputeHistory(uid, COMPUTE_HISTORY_WINDOW_MINUTES);
        if (gen !== generation.current) return; // stale: namespace changed while in flight
        const buffers = historyRef.current;
        // Identity, not presence: a pod that vanished and returned while the
        // read was in flight has a NEW buffer, and seeding it from the old
        // pod's history is what the drop-on-disappear rule exists to prevent.
        // Merging here rather than at read time also keeps every live sample
        // the poll collected while this was outstanding.
        if (buffers.get(uid) !== buffer) return;
        buffers.set(uid, seedSamples(buffer, historySamples(rows)));
        entry.failures = 0;
        entry.askedAt = issuedAt;
        entry.nextAt = Date.now() + COMPUTE_SEED_COOLDOWN_MS;
        setHistory(new Map(buffers));
      } catch (err) {
        if (gen !== generation.current) return;
        if (err instanceof ComputeUnsupportedError) {
          // Endpoint-level, not pod-level: the broker answers an unknown uid
          // with an empty row set (compute_api.rs), so a 404/501 here means
          // no /compute/history at all. Deliberately NOT `supported`, which
          // would stop the live polls and blank the whole map.
          historySupportedRef.current = false;
          console.debug(`[compute] ${err.message}; sparklines fall back to live samples only`);
        }
        // Anything else (a shed 503, a network blip) costs this pod its
        // seeded history for now and nothing more: it is not surfaced as
        // `error`, which is about the live poll the whole map depends on.
        // Backing off doubles per consecutive failure, so a struggling
        // broker is not asked again on the next poll — and never gives up
        // for good, because a shed read is explicitly retryable.
        entry.failures += 1;
        const backoff = Math.min(COMPUTE_SEED_RETRY_MS * 2 ** (entry.failures - 1), COMPUTE_SEED_MAX_BACKOFF_MS);
        entry.nextAt = Date.now() + backoff;
      } finally {
        // Only our own entry: the pod may have been dropped and re-seeded
        // while this was in flight, and clearing that newer entry's flag
        // would let a second read start alongside it.
        if (seedRef.current.get(uid) === entry) entry.inFlight = false;
      }
    })();
  }, [api]);

  const refreshLatest = useCallback(async () => {
    if (inflightLatest.current) return;
    inflightLatest.current = true;
    const gen = generation.current;
    try {
      const res = await api.getComputeLatest(namespace);
      if (gen !== generation.current) return; // stale: namespace changed while in flight
      const now = Date.now();
      const byUid = new Map<string, ComputeContainer[]>();
      for (const c of res.containers) {
        const list = byUid.get(c.pod_uid);
        if (list) list.push(c);
        else byUid.set(c.pod_uid, [c]);
      }
      const history = historyRef.current;
      byUid.forEach((rows, uid) => {
        let buf = history.get(uid);
        if (!buf) {
          buf = new RingBuffer<ComputeSample>();
          history.set(uid, buf);
        }
        appendSample(buf, podLevelSample(rows, now));
      });
      // Drop pods that stopped reporting so a recycled uid never inherits
      // history — but only after a few consecutive misses. A pod absent from
      // one poll is usually still there (see COMPUTE_MISSED_POLLS_BEFORE_DROP);
      // dropping at once would throw away an hour of seeded history and buy a
      // fresh history read to rebuild it.
      const missed = missedPollsRef.current;
      for (const uid of [...history.keys()]) {
        if (byUid.has(uid)) {
          missed.delete(uid);
          continue;
        }
        const misses = (missed.get(uid) ?? 0) + 1;
        if (misses < COMPUTE_MISSED_POLLS_BEFORE_DROP) {
          missed.set(uid, misses);
          continue;
        }
        missed.delete(uid);
        history.delete(uid);
        // Forget the seed bookkeeping too, or a uid that comes back could
        // never be seeded again this session.
        seedRef.current.delete(uid);
      }
      setContainers(res.containers);
      // Namespace-scoped node rows are the live ones; keep any other node we
      // learned from the one-shot /compute/nodes fetch.
      setNodes((prev) => {
        const byName = new Map(prev.map((n) => [n.node, n]));
        for (const n of res.nodes) byName.set(n.node, n);
        return [...byName.values()];
      });
      setHistory(new Map(history));
      setPolledAt(now);
      setError(null);
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      else setError(describe(err));
    } finally {
      if (gen === generation.current) inflightLatest.current = false;
    }
  }, [api, namespace, markUnsupported]);

  const refreshFindings = useCallback(async () => {
    if (inflightFindings.current) return;
    inflightFindings.current = true;
    const gen = generation.current;
    try {
      const res = await api.getComputeFindings({ namespace });
      if (gen !== generation.current) return;
      setFindings(res.findings);
      historyDisabledRef.current = res.history_disabled === true;
      setFindingsMeta({
        truncated: res.truncated === true,
        victimsEvaluated: typeof res.victims_evaluated === 'number' ? res.victims_evaluated : null,
        historyDisabled: res.history_disabled === true,
      });
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      else setError(describe(err));
    } finally {
      if (gen === generation.current) inflightFindings.current = false;
    }
  }, [api, namespace, markUnsupported]);

  // Every node's row, once per namespace load, so a pod with no sample yet
  // can still say `off` / `unsupported` / `pending` from its node's state.
  const loadNodes = useCallback(async () => {
    const gen = generation.current;
    if (nodesLoadedGen.current === gen) return; // once per namespace session
    nodesLoadedGen.current = gen;
    try {
      const rows = await api.getComputeNodes();
      if (gen !== generation.current) return;
      setNodes((prev) => {
        const byName = new Map(rows.map((n) => [n.node, n]));
        for (const n of prev) byName.set(n.node, n); // live rows win
        return [...byName.values()];
      });
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) {
        markUnsupported(err);
        return;
      }
      // Transient failure: let the next poll tick or visibility change retry
      // the one-shot fetch instead of leaving cluster-wide node state unknown
      // for the whole namespace session.
      nodesLoadedGen.current = -1;
    }
  }, [api, markUnsupported]);

  useEffect(() => {
    generation.current += 1;
    historyRef.current = new Map();
    seedRef.current = new Map(); // a new namespace seeds its own pods
    missedPollsRef.current = new Map();
    historySupportedRef.current = true; // same cheap retry signal as `supported`
    historyDisabledRef.current = false;
    inflightLatest.current = false;
    inflightFindings.current = false;
    /* eslint-disable react-hooks/set-state-in-effect -- reset-on-namespace, same shape as DataTable's reset-on-pod */
    setContainers([]);
    setNodes([]);
    setFindings([]);
    setFindingsMeta(NO_META);
    setHistory(new Map());
    setError(null);
    setSupported(true);
    setPolledAt(0);
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [namespace]);

  useEffect(() => {
    if (!supported) return; // an older broker: no timers, no listeners, nothing to clean up
    if (!hidden()) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as useSeccompProfiles
      void loadNodes();
      void refreshLatest();
      void refreshFindings();
    }
    const timers: ReturnType<typeof setInterval>[] = [];
    if (pollMs > 0) timers.push(setInterval(() => { if (!hidden()) void refreshLatest(); }, pollMs));
    if (findingsPollMs > 0) timers.push(setInterval(() => { if (!hidden()) void refreshFindings(); }, findingsPollMs));

    // Coming back to a hidden tab: refresh at once rather than waiting out
    // the interval, so the gauges never show a stale sample after a resume.
    const onVisibility = () => {
      if (!hidden()) {
        void loadNodes(); // no-op once it has run for this namespace session
        void refreshLatest();
        void refreshFindings();
      }
    };
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibility);
    return () => {
      timers.forEach(clearInterval);
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [refreshLatest, refreshFindings, loadNodes, pollMs, findingsPollMs, supported]);

  const containersByPodUid = useMemo(() => {
    const m = new Map<string, ComputeContainer[]>();
    for (const c of containers) {
      const list = m.get(c.pod_uid);
      if (list) list.push(c);
      else m.set(c.pod_uid, [c]);
    }
    return m;
  }, [containers]);

  const containersByPodName = useMemo(() => {
    const m = new Map<string, ComputeContainer[]>();
    for (const c of containers) {
      const key = podNameKey(c.namespace, c.pod_name);
      const list = m.get(key);
      if (list) list.push(c);
      else m.set(key, [c]);
    }
    return m;
  }, [containers]);

  const nodesByName = useMemo(() => new Map(nodes.map((n) => [n.node, n])), [nodes]);

  const enabled = useMemo(() => supported && nodes.length > 0 && nodes.some((n) => n.compute_enabled), [nodes, supported]);

  return {
    containersByPodUid,
    containersByPodName,
    nodesByName,
    findings,
    findingsMeta,
    history,
    enabled,
    supported,
    error,
    polledAt,
    seedPod,
  };
}
