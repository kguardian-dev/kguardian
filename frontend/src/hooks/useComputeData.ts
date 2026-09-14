import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ComputeUnsupportedError, apiClient } from '../services/api';
import type { ComputeContainer, ComputeFinding, ComputeFindingsMeta, ComputeNode, ComputeSample } from '../types/compute';
import {
  COMPUTE_HISTORY_SAMPLES,
  COMPUTE_HISTORY_WINDOW_MINUTES,
  RingBuffer,
  historySamples,
  podLevelSample,
  podNameKey,
  pushBucketed,
  seedHistory,
} from '../utils/compute';
import { withConcurrencyLimit } from '../utils/concurrency';

export const COMPUTE_POLL_MS = 5_000;
export const COMPUTE_FINDINGS_POLL_MS = 15_000;

/**
 * Pods the EAGER backfill seeds per namespace session. A 200-pod namespace
 * would otherwise fire 200 history reads for gauges nobody may ever expand;
 * the first N pods the broker reports (it orders `/compute/latest` by pod
 * name, so "first" is stable across polls) cover the common case with no
 * interaction at all.
 *
 * What makes this cap tolerable is `seedPod`: a card the user actually opens
 * is seeded on demand regardless of it. Raising the cap instead would trade a
 * bounded burst for one proportional to namespace size, which is what the cap
 * exists to prevent — fix a thin sparkline by seeding on expansion, never by
 * making this number bigger.
 */
export const COMPUTE_BACKFILL_MAX_PODS = 40;

/**
 * History reads in flight at once. Each is a windowed range read the broker
 * charges against its read budget and sheds with a 503 when it does not fit,
 * so this stays well below the 10 `usePodData` uses for its cheap reads —
 * a self-inflicted shed would cost exactly the history we came for.
 */
export const COMPUTE_BACKFILL_CONCURRENCY = 4;

/**
 * Attempts per pod before its history is written off for the session.
 *
 * The broker sheds a read that does not fit its budget with `503` and a
 * `Retry-After` (broker/src/read_budget.rs) — explicitly retryable, and
 * likeliest exactly when a namespace loads and several windowed reads land
 * together. Giving up on the first shed would mean one budget spike at load
 * denies every pod in the namespace its history for the whole session: the
 * regression this feature exists to remove. A small bound still keeps a
 * persistently failing broker from being asked every 5 s forever.
 */
export const COMPUTE_BACKFILL_MAX_ATTEMPTS = 3;

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
  /** Client-side ring buffer of the last 60 one-minute pod-level buckets per
   *  `pod_uid`, seeded from `/compute/history` and kept current by the poll. */
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
  /** Seed one pod's history now (the user expanded its card). Idempotent,
   *  exempt from the eager backfill's pod cap, and a no-op for a pod already
   *  seeded or being read. */
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
 * The per-pod sparkline buffers are one-minute buckets, seeded once per pod
 * from `GET /compute/history/{pod_uid}` after the first successful poll and
 * then kept current by it — so an expanded node opens on an hour of real
 * trend instead of an empty chart that fills while you watch.
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
  /** Per-pod seed bookkeeping: how many history reads have been attempted,
   *  and whether the pod is finished with (seeded, or out of attempts). An
   *  entry is dropped along with the pod's buffer, so a pod that genuinely
   *  went away and came back can be seeded again. */
  const backfillRef = useRef<Map<string, { attempts: number; done: boolean; inFlight: boolean }>>(new Map());
  /** Distinct pods this namespace session has EVER asked history for. The cap
   *  gates on this rather than on the bookkeeping map's size, which shrinks
   *  as pods come and go and so would bound nothing under churn. */
  const backfillPodsRef = useRef(0);
  /** Consecutive polls each known pod has been missing from /compute/latest. */
  const missedPollsRef = useRef<Map<string, number>>(new Map());
  /** False once /compute/history answered 404/501: an optional endpoint this
   *  broker does not have. Deliberately NOT `supported`, which would stop
   *  the live polls and blank the map (see backfillHistory). */
  const historySupportedRef = useRef(true);
  /** Mirrors findingsMeta.historyDisabled for the backfill gate, plus
   *  whether the findings poll has answered at all yet. */
  const historyDisabledRef = useRef(false);
  const findingsTriedRef = useRef(false);
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
   * Seed the ring buffers from the broker's stored history, so expanding a
   * node shows an hour of trend at once instead of a sparkline that draws
   * itself over the next five minutes while you watch.
   *
   * Fire-and-forget: the live poll never awaits this, and a pod whose read
   * fails simply keeps the pre-existing behaviour — a buffer that fills from
   * the poll alone. A pod is asked for at most COMPUTE_BACKFILL_MAX_ATTEMPTS
   * times per namespace session, counted BEFORE the request so a failure
   * that never resolves cannot be retried by every 5 s poll.
   *
   * Nothing here may touch `supported`. This is a cosmetic seed on top of a
   * working map: a broker that serves /compute/latest but predates
   * /compute/history (or has history off) must keep its gauges, micro bars,
   * status dots and findings — turning the whole feature off because an
   * optional read 404'd would be a far worse outcome than an empty
   * sparkline. `historySupported` is therefore tracked separately and gates
   * only this path.
   */
  const backfillHistory = useCallback(async (uids: readonly string[], opts: { onDemand?: boolean } = {}) => {
    const gen = generation.current;
    if (!historySupportedRef.current) return;
    // `retentionDays: 0` — the broker answers every history read with an
    // empty row set, after charging a read permit for it. Waiting for the
    // first findings response (issued alongside the first latest poll) costs
    // one round trip and saves a burst of guaranteed-empty reads per
    // namespace. `findingsTried` also flips on a failed findings poll: not
    // knowing is a reason to seed, not to give up on it.
    if (historyDisabledRef.current) return;
    // Only the eager path waits for that answer. An expansion is a deliberate
    // request for one pod's history: making it a no-op because the findings
    // poll has not landed yet would leave the card empty with nothing to
    // retry it, where the eager path simply tries again next poll.
    if (!opts.onDemand && !findingsTriedRef.current) return;

    const state = backfillRef.current;
    const todo: string[] = [];
    for (const uid of uids) {
      const pod = state.get(uid);
      if (pod?.done) continue;
      // Already being read. Without this, every 5 s poll re-issues a read for
      // a pod whose first one is still pending and burns another attempt on
      // it, so three polls exhaust the retry budget before any failure has
      // even happened — tripling the load on a budgeted endpoint and leaving
      // a genuinely shed pod with nothing left to retry with.
      if (pod?.inFlight) continue;
      // `continue`, not `break`: the cap only blocks pods never asked for
      // before. Stopping the scan here would also skip retries for
      // already-counted pods that sort after the first over-cap one.
      // On-demand seeding is exempt: the cap bounds a burst proportional to
      // namespace size, and one read for the card in front of the user is
      // neither a burst nor proportional to anything but their clicking.
      if (!pod && !opts.onDemand && backfillPodsRef.current >= COMPUTE_BACKFILL_MAX_PODS) continue;
      // No buffer means the pod is not being tracked (it stopped reporting);
      // there is nothing to seed, and counting an attempt for a read that is
      // never issued would spend the pod's budget on nothing.
      if (!historyRef.current.has(uid)) continue;
      if (!pod && !opts.onDemand) backfillPodsRef.current += 1; // the cap counts eager reads
      const attempts = (pod?.attempts ?? 0) + 1;
      // Marked done on the LAST attempt, so a retryable failure before that
      // leaves the pod eligible for the next poll to pick up again.
      state.set(uid, { attempts, done: attempts >= COMPUTE_BACKFILL_MAX_ATTEMPTS, inFlight: true });
      todo.push(uid);
    }
    if (todo.length === 0) return;

    // The rows are kept, not a finished buffer: merging has to happen at
    // COMMIT time. Reads run at COMPUTE_BACKFILL_CONCURRENCY against a
    // budgeted endpoint, so the last of them can land many polls after the
    // first — and a buffer merged at read time would then be committed over
    // live buckets collected since, which `pushBucketed` can never restore
    // because they are older than what it holds by then.
    const seeded: { uid: string; buffer: RingBuffer<ComputeSample>; samples: ComputeSample[] }[] = [];
    try {
      await withConcurrencyLimit(
        todo.map((uid) => async () => {
          // An older broker answered 404 on an earlier pod: stop asking for
          // the rest of this batch too.
          if (!historySupportedRef.current || gen !== generation.current) return;
          // Dropped between planning and running: no request goes out. Its
          // bookkeeping went with the buffer (see the drop in refreshLatest),
          // so there is no attempt left to refund.
          const buffer = historyRef.current.get(uid);
          if (!buffer) return;
          try {
            const rows = await api.getComputeHistory(uid, COMPUTE_HISTORY_WINDOW_MINUTES);
            if (gen !== generation.current) return; // stale: namespace changed while in flight
            seeded.push({ uid, buffer, samples: historySamples(rows) });
            const pod = state.get(uid);
            if (pod) pod.done = true; // seeded: never ask for this pod again
          } catch (err) {
            if (gen !== generation.current) return;
            if (err instanceof ComputeUnsupportedError) {
              historySupportedRef.current = false;
              console.debug(`[compute] ${err.message}; sparklines fall back to live samples only`);
            }
            // Anything else (a shed 503, a network blip) costs this pod its
            // seeded history and nothing more: it is not surfaced as `error`,
            // which is about the live poll the whole map depends on. The pod
            // keeps whatever attempts it has left.
          }
        }),
        COMPUTE_BACKFILL_CONCURRENCY,
      );

      if (gen !== generation.current || seeded.length === 0) return;
      // One commit for the whole batch. `history` is a dependency of the pods
      // memo in usePodData, so every commit rebuilds `compute` for every pod
      // and repaints the map: 40 of them in a burst is 40 repaints.
      const buffers = historyRef.current;
      const now = Date.now();
      let changed = false;
      for (const { uid, buffer, samples } of seeded) {
        // Identity, not presence: a pod that vanished and returned while the
        // read was in flight has a NEW buffer, and seeding it from the old
        // pod's history is exactly what the drop-on-disappear rule prevents.
        if (buffers.get(uid) !== buffer) continue;
        buffers.set(uid, seedHistory(buffer, samples, now));
        changed = true;
      }
      if (changed) setHistory(new Map(buffers));
    } catch (err) {
      // Nothing reaches this today: every read is already caught per pod
      // just below. It is here because both call sites are deliberately
      // un-awaited and the limiter is fail-fast, so the day a throw moves
      // outside that per-pod catch it would surface as an unhandled
      // rejection rather than the best-effort no-op this is documented as.
      console.debug(`[compute] history backfill failed: ${describe(err)}`);
    } finally {
      // Whatever happened, these pods are no longer in flight: a later poll
      // may retry the ones that still have attempts left.
      for (const uid of todo) {
        const pod = state.get(uid);
        if (pod) pod.inFlight = false;
      }
    }
  }, [api]);

  /**
   * Seed one pod's sparkline now, because the user just opened its card.
   *
   * The eager backfill is capped, so in a large namespace most pods are not
   * seeded and would otherwise fill a 60-minute window at one bucket per
   * minute — worse than the five minutes the old 5 s ring buffer took. This
   * is the seam that fixes that: it shares the eager path's bookkeeping, so
   * a pod already seeded, already being read, or out of attempts issues
   * nothing, and an expansion can never double-fetch what the eager backfill
   * already has in flight. Fire-and-forget, like everything else here.
   */
  const seedPod = useCallback((uid: string) => {
    void backfillHistory([uid], { onDemand: true });
  }, [backfillHistory]);

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
          buf = new RingBuffer<ComputeSample>(COMPUTE_HISTORY_SAMPLES);
          history.set(uid, buf);
        }
        // A clock step backwards can leave a pod with nothing: everything it
        // held was in the future. Re-open seeding so the hour it lost can be
        // fetched again, instead of leaving the card empty for an hour.
        if (pushBucketed(buf, podLevelSample(rows, now)) === 'restarted') backfillRef.current.delete(uid);
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
        backfillRef.current.delete(uid);
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
      setError(null);
      // Deliberately not awaited: the 5 s cadence is the contract, the seed
      // is best-effort and must never delay a poll (or the next one).
      void backfillHistory([...byUid.keys()]);
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      else setError(describe(err));
    } finally {
      if (gen === generation.current) inflightLatest.current = false;
    }
  }, [api, namespace, markUnsupported, backfillHistory]);

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
      if (gen === generation.current) {
        inflightFindings.current = false;
        // Answered or failed, we have asked: the backfill waits for this, and
        // an outage of the findings poll must not hold the seed hostage.
        const first = !findingsTriedRef.current;
        findingsTriedRef.current = true;
        // The two first polls race: the backfill needs `history_disabled`
        // from this one and the pod uids from the latest one, so whichever
        // lands second starts it. Waiting for the next 5 s tick instead would
        // delay every sparkline by a poll for no reason.
        if (first) void backfillHistory([...historyRef.current.keys()]);
      }
    }
  }, [api, namespace, markUnsupported, backfillHistory]);

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
    backfillRef.current = new Map(); // a new namespace seeds its own pods
    backfillPodsRef.current = 0;
    missedPollsRef.current = new Map();
    historySupportedRef.current = true; // same cheap retry signal as `supported`
    historyDisabledRef.current = false;
    findingsTriedRef.current = false;
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
    seedPod,
  };
}
