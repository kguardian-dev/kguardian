// Compute-contention wire types. Field names mirror the broker rows
// (snake_case, as on the wire) — see docs/design/compute-contention-monitoring.md
// and the shared wire contract. Counters are deltas over `interval_ms`,
// gauges are instantaneous.

export type CulpritKind = 'pod' | 'system' | 'kernel' | 'unknown';

/** One entry of a container's blame list (who was on the CPU while it waited). */
export interface ComputeBlame {
  cgroup_id: number;
  kind: CulpritKind | string;
  /** `ns/pod/container` for a pod, unit name for a system slice, `kernel`. */
  ref: string;
  container_uid: string | null;
  count: number;
  wait_ns: number;
}

/** Mirrors `pod_compute_latest` — one row per live container. */
export interface ComputeContainer {
  container_uid: string;
  pod_uid: string;
  namespace: string;
  pod_name: string;
  container: string;
  node: string;
  cgroup_id: number;
  ts: string;
  interval_ms: number;
  /** Derived by the broker: `usage_usec / interval_ms` in millicores. */
  cpu_usage_millis: number;
  cpu_quota_usec: number | null;
  cpu_period_usec: number;
  cpu_request_millis: number | null;
  cpu_limit_millis: number | null;
  cpu_nr_periods: number;
  cpu_nr_throttled: number;
  cpu_throttled_usec: number;
  cpu_psi_some10: number;
  cpu_psi_full10: number;
  mem_current: number;
  mem_working_set: number;
  mem_limit: number | null;
  mem_request: number | null;
  mem_psi_some10: number;
  mem_psi_full10: number;
  mem_events_high: number;
  mem_events_max: number;
  mem_oom_kill: number;
  mem_refault: number;
  mem_pgmajfault: number;
  /** Null when the scheduler probe is not loaded on the node. */
  runq_count: number | null;
  runq_p50_us: number | null;
  runq_p95_us: number | null;
  runq_p99_us: number | null;
  runq_max_us: number | null;
  runq_overflow: number | null;
  blame: ComputeBlame[] | null;
  updated_at: string;
}

/** Mirrors `node_compute_latest`. */
export interface ComputeNode {
  node: string;
  ts: string;
  interval_ms: number;
  ctxt_per_sec: number;
  compute_enabled: boolean;
  /** cgroup v2 ∧ PSI. */
  compute_supported: boolean;
  contention_loaded: boolean;
  cpu_some10: number;
  cpu_full10: number;
  mem_some10: number;
  mem_full10: number;
  cpu_cores: number | null;
  memory_bytes: number | null;
  bpf_runq_enqueued: number;
  bpf_runq_hist: number;
  bpf_pair: number;
  /** BPF map inserts dropped because the map was full (design D4: a leak or
   *  undersized map shows up as a number, not as a phantom p99). Absent from
   *  an older controller. */
  bpf_hist_update_failures?: number | null;
  bpf_pair_update_failures?: number | null;
  unknown_blame_share: number;
  updated_at: string;
}

export type ComputeFindingKind =
  | 'noisy-neighbor'
  | 'cpu-throttled'
  | 'cpu-contended'
  | 'memory-pressure'
  | 'memory-limit-thrash';

export type ComputeSeverity = 'critical' | 'high' | 'medium';

export interface ComputeFindingVictim {
  pod_uid: string;
  namespace: string;
  pod_name: string;
  container: string;
  container_uid: string;
  node: string;
}

export interface ComputeFindingCulprit {
  kind: CulpritKind | string;
  ref: string;
  pod_uid: string | null;
  namespace: string | null;
  pod_name: string | null;
  container_uid: string | null;
  /** 0..1. Kind-dependent: for `noisy-neighbor` / `cpu-contended` the
   *  culprit's share of the victim's CPU run-queue wait; for
   *  `memory-pressure` its share of the node's memory overage
   *  (utils/compute `blameShareLabel`). */
  blame_share: number;
  /** Null when the culprit opted out of sampling (`kguardian.dev/compute: off`):
   *  it can still be blamed, but its usage is unknown. */
  cpu_usage_millis: number | null;
  cpu_request_millis: number | null;
}

export interface ComputeFindingEvidence {
  window_minutes: number;
  cpu_psi_some10_max: number;
  cpu_psi_full10_max: number;
  runq_p99_us_max: number | null;
  throttled_ratio: number;
  mem_psi_some10_max: number;
  node_mem_some10_max: number;
  refault_delta: number;
  mem_events_high_delta: number;
}

/** Mirrors the broker's `Finding` from `GET /compute/findings`. */
export interface ComputeFinding {
  kind: ComputeFindingKind;
  severity: ComputeSeverity;
  victim: ComputeFindingVictim;
  culprit: ComputeFindingCulprit | null;
  evidence: ComputeFindingEvidence;
  first_seen: string;
  last_seen: string;
  message: string;
}

/** avg / max / last of a gauge over a history row's resolution window. */
export interface GaugeSummary {
  avg: number;
  max: number;
  last: number;
}

/** Mirrors `pod_compute_history` (minute or 5-minute rows). */
export interface ComputeHistoryRow {
  id: number;
  container_uid: string;
  pod_uid: string;
  namespace: string;
  pod_name: string;
  container: string;
  node: string;
  ts: string;
  resolution_secs: number;
  cpu_usage_millis_avg: number;
  cpu_usage_millis_max: number;
  cpu_usage_millis_last: number;
  cpu_quota_usec: number | null;
  cpu_period_usec: number;
  cpu_request_millis: number | null;
  cpu_limit_millis: number | null;
  cpu_nr_periods: number;
  cpu_nr_throttled: number;
  cpu_throttled_usec: number;
  cpu_psi_some10_avg: number;
  cpu_psi_some10_max: number;
  cpu_psi_full10_avg: number;
  cpu_psi_full10_max: number;
  mem_current_avg: number;
  mem_current_max: number;
  mem_current_last: number;
  mem_working_set_avg: number;
  mem_working_set_max: number;
  mem_working_set_last: number;
  mem_limit: number | null;
  mem_request: number | null;
  mem_psi_some10_avg: number;
  mem_psi_some10_max: number;
  mem_psi_full10_avg: number;
  mem_psi_full10_max: number;
  mem_events_high: number;
  mem_events_max: number;
  mem_oom_kill: number;
  mem_refault: number;
  mem_pgmajfault: number;
  runq_count: number | null;
  runq_p50_us: number | null;
  runq_p95_us: number | null;
  runq_p99_us: number | null;
  runq_max_us: number | null;
  runq_overflow: number | null;
  runq_hist: number[] | null;
}

/** Mirrors `pod_contention_history`. */
export interface ContentionPair {
  id: number;
  ts: string;
  node: string;
  victim_container_uid: string;
  victim_pod_uid: string;
  victim_namespace: string;
  culprit_cgroup_id: number;
  culprit_kind: CulpritKind | string;
  culprit_ref: string;
  culprit_container_uid: string | null;
  count: number;
  wait_ns: number;
}

export interface ComputeLatestResponse {
  containers: ComputeContainer[];
  nodes: ComputeNode[];
}

/** `GET /compute/findings`. The metadata fields are optional on the wire. */
export interface ComputeFindingsResponse {
  findings: ComputeFinding[];
  /** The engine's victim cap was hit; only the first `victims_evaluated` were scored. */
  truncated?: boolean;
  victims_evaluated?: number;
  /** `COMPUTE_HISTORY_RETENTION_DAYS=0`: no history rows ⇒ no findings can be computed. */
  history_disabled?: boolean;
}

/** Normalised findings metadata (hooks/useComputeData). */
export interface ComputeFindingsMeta {
  truncated: boolean;
  victimsEvaluated: number | null;
  historyDisabled: boolean;
}

/** One client-side sample of a pod's summed containers (utils/compute). */
export interface ComputeSample {
  /** Start of the minute bucket this sample belongs to (`bucketStart`), so a
   *  sample seeded from `/compute/history` and one folded in from a 5 s poll
   *  are on the same grid — not the instant the poll landed. */
  at: number;
  cpuMillis: number;
  workingSetBytes: number;
}

/** Which capacity a gauge percentage is normalised against (D8: limit → request → node). */
export type ComputeDenominator = 'limit' | 'request' | 'node';

/** `pending`: no sample for this pod yet (fresh pod, or its node has not reported). */
export type ComputeStatus = 'ok' | 'warning' | 'critical' | 'unsupported' | 'off' | 'pending';

/** Per-node compute state on `PodNodeData.compute` (see utils/compute). */
export interface PodComputeData {
  cpuPct: number | null;
  memPct: number | null;
  cpuDenominator: ComputeDenominator | null;
  memDenominator: ComputeDenominator | null;
  status: ComputeStatus;
  findings: ComputeFinding[];
  /** One slot per minute of the window, oldest first, in millicores;
   *  `null` where no sample covers that minute. Dense, because the
   *  sparkline plots by index — see `denseSeries`. */
  sparkCpu: (number | null)[];
  /** The same slots in bytes. */
  sparkMem: (number | null)[];
  /** Current pod-level values behind the percentages. */
  cpuMillis: number | null;
  memBytes: number | null;
  /** The capacity behind `cpuPct` / `memPct`, in millicores / bytes. */
  cpuCapacityMillis: number | null;
  memCapacityBytes: number | null;
  /** The pod's containers, for the detail panel. */
  containers: ComputeContainer[];
  /** Dropped BPF map inserts on the pod's node (either > 0 ⇒ status ≥ warning). */
  probeDrops?: ProbeDrops | null;
}

export interface ProbeDrops {
  hist: number;
  pair: number;
}
