# Live Compute Gauges & Noisy-Neighbour Detection

> **Status:** Draft · **Date:** 2026-09-10 · **Components:** controller, broker, frontend, llm-bridge, chart
> Engineering design proposal. Not part of the published (Mintlify) docs site.

Show every pod's CPU and memory on the network map as a live gauge, tell the
operator when a pod is degraded because it is starved of compute, and name the
pod on the same node that is starving it.

Three signals, cheapest first, each one gating the next:

| Layer | Question | Source | Cost |
|---|---|---|---|
| **Usage** | How much CPU / memory is this container using, against what limit? | cgroup v2 files (`cpu.stat`, `memory.current`, `cpu.max`, `memory.max`) | one file read per container per interval |
| **Stall** | Is it waiting for CPU it should have? Is it thrashing under its memory limit? Is it throttled by its *own* quota? | cgroup v2 `cpu.pressure`, `memory.pressure`, `cpu.stat` throttle counters, `memory.events`, `memory.stat` | same file walk |
| **Blame** | *Who* was on the CPU while it waited? | eBPF `sched_wakeup` / `sched_wakeup_new` / `sched_switch`, histogram + pair matrix aggregated **in kernel**, keyed by cgroup id | ~0.5 µs per context switch on the node |

Only the third layer needs a new BPF program. The first two are what the
kernel already accounts for free, and they are what turns "this pod looks
slow" into "this pod is *starved*, and not by its own limit". Blame without
the stall layer is how the reference experiment produced an 8-second p99 that
did not exist (see [Lessons from the references](#lessons-from-the-references)).

## Why kguardian, and where it stops

kguardian already runs a privileged eBPF DaemonSet on every node, already
resolves pod processes through containerd, and already draws every pod
as a node on a graph. That is exactly the vantage point a noisy-neighbour
detector needs and that a metrics-server / Prometheus stack does not have:
per-context-switch attribution is only possible from inside the kernel, and
nobody outside one 2026 research paper publishes a per-pair blame model.

It is also a security signal, not a departure from the product: a pod that
starves its neighbours is an availability problem the same way an
unexpectedly-open port is, and the roadmap already carries "observed
CPU/memory usage" under *Resource Quotas & Limits* (`docs/roadmap/
future-resources.mdx`). This design delivers the observation half. Generating
`resources:` recommendations from it is a follow-up (Phase 5) so the pending
roadmap decision stays open.

**Out of scope for this proposal**

- Any enforcement or mutation: no eviction, no `resources:` patching, no VPA.
  Same principle as `SeccompProfile`: kguardian observes, recommends, audits.
- Profiling (stack sampling). Different tool, different overhead class.
- I/O, network softirq, LLC / memory-bandwidth contention. The reference
  author proposes them; they need perf counters or block-layer probes and
  a separate design.
- cgroup v1 nodes. Per-cgroup PSI does not exist there. The feature reports
  itself unsupported on such a node (in the node sample, D10) and the node renders
  without gauges.

## Current state

What exists, from the integration map (`controller/`, `broker/`, `frontend/`
at `ebac67a04`):

### Controller

- Three BPF sources compiled by `libbpf-cargo` in `build.rs` (`syscall`,
  `network_probe`, `netpolicy_drop`); CO-RE via the pinned `vmlinux` crate.
  A fourth source is one more `SkeletonBuilder` block and one `include!`
  module (`controller/src/syscall.rs:14-16` is the pattern).
- Pod identity is the **network-namespace inode** (`ContainerMap`,
  `models.rs:96`; `inode_num` LRU map with the tier/generation bitfield in
  `bpf/helper.h:33-78`). No cgroup path or id is read anywhere.
- `container.rs` resolves a **host pid** through containerd `Tasks.Get`
  (`container.rs:166`) and reads `/proc/<pid>/ns/net`. But `PodInspect` is
  **one per pod**: `process_container_ids` (`pod_watcher.rs:633-660`)
  returns on the first container whose netns resolves, so the controller
  holds one pid per pod, not per container, and `PodInfo` has no pod UID.
  Host `/proc` is mounted read-only. **`/sys/fs/cgroup` is not mounted.**
- Load-time capability guards (`kernel_can_fentry`, `set_autoload(false)`,
  `bpf.rs:183-262`) let a missing hook degrade instead of crashloop.
- Cadences: flows batch 100 / 1 s (`network.rs:170`), syscalls diff every
  10 s (`syscall.rs:88`), node facts once at startup.
- `capture_tiers.rs` + the raise-only pod annotation (`pod_watcher.rs:556`)
  are the template for a per-feature config. `supervisor.rs:217-232` roster
  macro; `SeccompDistributor => MayRetire` is the opt-in-subsystem precedent.
- No Prometheus endpoint in the controller.

### Broker

- actix-web + Diesel on **plain PostgreSQL**. No TimescaleDB, no histogram or
  gauge storage. `pod_traffic` is the largest time series and it already
  forced `LIMIT`s, indexes and `read_budget.rs` after a 6.7 M-row incident;
  `audit_verdicts` is the other one and owns the only retention pass
  (`retention.rs:28-33`).
- New endpoint = handler + `pub use` in `lib.rs` + `.service()` in
  `main.rs:364-391`. New GET must declare a row cost and acquire a
  `ReadPermit`. New high-volume table needs a pass in `retention.rs`.
- Types are duplicated per component (no shared crate); the contract is the
  JSON field names.
- `node_facts` carries provider / distro / CNI / IP family / policy
  enforcement. **No CPU count, memory, kernel or cgroup version.**

### Frontend

- `reactflow` + `elkjs`; `NODE_WIDTH = 240`, `NODE_HEIGHT = 100`
  (`NetworkGraph.tsx:27-28`). `PodNode.tsx:129-144` renders two stat chips in
  the expanded body. No chart library.
- **The graph is not live.** `usePodData` fetches on namespace change and on
  the refresh button. The only poll is `useSeccompProfiles.ts:42`.
- Findings are computed client-side from already-fetched data
  (`FindingsView.tsx`); `FindingKind` in `utils/findingPolicyType.ts:5` maps
  every kind to a policy type.

### Chart / llm-bridge

- `syscalls:` and `seccomp:` are top-level feature blocks in `values.yaml`;
  `seccomp.distribute: false` is the "off by default, adds a hostPath when on"
  precedent.
- llm-bridge tools are one `TOOL_DEFS` entry + one executor line
  (`llm-bridge/src/tools/registry.ts`, `execute.ts`), parity-tested.

## Design decisions

### D1 — Identity for this feature is the cgroup id, layered on the existing pid

The netns inode is per pod and is the wrong key for CPU accounting: the
scheduler thinks in tasks and cgroups, and limits are per container. The
existing `ContainerMap` stays untouched (it is per pod, keyed by netns, and
the traffic and syscall paths depend on that). This feature adds a
**parallel, per-container registry** that reuses the same containerd
plumbing:

1. In `process_container_ids`, after the netns registration returns, walk
   **every** container id in the pod status (not just the first that
   resolves) and call the existing `get_pid` for each. Read
   `/proc/<pid>/cgroup` → the container's cgroup v2 path (one line,
   `0::/kubepods.slice/.../cri-containerd-<cid>.scope`).
2. Resolve the 64-bit cgroup id with `name_to_handle_at()` on
   `/sys/fs/cgroup/<path>`. This is what bpftrace's `cgroupid()` and systemd
   do; the working assumption is that it returns the same 64-bit value
   `bpf_get_current_cgroup_id()` / `kn->id` yields in BPF, generation bits
   included, which is what the reference implementation had to guess around
   with `& 0xFFFFFFFF` on GKE. Nothing in the controller touches cgroups
   today, so this is **verified, not assumed, in Phase 0** against
   `bpftool cgroup tree` on at least one managed provider (GKE) and one
   self-hosted node (Talos).
3. Store a `ContainerCompute { pod_uid, namespace, pod_name, container_name,
   container_id, pid, cgroup_path, cgroup_id, requests, limits }` in a new
   `ComputeMap = Arc<DashMap<u64 /*cgroup_id*/, Arc<ContainerCompute>>>`
   (read through a `lookup_*` wrapper, same clippy rule as `ContainerMap`),
   and register the id in the new BPF map `tracked_cgroups` (see D4).
   `pod_uid` comes from `pod.metadata.uid`, which `process_container_ids`
   already has in hand; `PodInfo` itself does not change.

Pods that were registered before the feature was enabled are picked up by the
existing periodic re-list (`PodResync`), so no separate backfill is needed.

Cost: one containerd `Tasks.Get` per **additional** container (the first is
already paid) plus two small reads, once per pod registration. No new
privilege: `/sys/fs/cgroup` mounted **read-only** as a new hostPath, only
rendered when `compute.enabled`. `hostPID` stays off; host `/proc` is
already mounted.

Pod-level rollup: the graph node (a pod / workload) shows a single gauge
that is the sum of its container rows; the pod-level cgroup is not sampled
(pause-container time is negligible and init containers have exited).
Per-container rows are kept in the broker because limits and throttling are
per container.

### D2 — Usage and stall come from cgroup files, not eBPF

For the gauges and the victim-side stall signal the kernel already keeps
exact counters; a BPF program would only re-derive them at higher cost
(Kepler dropped its sched-based CPU accounting for `/proc` + `/sys` in 2026
for this reason). Per container, per sample:

| File | Fields kept | Meaning |
|---|---|---|
| `cpu.stat` | `usage_usec`, `nr_periods`, `nr_throttled`, `throttled_usec` | CPU time; CFS-quota throttling |
| `cpu.max` | quota, period | CPU limit (`max` = unlimited) |
| `cpu.pressure` | `some avg10`, `full avg10`, `some total` | share of time ≥1 task waited for CPU / all tasks waited |
| `memory.current`, `memory.max` | | usage vs limit |
| `memory.stat` | `anon`, `file`, `inactive_file`, `workingset_refault_anon`, `workingset_refault_file`, `pgmajfault` | working set (`current − inactive_file`, cAdvisor's definition); thrashing under the limit |
| `memory.pressure` | `some avg10`, `full avg10` | reclaim stalls |
| `memory.events` | `high`, `max`, `oom`, `oom_kill` | limit hits and OOM kills |

Node level, once per sample: `/proc/pressure/{cpu,memory}`,
`/proc/stat` context-switch counter (drives the overhead estimate), and
node-total CPU / memory from `/proc/meminfo` and `/proc/stat`.

Requests are not in the cgroup; `cpu.weight` is derived from them but lossy.
The pod watcher already has the pod spec, so requests and limits per
container are captured **from the spec at registration** and shipped with
the sample so the broker never needs the API server to normalise a gauge.

Sample interval default **5 s** (`compute.sampleInterval`). One `openat`
+ read per file, ~10 files per container: on a 100-container node that is
~1 000 small reads every 5 s, well under the syscall probe's own budget.

### D3 — Throttling is separated from contention, always

The single most common misread in this space (called out by Netflix and
reproduced by the reference) is CFS throttling inflating run-queue latency
and being blamed on a neighbour. A pod that is throttled by its own
`limits.cpu` is not a noisy-neighbour victim; it is under-provisioned. The
two are different findings with different remediations:

- `cpu-throttled`: `throttled_usec / (nr_periods × period)` over the window
  ≥ `compute.thresholds.throttledRatio` (default 0.25). Remediation: raise
  or remove the limit. No culprit.
- `noisy-neighbor`: stall signal high **and** throttling ratio below
  `compute.thresholds.throttledRatioMax` (default 0.10) **and** a culprit
  passes D6. Remediation: point at the culprit's requests.

Both are computed broker-side (D7) so the CLI, MCP tools and UI agree.

### D4 — Blame comes from an in-kernel run-queue latency histogram plus a preemption-pair matrix

New source `controller/src/bpf/sched_contention.bpf.c`, four programs on
`tp_btf` tracepoints, using the `BPF_PROG()` macro so arguments are typed
(`prev`, `next`) rather than a hand-cast `ctx` array — the exact bug that
invalidated the reference's headline number. BTF (`/sys/kernel/btf/vmlinux`)
is required: CO-RE relocation needs it for any program type, so there is no
`raw_tp` fallback; without BTF the probe reports `contention_loaded=false`
and the gauge layers continue. The object is compiled with `-mcpu=v2` so the
atomics encode as legacy `lock xadd` and load on 5.10+ x86 and 5.15 arm64
regardless of the builder's clang.

```
tp_btf/sched_wakeup       → if p.on_cpu or p == current: return
                                                  # a wakeup can target a task that is
                                                  # still running (ttwu_runnable / self-wake);
                                                  # stamping it would fold run + sleep time
                                                  # into the next wait
                            runq_enqueued[p.pid] = now   (BPF_NOEXIST: a stamp set at
                                                  # preemption below must survive a later
                                                  # wakeup; with the guard above no stale
                                                  # stamp can exist, every stamp is popped
                                                  # by switch-in or exit)
tp_btf/sched_wakeup_new   → same (forked tasks; the reference missed these)
tp_btf/sched_switch(preempt, prev, next):
    if preempt or prev.state == TASK_RUNNING: # still runnable: preempted, or preempted
        runq_enqueued[prev.pid] = now         # between set_current_state() and schedule()
                                              # (__schedule only deactivates when not
                                              # preempting); bcc runqlat semantics —
                                              # Netflix's published snippet omits this
                                              # and it is the noisy-neighbour case
    ts = runq_enqueued.pop(next.pid) or return
    lat = now - ts
    victim = cgroup_id(next); if victim ∉ tracked_cgroups: return
    if lat < MIN_RUNQ_LAT_NS: return          # default 100 µs, map-configurable
    runq_hist[{victim, log2(lat µs)}] += 1    # 24 buckets, last = overflow
    culprit = cgroup_id(prev)
    pair[{victim, culprit}] += {count: 1, wait_ns: lat}
tp_btf/sched_process_exit → runq_enqueued.delete(pid)   # no orphans
```

Design points:

- **Filter to tracked victims in kernel.** Only pods kguardian tracks (same
  exclusion rules as traffic) get a histogram entry; everything else returns
  before any map write. The culprit side is recorded raw: a system unit or
  kernel thread is a legitimate answer ("starved by kubelet / by softirq").
- **Two maps, not one.** The reference keyed its histogram on
  `{victim, culprit, bucket}` — 50 000 entries and pods × neighbours × 24
  cardinality. Splitting into `runq_hist{victim,bucket}` (tracked pods × 24)
  and `pair{victim,culprit}` (LRU, 16 384) keeps the histogram exact and lets
  pair churn evict safely. This is Netflix's `runq.latency` +
  `sched.switch.out` split.
- **`tracked_cgroups`** is a plain `HASH<u64 cgroup_id, u32 flags>`. Unlike
  `inode_num` (`helper.h:44-66`) it needs no separate generation field: a
  cgroup v2 id is the 64-bit kernfs id, whose high 32 bits are already a
  generation counter, so a recycled directory gets a new key and a stale
  delta cannot be attributed to the wrong pod.
- **Cgroup reads use `BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id)`**, not
  the `bpf_rcu_read_lock` kfunc path. The kfunc route needs ≥ 6.2 and is what
  made the reference 6.x-only; the probe-read route costs 20–30 ns more per
  call and works on every kernel that already satisfies kguardian's CO-RE
  requirement. Revisit if profiling shows it matters.
- **Map sizes:** `runq_enqueued` HASH 65 536 (pid churn headroom — Netflix
  found plain HASH beat LRU by 40–50 ns and chose a large one),
  `runq_hist` HASH 65 536 (24 buckets × ~2 700 tracked cgroups; the map is
  exact, not LRU, so a full map means silent loss), `pair` LRU_HASH 16 384.
  Occupancy and update-failure counters are exported every sample so a leak
  or a full map shows up as a number, not as a phantom p99; `untrack`
  deletes the victim's histogram rows and `snapshot` sweeps orphans.
- **No ring buffer.** Userspace reads the maps every sample interval,
  computes deltas against the previous read, and ships summaries. Per-event
  delivery is the expensive part in every published implementation.

Budget: Cloudflare measures +15 ns for an empty `tp_btf`, Netflix < 600 ns
for its full path. At 50 000 context switches/s on a busy node this is
≤ 30 ms of CPU per second (≈ 3 % of one core, < 0.1 % of a 32-core node).
The sample carries the node's context-switch rate so the overhead can be
estimated per node and shown in the UI. Phase 4 measures it with `bpftop`
before `contention.enabled` defaults to on (D9).

### D5 — The controller ships summaries at two cadences; the broker stores a bounded "latest" plus minute rollups

Continuous numeric sampling is a new data shape for the broker and Postgres
row count is the risk. The controller therefore does the reduction:

- **Every sample interval (5 s):** one `POST /pod/compute/batch` per node
  with a `ComputeSample` per container and one `NodeComputeSample`. The
  broker **upserts** into `pod_compute_latest` (primary key
  `container_uid`), so that table never exceeds the number of live
  containers. This is what the live gauges read.
- **Every 60 s:** the controller folds one minute of samples into a
  `ComputeMinute` (avg / max / last for gauges, sum for counters, the
  merged runq histogram delta and the top-N culprit pairs) and POSTs
  `/pod/compute/history/batch`. The broker inserts into
  `pod_compute_history` and `pod_contention_history`.

Row budget: 3 000 containers × 1 440 min = 4.3 M minute rows per day.
Retention defaults to **7 days** (`compute.history.retentionDays` →
`COMPUTE_HISTORY_RETENTION_DAYS`, 0 disables), which at minute resolution
would be 30 M rows — the same order as the `pod_traffic` incident. So the
history is **tiered**: minute rows are kept for 24 h
(`COMPUTE_HISTORY_MINUTE_HOURS`, default 24), then a downsample pass in
`retention.rs` folds each container's minute rows into one 5-minute row
(avg of avgs, max of maxes, summed counters and buckets) and deletes the
minute rows. Steady state at the defaults is ≈ 4.3 M minute rows + 3 000 ×
288 × 6 days ≈ 5.2 M five-minute rows, under 10 M total, pruned by the same
batched-delete shape as audit verdicts. Both cadences live in the same table
with a `resolution_secs` column so the history endpoint returns whatever
resolution the requested window has. Index `(pod_uid, ts desc)`; read cost
declared in
`read_budget.rs` as `COMPUTE_ROW_COST_BYTES = 1_024` (in family with
`AUDIT_ROW_COST_BYTES`; these are in-memory footprint estimates, so the
number is confirmed by extending `broker/tests/read_memory_profile.rs`
before the endpoint ships).

Quantiles are computed controller-side from the histogram delta (p50 / p95
/ p99 / max) and shipped as scalars; the raw 24-bucket delta is also stored
as `int8[]` on the minute row so the broker can re-derive a quantile over a
longer window by summing buckets. The overflow bucket is stored as
`+Inf`-style overflow count and never given a finite upper bound.

### D6 — A culprit is named only when three independent signals agree

A `noisy-neighbor` finding for victim V on node N in window W (default last
5 minutes of history) requires **all** of:

1. **Victim stalled:** `cpu.pressure some avg10` ≥ `stallSome` (default 20 %)
   **or** runq p99 ≥ `runqP99Ms` (default 20 ms), sustained for ≥ 2
   consecutive minutes.
2. **Not self-throttled:** throttled ratio < `throttledRatioMax` (D3).
3. **A dominant neighbour on the same node:** a cgroup C ≠ V whose share of
   `pair[V,*].wait_ns` over W is ≥ `blameShare` (default 40 %) **and** whose
   own CPU usage over W exceeds its request (or it has no request). A pod
   running inside its request is entitled to that CPU; it is not a noisy
   neighbour even if it preempts V.

Severity: `critical` if `full avg10` ≥ 10 % or p99 ≥ 200 ms; `high` if
condition 1 holds on both signals; `medium` otherwise. The finding carries
the numbers that fired it so the UI and the assistant can show evidence, not
a verdict.

If 1 and 2 hold but no C passes 3, emit `cpu-contended` (no culprit,
"node is oversubscribed" — the blame list shows system units / kernel
threads). If the culprit is `system:*` or `kernel`, emit `noisy-neighbor`
with `culpritKind: system`; it is still actionable (kubelet, CNI agent,
log shipper).

**Memory** has no scheduler pair matrix; blame is a heuristic and is labelled
as one. `memory-pressure` finding: victim `memory.pressure some avg10` ≥
`memStallSome` (default 10 %) or `workingset_refault` rising **while** node
`/proc/pressure/memory some` ≥ 5 %; culprit = the container on the node with
the largest `memory.current − request` that also grew over W, ≥ 40 % of node
overage. `memory-limit-thrash` (victim thrashing under its **own**
`memory.max`, `memory.events` `high` + `max` rising, node not under pressure) is the
memory analogue of `cpu-throttled`: no culprit, raise the limit.

### D7 — Findings are computed in the broker, not the browser

Existing findings are client-side because all their inputs are in the
namespace the UI fetched. A noisy neighbour is cross-namespace by nature
(victim in `payments`, culprit in `batch`), so the rule engine lives in the
broker (`broker/src/compute.rs`, pure functions over the last W minutes,
table-tested) behind `GET /compute/findings?namespace=&node=`. The
self-inflicted kinds (`cpu-throttled`, `memory-limit-thrash`) need only a
single container's history, so the engine lands in Phase 1 with those two
and grows the cross-container kinds in Phase 3.

The frontend `FindingKind` union gains `noisy-neighbor | cpu-throttled |
cpu-contended | memory-pressure | memory-limit-thrash`. `policyTypeForFinding`
keeps its `PolicyType` return (its caller at `App.tsx:169` feeds it straight
into `useState<PolicyType>`); instead a new `findingAction(kind): 'policy' |
'resources'` decides which button `FindingRow` renders, and the App only
calls `policyTypeForFinding` for `'policy'` kinds. `cniPolicySupport.test.ts`
asserts every CNI × kind maps to a policy type and must exclude the compute
kinds explicitly. The **resources** action links to the culprit's or
victim's workload rather than opening the Policy Builder. The CLI and the
llm-bridge call the same endpoint.

Cross-namespace visibility: a finding in namespace A can name a pod in
namespace B. kguardian is a cluster-scoped operator tool and already lists
cluster-wide traffic peers; documented, not hidden.

### D8 — The graph becomes live for this data only

A 5 s poll of `GET /compute/latest?namespace=` (one row per container, tiny)
through a new `useComputeData` hook, paused when the tab is hidden, following
the `useSeccompProfiles` precedent. Traffic and syscalls stay on manual
refresh; nothing else in `usePodData` changes. Node rendering:

- **Collapsed header:** a status dot (`success` / `warning` / `error` tokens)
  driven by the pod's worst active compute finding, and a two-segment micro
  bar (CPU %, memory %) normalised to limit → request → node capacity, in
  that order, with the denominator in the tooltip.
- **Expanded body:** two hand-rolled SVG sparklines (no chart dependency) with
  the current value and denominator; a `Starved by <pod>` chip when a finding
  names a culprit; a `Throttled 34 %` chip for `cpu-throttled`. The series is
  60 one-minute buckets — the last hour — held client-side per pod. It is
  seeded per pod per namespace session from `GET /compute/history/{pod_uid}`,
  so an expanded card opens on real trend instead of drawing itself over the
  following minutes, and the 5 s poll then upserts the current bucket (a
  rollover pushes a new one; buckets are evicted by age, since a sparse series
  can hold 60 of them spanning far more than 60 minutes). What the sparkline
  receives is a dense 60-slot series with an explicit empty slot for any
  minute the pod did not report, and the line breaks across those rather than
  joining their neighbours — it plots by index, so a sparse series would draw
  an outage as one short step and place everything before it too recently. A
  minute is the grid because it is the finest resolution the broker stores,
  un-downsampled for `compute.history.minuteResolutionHours` (24 h by
  default) — comfortably wider than the window. Rows are not mapped by
  flooring `ts`, because neither resolution is stamped on the grid the same
  way. A minute row is stamped at the END of the fold it closes
  (`MinuteFold::finish` takes the last sample's timestamp, and the fold
  closes on its Nth sample rather than on a clock boundary, so stamps drift);
  it goes to the one bucket holding its window's midpoint, which keeps each
  row's own measurement in the minute it describes instead of writing it into
  a neighbour's and losing it to the next row. The downsampler floors its
  five-minute rows to the START of an exact, non-overlapping window, so those
  spread their `_avg` across all five minutes they summarise. Either way the
  axis stays one entry per minute. The backfill is best-effort: capped per
  namespace at a count of pods ever asked for, retried a small bounded number
  of times so one shed read does not cost a pod its history for the session,
  never awaited by the poll, and a pod whose reads fail simply fills from the
  poll alone. It never touches the feature's `supported` flag — a broker
  without `/compute/history` loses its seeded sparklines, nothing else.
- **Contention edges:** when `showContention` (new `GraphControls` toggle,
  default on) is set, a dashed `error`-coloured edge from culprit to victim,
  labelled with the blame share. Culprits outside the selected namespace
  are drawn as external nodes, the same way cross-namespace traffic peers
  already are.
- `NODE_HEIGHT` becomes a function of expansion state in **both** places it
  is used: the ELK node size (`NetworkGraph.tsx:503`) and the ELK-failure
  fallback grid (`:556`).
- The bottom `DataTable` (collapsible sections, not tabs — `isTrafficExpanded`
  / `isSyscallsExpanded`) gets a third **Compute** section for the selected
  pod: per container rows with requests / limits / usage / throttle / PSI /
  p99 and the blame list.

The Findings view gains the five kinds with the existing `FindingRow`, and a
node-level filter.

### D9 — Gauges ship on by default; the scheduler probe ships off until measured

```yaml
compute:
  enabled: true             # mounts /sys/fs/cgroup ro, starts the sampler
  sampleInterval: 5s
  contention:
    enabled: false          # loads sched_contention.bpf.c (needs compute.enabled)
    minRunqLatency: 100us   # in-kernel filter
  thresholds:
    stallSome: 20           # cpu.pressure some avg10, percent
    runqP99Ms: 20
    throttledRatio: 0.25    # cpu-throttled finding
    throttledRatioMax: 0.10 # above this, never blame a neighbour
    blameShare: 0.40
    memStallSome: 10
  history:
    retentionDays: 7        # 0 disables history; latest-only
    minuteResolutionHours: 24
```

`compute.enabled` is the master switch and is **on by default**: the gauge
and stall layers are a file walk with no BPF and near-zero cost, and the
value of the feature is highest when every pod already has history the
first time someone looks. It renders the read-only `/sys/fs/cgroup`
hostPath and starts the sampler subsystem; set it false to remove both.
`contention.enabled` is a second switch **beneath** it and defaults to
**false** until Phase 4 has measured the scheduler probe against the
roadmap's `< 0.5 %` controller-overhead line; flipping that default is the
Phase 4 decision. Set it true on any cluster to get blame today.

Per-workload opt-out via the annotation `kguardian.dev/compute: "off"` on
the pod (or its template): the pod is neither sampled nor registered in
`tracked_cgroups`, and it can still appear as a **culprit** for other pods
(blame is recorded from the victim's side). There is no opt-in mode; a
victim that is not sampled cannot be found.

### D10 — Node facts grow the fields a gauge needs

Node facts are reported **once at startup** (`main.rs:53`), before the BPF
programs are loaded (`main.rs:115`), so they can only carry what is static:
`node_facts` gains `cpu_cores`, `memory_bytes`, `kernel_version`,
`cgroup_version` (1 / 2), `psi_available`. New columns go last (Diesel
positional `Queryable`).

Anything that depends on configuration or on a load result is **live** and
travels with every node sample into `node_compute_latest` instead:
`compute_enabled`, `compute_supported` (cgroup v2 ∧ PSI), and
`contention_loaded` (`tp_btf` attach succeeded; requires kernel BTF). The UI reads
`node_compute_latest` to render a node's pods without gauges and a tooltip
that says *why* (feature off vs cgroup v1 vs probe failed), instead of an
empty bar. A disabled controller still posts a node-only heartbeat every
five minutes with `compute_enabled=false`, so a node that has no
`node_compute_latest` row at all is "controller older than this feature"
(or a heartbeat that has not arrived yet). When every node reports
`compute_enabled=false` the UI hides the compute layer entirely and pods
render exactly as before the feature.

## Data model

### Wire types (controller → broker, JSON)

```jsonc
// POST /pod/compute/batch  — every sampleInterval, one per node
{
  "node": "worker-3",
  "ts": "2026-09-10T02:41:05Z",
  "interval_ms": 5000,
  "ctxt_per_sec": 41250,                   // node context-switch rate
  "node_pressure": { "cpu_some10": 3.1, "mem_some10": 0.0 },
  "bpf": { "runq_enqueued": 1130, "runq_hist": 640, "pair": 2210 }, // occupancy
  "containers": [{
    "pod_uid": "…", "pod_name": "api-7c9…", "namespace": "payments",
    "container": "api", "cgroup_id": 18944, "container_uid": "<uid>/api",
    "cpu": { "usage_usec": 412000, "quota_usec": 500000, "period_usec": 100000,
             "request_millis": 250, "limit_millis": 500,
             "nr_periods": 50, "nr_throttled": 2, "throttled_usec": 8100,
             "psi_some10": 12.4, "psi_full10": 0.8 },
    "memory": { "current": 183500800, "working_set": 171000000, "limit": 268435456,
                "request": 134217728, "psi_some10": 0.0, "psi_full10": 0.0,
                "events": { "high": 0, "max": 0, "oom_kill": 0 },
                "refault": 120, "pgmajfault": 0 },
    "runq": { "count": 340, "p50_us": 90, "p95_us": 1800, "p99_us": 24000,
              "max_us": 61000, "overflow": 0 },
    "blame": [ { "cgroup_id": 21003, "kind": "pod", "ref": "batch/etl-1-x…/worker",
                 "count": 210, "wait_ns": 6100000000 },
               { "cgroup_id": 77, "kind": "system", "ref": "system.slice/kubelet.service",
                 "count": 40, "wait_ns": 300000000 } ]
  }]
}
```

`POST /pod/compute/history/batch` carries the same shape aggregated per
minute (`avg` / `max` / `last` for gauges, sums for counters, `hist: int8[24]`).

### Tables (Diesel migrations, `broker/db/migrations/2026-09-*`)

- `pod_compute_latest` — PK `container_uid`; every field above flattened;
  `updated_at`. Upsert on conflict.
- `pod_compute_history` — `id`, `container_uid`, `pod_uid`, `namespace`,
  `pod_name`, `container`, `node`, `ts`, `resolution_secs` (60 or 300),
  gauges (avg/max/last), counters, `runq_hist int8[]`, quantiles. Index
  `(pod_uid, ts desc)`, `(node, ts desc)`.
- `pod_contention_history` — `id`, `ts`, `node`, `victim_container_uid`,
  `culprit_cgroup_id`, `culprit_kind` (`pod` / `system` / `kernel` /
  `unknown`), `culprit_ref`, `count`, `wait_ns`. Index
  `(victim_container_uid, ts desc)`.
- `node_compute_latest` — PK `node`; node pressure, ctxt rate, BPF map
  occupancy, `updated_at`.
- `node_facts` — new columns per D10.

### Read endpoints

| Endpoint | Returns | Budget |
|---|---|---|
| `GET /compute/latest?namespace=` | one row per live container + node rows | rows × 1 024 B |
| `GET /compute/history/{pod_uid}?minutes=60` | minute rows for a pod: `minutes × containers`, `minutes` capped at 1 440 | rows × 1 024 B |
| `GET /compute/contention?namespace=&node=&minutes=5` | pair rows for victims in scope, `LIMIT` per victim | rows × 1 024 B |
| `GET /compute/findings?namespace=&node=` | D6 findings with evidence | computed; capped at 500 victims per call |
| `GET /compute/nodes` | node compute/contention support + overhead estimate | tiny |

## Culprit resolution in userspace

A cgroup id that is not in `tracked_cgroups` is resolved by a
`cgroup_index` walk of `/sys/fs/cgroup` every 30 s (id → path via
`name_to_handle_at`, bounded to 20 000 entries) and classified:

| Path | `kind` | `ref` |
|---|---|---|
| `kubepods.slice/…/cri-containerd-<cid>.scope`, tracked | `pod` | `ns/pod/container` |
| `kubepods.slice/…`, not registered yet (or unresolvable) | `pod` | `pod:<uid8>` |
| `system.slice/<unit>`, `init.scope` | `system` | unit name |
| id 0 / pid 0 | `kernel` | `kernel` |
| anything else beside `kubepods` (Talos `podruntime/kubelet`, `system/apid`, `init`; systemd `user.slice/…`) | `system` | last two path components |

`unknown` is reserved for ids that resolve to no path at all (a cgroup that
exited within the tick, or an index miss). Its share is exported per node;
if it climbs, attribution is broken and the UI says so rather than blaming
"unknown".

## Lessons from the references

The two references converge from opposite directions and both are folded in:

- **Netflix (2024)** shipped exactly the run-queue-latency + switch-out-cause
  pair on `tp_btf`, measured < 600 ns per hook, and insisted that runq
  latency alone misleads because of CFS throttling. → D3, D4's map split,
  the overhead budget.
- **olga-mir/experiments #86 + PR #20 (2025–2026)** reimplemented it and
  then showed its own 8.3 s p99 was a map leak: `ctx` cast instead of
  `ctx[0]`, no exit-hook cleanup, no `sched_wakeup_new`, and a histogram
  overflow bucket clamped to a finite `le`. The corrected run found no real
  multi-second starvation and PSI cleanly separated "node contended" from
  "this pod is the cause". → typed `BPF_PROG` args, `sched_process_exit`
  hook, `sched_wakeup_new`, exported map occupancy, `+Inf` overflow, and
  PSI as the gate that runq must agree with.
- **bcc `runqlat`** re-timestamps a preempted `prev`; Netflix's published
  snippet does not. Preemption *is* the noisy-neighbour mechanism, so it is
  in. → D4.
- **SchedBlame (DiDi, arXiv 2609.02052, Sep 2026)** is the rigorous version:
  per-CPU set of waiting targets, every run slice charged to the competitor,
  ~1 % overhead on 96 cores, not open source. The pair matrix here is the
  Netflix approximation (who was on the CPU at the switch, not across the
  whole wait). It is enough to distinguish self / neighbour / system; the
  occupancy model is Phase 5 if pair blame proves too coarse.
- **Cloudflare `ebpf_exporter`** aggregates histograms in kernel and reads
  maps only at scrape; its `cfs-throttling` example (`fentry/
  unthrottle_cfs_rq`) is the exact-duration alternative to `cpu.stat`
  throttle counters if the 5 s granularity turns out too coarse. → Phase 5.
- **Coroot** gets "CPU delay" from taskstats over netlink, not eBPF; needs
  `delayacct`, victim-side only. Considered and rejected: it cannot name a
  culprit and needs a boot parameter on most distros.
- **Kubelet PSI (KEP-4205, GA in 1.36)** exposes the same `*.pressure`
  numbers through cAdvisor. Considered as the source for layer 2 and
  rejected for now: kguardian already sits on the node with cgroup access,
  reading the files directly is lower latency, and it works on 1.19 – 1.35.
  It is the right fallback for a future unprivileged mode.

## Phased delivery

Each phase is independently shippable behind `compute.enabled=false`.

### Phase 0 — Cgroup identity, node facts, chart plumbing

**Changes**

- *controller* — `compute_registry.rs`: `ContainerCompute` + `ComputeMap`
  (D1); `pod_watcher.rs::process_container_ids` walks every container id
  when `compute.enabled`, calling the existing `get_pid`, reading
  `/proc/<pid>/cgroup`, resolving the id via `name_to_handle_at`, and
  capturing `requests` / `limits` per container and `metadata.uid` from the
  `Pod` it already holds; removal on pod delete alongside the `ContainerMap`
  removal. The pod-level cgroup (parent of the container scopes) is recorded
  once per pod.
- *controller* — `node_facts.rs`: D10 fields from `/proc/cpuinfo`,
  `/proc/meminfo`, `uname`, `/sys/fs/cgroup/cgroup.controllers`,
  `/proc/pressure/cpu`.
- *broker* — migration adding the static `node_facts` columns (D10); type
  update.
- *chart* — `compute:` block (D9); hostPath `/sys/fs/cgroup` (ro) and
  `COMPUTE_*` env rendered only when `compute.enabled`; `helm-docs`.
- *docs* — this file; `values` reference.

**Done when** every container of a tracked multi-container pod has a
`ContainerCompute` entry whose cgroup id equals the id printed by `bpftool
cgroup tree` on the node; node facts show `cgroup_version` / `psi_available`
correctly on a cgroup v2 node and a v1 node (fixture test); chart renders
no new mounts when disabled (`helm-values-compat.sh` unchanged).

### Phase 1 — Usage & stall sampler, live gauges

**Changes**

- *controller* — `compute_sampler.rs` (`Subsystem::ComputeSampler =>
  MayRetire`): timer loop every `sampleInterval`, cgroup file parser (pure
  fns, fixture-tested against captured files from containerd 1.7 / 2.0,
  runc / crun, Talos and Ubuntu nodes), delta computation, `POST
  /pod/compute/batch` and the minute rollup. Reuses `client.rs` and the
  network batcher's hold-and-cap retry shape.
- *broker* — `pod_compute_latest`, `pod_compute_history`,
  `node_compute_latest` migrations; `add.rs` ingest handlers; `get.rs`
  `latest` / `history` / `nodes`; `retention.rs` pass; `read_budget.rs`
  costs; `compute.rs` rule engine with the two single-container kinds
  (`cpu-throttled`, `memory-limit-thrash`) and `GET /compute/findings`;
  tests in `broker/tests/`.
- *frontend* — `useComputeData` poll, `PodNode` header dot + micro bar,
  expanded sparklines, Compute section in the `DataTable`, `NODE_HEIGHT`
  by state in both call sites. `FindingKind` + `findingAction` (D7) with
  the two Phase 1 kinds; `cniPolicySupport.test.ts` exclusion.
- *llm-bridge* — `get_pod_compute` tool.

**Done when** on the dev cluster every pod in a namespace shows a gauge that
updates within 10 s of a `stress-ng --cpu 1` in that pod; a pod with
`limits.cpu: 100m` running `stress-ng` raises `cpu-throttled` within two
minutes; with `retentionDays: 1` and `minuteResolutionHours: 1` on the dev
cluster, broker row count plateaus and the downsample pass produces
5-minute rows (retention verified without a week-long soak); sampler CPU
on the controller measured and recorded in the docs.

### Phase 2 — Scheduler blame probe

**Changes**

- *controller* — `bpf/sched_contention.bpf.c` per D4; `build.rs` block;
  `tracked_cgroups` population from the registration channel (kernfs ids
  carry their own generation, see D4); load guard (`tp_btf` requires
  kernel BTF → otherwise disabled, reported as `contention_loaded=false`
  in the node sample); map readers in
  `compute_sampler.rs`; histogram → quantile fn (unit-tested against the
  overflow case); culprit resolution index; map-occupancy export.
- *broker* — `pod_contention_history` migration; `runq` / `blame` fields on
  latest / history; `GET /compute/contention`.
- *frontend* — p99 and blame list in the Compute section (no graph changes yet).

**Done when** on a node with a Guaranteed 1-CPU ballast fencing two pods
onto one core (the reference's `ballast.yaml` + static CPU manager recipe),
a `stress-ng --cpu 4` "bully" appears as ≥ 80 % of the victim's blame
share, the victim's p99 rises and falls with the bully, and with the bully
removed the map-occupancy numbers return to baseline (no leak);
`bpftop` per-hook average is recorded.

### Phase 3 — Findings engine, contention edges, assistant tools

**Changes**

- *broker* — `compute.rs` grows the cross-container kinds
  (`noisy-neighbor`, `cpu-contended`, `memory-pressure`) per D6, table-tested
  for each kind and each "must not fire" case (throttled victim, culprit
  within request, unknown-dominated blame); `GET /compute/findings` gains
  the `node=` filter.
- *frontend* — the three remaining `FindingKind`s, `showContention` toggle,
  dashed culprit → victim edges, external-namespace culprit nodes,
  `Starved by` chip, node filter on Findings.
- *llm-bridge* — `get_compute_findings`, `get_node_contention` tools;
  `toolSelectionGuide` text.
- *advisor* — `kubectl kguardian compute findings [-n ns] [--node n]`
  (table output only; no generation).

**Done when** the bully/victim fixture produces exactly one `noisy-neighbor`
finding naming the bully; adding `limits.cpu` to the victim flips it to
`cpu-throttled` with no culprit; the assistant answers "why is
payments/api slow?" from the tools alone.

### Phase 4 — Validation, overhead, default decision

- `test/fixtures/compute/`: `victim`, `bully-cpu`, `bully-mem`, `ballast`
  manifests and a `task compute:e2e` that runs them on kind (kind nodes are
  cgroup v2 on a modern host) and asserts the findings. Wired as a
  `workflow_dispatch` job, not on every PR (Actions minutes).
- Overhead table in `docs/`: controller CPU with sampler on / off, per-hook
  ns from `bpftop`, at three context-switch rates. Compared against the
  roadmap's `< 0.5 %` line.
- Docs site pages: concept (`concepts/compute-contention.mdx`), guide,
  reference for `compute.*` values and the finding kinds, FAQ on cgroup v1.
- Decision recorded in this file's revision table: flip
  `contention.enabled` to on by default, or keep it off and document why.

### Phase 5 — Optional follow-ups

- SchedBlame-style occupancy attribution (per-CPU waiting-target bitmap,
  slice records) if pair blame is too coarse in practice.
- `fentry/unthrottle_cfs_rq` throttle-duration histogram (Cloudflare) for
  sub-interval throttle spans.
- `kprobe/oom_kill_process` for the exact killed cgroup at the instant of
  the kill.
- `kubectl kguardian gen resources` from `pod_compute_history` percentiles —
  the roadmap item, now with its own data.
- Unprivileged mode reading kubelet PSI (KEP-4205) instead of cgroup files.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| `sched_switch` hook cost on very busy nodes | In-kernel victim filter + `minRunqLatency` cut; no per-event delivery; `contention.enabled=false` unloads the probe while keeping gauges; per-node ctxt rate shipped so overhead is visible; Phase 4 numbers gate the default. |
| Phantom starvation from map leaks (the reference's failure) | Typed `BPF_PROG` args, exit-hook cleanup, `sched_wakeup_new`, occupancy exported and alerted in UI, overflow never finite, soak test asserts occupancy returns to baseline. |
| Throttling blamed on a neighbour | D3 hard gate; separate finding kinds; test case that must not fire. |
| Postgres growth (the `pod_traffic` incident) | Controller-side reduction; `latest` is upsert-bounded; minute rows downsampled to 5-minute after 24 h; 7-day retention pass; read budgets; row estimates in this doc checked against an accelerated-retention run in Phase 1. |
| Cgroup id generation bits differ by provider (GKE) | `name_to_handle_at` for the userspace side, `kn->id` in BPF — expected to be the same 64-bit value; the Phase 0 exit test compares both against `bpftool cgroup tree` on GKE and Talos, and if they differ the sampler falls back to matching on the low 32 bits with a logged warning. |
| cgroup v1 / no PSI nodes | Detected in node facts; feature reports unsupported per node; no crash, no empty bars. |
| Cross-namespace culprit exposure | Documented behaviour of a cluster-scoped tool. `EXCLUDED_NAMESPACES` only switches off traffic/syscall capture; compute sampling covers every namespace (decision 2026-09-10: the `kguardian` namespace must show gauges too), with the per-pod annotation as the only opt-out. |
| `NODE_HEIGHT` change disturbs existing layouts / screenshots | Height only changes on expanded nodes; README screenshots re-shot once at Phase 1 with neutral sample data. |
| A pod without requests is always "eligible" as culprit | Intentional: it is the textbook noisy neighbour. The finding text says "no CPU request set". |

## Decisions taken 2026-09-10

| Question | Decision |
|---|---|
| Per-container vs per-pod blame in the UI | **Pod-level** on the graph node (worst container drives the status dot; the gauge is the sum of the pod's container rows, so the controller does not sample the pod-level cgroup); **per-container breakdown** in the Compute section of the detail panel. |
| History retention default | **7 days**, configurable as `compute.history.retentionDays`; minute rows downsampled to 5-minute rows after 24 h so the default stays under 10 M rows (D5). |
| Default-on | **Gauges on by default** (`compute.enabled: true`), configurable; scheduler probe (`contention.enabled`) off until Phase 4 measures it (D9). |
| Opt-out annotation | **Yes**, `kguardian.dev/compute: "off"` on the pod; opted-out pods are not sampled but can still be named as culprits (D9). |

## Open questions

1. **Frontend polling vs SSE.** 5 s polling is the precedent and is cheap at
   one row per container. If the assistant's SSE plumbing is ever
   generalised, compute is the first candidate to move.

## References

- Netflix, *Noisy Neighbor Detection with eBPF* (2024) —
  https://netflixtechblog.com/noisy-neighbor-detection-with-ebpf-64b1f4b3bbdd
- Netflix `bpftop` — https://github.com/Netflix/bpftop
- olga-mir/experiments `86-2025.02-ebpf` and PR #20 —
  https://github.com/olga-mir/experiments/tree/main/86-2025.02-ebpf ,
  https://github.com/olga-mir/experiments/pull/20
- Cloudflare `ebpf_exporter` (`cfs-throttling`, `sched-trace`, benchmark) —
  https://github.com/cloudflare/ebpf_exporter
- SchedBlame (DiDi, 2026) — https://arxiv.org/abs/2609.02052
- Kernel docs: cgroup v2 — https://docs.kernel.org/admin-guide/cgroup-v2.html ;
  PSI — https://docs.kernel.org/accounting/psi.html
- KEP-4205, PSI metrics in kubelet —
  https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/4205-psi-metric
- bcc `libbpf-tools/runqlat.bpf.c` (preempted-`prev` re-timestamp semantics)
