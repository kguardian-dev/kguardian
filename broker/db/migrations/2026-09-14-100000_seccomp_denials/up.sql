-- Kernel seccomp verdicts, captured on the node from `audit_seccomp`
-- (DEVOPS-2101). This is the first kguardian signal that reports what the
-- KERNEL actually did with a profile, as opposed to what the eBPF syscall
-- observer inferred the profile was missing. The existing `Drift` condition
-- says "the CR's allow-list does not match what we saw"; a row here says
-- "the filter was consulted and it acted".
--
-- Aggregated, not an event log. The controller drains a BPF LRU hash keyed
-- on (netns, generation, syscall_nr, action) every 10 s and ships counts, so
-- one row covers an arbitrary number of kernel events. That is deliberate:
-- a compromised or crash-looping decoder can trip seccomp at kernel rates,
-- and a row-per-event table would make the broker the amplifier for it.
--
-- `count` therefore accumulates across drains via the ingest upsert, and
-- `first_seen` / `last_seen` bracket the whole accumulation rather than one
-- report.
CREATE TABLE IF NOT EXISTS seccomp_denials (
    id              BIGSERIAL PRIMARY KEY,
    -- The pod identity the probe resolved from the network namespace
    -- inode. `pod_uid` is the stable half of the key: a pod name can be
    -- reused by a new pod of the same workload, a uid cannot.
    pod_uid         TEXT NOT NULL,
    pod_name        TEXT NOT NULL,
    pod_namespace   TEXT NOT NULL,
    -- Top-level owning controller, resolved BROKER-side by joining the
    -- pod to `pod_details` at ingest, which is where the controller
    -- already stamps ownerReference resolution (ReplicaSet -> Deployment,
    -- Job -> CronJob). Denormalised onto the row rather than joined at
    -- read time because the pod outlives nothing here: `pod_details`
    -- rows are pruned by retention while a denial row is still inside
    -- its own window, and a denial that loses its workload attribution
    -- disappears from the per-workload rollup the CR status is built
    -- from. NULL means attribution was not resolvable when the row was
    -- first written (bare pod, or the pod spec had not arrived yet);
    -- the upsert COALESCEs rather than overwrites, so a later report
    -- that CAN resolve it fills the gap and one that cannot never
    -- erases it.
    workload_kind   TEXT,
    workload_name   TEXT,
    node_name       TEXT,
    -- Resolved name (`ptrace`), or `syscall_<nr>` when libseccomp could
    -- not resolve the number. Never dropped: an unresolvable number on a
    -- new kernel is exactly the case an operator needs to see.
    syscall         TEXT NOT NULL,
    syscall_nr      INTEGER,
    -- `SCMP_ACT_*` spelling, matching the CRD enum and the rest of the
    -- codebase. `SCMP_ACT_UNKNOWN` for a raw value we do not map.
    action          TEXT NOT NULL,
    -- The raw `SECCOMP_RET_*` the kernel reported, kept because `action`
    -- alone makes an unmapped verdict unactionable: `SCMP_ACT_UNKNOWN` with
    -- no number tells an operator on a newer kernel that something happened
    -- and nothing about what. BIGINT, not INTEGER — `SECCOMP_RET_KILL_
    -- PROCESS` is 0x80000000, which overflows a signed 32-bit column.
    action_raw      BIGINT,
    arch            TEXT,
    count           BIGINT NOT NULL,
    -- TIMESTAMPTZ, unlike every other table here, which stores UTC-naive
    -- TIMESTAMP. These two are the only timestamps in the schema that are
    -- produced on the NODE (from the BPF map's boot-relative nanoseconds,
    -- converted by the controller) rather than stamped by the broker at
    -- ingest, so they cross a clock boundary and carry an offset the
    -- broker must not have to assume. The wire format is RFC3339 with an
    -- explicit zone for the same reason.
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL
);

-- The accumulation key. One row per (pod, syscall, action) for the life of
-- the pod: the BPF map's `generation` is deliberately NOT part of it, so a
-- pod that trips the same syscall across container restarts keeps one row
-- with a growing count instead of fanning out. Without this constraint the
-- ingest upsert has nothing to conflict on and every 10 s drain inserts a
-- duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS uq_seccomp_denials_pod_syscall_action
    ON seccomp_denials (pod_uid, syscall, action);

-- The per-workload rollup behind `GET /seccomp/denials` (filtered) and the
-- `denials` block on `GET /seccomp/profiles` (grouped). Leading with
-- pod_namespace keeps it usable for a namespace-only filter too.
CREATE INDEX IF NOT EXISTS idx_seccomp_denials_workload
    ON seccomp_denials (pod_namespace, workload_kind, workload_name);

-- Retention scans this, and the query endpoint orders by it.
CREATE INDEX IF NOT EXISTS idx_seccomp_denials_last_seen
    ON seccomp_denials (last_seen);
