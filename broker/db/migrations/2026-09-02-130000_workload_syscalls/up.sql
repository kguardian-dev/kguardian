-- Per-workload aggregate of every syscall kube-guardian has observed from
-- any pod of that workload. pod_syscalls holds one row per pod (keyed on
-- pod_name, which churns every rollout); this table collapses those to the
-- stable (namespace, kind, name) identity the controller resolves into
-- pod_details.workload_kind / workload_name, and is what a per-workload
-- seccomp profile is generated from.
--
-- The aggregate is MONOTONIC: `syscalls` only ever grows. A rollout to a
-- new image that exercises a new syscall widens the set; a scaled-down or
-- deleted pod never shrinks it. That is deliberate — a seccomp profile
-- must cover every code path the workload has been seen to take, and a
-- profile that narrowed because a replica went away would start ERRNO-ing
-- calls the app still makes.
--
-- `syscalls` and `arches` are comma-joined, lexically sorted sets (so the
-- stored form is canonical and the hash is stable). `hash` is a short
-- content fingerprint of (syscalls, arches) — it changes exactly when the
-- set changes, and names the generated profile file so an app team can pin
-- one version and a distributor can tell "already have this" from "fetch
-- the new one". It is a fast non-cryptographic hash (FNV-1a): the input is
-- broker-generated and never adversarial, and a crypto hash would pull a
-- new dependency chain into the broker for no security benefit here.
CREATE TABLE IF NOT EXISTS workload_syscalls (
    pod_namespace VARCHAR   NOT NULL,
    workload_kind VARCHAR   NOT NULL,
    workload_name VARCHAR   NOT NULL,
    syscalls      TEXT      NOT NULL DEFAULT '',
    arches        TEXT      NOT NULL DEFAULT '',
    hash          VARCHAR   NOT NULL,
    updated_at    TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (pod_namespace, workload_kind, workload_name)
);
