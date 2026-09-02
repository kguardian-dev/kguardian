# Per-Workload Seccomp Profile Distribution

> **Status:** Draft · **Date:** 2026-09-02 · **Components:** controller, broker, advisor, chart
> Engineering design proposal. Not part of the published (Mintlify) docs site.

Turn the syscalls kube-guardian already observes into named, versioned seccomp
profiles that land on every node — so an application team can reference one by
path and nothing else has to change.

## Ownership split

**kube-guardian guarantees that a named profile exists at a known path on every
node, and reports when that is true.** The application team owns the
`securityContext.seccompProfile` reference in their own manifest and owns the
blast radius if a profile is too tight. kube-guardian never mutates a workload.

## What ships

- Syscall attribution & aggregation per **workload**, not per pod
  (Deployment / StatefulSet / DaemonSet / CronJob).
- Deterministic, content-hashed profile names.
- A distributor DaemonSet that writes profiles under the kubelet seccomp root.
- A readiness API + UI so teams know a profile is safe to reference.

## Out of scope

- Mutating admission webhook / auto-injection into workloads (possible follow-up).
- Garbage collection — stale profiles accumulate by design.
- Per-container profiles — eBPF attribution is per-netns (per-pod).
- Any enforcement decision — teams opt in themselves.

## Hard prerequisite

The controller today only traces ~55 allowlisted syscalls
(`controller/src/bpf.rs:88`, `populate_syscall_allowlist`). A deny-by-default
profile built from that partial set **will kill the app**. Phase 0 adds opt-in
full capture and must land first.

---

## Pipeline

`observe → attribute → aggregate → distribute → reference`

| Stage | Home | Notes |
|-------|------|-------|
| 1 · Observe | controller (eBPF) | `syscall.bpf.c` traces `raw_syscalls:sys_enter` for tracked netns. Phase 0 lets opted-in workloads bypass the allowlist. |
| 2 · Attribute | controller | `pod_watcher.rs` already walks owner refs for NetworkPolicy. Extend it to emit a `(kind, name)` workload tuple: ReplicaSet→Deployment, Job→CronJob, StatefulSet/DaemonSet direct. |
| 3 · Aggregate | broker | Join per-pod syscall rows to `pod_details`, **union** across replicas and over time into a `workload_syscalls` table, recompute a content hash, render the profile JSON. |
| 4 · Distribute | new DaemonSet | `profile-distributor` polls the broker and writes `kguardian/<ns>/<kind>-<name>-<hash>.json` under the kubelet seccomp root, atomically, never deleting. Reports per-node status back. |
| 5 · Reference | application team | Team reads the ready profile path from the API or UI and adds a `type: Localhost` reference to their pod template on their own schedule. |

---

## Current state

### Controller

- `src/bpf/syscall.bpf.c` — tracepoint on `sys_enter`, filtered against the
  `allowed_syscalls` BPF map.
- `src/bpf.rs:88` `populate_syscall_allowlist` — hard-codes ~55
  "security-relevant" syscalls. Empty allowlist ⇒ trace everything (already
  supported).
- `src/syscall.rs` — dedupes per pod in a moka cache;
  `send_syscall_cache_periodically` POSTs new syscalls to broker `pod/syscalls`
  every 10s with `arch` from `std::env::consts::ARCH`.
- `src/pod_watcher.rs` — *already* traces owner refs (ReplicaSet→Deployment,
  StatefulSet, DaemonSet) and stores `pod_identity` (label-derived, ambiguous)
  and `workload_selector_labels` on `pod_details`.

### Broker

- `pod_syscalls (pod_name PK, pod_namespace, syscalls CSV, arch, time_stamp)` —
  `add.rs:601` upserts the whole CSV per pod.
- `GET /pod/syscalls/{name}` — `get.rs:462`.

### Advisor

- `gen seccomp [pod]` → `BuildSeccompProfile` (`pkg/k8s/seccomp.go:58`) → writes
  `<pod>-seccomp.json` to a local dir. `defaultAction` flag:
  `SCMP_ACT_ERRNO|KILL|LOG`.
- `MergeSyscalls` helper exists (`seccomp.go:168`) but is currently unused.
- Arch map: `x86_64 → SCMP_ARCH_X86_64`, `aarch64 → SCMP_ARCH_ARM64`.

**Gap:** nothing groups pods into workloads, nothing versions a profile, and
nothing gets a file onto a node.

---

## Design decisions

### D1 — Enforceable profiles require full syscall capture

The `bpf.rs:88` allowlist is right for *monitoring* but a deny-by-default
profile built from a partial set errors out legitimate calls. Add an opt-in — a
workload or namespace annotation (e.g. `kguardian.io/seccomp-record: "true"`) —
that makes the controller skip the allowlist for those netns. Widen the
`inode_num` map value from a bare `1u32` to a flag bitfield carrying "record
mode".

**Decision:** Phase 0, blocking. Capture stays allowlist-filtered by default;
full capture is explicit and per-workload.

### D2 — Attribution key is the top-level workload controller

Resolve Pod → owner and collapse transient layers: `ReplicaSet → Deployment`,
`Job → CronJob` (strip the Job's generated suffix), `StatefulSet` / `DaemonSet`
direct, standalone `Job` keyed on its stripped name, bare pods skipped unless
annotated. Store `workload_kind` + `workload_name` as their own columns — do
*not* reuse `pod_identity`, which is label-derived and collides across workloads
that share `app: web`.

**Decision:** new explicit columns on `pod_details`; tracing logic extends the
existing `trace_owner_to_workload_*` path.

### D3 — Aggregation is a monotonic union

A workload's profile is the union of every syscall seen from any of its pods,
across replicas and across rollouts — the set only grows. Architectures union
the same way. A new image that hits a new syscall grows the set, which changes
the hash, which produces a new file.

**Decision:** broker owns a `workload_syscalls` table, updated on ingest or by a
periodic reconcile.

### D4 — Names are deterministic and content-hashed

```
kguardian/<namespace>/<kind>-<name>-<hash>.json
```

`hash` is the first 8 hex of `sha256(sorted(syscalls) + "\n" + sorted(arches))`.
The path is relative under `<kubelet-root>/seccomp/`; segments are DNS-1123-safe,
no `..`. A changed set ⇒ a new file beside the old one; old files are never
touched, so rollback is just pointing back at the previous hash.

**Decision:** content hash in the filename; the app team pins a specific hash.

### D5 — Distribution is a separate, minimal DaemonSet

A new `profile-distributor` DaemonSet with a hostPath mount of
`{{ .Values.seccomp.kubeletRoot }}/seccomp` (default `/var/lib/kubelet/seccomp`,
configurable exactly like `containerdSockPath` already is). It polls the broker,
writes files atomically (temp + rename), never deletes, and POSTs per-node
status. It carries no BPF, no host PID, no privileged flag — so a distribution
bug cannot take down tracing.

**Decision:** its own DaemonSet, not folded into the controller. Blast radius
over convenience.

### D6 — Readiness is a first-class signal

Referencing a profile that has not reached a node yet leaves the pod in
`CreateContainerError`. The broker aggregates node-status rows into a
`distribution.state` of `Pending / Partial / Ready` and serves it alongside the
profile path and a copy-paste `securityContext` snippet. Surface it in the
frontend policy editor (`useSeccompProfileEditor.ts` already exists).

**Decision:** `GET /seccomp/profiles` is the contract app teams consume; UI is a
view on it.

### D7 — Security Profiles Operator is an alternate output, not a dependency

Add `advisor gen seccomp --format=spo` to emit `SeccompProfile` CRs for shops
already running SPO — it then handles distribution and status, and optionally
`ProfileBinding` for injection. The native distributor stays the zero-dependency
default.

**Decision:** ship native; document SPO mode as a supported alternative in
Phase 5.

---

## Phased delivery

Each phase is independently shippable and reviewable. Everything after Phase 0
is additive and can land behind `seccomp.enabled=false`.

### Phase 0 — Full syscall capture

**Goal:** let a named workload opt into complete, unfiltered syscall observation
without changing the default for everyone else.

**Changes**

- *controller* — watch a workload/namespace annotation; resolve which netns
  inodes are "record mode".
- *controller* — widen `inode_num` map value to a flag bitfield; `syscall.bpf.c`
  skips the `allowed_syscalls` check when the record flag is set.
- *controller* — thread the annotation state through `pod_watcher.rs` → pod spec
  POST.
- *broker* — persist annotation/record state on `pod_details`.

**Done when**

- An opted-in pod reports a full syscall set; a non-opted pod is byte-for-byte
  unchanged.
- Per-node CPU overhead of full capture is measured and documented.

### Phase 1 — Workload attribution

**Goal:** every syscall-reporting pod carries an unambiguous top-level workload
identity.

**Changes**

- *controller* — extend owner tracing in `pod_watcher.rs` to return
  `(kind, name)`; add the `Job → CronJob` hop and Job-suffix stripping.
- *controller* — add `workload_kind` / `workload_name` to the pod spec payload.
- *broker* — Diesel migration: two nullable columns on `pod_details`; positional
  `Queryable` order preserved (see the `pod_ips` precedent).

**Done when**

- Correct tuple recorded for all four controller kinds, plus standalone Job and
  bare pod.
- ReplicaSet pod-template-hash never leaks into the workload name.

### Phase 2 — Aggregation & profile rendering in the broker

**Goal:** the broker can hand out a finished, versioned profile JSON for any
workload.

**Changes**

- *broker* — new table
  `workload_syscalls ((namespace, kind, name) PK, syscalls, arches, hash, updated_at)`.
- *broker* — on `pod/syscalls` ingest (or a periodic reconcile task): join to
  `pod_details`, union into `workload_syscalls`, recompute hash.
- *broker* — port the `BuildSeccompProfile` shape to Rust so the distributor
  stays dumb; keep the Go copy for the CLI.
- *broker* — endpoints: `GET /seccomp/profiles`,
  `GET /seccomp/profiles/{ns}/{kind}/{name}`,
  `GET /seccomp/profile-file/{ns}/{kind}/{name}/{hash}`.

**Done when**

- A Deployment's profile equals the union of its pods' syscalls.
- Hash is stable while the set is stable and changes only when it grows.

### Phase 3 — Distributor DaemonSet

**Goal:** every profile the broker knows about exists as a file on every node,
idempotently.

**Changes**

- *advisor* — new Go binary `profile-distributor` in the advisor module (reuses
  its k8s + broker client code).
- *chart* — `templates/distributor/daemonset.yaml` + RBAC; values
  `seccomp.enabled`, `seccomp.kubeletRoot`; high `priorityClassName`.
- *advisor* — loop: list profiles → for each missing local `hash`, fetch JSON,
  write under `kguardian/<ns>/` via temp + `rename(2)` → POST
  `/seccomp/node-status`.
- *advisor* — preflight: assert the seccomp dir exists and sits on a mount; log
  loudly if the kubelet root looks wrong.

**Done when**

- A throwaway pod referencing a distributed profile starts cleanly on every
  node.
- Distributor restart re-writes nothing; broker outage retries without data
  loss.

### Phase 4 — Readiness surface & docs

**Goal:** an app team can self-serve a ready profile path without touching
kube-guardian internals.

**Changes**

- *broker* — fold node-status rows into `distribution: { ready, total, state }`
  on the profile response; add the `recommendedSnippet`.
- *frontend* — show profile name, readiness pill, and a copy button in the
  policy editor.
- *advisor* — optional: publish a per-namespace ConfigMap
  `kguardian-seccomp-<kind>-<name>` for GitOps discovery.
- *docs* — guide: how to reference, the `LOG → ERRNO` promotion workflow, the
  node scale-up race caveat, sidecar behaviour.

**Done when**

- From the UI or a single `kubectl get`, a team obtains a ready path + a valid
  `securityContext` snippet.

### Phase 5 — SPO interop (optional)

**Goal:** fit cleanly into clusters already running the Security Profiles
Operator.

**Changes**

- *advisor* — `gen seccomp --format=spo|json|localhost`; `spo` emits
  `SeccompProfile` CRs.
- *docs* — comparison: native distributor vs SPO distribution + `ProfileBinding`.

**Done when**

- A generated CR reconciles to a node path SPO manages, and a pod can reference
  it.

---

## Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Node scale-up race** | Pod schedules on a fresh node before the file arrives → `CreateContainerError`. | High-priority DaemonSet; readiness only reports `Ready` when all Ready nodes have the hash; document the window. |
| **Wrong kubelet root** | Files written to a path the kubelet never reads; profiles silently absent. | Configurable `seccomp.kubeletRoot`; distributor preflight checks the dir exists on a mount and logs loudly. |
| **Sidecar / mesh bloat** | Injected `istio-proxy` syscalls merge into every workload's profile. | Acceptable — profile is a safe superset. Document that per-container profiles are unsupported. |
| **CronJob under-capture** | A single short run misses code paths; profile too tight. | Union across runs; readiness flips only after the set is stable for a configurable interval. |
| **Profile too tight under ERRNO** | App breaks on next restart, not immediately — easy to miss. | `defaultAction` stays `SCMP_ACT_LOG` until the team opts up; promotion workflow in docs. |
| **Unbounded disk from no GC** | Old hash files accumulate on every node. | Profiles are ~2 KB each; ship a manual prune recipe; revisit automatic GC after v1. |
| **Multi-arch workload** | One profile must cover x86_64 and aarch64 nodes. | Architectures unioned into a single profile; per-arch file split kept as a future option. |

---

## Open questions

Decide before Phase 2.

- **JSON generator location** — broker (proposed) vs distributor. Broker keeps
  the distributor trivial and versioned centrally.
- **Distributor language** — Go (proposed, shares the advisor module and k8s
  libs) vs a new Rust crate sharing the broker client.
- **Reconcile model** — continuous in the broker with the distributor polling
  (proposed), vs an `advisor`-triggered snapshot export. A manual `--oneshot`
  export is worth keeping either way.
- **Discovery surface for v1** — is the API + UI enough, or is the per-namespace
  ConfigMap needed for GitOps shops from day one?
- **Annotation domain** — `kguardian.io/` vs `kguardian.dev/`; match whatever the
  project already uses elsewhere.
- **Readiness scope** — "all Ready nodes" vs "nodes matching the workload's
  scheduling constraints". The latter is tighter but needs the distributor to
  understand affinity/taints.
