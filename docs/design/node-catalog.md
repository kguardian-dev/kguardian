# Node SBOMs: in-house cataloging (node catalog)

Status: approved (rev 2 plus the binding "Final review changes" at the end, which win where the two
conflict). Written against `main` at ac59f5e0. The Broker side (PR 1) is `broker/src/node_catalog.rs`
and migration `2026-10-03-100000_node_catalog`; its implementation notes are at the end of section 2.

## At a glance
- **Privileged half, in the controller** (already `privileged: true`, the only container with `hostproc`): verifies each container's identity, opens its root filesystem as a directory handle, runs the claim loop, and posts SBOMs to the broker with a new `BROKER_TOKEN_CATALOG`.
- **Worker half, the `cataloger` sidecar:** turns a directory handle into an SBOM and nothing else. No token, no network, no hostproc, no service-account token. Runs as uid 2000000000 with every capability dropped except `DAC_READ_SEARCH`, under a seccomp filter. Receives the handle over a Unix socket (SCM_RIGHTS) and runs Syft's catalogers through a custom resolver that the kernel confines to the image root.
- **Broker:** grants each inventory digest to exactly one node that really runs it, and stores the result as SBOM source `node` (trust `scanned`). supplychain matches it with Grype. Trivy stays authoritative; registry SBOMs still only add.
- **In-use:** the existing path→package logic (`in_use.rs`, `kg_pkg_in_use`) gains the file lists it lacks. It never concludes `installed_not_observed` from partial, mixed-platform, interpreted or exec-only evidence.
- **Default off.** When disabled, templates render byte-identical output (golden test). When enabled, the controller DaemonSet and the broker restart once (new env var).

## 1. Placement and process model
### 1a. Why this split
Syft (Go) is the only realistic cataloger: a Rust port would re-implement apk/dpkg/rpm (sqlite, bdb, ndb), Go/Rust build info and Java, and would drift from the package identifiers Grype expects. It must live outside the controller process. The privileged work (host `/proc`, PID checks, broker token) belongs in the already-privileged component; code that parses untrusted image content holds nothing worth stealing.

### 1b. Controller (`controller/src/catalog/`: mod.rs, feed.rs, claim.rs, post.rs)
Gated by `NODE_CATALOG=on`; unset means no task and no socket.
1. **Container list:** pod registry (`runtime_inventory.rs` `pod_runtime`) plus containerd Tasks.Get for the task PID (`container.rs`). Digest and kind from `parse_image_id` / `DigestKind` (`controller/src/image_inventory.rs:40,234`). Platform from the node (`node_facts.rs`).
2. **Claim loop:** offer local digests → at most one grant (§2).
3. **Open the root:** `pidfd_open(pid)` → `/proc/<pid>/cgroup` must contain the container ID (reuse `early_capture::parse_kubepods_cgroup_path`) → check start time (stat field 22) → open `/proc/<pid>/root` with `O_PATH|O_DIRECTORY` → re-check cgroup, start time and pidfd liveness. Any mismatch → `pid_gone`.
4. **Metadata:** from `/proc/<pid>/mountinfo`: root fs type (must be `overlay`, else `unsupported_rootfs`, or `lazy_snapshotter` for fuse/stargz/SOCI), submount paths, the upperdir.
5. **Drift check:** `fstatat` on the four package-DB paths (`lib/apk/db/installed`, `var/lib/dpkg/status`, `var/lib/rpm`, `usr/lib/sysimage/rpm`) inside the upperdir, single-name lookups only. Present → `drift`: skip this container, try another instance. No upperdir walk.
6. **Hand off:** send `{fd, request}` over `/run/kguardian/catalog/worker.sock` (emptyDir shared by the two containers, mode 0770, group 2000000000) with SCM_RIGHTS; check the peer with `SO_PEERCRED` (uid must be 2000000000). Request carries scan id, submount list, container start time, budgets, catalog epoch. The controller then closes its own copy of the fd.
7. **Result:** read the SBOM back on the same connection, size-limited; validate (component and path caps, UTF-8, no paths outside `/`); page-post to the broker; renew the lease every 60 s.

The controller never parses image files; it only reads `/proc` metadata and does four `fstatat` calls.

### 1c. Worker (`cataloger/`: new Go module, image `kguardian-cataloger`)
- **Pod spec:** `runAsUser/runAsGroup: 2000000000`, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`; `capabilities: {drop: [ALL], add: [DAC_READ_SEARCH]}` (file capability on the binary or ambient via entrypoint: spike decides); `seccompProfile: RuntimeDefault`; memory-backed emptyDir `/tmp` (256 Mi) for Syft temp files; **empty emptyDir over `/var/run/secrets/kubernetes.io/serviceaccount`** (the pod has `automountServiceAccountToken: true`); no hostproc, no host mounts; `seLinuxOptions` / `appArmorProfile` configurable, confined by default.
- **Per scan** a fresh re-executed child. Before parsing it: (1) `close_range` from 3 keeping only the root fd, the result pipe and stderr; (2) `no_new_privs`, `nice 19`, idle I/O, `GOMAXPROCS=1`, `GOMEMLIMIT`, `RLIMIT_NOFILE=4096`, `RLIMIT_CORE=0`; (3) **seccomp** (pure-Go BPF, TSYNC, no libseccomp): EPERM for `open_by_handle_at`, `name_to_handle_at`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `mount`, `umount2`, `unshare`, `setns`, `bpf`, `perf_event_open`, `keyctl`, `add_key`, `chroot`, `pivot_root`, `kexec_*`, `init_module`/`finit_module`; `socket` only for AF_UNIX; writes to its own `/tmp` allowed.
- **Resolver: (a) custom (`cataloger/internal/rootfs`), not (b) chroot.**
  - Deciding point: Syft's Java cataloger needs a writable temp dir (archives, nested jars). After `chroot(container root)` the only writable temp is the workload's own `/tmp`, i.e. modifying the workload; blocking it silently drops fat-jar packages (log4j in Spring Boot jars).
  - (a) confines by kernel, not path: every lookup from the root fd, component by component, `openat2(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW, RESOLVE_IN_ROOT|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS)`; files opened the same way `O_RDONLY|O_NONBLOCK`, `fstat` must report a regular file before reading. Metadata via single-name `fstatat(..., AT_SYMLINK_NOFOLLOW)`. Mounts detected by EXDEV plus `STATX_MNT_ID`; never `st_dev`. Volumes, the pod's SA token, `/etc/hosts`, or mid-scan mounts can't be entered, race-free.
  - Gate: **differential test in CI** against `syft dir:` over unpacked fixtures (alpine, debian, ubi, distroless, static Go, Rust cargo-auditable, Spring Boot fat jar, python, node): identical package sets (name, version, type, PURL); file-ownership compared with tolerance only for mount-excluded paths.
  - Fallback: if (a) fails the differential test in the spike, (b) with Java catalogers limited to temp-free parsing and `completeness=partial`.
- **Kernel:** `openat2` ≥5.6, `STATX_MNT_ID` ≥5.8 (AL2023/Bottlerocket 6.1 fine); else `kernel_unsupported`, never weaker resolution.
- **LSM:** EACCES/EPERM on the root fd or os-release → `lsm_denied`, never `no_packages_found`. `nodeCatalog.worker.seLinuxOptions` exposed.
- **Supply chain:** syft pinned to the version grype v0.119 pulls in (syft v1.52.0); CI fails on divergence; Renovate group bumps both. Multi-arch distroless static image, cosign-signed, SLSA provenance, own SBOM.

## 2. Claims, assignment, platform
- **Key:** `inventory_digest` only; the row records the `platform` it was cataloged for. One SBOM per inventory digest in v1: no duplicate grype sets across platforms. `index_digest=inventory_digest`; `platform_manifests`/`manifest_digest` filled when resolvable via containerd (read-only). Config-only digests keyed by config digest. Pinned (not running) digests never offered.
- **Node → platform:** recorded from every offer in `node_catalog_platforms(node, platform, seen_at)`.
- **Coverage guard** (`in_use_store.rs::refresh_coverage`): a (workload container, digest) pair is `covered` only if every node that ran an instance in the window (`runtime_coverage.node_name`) maps to the SBOM's platform and the SBOM is `completeness=full`; otherwise `unknown` with `platform_mismatch` or `sbom_incomplete`. UI labels "cataloged for linux/arm64".
- **Claim SQL** (one transaction, DB `now()` only; as implemented, `node_catalog.rs` `GRANT_SQL`):
```sql
INSERT INTO node_catalog_claims (inventory_digest, state, updated_at)
  SELECT d, 'pending', now() FROM unnest($offer) d
   WHERE EXISTS (SELECT 1 FROM images i WHERE i.digest = d)  -- sorted offer
  ON CONFLICT DO NOTHING;
UPDATE node_catalog_claims c SET state='claimed', node=$node, claim_token=gen_random_uuid(),
       lease_expires_at=now()+interval '15 minutes', attempts=c.attempts+1,
       grant_epoch=$epoch, claimed_at=now(), updated_at=now()   -- epoch untouched
  FROM (
   SELECT inventory_digest, <why> FROM node_catalog_claims n
    WHERE inventory_digest = ANY($offer)
      AND ( state='pending'
         OR (state='failed'  AND next_attempt_at <= now())
         OR (state='claimed' AND lease_expires_at <= now())
         OR (state='done'    AND (epoch < $epoch
             OR (reason IS DISTINCT FROM 'no_packages_found'        -- sbom_missing
                 AND NOT EXISTS (SELECT 1 FROM vuln_sources vs WHERE vs.digest = n.inventory_digest
                                   AND vs.source = 'node' AND vs.kind = 'sbom')))) )
      AND NOT COALESCE((skipped_nodes ->> $node)::timestamptz > now() - interval '24 hours', false)
      AND kg_digest_runs_on_node(inventory_digest, $node, $running_window)
    ORDER BY priority DESC, inventory_digest LIMIT 1
    FOR UPDATE SKIP LOCKED) g
 WHERE c.inventory_digest = g.inventory_digest
RETURNING c.inventory_digest, c.claim_token, c.lease_expires_at, g.why;
```
  `epoch` is set only when an SBOM is stored (to the upload's epoch); epochs above
  `NODE_CATALOG_MAX_EPOCH` are refused.
  - Priority: running containers desc, then first seen. `kg_digest_runs_on_node`: a live `pod_details.node_name = $node` whose containers report the digest (exact join pinned in PR 1, below).
  - Epochs: a done row is re-granted only to a higher node epoch; ingest refuses payloads below the grant's epoch (`grant_epoch`).
  - Final page commit re-checks `claim_token` and `lease_expires_at > now()` in the same transaction; stale token → 409.
  - Failure reasons: backoff 1 h → 6 h → 24 h cap for `timeout`, `oom`, `error`; `pid_gone`/`drift` immediately claimable by others, capped at 3 per (digest, node) per 24 h, then that node goes into `skipped_nodes` for 24 h; per-node, non-blocking: `sandboxed`, `lazy_snapshotter`, `unsupported_rootfs`, `kernel_unsupported`, `lsm_denied`, `deferred_pressure`.
  - Kill switch: `NODE_CATALOG_GRANTS=false` on the broker → no grants instantly; uploads under a live lease still complete.

### 2a. PR 1 implementation notes (Broker)
- **`kg_digest_runs_on_node(digest, node, window_secs)`** (SQL function in the migration). The inventory is
  per workload, not per pod: `workload_containers` has no node column and `pod_details.pod_obj` is
  compacted before storage, so the join goes through the workload key both tables already carry
  (`/pod/spec` posts `workload_kind`/`workload_name` with the pod and `containers[]` with digests):
  ```sql
  EXISTS (SELECT 1 FROM workload_containers wc
          JOIN pod_details pd ON pd.pod_namespace = wc.pod_namespace
                             AND pd.workload_kind = wc.workload_kind
                             AND pd.workload_name = wc.workload_name
          WHERE wc.image_digest = $digest AND pd.node_name = $node AND NOT pd.is_dead
            AND <running state> AND (wc.last_seen >= now - window OR wc.last_pod_name = pd.pod_name))
  OR EXISTS (/* bare pod: wc keyed ('Pod', pod_name) */
          SELECT 1 FROM workload_containers wc
          JOIN pod_details pd ON pd.pod_name = wc.workload_name AND pd.pod_namespace = wc.pod_namespace
          WHERE wc.image_digest = $digest AND wc.workload_kind = 'Pod'
            AND (NULLIF(pd.workload_kind, '') IS NULL OR NULLIF(pd.workload_name, '') IS NULL)
            AND pd.node_name = $node AND NOT pd.is_dead
            AND <running state> AND (wc.last_seen >= now - window OR wc.last_pod_name = pd.pod_name))
  ```
  `<running state>` is the inventory's own rule (`running`, or `waiting` in `CrashLoopBackOff`, or a
  NULL state from an older Controller), and the window is `IMAGE_INVENTORY_RUNNING_WINDOW_SECS`.
  Limit: during a rollout that runs two digests of one container on different nodes, a node running
  either passes for both. The node name is self-asserted (one catalog token serves every node), so
  the check is not identity: it keeps an honest Controller to digests it can reach, and bounds a
  stolen catalog token to digests running on some node (by naming that node). Pod-level digest rows
  would tighten the rollout case but change `/pod/spec` ingest for every install; node identity
  would need per-node tokens (out of scope).
- **Claim SQL as shipped** (`GRANT_SQL`): the design's statement, with the `LIMIT 1 FOR UPDATE SKIP
  LOCKED` subquery in `FROM` so the grant can return which clause made the row claimable (the
  `granted_total{reason}` label); `skipped_nodes` holds `{node: timestamp}` compared with `now() -
  24 h` (Final review change 1); the offer insert only records digests present in `images`; the
  offer is sorted so concurrent inserts lock rows in one order. Every time is the database's `now()`.
- **Upload body:** `ImageSBOM` v1 plus `cataloger/PROTOCOL.md` 4.1's `epoch`, `completeness`,
  `partial_reasons`, `stats`, and per component `files_truncated` / `interpreted_content`, so the
  Controller forwards the worker's response unchanged. Up to 4096 file paths per component (the
  generic route keeps 16), 200 000 per page counted while parsing, 8 MiB compressed / 16 MiB inflated
  per page. Flags land in `node_sbom_package_flags` keyed `name@version`.
- **Extra columns** on `node_catalog_claims` beyond section 4: `failures` (backoff step),
  `node_retries` (per-node `pid_gone`/`drift` count and window start), `partial_reasons`,
  `cataloged_at`. Times are `timestamptz`.
- **Reasons:** backoff `timeout`, `oom`, `error`; release at once (capped) `pid_gone`, `drift`,
  `exited_before_catalog`; per node `sandboxed`, `lazy_snapshotter`, `unsupported_rootfs`,
  `kernel_unsupported`, `lsm_denied`, `caps_unavailable`, `deferred_pressure`, `worker_unavailable`,
  `no_cataloger`; terminal `no_packages_found`. Anything else is refused (422).
- **In-use withheld until PR 6:** `kg_pkg_in_use` (redefined in the same migration) and
  `in_use_store::refresh_package_use_batch` ignore `source = 'node'`, so a node SBOM yields no
  `executed`/`loaded`/`installed_not_observed` verdict and no VEX statement. Its packages, findings
  and CycloneDX export are unaffected. PR 6 drops the exclusion together with the section 5 guard
  (done: see "PR 6 implementation notes" below).
- **Review changes (PR 1):** the grant records `grant_epoch` and `claimed_at` and never raises
  `epoch`, which only a stored SBOM sets (to the upload's epoch); epochs above
  `NODE_CATALOG_MAX_EPOCH` (1000) are refused; a done row with its node SBOM collected is claimable
  again (`sbom_missing`); a node SBOM links only to its claimed digest, and coverage counts only done
  claims; component reads return at most 16 paths plus `filePathsTotal`; uploads take one of 16 slots
  before the body is read, and node traffic gets half the ingest queue and half the page staging
  ceiling; renew is refused after `NODE_CATALOG_MAX_HOLD_SECS` (2 h); priorities refresh in
  200-row `SKIP LOCKED` batches.
- **Token:** the catalog writes need `BROKER_TOKEN_CATALOG` itself to be set (an admin token alone
  does not enable them, since the Controller would have nothing to post with); the catalog token
  carries only `catalog`, not `read`.

#### PR 3 implementation notes (Controller)
Deviations from section 1b and the final review changes, with the reason:
- **No `pidfd_open`.** The Controller does not run with `hostPID`, and `pidfd_open` resolves a pid in
  the caller's namespace, while the pids it has (containerd `Tasks.Get`, host `/proc`) are host pids.
  The process handle is instead a directory fd on `/proc/<pid>` of the host procfs: procfs binds it
  to the process's `struct pid` (the object a pidfd names), so once the process exits every `openat`
  through it fails with `ESRCH`, even if the number is reused. The sequence is unchanged: check
  cgroup and start time through the handle, open `root` through it, check again.
- **Worker verification** follows `cataloger/PROTOCOL.md` 1.1 rather than `SO_PEERCRED` plus the
  peer's cgroup alone, because the worker is in another pid namespace and `SO_PEERCRED` reports pid
  0. Before every connection the socket file is checked: socket and directory opened
  `O_PATH|O_NOFOLLOW` and `fstat`ed (socket uid 0 mode 0600, directory uid 0 mode 0700), the connect
  goes through `/proc/self/fd/<n>` of the checked fd, then `SO_PEERCRED` uid 0. On Linux 6.5 and
  later `SO_PEERPIDFD` adds the same-pod cgroup check (decided once at startup; a runtime pidfd
  error rejects one connection, never degrades).
- **Snapshot binding via containerd.** The root is tied to the container's own snapshot: the `/`
  mountinfo entry must be a whole overlay mount (root field `/`) with an upperdir, the root fd's
  `STATX_MNT_ID` must be that entry's mount id, and its upperdir must equal the one containerd's
  `Snapshots.Mounts` returns for the container's snapshotter and key. A mismatch is
  `unsupported_rootfs`; containerd not answering is node-local (next replica, else `pid_gone`).
- **Drift** also counts whiteouts and opaque directories (`trusted.`/`user.overlay.opaque` = `y` or
  `x`) on the package-database paths, and forces `drift_unknown` when the Controller lacks
  `CAP_SYS_ADMIN` (trusted xattrs read as absent without it).
- **Language packages (I1).** Deletion of an application-local language package (a whiteout of a
  `dist-info` or `package.json` under `/app/node_modules`, a virtualenv) is **not** detected.
  `lang_whiteout` covers only the system-wide directories (`usr{,/local}/lib/python*/
  {site,dist}-packages`, `usr{,/local}/lib/node_modules`, Ruby gem directories), read with a 64k
  entry budget; an incomplete read is `lang_whiteout_unknown`.

#### PR 6 implementation notes (Broker in-use guard)
Migration `2026-10-04-100000_node_in_use_guard` (functions plus one new derived table, nothing
existing altered; its down restores the PR 1 `kg_pkg_in_use` byte for byte):
- **`kg_node_sbom_guard(cluster, ns, kind, name, container, image, window_hours)`**: NULL when the
  node SBOM linked to the image may support `installed_not_observed`, else the first failing of
  `sbom_incomplete` (no SBOM, no claim row whose `content_hash` is the stored SBOM's, or
  `completeness` not `full`), `libraries_not_tracked` (an instance in the window without the
  library probe in mode `full`; `kg_runtime_coverage` already refuses coverage then, checked again
  so the guard stands alone), `platform_mismatch` (no instance in the window, or a
  `runtime_coverage.node_name` whose `node_catalog_platforms` row is missing or differs from the
  claim's `platform`, or the claim has none). "In the window" is `kg_runtime_coverage`'s rule (a
  heartbeat within `window_hours`). Platforms compare as exact strings.
- **`runtime_node_sbom_guard`**: `kg_node_sbom_guard` once per workload container of an image
  with a node SBOM, rebuilt by `refresh_coverage` in the same transaction and window as
  `runtime_in_use_coverage`, so `kg_pkg_in_use` does not re-evaluate it per package. A container
  without a row fails closed (`sbom_incomplete`). A live reference (the first, per-call version,
  `test/fixtures/node_guard_per_call.sql`) is compared with it after every refresh in the tests.
- **`kg_node_pkg_flags(image, pkg)`**: the package's flags over every version the SBOM lists:
  bit 2 → `interpreted_content`, bit 1 → `sbom_incomplete`.
- **`kg_pkg_in_use`**: unchanged up to the file-list test. A non-node SBOM listing the package's
  files → `installed_not_observed` exactly as before; no SBOM → `no_package_files`; only the node
  SBOM → `installed_not_observed` when the container's guard row and then `kg_node_pkg_flags` pass,
  else `unknown:<the first reason>`. Trivy-only and registry-only data is byte-identical (a live
  test compares it with the PR 1 definition across the capture reasons). A live test checks the
  SQL against the Rust mirror (`in_use::NodeFiles::guard`) on all 32 guard combinations.
- **"In-use SBOM source is node"** (the coverage guard in `refresh_coverage`) is read as "the
  node SBOM is the image's only SBOM". With a Trivy Operator or registry SBOM beside it, the
  container's coverage is not guarded, Trivy/registry-listed packages are judged as before, and
  only node-only packages meet the guard (per package, in `kg_pkg_in_use`). A capture reason is
  never replaced by a guard reason.
- **Positive evidence and drift:** node file lists join the path → package match in
  `refresh_image_use`, ranked separately from the Trivy/registry lists and then united, so a node
  package matched at the exact path never hides a Trivy package matched only through the
  merged-/usr alias or a soname (Trivy owners and ranks are exactly those without the node SBOM; a
  package both list keeps the stronger rank). A runtime row whose `origin` is `writableLayer`, `memfd` or `deleted`
  (`runtime_inventory::UNSHIPPED_ORIGINS`) is matched against non-node lists only, so it never
  credits a package through node data (it shows as unowned instead). The inventory records no
  ctime; created-after-start files are the cataloger's side (dropped, package `files_truncated`).
- **Reasons** added to `UnknownReason` and the API (`inUseDetail.reason`): `sbom_incomplete`,
  `platform_mismatch`, `interpreted_content`, and `libraries_not_tracked`, which
  `kg_runtime_coverage` already reported but the API folded into `capture_gap`; an exec-mode
  container's reason now reads `libraries_not_tracked`. Tiers and VEX are unchanged (unknown
  counts as in use; VEX needs `installed_not_observed`).
- **Open question 5, measured on the fixtures:** the `interpreted_content` rule flags Debian and
  Ubuntu `libc6` (gconv module lists under `/usr/lib`) and Ubuntu `libssl3t64` (a lintian override
  under `/usr/share/lintian`), so those never become `installed_not_observed` from node data.
  Excluding `share/lintian` (and perhaps `gconv`) in the cataloger would recover them.

## 3. Edge cases (case → handling → test)
- Init containers, short-lived Jobs → running containers only in v1; exits first → `pending` / `exited_before_catalog`; recurring CronJobs caught later. → kind Job `sleep 2`, per-minute CronJob.
- Distroless / scratch → dpkg `status.d`, Go build info, cargo-auditable; zero components with readable root → `no_packages_found`, shown "not assessable", never "0 CVEs". → distroless, static Go, stripped-C scratch.
- LSM blocks access → `lsm_denied`. → kind with SELinux/AppArmor deny profile.
- Very large images → 2 M files, 50 k components, 10 min; over budget → one retry OS-plus-binaries → `completeness=os_only`. 1 GiB default; OOM → `oom` → retry `os_only`; measure dev p99 first. → `node:22`; OOM test with 256 Mi.
- Runtime drift → DB `fstatat` in upperdir → `drift`; runtime paths with `origin=upper` or ctime after container start are never credited to a package. → `apk add` in running container; binary copied into /usr/bin not credited.
- Volumes, bind mounts, the pod's SA token → never entered (NO_XDEV + `STATX_MNT_ID`). → no path under `/var/run/secrets`; a volume with a dpkg DB ignored.
- Nested mount ns / chroot inside the container → always the containerd task PID; root must be overlay. → DinD pod.
- Lazy snapshotters → `lazy_snapshotter`. → mountinfo unit test.
- Windows → Linux-only DaemonSet → `no_cataloger`.
- gVisor / Kata → `runtime_class` + cgroup process → `sandboxed` (this node only).
- PID reuse → pidfd + cgroup + start time before/after → `pid_gone`. → PID-swap test.
- Symlink escapes → component-wise `RESOLVE_IN_ROOT`; seccomp denies handle-based opens. → fuzz: absolute/`..`/loops, dir swapped for symlink mid-scan, `/proc/1/root` targets.
- FIFOs, devices, sockets → `O_PATH` + regular-file check before reading, `O_NONBLOCK`. → FIFO at `/lib/apk/db/installed`.
- Unreadable files, deep trees → `DAC_READ_SEARCH`, depth cap 4096, EACCES counted.
- Node pressure → one scan per node, ≥30 s gap, idle I/O; defer while PSI `some avg10` > 40 %, max defer 30 min then run at lowest priority; `deferred_pressure` counted.
- Controller or worker restart mid-scan → lease expires, re-grant; stale token → 409.
- Broker down → no claim, no scan; one result held until its lease ends.
- Tag-only / mutable tags → digest-keyed only.
- Node without controller → `no_cataloger`.
- supplychain disabled → stored and viewable, "not matched".
- Trivy also installed → Trivy authoritative on collisions, keeps the single OS component; node only adds; node input yields `grype` findings beside Trivy's. → property test: Trivy findings survive, no double counting.
- Registry SBOMs → unchanged (only add).
- Storage → executable-looking paths only (execute bit or `*.so*`), ≤4096 per package, else `files_truncated`; ~100–400 MB for 1.5 k images.
- Retention → 14 days after the digest leaves `images.last_seen`, in `retention::spawn_supplychain` (leader).

## 4. Data model and API
- Migration `broker/db/migrations/2026-10-03-100000_node_catalog/`: new tables only (no locks on existing tables):
  - `node_catalog_claims (inventory_digest PK, platform, manifest_digest, state, node, claim_token UUID, lease_expires_at, attempts, next_attempt_at, reason, skipped_nodes JSONB, epoch, completeness, stats JSONB, sbom_set_id, content_hash, priority, updated_at)`; indexes `(state, next_attempt_at)`, `(lease_expires_at) WHERE state='claimed'`.
  - `node_catalog_platforms (node PK, platform, seen_at)`.
  - `node_sbom_package_flags (digest, pkg_key, flags SMALLINT, PK (digest, pkg_key))`: bit 1 `files_truncated`, bit 2 `interpreted_content`. Side table rather than a column on `image_sbom_components` (ADD COLUMN takes ACCESS EXCLUSIVE at startup behind long reads; `stats` JSON would be unindexed).
- SBOM rows reuse `vuln_sources` + `image_sbom_components` with `source='node'`, `sbom_trust='scanned'`, `scanner_name='kguardian-cataloger'`. Wire format: existing `ImageSBOM` v1 with pages. Export: CycloneDX 1.6 via `/images/{digest}/sbom/cyclonedx`.
- `SOURCES` split (`supplychain.rs:121`, used at :854, :1076): `INGEST_SOURCES = [trivy-operator, grype, registry]` → `valid_source` (unchanged); `KNOWN_SBOM_SOURCES = INGEST_SOURCES + [node]` → the `sbom_sources` filter; `NODE_SOURCE = "node"` → only source the catalog route writes.
- Auth: `Scope::Catalog` (value 16; Admin also gets it), token `BROKER_TOKEN_CATALOG`. Chart key `broker.auth.keys.catalog` in the `existingSecret`; `brokerAuthServerEnv` renders the env only when `nodeCatalog.enabled`, `optional: true`; the controller DaemonSet gets it under the same condition. Missing key → catalog routes 503, controller idles with `token_missing` gauge (no crash loops). Enabling restarts broker and controller once; rotation needs both restarted. Refuses unless auth is scoped.
- Routes: `POST /catalog/claims {node, platform, epoch, offer[]}` CATALOG; `PUT /catalog/claims/{digest}` (renew/fail/skip, with token) CATALOG; `POST /catalog/images/{digest}/sbom` (pages, `X-Kguardian-Claim`) CATALOG; `GET /catalog/coverage`, `GET /catalog/status?node=` READ; `GET /images` items gain `sbomSources` and `nodeCatalog {state, reason, platform, completeness, catalogedAt}` (new fields only).
- Default SBOM read source: Trivy if present, else node, else registry; unchanged without node SBOMs.
- supplychain `pkg/nodesource`: lists inventory, fetches changed node SBOMs (components only), feeds the matcher union; old broker → idle.

## 5. Per-package in-use
- Unchanged: `in_use_of`, ranks, tiers. Positive evidence always wins. New input: node file lists feed `has_files`.
- `installed_not_observed` from node data requires ALL of: `completeness=full`; platform guard; not `files_truncated`; not `interpreted_content`; runtime capture in `full` mode covering the window; observable package type. Otherwise `unknown` with `sbom_incomplete`, `platform_mismatch`, `interpreted_content` or `libraries_not_tracked`.
- `interpreted_content` (set by the worker from the complete owned-file list before trimming): any owned regular file with an interpreter, bytecode or foreign-runtime extension, wherever it is (`.py .pyc .pyo .pyz .pl .pm .rb .js .mjs .cjs .ts .wasm .php .phar .lua .luac .tcl .r .sh .bash .zsh .ksh .csh .fish .awk .ps1 .jar .class .groovy .beam .ex .exs .el .elc .scm .ss .xsl .xslt .dll`; `.rules` only under a `polkit-1/` path, `.go` only under a `guile/` path); a shell start-up snippet (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/bash_completion`, `/etc/bash_completion.d/*`, `/etc/zsh/{zshrc,zprofile,zshenv,zlogin,zlogout}`, `/etc/csh.cshrc`, `/etc/csh.login`, `/etc/X11/Xsession.d/*`, `/etc/default/*`, `/etc/skel/.*`, `*.bashrc`, `*.profile`, `*.zshrc`); or non-executable, not `*.so*`, under a lib root (`/lib`, `/lib64`, `/lib32`, `/usr/lib`, `/usr/lib64`, `/usr/lib32`, `/usr/libx32`, `/usr/local/lib`), `/usr/libexec`, `/usr/local/libexec` or a share root (`/usr/share`, `/usr/local/share`), excluding known data never loaded as code: documentation and Debian packaging metadata (`share/{doc,man,info,locale,licenses,lintian,doc-base,common-licenses,menu}`, `share/bug/*/{control,presubj}`); pure data (`share/{zoneinfo,terminfo,mime,xml,icons,pixmaps,applications,metainfo,pkgconfig,dbus-1,binfmts}`, `share/polkit-1/actions`, `share/debianutils/shells.d`, `lib/terminfo`, `lib/locale`); host configuration (`lib/{tmpfiles.d,sysctl.d,sysusers.d,modprobe.d,modules-load.d,binfmt.d,environment.d,mime/packages}`, `lib/udev/{rules.d,hwdb.d,hwdb.bin}`, `lib/systemd/{system,user,network,*-preset,catalog}`, `lib/kernel/install.conf`, `lib/os-release`); glibc gconv configuration (`gconv/gconv-modules`, `gconv/gconv-modules.cache`, `gconv-modules.d/*.conf`; the `.so` modules are exec-mapped and captured); and build-time files (`*.a *.la *.pc *.h`). Exclusions list known data subtrees, never whole trees that can also hold scripts. Such packages can be executed/loaded but never `installed_not_observed`. With these rules libc6 and libssl3/libssl3t64 are not flagged; Python's stdlib, bash-completion and bash's start-up files are (fixture test over real package file lists: `cataloger/internal/scan/testdata/owned`).
- C3 pin: exec-mode coverage reports `libraries_not_tracked` (`runtime_inventory.rs:2649`); unit + live-DB tests assert a `.so`-only package stays `unknown:libraries_not_tracked` even with a full node SBOM.
- Drift evidence: `origin=upper` or created-after-start paths never credited.
- Honest limit: musl correctly `loaded` in every dynamic Alpine process; fix targets guessed packages (busybox, ssl, zlib, …).

## 6. Security
- Controller: privileges unchanged (already privileged + hostproc); gains the catalog token, pidfd, `/proc` reads, four `fstatat`s, a Unix socket in its own pod; parses no image content.
- Worker: uid 2000000000, runAsNonRoot, RO root fs, drop ALL + `DAC_READ_SEARCH`, RuntimeDefault + in-process seccomp; fds closed to root handle and pipe; no network (AF_UNIX only), no token (SA token shadowed), no host mounts; kernel-confined resolution. A fully compromised worker reads only the one image root it was handed and returns an SBOM the controller size-checks.
- Data sent: package metadata and package-owned executable paths only.
- Crafted images: Syft depth limits; memory/time/file caps; fresh child per scan; panic → `error`.
- Stolen catalog token: only claimed `node` SBOMs, for digests the broker sees running on some node (the node name is self-asserted, see 2a); cannot override Trivy. It can pin a digest's epoch at `NODE_CATALOG_MAX_EPOCH` by uploading at the ceiling, which blocks re-cataloging that digest; recover by deleting the digest's `node_catalog_claims` row, or by raising `NODE_CATALOG_MAX_EPOCH` and bumping the Controller's epoch above it.
- Supply chain: syft lock-step with grype; signed; SLSA.

## 7. Rollout, release, operations
- Chart values (all off by default):
```yaml
nodeCatalog:
  enabled: false
  worker:
    image: {...}
    resources: {requests: {cpu: 50m, memory: 128Mi}, limits: {cpu: 500m, memory: 1Gi}}
    seLinuxOptions: {}
    appArmorProfile: {}
  scanTimeout: 10m
  maxFiles: 2000000
  maxComponents: 50000
  minScanInterval: 30s
  pressureThreshold: 40
  maxPressureDefer: 30m
  retentionDays: 14
  grants: true              # NODE_CATALOG_GRANTS on the broker
supplychain.sources.node.enabled   # defaults to nodeCatalog.enabled
broker.auth.keys.catalog: catalog
```
- Golden test: disabled output byte-identical to the previous chart release. `fail` if enabled with unscoped auth. Dev enabled via the platform-components overlay.
- Release/CI: release-please config + manifest `cataloger: 0.1.0`; `.github/workflows/cataloger-release.yaml` (multi-arch, push, cosign, SLSA, modelled on supplychain-matcher's); `pr-build.yaml`, `security-scan.yaml` entries; chart image pin bumped by release-please; Renovate group tying syft (cataloger) to grype (matcher) plus a CI check they resolve to the same syft.
- Metrics (broker): `kguardian_node_catalog_{granted,cataloged,failed,skipped}_total{reason}`, `…_scan_duration_seconds`, `…_queue_depth`, `…_coverage_ratio`, `…_grants_enabled`, `…_token_missing`.
- Alerts (optional PrometheusRule): coverage flat 6 h with non-empty queue; failures >20 % over 1 h by reason; any `lsm_denied` or `token_missing`; `deferred_pressure` sustained 2 h.
- Compatibility: old broker → 404 → controller idles, logs once; worker missing/old → `worker_unavailable`; old supplychain → stored, not matched; old frontend/llm-bridge → extra data only; either rollout order safe.

## PR plan (dependency order, each additive)
1. **feat(broker):** migration, `Scope::Catalog`, routes, claim SQL, grant-time node check, epochs, retry caps, kill switch, `SOURCES` split, coverage/status endpoints, retention, metrics. Done: route-table and state-machine unit tests; live DB 50 concurrent claimers → exactly one grant; SKIP LOCKED; lease expiry; stale token 409; epoch can't go backwards; kill switch; migration idempotent; existing supplychain tests green.
2. **feat(cataloger):** Go worker (resolver, seccomp, fd→SBOM protocol, `interpreted_content`/`files_truncated` flags) + release/CI wiring; not deployed by the chart yet. Done: differential test vs `syft dir:` identical on 9 fixtures; symlink/FIFO/device/swap fuzz corpus; seccomp denial tests; LSM → `lsm_denied`; limit/OOM tests; signed image published.
3. **feat(controller):** `controller/src/catalog/` (identity checks, `O_PATH` root, SCM_RIGHTS hand-off, drift `fstatat`, claim loop, lease renewal, paged posting, response validation), gated by `NODE_CATALOG`. Done: unit tests with fake worker and fake broker; PID-swap test; no socket/task when unset; containerd timeouts reuse existing bounds.
4. **feat(chart):** sidecar, SA-token shadow, shared socket emptyDir, env, auth key (`optional`), PrometheusRule, `fail` guards. Done: golden default-off identical; enabled render reviewed; `--reuse-values` from a pre-feature release renders; validated on the dev cluster (Bottlerocket, SELinux enforcing) before it is enabled anywhere else. The kind e2e (alpine, debian, distroless, static Go, `node:22`, Job, drifted container, readOnlyRootFilesystem, asserting SBOM contents and coverage) is deferred to a follow-up (see Testing).
5. **feat(supplychain):** `pkg/nodesource`, union precedence (Trivy > node > registry), single-platform join. Done: property test; old-broker idle test; matcher e2e yields a known CVE from a node SBOM.
6. **feat(broker):** in-use platform guard in `refresh_coverage`, flags in `kg_pkg_in_use` (`CREATE OR REPLACE`), new reasons, upper-origin exclusion. Done: `in_use_paths.json` fixtures with Syft file lists; C3 test; mixed-arch stays `unknown`; interpreted/truncated never `installed_not_observed`; tier regression suite unchanged without node SBOMs.
7. **feat(frontend,llm-bridge) + docs:** provenance chip, coverage banner ("N of M running images have a trusted SBOM: T Trivy, K node; P pending, F failed by reason"), "not assessable", reason copy, mock-broker preview routes, llm-bridge contract goldens, cataloger README, supplychain trust table, runbook (kill switch, rotation, alerts).

## Testing
Unit and live DB per PR; differential test vs `syft dir:` (gate for resolver (a)); resolver fuzzing; kind e2e with real containers (deferred, below); resource tests with `stress-ng` (PSI deferral, 1 GiB OOM path); compatibility matrix previous chart ↔ this one; existing API goldens unchanged.

**Chart e2e deferred (PR 4).** The chart ships without the kind scenario. Validation happens on the dev cluster (Bottlerocket, SELinux enforcing), the environment the SELinux and capability decisions were proven on, and the feature is not enabled on any other cluster until it passes there: sidecar Running with capability model (i), no `lsm_denied` or `token_missing`, coverage rising on `GET /catalog/coverage`. The kind scenario above (cataloger image published, scoped auth, the fixture workloads) is a follow-up; kind nodes have no SELinux, so it cannot replace the dev run.

## Open questions
1. Bottlerocket: is `super_t` (or other `seLinuxOptions`) needed for `DAC_READ_SEARCH` across container labels? Spike.
2. Non-root worker getting `DAC_READ_SEARCH`: file capability vs ambient entrypoint; confirm with `no_new_privs` and RuntimeDefault.
3. ~~Exact `kg_digest_runs_on_node` join~~ Pinned in PR 1 (section 2a): workload-key join, no pod-level digest rows.
4. v2: on-disk snapshots (Jobs, init containers) and per-platform SBOMs for mixed-arch digests.
5. Is the `interpreted_content` exclusion list right? Measure on dev before PR 6.
6. Is 1 GiB enough? Set from dev p99.

---
## Final review changes (binding, supersede rev 2 where they conflict)
**Verdict:** APPROVE WITH CHANGES. Resolver (a) accepted, on condition that the differential test runs on every syft or Renovate bump (not once), compares file ownership as well as package sets, and has fixtures with merged-/usr symlinks and symlinked package-DB dirs.

**SELinux (proven on dev, Bottlerocket 1.64–1.66, kernel 6.12, containerd 2.2, 2026-09-29 spike):**
- The privileged controller container runs as `control_t:s0:c0.c1023` (not `super_t`).
- A worker with the default label (`container_t:s0:cX,cY`) receives the fd but is denied every read.
- A worker with `seLinuxOptions {type: container_t, level: "s0-s0:c0.c1023"}` (or `level: s0:c0.c1023`) reads the passed root: listdir, a root-owned 0600 file, and the apk DB, with only `DAC_READ_SEARCH` effective. No MSG_CTRUNC, so fd passing is allowed.
- **Default the worker to `container_t` + `s0-s0:c0.c1023`.** Chart-configurable. Never `super_t` or `control_t`.
- Fallback if a platform denies `fd use`: a worker spawned inside the controller container (same label, new uid, caps dropped, seccomp).
- Optional hardening (PR 3, if cheap): a forked single-threaded controller helper does `setns` into the container mount ns, then `open_tree(OPEN_TREE_CLONE)` (non-recursive) and `mount_setattr(RDONLY|NOSUID|NODEV|NOEXEC)`, and passes that fd. The result is a read-only copy without volumes, the SA token or /etc/hosts. Fall back to the plain O_PATH root when unavailable.

**Capabilities (rev 2 gap):**
- With `runAsNonRoot` + NNP, `DAC_READ_SEARCH` is unattainable: no file caps, no Kubernetes ambient caps, and containerd gives non-root containers no caps.
- **Model (i):** the worker container runs as uid 0 with caps drop ALL, add `DAC_READ_SEARCH`, `SETUID`, `SETGID`. The parent parses nothing and holds no token. It spawns each scan child with `SysProcAttr.Credential{Uid,Gid: 2000000000}` + `AmbientCaps: [DAC_READ_SEARCH]`, then the child sets NNP and installs seccomp before parsing.
- `SO_PEERCRED` check on the controller side: the peer is the worker parent (uid 0 inside the worker container). Also verify the peer pid's cgroup is the worker container's, not just the uid.
- If ambient caps can't be proven in CI and kind, **model (ii):** drop `DAC_READ_SEARCH` and count EACCES under `completeness=partial`.

**Other required changes:**
1. **Platform guard fails closed.** A node absent from `node_catalog_platforms` counts as a mismatch. `skipped_nodes` stores timestamps and is compared against now (24 h expiry), not tested with `?` for presence.
2. **Mountinfo robustness.** Don't validate lowerdirs (containerd compacts them to relative paths). Resolve upperdir under `/proc/1/root` with `RESOLVE_IN_ROOT`. No or unparseable upperdir → drift unknown → `completeness=partial`.
3. **Ctime-dropped files.** If the worker drops an owned file because its ctime is after container start, mark that package partial (`files_truncated`), so a shortened list never supports `installed_not_observed`.
4. **Memory.** The tmpfs `/tmp` counts against the memory limit. Cap Syft's archive temp usage, and treat ENOSPC as `oom` → `os_only`, not an error loop.
5. **Security doc.** Record the `container_t:c0.c1023` rationale, and note in the threat model that SELinux checks each file.
