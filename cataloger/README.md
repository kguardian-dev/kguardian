# kguardian-cataloger

The node SBOM worker. The Controller opens a running container's root
filesystem and hands it here as a directory file descriptor over a Unix
socket; the worker returns the container's packages, catalogued by Syft
through a resolver the kernel confines to that root. The Broker stores the
result as SBOM source `node` (trust `scanned`), and the supplychain matcher
matches it with Grype.

It runs as a second container in the Controller's DaemonSet pod, only when
`nodeCatalog.enabled` is set (the chart wiring lands separately; this
module is not deployed by the chart yet).

- [PROTOCOL.md](PROTOCOL.md) is the Controller-worker contract.
- Syft is pinned to the version Grype resolves in `supplychain-matcher`
  (v1.52.0 today). `hack/check-syft-version.sh` fails CI if the two
  modules drift (see "Keeping Syft in step with Grype").

## Boundaries

- **No token, no network, no host view.** The worker has no Broker token
  and no service-account token (the chart shadows the token mount with an
  empty directory), no host mounts and no hostPath `/proc`. The scan child
  may open no socket at all: its one channel, fd 4, is already connected.
- **One root per scan.** Everything a scan knows comes from the one fd it
  was handed and the request's budgets.
- **Parses in a throwaway process.** Image content is parsed only by a
  fresh child per scan, under the sandbox below. The parent validates the
  child's answer and parses nothing from the image.

## Process model

The worker container runs as **uid 0 with every capability dropped except
`CAP_DAC_READ_SEARCH`, `CAP_SETUID` and `CAP_SETGID`**, with
`allowPrivilegeEscalation: false` (no_new_privs) and `RuntimeDefault`
seccomp. That is model (i) from the design review:

1. The **parent** (`serve`) limits its own capability sets to those three,
   listens on the socket, receives `{fd, request}`, and starts each scan by
   re-executing itself as `scan-child` with
   `SysProcAttr.Credential{Uid, Gid: 2000000000}` and
   `AmbientCaps: [CAP_DAC_READ_SEARCH]`, passing only the root fd, one end
   of a socketpair and stderr. It enforces the wall-clock deadline with
   SIGKILL, bounds and validates the child's response, and applies the one
   `os_only` retry.
2. The **scan child** runs as uid/gid 2000000000 with `CAP_DAC_READ_SEARCH`
   as its only capability, so it can read root-only files in the image
   (package databases are sometimes 0600) and nothing else a root process
   could do.

Why uid 0 at all: with `runAsNonRoot` and no_new_privs a container gets no
capabilities (containerd grants non-root containers none, Kubernetes has no
ambient-capability support, and no_new_privs ignores file capabilities).
The only way to a non-root process holding `CAP_DAC_READ_SEARCH` is a
uid-0 parent that sets the ambient set when it drops to the scan uid. The
parent's uid 0 buys nothing else: no `CAP_DAC_OVERRIDE`, `CAP_CHOWN`,
`CAP_FOWNER`, `CAP_KILL` or `CAP_SYS_*`, a read-only root filesystem, no
token. It cannot even signal its children with a plain `kill`; it
borrows the scan uid as its effective uid on one locked thread for the
`pidfd_send_signal` (which `CAP_SETUID` allows).

The parent starts every child as the leader of its own process group,
and its SIGKILL (on the deadline, on a Controller hang-up, or at once if
the deadline fires before `Start` returns) goes to the pinned pidfd and to
the whole group.

**The startup probe.** Before listening, the parent starts a `probe-caps`
child exactly as it starts scans and reads back its uid and capability
sets. If the child is uid 2000000000 with exactly `CAP_DAC_READ_SEARCH`
effective, it runs model (i). Otherwise it falls back to **model (ii)**:
children start as uid 2000000000 with no capabilities, unreadable entries
are counted (`stats.eacces`), and every result is `completeness: partial`
with the reason `no_dac_read_search`. If the parent is uid 0 but cannot
change uid at all (no `CAP_SETUID`/`CAP_SETGID`), it refuses to start
rather than parse image content as root. The image's default user is
65532, which yields model (ii) (useful outside the chart).

Under model (ii) an image with no packages and some unreadable entries can
never prove it has none, so it is reported as a partial
`no_packages_found` (`eacces`, `no_dac_read_search`). The Controller treats
that as `error` and backs off (1 h, 6 h, then 24 h): expected and bounded,
and it does not happen under model (i), which the chart runs.

Every scan child re-checks its capabilities before reading anything: a
set that differs from what the probe established fails the scan with
`caps_unavailable`.

The two helper children, `probe-caps` (at startup) and `clean-tmp` (after
a killed scan), run as the scan uid with the same capabilities but
without the seccomp filter and hardening. That is deliberate and safe:
neither receives a container root or reads image content (`probe-caps`
reports its own uid, capabilities and descriptors; `clean-tmp` removes
`kg-scan-*` directories under the temp dir, which only the scan uid can
own), and both are short-lived and bounded by a timeout.

Both models are exercised by `hack/privileged-tests.sh` in containers set
up as above (uid 0, `--cap-drop ALL`, the capabilities under test,
no-new-privileges, Docker's default seccomp profile).

## When the environment is wrong: degraded, not crashing

The parent exits only for a broken configuration (an environment
variable it cannot parse: a chart bug). Environment problems found at
startup leave it running **degraded** instead of crash-looping, which
would take the Controller's whole pod NotReady:

- capabilities it cannot limit to the three it needs (it then starts no
  child at all), or a capability probe that fails (no usable model);
- descriptors it cannot mark close-on-exec;
- a socket it cannot create (a directory owned by another uid, a regular
  file at the path): it retries every 30 s.

It logs the cause at once and warns again hourly, and it **recovers by
itself**: the failed step (the capability drop, the close-on-exec sweep
and capability probe, or the socket) is retried on a backoff of 30 s
doubling to 10 min, and the worker leaves degraded mode as soon as it
succeeds. While degraded it
answers every request, ping included, with `status: failed`, `reason:
worker_unavailable` (PROTOCOL.md §3.3) and refuses scans; the Controller
then reports the node as `worker_unavailable` and claims nothing.

`kguardian-cataloger ping` (the chart's liveness probe) exits 0 as long
as the process is alive, degraded or not, so the kubelet does not restart
it into the same error: it accepts a `worker_unavailable` answer, and
without a socket it accepts the heartbeat file a degraded parent keeps
fresh in `CATALOG_TMP_DIR` (`kguardian-cataloger.degraded`, holding the
cause). The heartbeat only counts if it is a regular file owned by the worker's
uid (the temp dir is shared with the scan children). It exits 1 when
nothing answers and no fresh heartbeat exists, and also once the worker
has been degraded continuously for longer than `CATALOG_MAX_DEGRADED`
(default `6h`), so the kubelet does restart a worker that cannot recover
on its own, just not in a tight loop.

## The scan child's sandbox

In this order, before the first byte of the container is read:

1. Close every inherited descriptor except the root fd, the socketpair and
   stdio (the Go runtime's own epoll, eventfd and cgroup CPU files are
   kept).
2. `oom_score_adj` 1000 (the child is the kernel OOM killer's first
   choice, never the parent), `nice 19`, idle I/O class, `GOMAXPROCS=1`,
   `GOMEMLIMIT` (85 % of `CATALOG_MEMORY_LIMIT`), a hard `RLIMIT_DATA` of
   `CATALOG_MEMORY_LIMIT` + 64 MiB (a single burst allocation fails inside
   the child with the Go runtime's out-of-memory abort, reported as `oom`,
   before the cgroup limit is reached), `RLIMIT_NOFILE=4096`,
   `RLIMIT_CORE=0`, `RLIMIT_FSIZE=CATALOG_TMP_LIMIT` (a temp file past the
   budget fails with `EFBIG` instead of filling the memory-backed `/tmp`),
   and `PR_SET_DUMPABLE` 0 (its `/proc/<pid>` turns root-owned, so no other
   process of the scan uid can read its descriptors or memory).
3. Verify uid and capabilities (above).
4. `no_new_privs` and a pure-Go seccomp filter on every thread
   (`SECCOMP_FILTER_FLAG_TSYNC`), then prove it is live with calls only
   this filter refuses (`socket(AF_UNIX)` and, on amd64, `fork` must fail
   with `EPERM`; `unshare` would not do, since containerd's RuntimeDefault
   profile already denies it). A failed check fails the scan. Denied with `EPERM`: `open_by_handle_at`, `name_to_handle_at`,
   `ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd`, `kcmp`, `mount`,
   `umount2`, `unshare`, `setns`, `chroot`, `pivot_root`, the new mount API,
   `bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, `add_key`,
   `request_key`, `kexec_*`, `init_module`/`finit_module`/`delete_module`,
   `fanotify_init`, `io_uring_*`, `execve`/`execveat`, `fork`/`vfork`
   (amd64) and `setsid`, `socket`/`socketpair` of every family (the
   Controller pod is `hostNetwork`, so even `AF_UNIX` would reach host
   abstract sockets), and host administration calls. `clone` is allowed
   only for threads (`CLONE_THREAD` set, no namespace flags), so the child
   cannot create a process that would outlive its SIGKILL. `clone3`
   returns `ENOSYS` (its flags are in memory the filter cannot read; the Go
   runtime creates threads with `clone`). x32 syscalls on amd64 return
   `EPERM`; a foreign architecture kills the process.
5. A watchdog ends the scan with `oom` if the heap passes
   `CATALOG_MEMORY_LIMIT` or the temp dir passes `CATALOG_TMP_LIMIT` (or
   Syft reports `ENOSPC`/`EFBIG`); the parent retries once with the
   `os_only` profile.

## The resolver (`internal/rootfs`)

A Syft `source.Source` and `file.Resolver` over the root fd. The kernel,
not path strings, keeps every access inside the root:

- The tree is walked component by component: each directory is opened by
  one name from its parent's fd with
  `openat2(O_RDONLY|O_DIRECTORY|O_NOFOLLOW, RESOLVE_IN_ROOT|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS)`,
  and must be the inode that was just `statx`'d (a swap in between is
  skipped and counted).
- Metadata comes from single-name `statx(AT_SYMLINK_NOFOLLOW)`. Mounts are
  detected by `STATX_MNT_ID` (never `st_dev`) and `EXDEV`: volumes, the
  service-account token, `/etc/hosts`, `/proc`, and anything mounted
  mid-scan are never entered. The request's submount list is honoured on
  top.
- Every read re-opens the file through the root fd with the same
  resolution flags, `O_NONBLOCK` (a FIFO cannot block the open), and
  checks it is a regular file on the root's mount before reading. Devices,
  FIFOs and sockets are never indexed or opened.
- Symlinks resolve inside the root: `..` stops at `/`, absolute targets
  are relative to the root, `/proc/<pid>/root` is just a path in the image.
- Path, glob, MIME and link semantics are Syft's own: the resolver builds a
  stereoscope file tree and index and serves the same search context
  Syft's directory resolver uses. The differential test (below) holds it
  to that.
- Kernels without `openat2` (< 5.6) or `STATX_MNT_ID` (< 5.8) get
  `kernel_unsupported`; there is no weaker fallback. An `EACCES`/`EPERM` on
  the root or an existing os-release is `lsm_denied`, never
  `no_packages_found`.
- A non-directory whose ctime is after the container's start is runtime
  drift: it is left out, and every package that owns it is flagged
  `files_truncated` (so a shortened file list never supports
  `installed_not_observed`).

## What is sent

Package metadata (name, version, PURL, type, class, source package,
licenses) and, per package, the **executable-looking** files it owns
(execute bit or `*.so*`), as real in-root paths, at most 4096. Never file
contents, digests, or data files. Each package also carries:

- `files_truncated`: the path list is incomplete (over 4096, runtime drift,
  or trimmed to fit the response).
- `interpreted_content`: the package owns interpreted or loadable
  non-executable content (design §5 rules), computed from the complete
  owned-file list before any trimming.

## SELinux

**Requirement: the worker runs as `container_t` with the MCS level
`s0-s0:c0.c1023`** (`seLinuxOptions: {type: container_t, level:
"s0-s0:c0.c1023"}`). The chart wiring (a later change) defaults the
worker's `seLinuxOptions` to it and keeps it configurable.

Proven on dev (Bottlerocket 1.64 to 1.66, kernel 6.12, containerd 2.2,
2026-09-29): the privileged Controller runs as `control_t:s0:c0.c1023`.
A worker with the default label (`container_t:s0:cX,cY`) receives the fd
(no `MSG_CTRUNC`) but every read through it is denied, because the files
of another container carry that container's categories. With the full
category range `s0-s0:c0.c1023` the worker reads the passed root (listing,
a root-owned 0600 file, the apk database) with only `CAP_DAC_READ_SEARCH`
effective.

Why this label and no other: `container_t` keeps the worker in the
confined container domain (no host access, no domain transitions); the
category range only lifts MCS separation between containers, which is
exactly what reading another container's files needs. Never `super_t` or
`spc_t` (unconfined) and never `control_t` (the Controller's domain). If a
platform refuses `fd use` across the two containers, the fallback is a
worker spawned inside the Controller container (same label, new uid,
capabilities dropped, same seccomp).

SELinux still checks every file access: `CAP_DAC_READ_SEARCH` bypasses
DAC, not MAC.

## Threat model

**Asset:** everything outside the one container root handed to a scan:
other containers' files, the host, the node's credentials, the Broker
token (which the worker never has), the Controller.

**Attacker:** whoever controls a scanned image's content (a malicious or
compromised image running on the node). They can plant any file, symlink,
FIFO, device node, deep tree, huge or malformed archive, or parser-crashing
database.

**What a fully compromised scan child can do**, assuming a Syft parser bug
gives the attacker code execution:

- Read the root it was handed, including root-only files (it has
  `CAP_DAC_READ_SEARCH`, so it can read files there that DAC alone would
  deny), subject to SELinux on every file. It cannot name anything outside
  that root: it holds no other directory fd, handle-based opens are
  denied, and its own filesystem view is the worker's read-only image and
  its empty `/tmp`.
- Lie in its answer, within the protocol's limits: the parent and the
  Controller validate sizes, fields and paths; the Broker stores it as
  `scanned` (never overriding Trivy) and only for a digest the Broker sees
  running on that node.
- Waste resources up to its budgets: a hard deadline (SIGKILL), a heap
  watchdog under the pod's memory limit, a temp-size cap, idle priority.

It cannot open any socket (no network, no DNS, no host abstract sockets),
execute anything (`execve` denied), fork a process that outlives its
SIGKILL (`clone` is threads only, `fork`/`vfork`/`setsid` denied, and the
kill covers its process group), create namespaces or mounts, load kernel
code, attach to or read other processes (and, being non-dumpable, cannot
be read by a later child either), gain privileges (no_new_privs, non-root
uid, no file capabilities honoured), exhaust the node's memory
(`RLIMIT_DATA`, the heap watchdog, `oom_score_adj` 1000), or affect the
next scan (fresh process; its temp dir is removed by a same-uid cleaner if
it is killed).

**What a compromised parent could do:** the parent parses nothing, but if
it were compromised it would hold uid 0 with `CAP_DAC_READ_SEARCH`,
`CAP_SETUID` and `CAP_SETGID` inside the worker container: read what the
fds it is sent reach, and nothing the Controller does not send. It still
has no token and a read-only filesystem.

**Residual risk:** kernel bugs in `openat2`/overlayfs/seccomp; a Syft
parser bug that returns wrong but plausible data (bounded by the trust
level `scanned`); root-only image files are readable by the child (their
contents never leave it, only package metadata does).

## Configuration

| Env | Default | |
|---|---|---|
| `CATALOG_SOCKET` | `/run/kguardian/catalog/worker.sock` | Socket path: created 0600 in a directory the worker makes 0700 (PROTOCOL.md §1.1). |
| `CATALOG_ALLOWED_PEER_UIDS` | `0` | Comma-separated uids allowed to connect (`SO_PEERCRED`). |
| `CATALOG_MEMORY_LIMIT` | `640Mi` | Scan child heap cap; `GOMEMLIMIT` is 85 % of it. |
| `CATALOG_TMP_LIMIT` | `192Mi` | Scan child temp space (archive extraction). |
| `CATALOG_TMP_DIR` | `/tmp` | Where scan temp dirs go (a memory-backed emptyDir). |
| `CATALOG_MAX_DEGRADED` | `6h` | How long `ping` (the liveness probe) tolerates a degraded worker before failing. |
| `LOG_LEVEL` | `info` | `debug` also forwards Syft's debug logs from children. |

`CATALOG_MEMORY_LIMIT` plus `CATALOG_TMP_LIMIT` plus the parent must fit
the container's memory limit: the tmpfs counts against it.

**Memory, for the chart (PR 4).** The child fails on its own before the
container limit: its heap watchdog reports `oom` at `CATALOG_MEMORY_LIMIT`,
and `RLIMIT_DATA` stops a single burst just above it. Two things only the
pod spec can guarantee:

- The `/tmp` emptyDir (`medium: Memory`) needs `sizeLimit` equal to
  `CATALOG_TMP_LIMIT`. Tmpfs pages are charged to the container and are
  not the child's own mapping, so neither `RLIMIT_DATA` nor
  `RLIMIT_FSIZE` (per file) bounds the total; the watchdog and the size
  limit do.
- On cgroup v2 kubelet sets `memory.oom.group=1` for each container, so a
  cgroup OOM kill takes every process in it, the parent included, and the
  next scan on another node may do the same. `oom_score_adj` 1000 only
  picks the victim when the group kill is off: with kubelet's
  `singleProcessOOMKill: true` (Kubernetes 1.32 and later) the kernel
  kills just the child. Size the container limit so the child's own
  limits always trip first (`CATALOG_MEMORY_LIMIT` + 64 MiB +
  `CATALOG_TMP_LIMIT` + about 64 MiB for the parent), and prefer nodes
  with `singleProcessOOMKill` where available. Budgets (files,
components, depth, timeout, paths, response size) come per request from
the Controller (PROTOCOL.md §3.2).

Pod settings the chart must set (PR 4): `runAsUser: 0`, `runAsNonRoot:
false`, `capabilities: {drop: [ALL], add: [DAC_READ_SEARCH, SETUID,
SETGID]}`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem:
true`, `seccompProfile: RuntimeDefault`, the SELinux options above, a
memory-backed emptyDir on `/tmp` with `sizeLimit: CATALOG_TMP_LIMIT`,
the shared socket emptyDir on
`/run/kguardian/catalog`, and an empty emptyDir over
`/var/run/secrets/kubernetes.io/serviceaccount`.

## Keeping Syft in step with Grype

The cataloger's SBOMs are matched by Grype, so the cataloger must use the
Syft (and stereoscope) that Grype resolves in `supplychain-matcher`. Syft
usually releases ahead of Grype, so the cataloger never takes a Syft bump
on its own:

1. Renovate ignores `syft` and `stereoscope` in `cataloger/go.mod`, and
   bumps Grype in `supplychain-matcher` (group `syft-grype`, manual
   review), which moves the matcher's Syft.
2. That PR fails the cataloger's lock check
   (`hack/check-syft-version.sh`) until someone runs
   `cataloger/hack/sync-syft.sh` on the branch and commits the result: it
   sets the cataloger's `syft` and `stereoscope` to the matcher's versions
   and tidies.
3. The sync changes `cataloger/go.mod`, which runs the differential test
   (`cataloger-difftest.yaml`) against the new Syft.

The differential test is path-filtered (it only runs when a Syft, Grype or
resolver change could move its result), so it cannot be a required status
check: a required check that never runs would block every other PR.
Reviewers of a Syft or Grype bump must see it green before merging; the
always-running `test-cataloger` job carries the lock check.

## Commands

| | |
|---|---|
| `serve` | Run the worker. |
| `ping` | Exit 0 if the local worker answers (exec probe). |
| `request DIR` | Act as the Controller: send `DIR` to the worker, print the response. |
| `scan-dir DIR` | Scan `DIR` in-process without the sandbox (debugging only). |
| `version` | Worker and Syft versions. |

## Tests

```sh
go test ./...                    # unit, protocol round trips, seccomp, typed reasons
hack/privileged-tests.sh         # capability models (i) and (ii) in containers
hack/check-syft-version.sh       # syft/stereoscope lock-step with the matcher

# Differential test against Syft's directory source (the design's gate):
testdata/difftest/fixtures.sh /tmp/kgc-fixtures
KG_DIFFTEST_FIXTURES=/tmp/kgc-fixtures go test -tags difftest ./internal/difftest
```

The differential test runs in CI on every change to `cataloger/go.mod` or
`supplychain-matcher/go.mod` (so on every Syft or Grype bump) over all
fixtures: alpine, debian, ubi-minimal, distroless, a static Go binary, a
Rust binary built with cargo-auditable, a Spring Boot layout fat jar,
python and node, plus merged-`/usr` and symlinked package-database
variants. Package sets (type, name, version, PURL), the distro, owned
files, evidence locations and relationships must be identical.
