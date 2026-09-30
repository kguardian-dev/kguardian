# Cataloger worker protocol (v1)

The contract between the Controller (`controller/src/catalog/`, the client)
and the `cataloger` worker (this module, the server). The Controller opens a
container's root filesystem, passes the directory handle to the worker over a
Unix socket, and reads back a package list. The worker has no network, no
token and no view of the host; everything it knows about the container comes
from the one fd and the request below.

`cataloger/internal/protocol` is the reference implementation (Go types,
framing, fd passing) and its tests are the executable form of this document.
If the two disagree, the code is wrong: fix it and keep this file as the
contract.

## 1. Transport

- **Socket:** `SOCK_STREAM` Unix socket at `CATALOG_SOCKET` (default
  `/run/kguardian/catalog/worker.sock`), on an `emptyDir` shared by the
  Controller and worker containers (see §1.1 for how it is created and
  checked).
- **Peer checks, both directions:**
  - The worker reads `SO_PEERCRED` on accept and refuses (closes without a
    response) any peer whose uid is not in `CATALOG_ALLOWED_PEER_UIDS`
    (default `0`).
  - The Controller checks the socket before it connects and the peer after
    (§1.1).
- **One connection per scan.** The Controller connects, sends exactly one
  request, reads exactly one response, and the worker closes the
  connection. No pipelining, no reuse.
- **One scan at a time.** A request that arrives while a scan is running is
  answered at once with `status: failed, reason: busy` (its fd is closed
  unused). The Controller retries later; it never queues on the socket.
- **Cancellation:** closing the connection before the response cancels the
  scan (the worker SIGKILLs the scan child). There is no response.
- **Timeouts (Controller side):** connect 5 s; write 5 s; read
  `budgets.scan_timeout_ms + 30 s`. The worker enforces the scan deadline
  itself; the extra 30 s covers the retry bookkeeping and the write.

### 1.1 Socket and peer verification

Anything in the pod that can write to the shared emptyDir could otherwise
plant a socket there and receive container root fds. So both sides pin
the socket to the worker parent (uid 0):

**Worker, at startup** (`internal/server.Listen`):

1. The socket directory (the socket path's parent, the shared emptyDir) is
   opened `O_NOFOLLOW` (a symlinked directory is refused), must be owned by
   the worker's uid (0), and is `fchmod`ed to `0700`. Kubelet creates
   emptyDirs owned by uid 0 with mode `0777`, so this only tightens the
   mode; the worker has no `CAP_CHOWN`/`CAP_FOWNER`, so a directory owned
   by any other uid is an error, not something it takes over.
2. A stale socket at the path is removed; anything else there (a regular
   file, a symlink) is refused.
3. The socket is bound with umask `0177`, so it is created `0600` (owned by
   uid 0) with no moment at which it is wider, and then re-checked with
   `lstat`.
4. The listening socket and accepted connections are `O_CLOEXEC`; no scan
   child inherits them (tested: a child's descriptors are stdio, the root
   fd and its own socketpair, plus the Go runtime's own).

**Controller, before every connection:**

1. Open the socket path `O_PATH|O_NOFOLLOW`; `fstat` must show a socket,
   uid 0, mode `0600`. Open the directory `O_PATH|O_NOFOLLOW|O_DIRECTORY`;
   it must be uid 0, mode `0700`.
2. Connect through `/proc/self/fd/<N>` of that `O_PATH` fd, so the socket
   that was checked is the one connected to (no path race).
3. After connecting, `SO_PEERCRED` uid must be 0.
4. On kernels ≥ 6.5, additionally take `SO_PEERPIDFD` and check that the
   peer's cgroup (`/proc/<pid>/cgroup`, read with the pidfd kept open) is
   the worker container's. On older kernels steps 1 to 3 are the check.



Every message, in both directions, is one frame:

```
+----------------------+---------------------------+
| length: u32, big end | payload: `length` bytes   |
+----------------------+---------------------------+
```

- `payload` is one UTF-8 JSON object. No trailing data, no gzip.
- `length` must be `>= 2` and at most the direction's limit (below).
  A larger length is a protocol error: the reader closes the connection
  without reading the payload.

| Direction | Limit |
|---|---|
| Request (Controller -> worker) | 64 KiB |
| Response (worker -> Controller) | `budgets.max_response_bytes`, which the Controller sets (its default 16 MiB, at most 64 MiB) |

## 3. Request

### 3.1 The fd

The request frame (length prefix and payload) is sent with **one**
`sendmsg(2)` that carries **exactly one** file descriptor in an
`SCM_RIGHTS` control message: the container root, opened by the Controller
as `O_PATH|O_DIRECTORY|O_CLOEXEC` from `/proc/<pid>/root` after the
identity checks. After `sendmsg` returns, the Controller closes its copy.

Kernel semantics the Controller must respect: with `SOCK_STREAM`, ancillary
data is attached to the first byte of the `sendmsg` payload, so the fd and
the start of the frame travel together. The worker receives with
`recvmsg(MSG_CMSG_CLOEXEC)` and a control buffer sized for several fds so it
can detect extras. It then reads the rest of the frame with plain reads if
the first `recvmsg` returned less than the whole frame.

The worker rejects:

| Condition | Response |
|---|---|
| `MSG_CTRUNC` set and no fd received (an LSM refused `fd use`, e.g. SELinux) | `failed`, `lsm_denied` |
| No fd, or more than one fd (all are closed) | `failed`, `bad_request` |
| Any non-`SCM_RIGHTS` control message | `failed`, `bad_request` |
| The fd is not a directory (`fstat`) | `failed`, `bad_request` |

### 3.2 Payload

```json
{
  "protocol_version": 1,
  "op": "scan",
  "scan_id": "4b1f5c2e-8f0e-4d3e-9a7c-0b8f0c6d9e21",
  "epoch": 3,
  "container_start_unix_nanos": 1790000000123456789,
  "submounts": [
    "/dev",
    "/etc/hosts",
    "/proc",
    "/var/run/secrets/kubernetes.io/serviceaccount"
  ],
  "profile": "full",
  "budgets": {
    "max_files": 2000000,
    "max_components": 50000,
    "max_depth": 4096,
    "scan_timeout_ms": 600000,
    "max_paths_per_package": 4096,
    "max_response_bytes": 16777216
  }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `protocol_version` | int | yes | `1`. Anything else: `failed`, `unsupported_protocol`. |
| `op` | string | yes | `scan`, or `ping` (§3.3). |
| `scan_id` | string | yes | Controller-chosen id, 1..128 chars of `[A-Za-z0-9._:-]`. Echoed back. |
| `epoch` | int64 | yes | Catalog epoch the grant was made under. Echoed back unchanged; the worker does not interpret it. |
| `container_start_unix_nanos` | int64 | yes | Container start, `CLOCK_REALTIME` unix nanoseconds (from `/proc/<pid>/stat` field 22 + boot time). A non-directory whose `ctime` is strictly later is runtime drift: it is never catalogued and never credited to a package (§4.3). `0` disables the check (tests only; the Controller always sends it). |
| `submounts` | string[] | no | Mount points inside the container other than `/`, from `/proc/<pid>/mountinfo`, as absolute clean paths. At most 1024 entries of at most 4096 bytes. The worker never descends into or reads them. This is an extra exclusion: the worker independently refuses to cross any mount (EXDEV + `STATX_MNT_ID`). |
| `profile` | string | no | `full` (default) or `os_only` (§4.2). |
| `budgets` | object | no | Every field optional; `0` or absent means the default. Values above the worker's ceiling are clamped to it (the effective values are echoed in `stats.budgets`). |

Budgets:

| Field | Default | Ceiling | Meaning |
|---|---|---|---|
| `max_files` | 2 000 000 | 10 000 000 | Directory entries read, of every kind (files, directories, links, and entries never indexed: devices, FIFOs, sockets, excluded or cross-mount names). One directory is also read in bounded chunks and at most 262 144 of its names (more: the rest is skipped, `file_budget`). |
| `max_components` | 50 000 | 50 000 | Components returned (the broker's `MAX_SBOM_COMPONENTS`). |
| `max_depth` | 4096 | 4096 | Directory depth. Deeper directories are not entered (`partial`). |
| `scan_timeout_ms` | 600 000 | 1 800 000 | Wall-clock deadline for the whole request, including the `os_only` retry. |
| `max_paths_per_package` | 4096 | 4096 | `file_paths` per component; more sets `files_truncated`. |
| `max_response_bytes` | 16 MiB | 64 MiB | Encoded response payload size. The Controller always sends it (16 MiB by default, configurable up to 64 MiB); the worker's default applies only if it is absent. |

Memory and temp-space limits are **not** in the request: they belong to the
worker container, so they are worker settings (`CATALOG_MEMORY_LIMIT`,
`CATALOG_TMP_LIMIT`; README).

Unknown request fields are ignored (additive changes need no version bump).

### 3.3 `ping`

`{"protocol_version":1,"op":"ping","scan_id":"..."}`, sent **without** an
fd (an fd sent with a ping is closed). The response is `status: ok` with no
components and `stats` holding `caps_model`, `syft_version` and
`worker_version`. The Controller uses it to report `worker_unavailable`
before claiming, and a readiness probe can use it.

## 4. Response

### 4.1 Payload

```json
{
  "protocol_version": 1,
  "scan_id": "4b1f5c2e-8f0e-4d3e-9a7c-0b8f0c6d9e21",
  "epoch": 3,
  "status": "ok",
  "reason": "",
  "message": "",
  "completeness": "full",
  "partial_reasons": [],
  "retry_reason": "",
  "scanner": { "name": "kguardian-cataloger", "vendor": "kguardian", "version": "0.1.0" },
  "os": { "family": "alpine", "name": "3.20.3" },
  "stats": {
    "files": 412, "dirs": 97, "components": 16, "duration_ms": 184,
    "syft_version": "v1.52.0", "worker_version": "0.1.0",
    "eacces": 0, "ctime_dropped": 0, "mount_skipped": 3, "depth_limited": 0,
    "components_dropped": 0, "attempts": 1, "caps_model": "i",
    "max_rss_bytes": 58720256,
    "budgets": { "max_files": 2000000, "max_components": 50000, "max_depth": 4096,
                 "scan_timeout_ms": 600000, "max_paths_per_package": 4096,
                 "max_response_bytes": 16777216 }
  },
  "components": [
    {
      "name": "alpine", "version": "3.20.3", "type": "operating-system"
    },
    {
      "name": "busybox",
      "version": "1.36.1-r29",
      "purl": "pkg:apk/alpine/busybox@1.36.1-r29?arch=aarch64&distro=alpine-3.20.3",
      "type": "apk",
      "class": "os-pkgs",
      "src_name": "busybox",
      "src_version": "1.36.1-r29",
      "licenses": ["GPL-2.0-only"],
      "file_paths": ["/bin/busybox"],
      "files_truncated": false,
      "interpreted_content": false
    }
  ]
}
```

Top level:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | int | `1`. |
| `scan_id`, `epoch` | | Echoed from the request (set by the worker parent, never by the scan child). |
| `status` | string | `ok` or `failed`. `failed` responses carry no components. |
| `reason` | string | Empty when `ok`; otherwise one of §4.4. |
| `message` | string | Human detail for logs, at most 1024 bytes. Not for display to users verbatim; may contain container paths. |
| `completeness` | string | `full`, `partial` or `os_only` (§4.2). Empty when `failed`, except for `no_packages_found`, which carries it (§4.4). |
| `partial_reasons` | string[] | Why a successful scan is not `full` (§4.2). |
| `retry_reason` | string | Set when the first attempt failed and the `os_only` retry produced this response: `oom`, `too_many_files` or `too_many_components`. |
| `scanner` | object | Maps to `ImageSBOM.scanner`. |
| `os` | object | `{family, name}`: os-release `ID` and `VERSION_ID` (or `PRETTY_NAME` without one). Maps to the broker's `WireOs`. Omitted when no os-release was found, or when either value is over 64 bytes (the broker's limit) or holds control characters. |
| `stats` | object | Always present, also on failure (what was measured before it). |
| `components` | object[] | §4.3. |

### 4.2 Completeness

| Value | Meaning |
|---|---|
| `full` | The `full` profile ran over the whole tree: no unreadable entry, no depth or response trimming, no ctime-dropped owned file, caps model (i). Only a `full` SBOM may support `installed_not_observed` (design §5). |
| `partial` | The `full` profile ran, but some evidence may be missing. `partial_reasons` lists why. |
| `os_only` | The `os_only` profile ran (requested, or the retry after `oom` / `too_many_files` / `too_many_components`): OS package databases plus compiled binaries (Go, Rust cargo-auditable, ELF notes, the binary classifier); no Java, Python, Node or other language catalogers; directories are indexed system-first (`/etc`, `/lib*`, `/usr`, `/bin`, `/sbin`, `/var/lib`, then the rest) until `max_files`. |

`partial_reasons` values: `eacces` (entries that could not be read,
`stats.eacces`), `no_dac_read_search` (caps model (ii): the scan ran without
`CAP_DAC_READ_SEARCH`), `ctime_dropped` (runtime-changed files left out,
§4.3), `depth_limited`, `files_truncated` (some component has
`files_truncated`), `response_trimmed` (file paths dropped to fit
`max_response_bytes`), `components_dropped` (components that failed
validation, §4.3), `file_budget` (entries skipped: `max_files` reached under
`os_only`, or a directory with more than 262 144 names).

### 4.3 Components

Each component maps **1:1** onto the broker's ImageSBOM v1 `WireComponent`
(`broker/src/supplychain.rs`; `supplychain/pkg/types.Component`), plus two
per-package flags the Controller forwards to the catalog route (they end up in
`node_sbom_package_flags`):

| Field | Broker `WireComponent` | Meaning |
|---|---|---|
| `name` | `name` | Package name. Non-empty, at most 256 bytes. |
| `version` | `version` | At most 128 bytes. |
| `purl` | `purl` | Syft's package URL (deb/rpm carry the `upstream` and `distro` qualifiers Grype matches on). At most 1024 bytes. |
| `type` | `type` | Syft package type (`apk`, `deb`, `rpm`, `go-module`, `rust-crate`, `java-archive`, `python`, `npm`, `binary`, ...), or `operating-system` for the distro entry (one per response, `name` = os-release `ID`, `version` = `VERSION_ID`; no other fields). |
| `class` | `class` | `os-pkgs` for OS package-manager types (`apk`, `deb`, `rpm`, `alpm`, `portage`), `lang-pkgs` for everything else; absent on `operating-system`. |
| `src_name`, `src_version` | same | Source package: dpkg `Source`, apk origin, rpm source RPM. At most 256 / 128 bytes. Omitted when unknown. |
| `licenses` | `licenses` | At most 8, each at most 128 bytes. |
| `file_paths` | `file_paths` | See below. |
| `files_truncated` | (flags bit 1) | `true` if `file_paths` is not the package's complete executable-looking file list. |
| `interpreted_content` | (flags bit 2) | `true` if the package owns interpreted or loadable non-executable content (below). |
| (none) | `layer_digest` | Never sent: a mounted root has no layer attribution. |

`file_paths`:

- Only **executable-looking** files the package owns: regular files with any
  execute bit, or whose base name matches `*.so` or `*.so.*`. Package
  databases, docs and data files are never sent.
- "Owns": the package database's file list (dpkg, apk, rpm, Python RECORD,
  ...) plus the package's own evidence location for binaries (the Go or Rust
  executable itself).
- Absolute, clean (`path.Clean`), valid UTF-8 without control characters,
  at most 1024 bytes each, sorted, unique. Each is the **real path inside the container root**, with
  symlinks resolved in-root (so `/bin/sh -> busybox` is sent as
  `/bin/busybox`, and a merged-`/usr` `/bin/bash` as `/usr/bin/bash`).
- At most `max_paths_per_package`. More sets `files_truncated`.
- A path whose file, or any symlink on the way to it, is runtime drift
  (non-directory `ctime` after `container_start_unix_nanos`) is dropped and
  sets `files_truncated` on every package that owns it; a runtime-created binary never becomes a
  package of its own.
- The broker's generic SBOM route keeps 16 paths per component
  (`MAX_FILE_PATHS`); the catalog route accepts 4096 (§4.5).

`interpreted_content` is computed from the **complete** owned-file list,
before the executable filter and the cap. It is `true` if any owned regular
file:

- has one of the extensions `.py .pyc .pl .pm .rb .js .mjs .cjs .php .lua
  .tcl .sh .bash .jar .class .el`, or
- is non-executable, does not match `*.so*`, and is under `/lib`, `/usr/lib`,
  `/usr/local/lib`, `/usr/libexec`, `/usr/share` or `/usr/local/share`, but
  not under `share/doc`, `share/man`, `share/info`, `share/locale` or
  `share/licenses` of those.

Validation the worker applies before answering (so the Controller's own
checks should never fire, but it must still apply them): a component with an
empty or over-long name or version is dropped (`stats.components_dropped`,
`partial`); paths failing the rules above are dropped with
`files_truncated`; if the encoded response still exceeds
`max_response_bytes`, `file_paths` are removed from the components with the
most paths first (each gets `files_truncated`, the response gets
`response_trimmed`); if even an empty-paths response is too large,
`failed`, `output_too_large`.

Unknown response fields must be ignored by the Controller.

### 4.4 Failure reasons

| `reason` | When | Retry class (broker) |
|---|---|---|
| `timeout` | `scan_timeout_ms` elapsed; the child was SIGKILLed. No `os_only` retry (no time left). | backoff (`timeout`) |
| `oom` | Memory or temp space ran out (the child's heap watchdog, a Go runtime out-of-memory abort, a cgroup OOM kill, or `ENOSPC`/`EFBIG` in the capped temp dir) **and** the `os_only` retry also failed or had no time. | backoff (`oom`) |
| `too_many_components` | More than `max_components` even with `os_only`. | backoff (`error`) |
| `no_packages_found` | The scan completed and found zero packages (the `operating-system` entry does not count). **Terminal only when clean**: `completeness: "full"` and empty `partial_reasons`, meaning the whole tree was readable and nothing was skipped. Otherwise the response says why (`completeness: "partial"` with `partial_reasons` such as `eacces` + `no_dac_read_search` under model (ii), `ctime_dropped`, `depth_limited`, `file_budget`, `components_dropped`; or `completeness: "os_only"`), and the Controller treats it as a retryable `error`. Under capability model (ii) this is what a zero-package image with unreadable entries always gets: the Controller backs it off as `error` (1 h, 6 h, then 24 h), which is expected and bounded; the chart runs model (i), where DAC does not refuse. Shown as "not assessable", never "0 CVEs". | terminal only when clean; else backoff (`error`) |
| `lsm_denied` | `EACCES`/`EPERM` opening the root for listing or reading an existing `/etc/os-release` / `/usr/lib/os-release`; zero packages with unreadable entries under capability model (i) (DAC is bypassed there, so only an LSM refuses); or the fd was stripped in transit (`MSG_CTRUNC`). Under model (ii) unreadable entries are plain DAC refusals and give a partial `no_packages_found` instead. | per node, non-blocking |
| `kernel_unsupported` | `openat2(2)` missing (< 5.6) or `statx` does not return `STATX_MNT_ID` (< 5.8). The worker never falls back to weaker resolution. | per node, non-blocking |
| `caps_unavailable` | The scan child's capabilities are not what the startup probe established (e.g. `CAP_DAC_READ_SEARCH` missing under model (i), or any other capability present). | per node, non-blocking |
| `error` | Anything else: a panic, an unexpected child exit, invalid child output. | backoff (`error`) |
| `busy` | Another scan is running. | retry soon, not a failure |
| `bad_request` | Malformed frame or JSON, invalid field, fd missing/extra/not a directory. | Controller bug |
| `unsupported_protocol` | `protocol_version` is not supported. | Controller/worker version skew |
| `output_too_large` | Even without file paths the response exceeds `max_response_bytes`. | backoff (`error`) |

The Controller maps `too_many_components` and `output_too_large` to the
broker's `error` backoff, `busy` to a local retry, and `bad_request` /
`unsupported_protocol` to a logged `error` (a bug, not the image's fault).

### 4.5 Catalog route body (`POST /catalog/images/{digest}/sbom`)

The worker does not know the image; the Controller builds each page. The
body is the supply-chain `ImageSBOM` v1 (same pages, same staging) plus the
catalog route's own top-level fields (`broker/src/node_catalog.rs`), with
the `X-Kguardian-Claim` header carrying the claim token:

| Body field | From |
|---|---|
| `schema_version` | `1` |
| `image.digest` etc. | the Controller's claim (inventory digest, platform manifests) |
| `source` | `node` |
| `sbom_trust` | `scanned` |
| `scanner` | response `scanner` |
| `scanned_at` | Controller clock when the response arrived |
| `format` | `kguardian-cataloger` |
| `page` | `{set_id, index, total}`, as for any paged `ImageSBOM` |
| `components` | response `components` **as they are, including `files_truncated` and `interpreted_content`**: the catalog route reads both per component (they end up in `node_sbom_package_flags`) |
| `epoch` | **required on every page**; the epoch the Controller sent on the claim (echoed in the response). Missing is 400; below the claim's grant epoch is 409; above `NODE_CATALOG_MAX_EPOCH` (default 1000) is 422. |
| `completeness` | response `completeness` |
| `partial_reasons` | response `partial_reasons` (the broker keeps at most 16) |
| `stats` | response `stats` (the broker keeps at most 16 KiB serialised) |
| `platform` | optional: the platform the SBOM was catalogued for (`os/arch[/variant]`) |

Send `epoch`, `completeness`, `partial_reasons`, `stats` and `platform` at
the top level of **every** page; the broker stores the values from the page
that completes the set.

Catalog-route limits, which set how the Controller pages:

| Limit | Value |
|---|---|
| File paths per component | 4096 (the generic SBOM route keeps 16) |
| File paths per page, all components | 200 000 |
| Components per page | 10 000 (the Controller uses 2 000, and fewer when the page would pass 200 000 paths) |
| Components per SBOM | 50 000 |
| Page body | 8 MiB compressed, 16 MiB inflated |

Broker answers the Controller must handle:

| Answer | Meaning | Controller |
|---|---|---|
| 503 with `Retry-After` on an upload page | every upload slot is busy | retry that page after `Retry-After`; never fail the claim for it |
| 409 on an upload page | stale claim token, lease gone, or epoch below the claim's grant epoch | stop; the claim is lost |
| 422 | epoch above `NODE_CATALOG_MAX_EPOCH` | a Controller bug; log and stop |
| 409 on a lease renewal | the claim has been held for `NODE_CATALOG_MAX_HOLD_SECS` (default 7200) and cannot be renewed further | stop; the claim is lost |

The response's `os` is for the Controller's logs; the SBOM carries the
distro as its `operating-system` component.

## 5. Versioning

- `protocol_version` is an integer, currently `1`, carried in both
  directions.
- **Additive changes** (a new optional request field, a new response field,
  a new `partial_reasons` value) keep the version. Both sides ignore unknown
  fields. A Controller that sees an unknown `reason` treats it as `error`;
  an unknown `completeness` as `partial`.
- **Breaking changes** (a field's meaning, framing, fd semantics) bump the
  version. The worker answers an unsupported version with
  `unsupported_protocol` and its own `protocol_version`, so a Controller can
  log the skew. A worker may support the previous version for one release.
- The worker image and the Controller ship in the same chart release, but
  either may roll first: `ping` tells the Controller what it is talking to.

## 6. Security properties the Controller can rely on

- The worker never writes to the root fd (it opens only `O_RDONLY` /
  `O_PATH`), never follows a path outside it (`RESOLVE_IN_ROOT`), never
  crosses a mount (`RESOLVE_NO_XDEV`, `STATX_MNT_ID`), never follows magic
  links (`RESOLVE_NO_MAGICLINKS`), and never reads a non-regular file.
- The scan child runs as uid/gid 2000000000 with at most
  `CAP_DAC_READ_SEARCH`, `no_new_privs`, a seccomp filter (no handle-based
  opens, no `ptrace`, no namespaces, no mounts, no `execve`, no fork, no
  socket of any family), a hard memory limit, a fresh process per scan,
  and a hard deadline that kills its whole process group.
- The response is untrusted input nonetheless: a fully compromised child
  can return any JSON within the limits above. The Controller validates it
  (sizes, UTF-8, absolute paths) before posting, as the design requires.
