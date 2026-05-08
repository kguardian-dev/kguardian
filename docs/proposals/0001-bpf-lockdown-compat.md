# Proposal: BPF compatibility with kernel lockdown=confidentiality

Status: draft, looking for sign-off before implementation.

## Problem

The controller's BPF programs fail to load on hosts running with the
kernel `lockdown` LSM in `confidentiality` mode. Symptoms:

- `BPF program load failed: -EINVAL` from libbpf at startup
- Verifier log shows `program of this type cannot use helper bpf_probe_read#4`
- Host dmesg shows the matching kernel-side reason:
  `Lockdown: <process>: use of bpf to read kernel RAM is restricted`
- Controller pod crashloops; no traffic gets observed on the affected node

The verifier message and the dmesg notice are surfacing two separate
gates. The verifier rejects helper #4 (`bpf_probe_read`, the legacy
unsplit-pointer-source helper) for `fentry` programs as a helper-compat
rule; that's the immediate failure. If we fixed that to emit the typed
`bpf_probe_read_kernel` (#113), the kernel's `LOCKDOWN_BPF_READ_KERNEL`
hook would block the load instead, since under confidentiality every
`bpf_probe_read_kernel` call is denied. Both gates close.

The root cause is the same on either path: `network_probe.bpf.c` walks
pointer chains into `struct sock` to extract the network-namespace
inode, which it uses to filter flows by pod. Every level of the chain
compiles to a kernel-RAM read, and the kernel won't allow that under
confidentiality.

## Where this matters in practice

Talos with Secure Boot defaults to `lockdown=confidentiality`. This is
opinionated harder than mainstream distros — RHEL, Ubuntu, Debian, and
Fedora all default to `integrity` under Secure Boot, which doesn't
block this code path (see `include/linux/security.h`'s
`lockdown_reason` enum, where `LOCKDOWN_BPF_READ_KERNEL` sits between
the integrity and confidentiality boundary markers).

Talos clusters frequently mix Secure Boot bare-metal nodes with VM
nodes that boot normally. A typical split is 50–80% Secure Boot. The
nodeSelector workaround (point the DaemonSet at the non-locked-down
nodes only) is fine as a per-cluster opt-out but unacceptable as a
default — it hides the controller from most of the cluster.

## How other BPF agents handle this

Cilium loads on confidentiality kernels. Its hot-path programs use
`__sk_buff` direct field access, which is verifier-allowed regardless
of lockdown mode. Optional features that need kernel-RAM reads are
behind feature detection: Cilium probes once at startup, the kernel
emits the lockdown notice, the agent flags the feature off, the rest
of the load proceeds. Falco and Tetragon behave similarly. None of
them have a single mandatory load path that requires
`bpf_probe_read_kernel`.

The pattern that makes this work is consistent: don't put kernel-RAM
reads on a load-or-die path. Either the program type provides what
you need via context, or userspace pre-populates a map and the BPF
program reads that map.

## Proposed change

Replace the kernel-side netns inode lookup with a userspace-side
lookup table populated by the controller's existing pod watcher.

### Today

```c
// helper.h
__u32 net_ns_inum = 0;
BPF_CORE_READ_INTO(&net_ns_inum, sk, __sk_common.skc_net.net, ns.inum);

__u64 key = (__u64)net_ns_inum;
__u32 *user_space_inum_ptr = bpf_map_lookup_elem(&inode_num, &key);
```

Three chained dereferences from `sk` into `struct net`. Each is a
`bpf_probe_read_kernel`. The result is matched against the
userspace-populated `inode_num` map.

### Proposed

```c
// helper.h
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u32 pid = pid_tgid >> 32;

__u32 *net_ns_inum_ptr = bpf_map_lookup_elem(&pid_to_netns, &pid);
if (!net_ns_inum_ptr)
    return false;

__u64 key = (__u64)(*net_ns_inum_ptr);
__u32 *user_space_inum_ptr = bpf_map_lookup_elem(&inode_num, &key);
```

`bpf_get_current_pid_tgid` is allowed under confidentiality. Map
lookups don't read kernel RAM. The `pid_to_netns` map is owned by
userspace.

### Userspace side

A new task in `pod_watcher.rs` (or a sibling module) maintains the
`pid_to_netns` map. For each pod the controller is monitoring:

1. Resolve the pod's container PIDs from the cgroup hierarchy.
2. Read the netns inode by `stat(2)`-ing `/proc/<pid>/ns/net` (the
   inode number is the link target's inode, not the link itself).
3. Insert `(pid, netns_inum)` into the BPF map.

Pod-create events trigger an insert; pod-delete events trigger a
delete. Periodic full re-scan handles drift.

### Trade-offs

There's a window between a pod starting and userspace updating the
map where the BPF program can't attribute flows from that pod's
processes. Bounded; observed flows during the window are dropped at
the netns filter (we already do this for unknown netns inums). Same
shape as the existing startup window; widens slightly per pod
restart. Acceptable.

The userspace work is small. The controller already runs a
Kubernetes pod informer; the netns scrape adds one syscall per
pod per resync.

## Audit of remaining kernel-RAM reads

This proposal targets the netns lookup specifically. Other BPF
programs in `controller/src/bpf/` need a sweep before the redesign
ships. Initial grep finds:

- `network_probe.bpf.c`: 9 `BPF_CORE_READ*` macro calls (the netns
  ones plus 6 others reading TCP/UDP socket fields)
- `netpolicy_drop.bpf.c`: probably similar; not yet inspected
- `syscall.bpf.c`: tracepoint-based; likely uses `__sk_buff`-style
  context access, but TBC

Some of these reads access fields available via direct-context access
on the appropriate program type and don't actually need
`bpf_probe_read_kernel` — that's a finding for the implementation
phase. Anything that does need a kernel-RAM read gets the same
userspace-map treatment as the netns case, or the program migrates to
a context-providing attach type.

## What's not in scope

- Full migration to cgroup-attached programs
  (`cgroup_skb/ingress`, `cgroup_skb/egress`). That's the long-term
  direction — same approach Cilium uses — but it's a different
  program type with a different attach surface, and rewires the data
  path. Worth a separate proposal once this lands.
- Detect-and-degrade behaviour. Falling back from
  `bpf_probe_read_kernel` to the new path at runtime adds load-path
  branching and there's no case where the kernel read beats the map
  lookup. Just switch.
- BPF program signing. Linux 6.18 added the kernel infrastructure;
  the userspace tooling and distro signing pipelines aren't
  deployable yet. Track separately.

## Implementation plan

Roughly three landings:

1. **Lockdown detection at startup** — controller reads
   `/sys/kernel/security/lockdown` on init, crashloops with a clear
   error message naming this proposal if confidentiality is active.
   ~30 lines. Ships before any redesign so users hitting this on the
   current code get a useful message instead of a verifier log dump.
2. **Documentation** — `docs/installation.mdx` calls out Talos+SecureBoot
   specifically, gives the diagnostic command
   (`talosctl read /sys/kernel/security/lockdown` /
   `cat /sys/kernel/security/lockdown`), and points at this proposal.
   Ships with (1).
3. **The redesign itself** — userspace populates `pid_to_netns`,
   BPF programs switch to map-based lookup, audit and remediate
   any other kernel-RAM reads found in the BPF source. Validation:
   integration test on a non-locked-down kernel to confirm no
   regression, then a build for someone running Talos+SecureBoot to
   smoke-test on actual confidentiality.

(1) and (2) are session-sized. (3) is a sprint.

## References

- `include/linux/security.h` — `lockdown_reason` enum and
  integrity/confidentiality boundary markers
- `kernel/bpf/helpers.c` — `bpf_probe_read_kernel` checks
  `security_locked_down(LOCKDOWN_BPF_READ_KERNEL)`
- `kernel/trace/bpf_trace.c` — same check on the tracing path
- `man kernel_lockdown.7`
- Tetragon FAQ — kernel lockdown modes
- LWN: "Signed BPF programs" (Linux 6.18, Nov 2025) — eventual
  upstream answer, not deployable end-to-end yet
