# Proposal: BPF compatibility with kernel lockdown=confidentiality

Status: draft, looking for sign-off before implementation.

## Problem

The controller's BPF programs fail to load on hosts running with the
kernel `lockdown` LSM in `confidentiality` mode. Symptoms from a real
environment:

```
controller libbpf: prog 'trace_udp_send': BPF program load failed: -EINVAL
controller libbpf: prog 'trace_udp_send': -- BEGIN PROG LOAD LOG --
...
controller ; BPF_CORE_READ_INTO(&net_ns_inum, sk, __sk_common.skc_net.net, ns.inum);
controller 10: (85) call bpf_probe_read#4
controller program of this type cannot use helper bpf_probe_read#4
controller -- END PROG LOAD LOG --
controller libbpf: failed to load BPF skeleton 'network_probe_bpf': -EINVAL
controller Error: Custom("Failed to load network probe eBPF: Invalid argument (os error 22)")
```

Host dmesg, from the same load attempt:

```
kern: notice: Lockdown: tokio-runtime-w: use of bpf to read kernel RAM is restricted; see man kernel_lockdown.7
```

`tokio-runtime-w` is the controller's tokio worker thread loading the
BPF skeleton.

There are two gates closing on the same call:

1. The BPF verifier rejects `bpf_probe_read#4` (legacy helper) for
   `fentry`-type programs as a helper-compat rule. This is the
   immediate failure visible in the verifier log.
2. If we fixed (1) by emitting the typed `bpf_probe_read_kernel#113`
   instead, the kernel's `LOCKDOWN_BPF_READ_KERNEL` LSM hook would
   block the load. That's the dmesg notice.

Both gates fire on the same underlying issue: the BPF programs read
kernel memory by chasing pointers through `struct sock`, and
confidentiality mode forbids that.

## Why this hits us harder than it hits Cilium

Worth being explicit, because the typical operator question is "Cilium
runs on the same node, Hubble shows all the traffic, why doesn't
kguardian?" The answer is the program type we attach to.

### What Cilium does

Cilium attaches its data-plane programs as `tc` classifiers (program
type `BPF_PROG_TYPE_SCHED_CLS`) on per-endpoint virtual interfaces, or
as `cgroup_skb` programs (program type `BPF_PROG_TYPE_CGROUP_SKB`) on
the pod's cgroup. Both program types receive `__sk_buff` as their
context. The verifier knows the layout of `__sk_buff` and rewrites
field access to safe loads at verification time.

```c
// Cilium-style: __sk_buff is the context
SEC("classifier/from-container")
int handle_from_container(struct __sk_buff *skb)
{
    __u32 src_ip = skb->saddr;     // direct access, no helper
    __u32 dst_ip = skb->daddr;     // direct access, no helper
    __u32 cgroup = skb->cgroup_id; // direct access, no helper
    // ... no bpf_probe_read_kernel calls anywhere
}
```

There's no `bpf_probe_read_kernel` in that path. The verifier's
context-rewriting logic compiles each field access into a direct load
from a kernel-controlled offset; lockdown's `LOCKDOWN_BPF_READ_KERNEL`
hook is never invoked because no helper call is made.

For pod identity, Cilium uses cgroup membership. `bpf_get_current_cgroup_id()`
is a helper that returns the cgroup ID directly; it doesn't read
arbitrary kernel memory and isn't gated by lockdown. Userspace
maintains a cgroup-id-to-pod-id table.

Cilium does have a few optional features that need kernel-RAM reads
(some L7 visibility, certain socket-level enrichment). Those features
are behind feature detection: Cilium probes once at startup, the kernel
emits one lockdown notice, the agent flags those features off, the
rest of the load proceeds. The hot path stays alive.

Hubble is downstream of all this. Hubble reads flow data from Cilium's
BPF maps via the agent's gRPC API — userspace-to-userspace, no BPF
load involved. Hubble keeps showing flows because Cilium's data plane
keeps producing them, even with the confidentiality-restricted optional
features turned off.

### What kguardian does today

The controller attaches `fentry` programs to internal kernel functions
(`tcp_v4_connect`, `tcp_set_state`, `udp_sendmsg`, etc.) and `kprobe`
programs to others (`inet_csk_accept`). These program types receive raw
kernel arguments — `struct sock *sk`, `struct msghdr *msg`. The
verifier has no special context-rewrite for these pointers; anything
read from them goes through `bpf_probe_read_kernel`.

From `controller/src/bpf/network_probe.bpf.c`, the actual pattern:

```c
SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_state_change, struct sock *sk, int state)
{
    if (!sk)
        return 0;

    if (state != 1)  // TCP_ESTABLISHED
        return 0;

    // This compiles to a single bpf_probe_read_kernel call covering
    // the whole sock_common struct — addresses, ports, family, the
    // entire embedded chunk.
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    if (skc.skc_family != 2)
        return 0;

    // Another bpf_probe_read_kernel chain — three levels:
    // sk -> __sk_common.skc_net.net -> ns.inum
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // ... rest of the function uses skc fields read above
}
```

Every BPF program in `network_probe.bpf.c` does this. There are 9
`BPF_CORE_READ*` calls in the source today across three programs;
each one is a `bpf_probe_read_kernel` call at the helper level. Under
confidentiality, every one of them gets denied.

This is the load-bearing observation: fixing only the netns lookup
doesn't help. The socket-common read fails the same way. The fix has
to be a program-type change, not a per-read workaround.

## Proposed change

Migrate the network observation programs from `fentry`/`kprobe` on
internal kernel functions to `cgroup_skb`/`cgroup_sock_addr` programs
attached at the pod cgroup. This is the same approach Cilium uses for
the same reason.

### Sketch of the new attach

```c
// Attached at /sys/fs/cgroup (or per-pod via cgroup ID), one program
// covers ingress and another egress.
SEC("cgroup_skb/egress")
int handle_egress(struct __sk_buff *skb)
{
    // Direct context access — no probe_read, no lockdown gate.
    __u32 src_ip = skb->local_ip4;
    __u32 dst_ip = skb->remote_ip4;
    __u32 dport  = skb->remote_port;
    __u32 sport  = skb->local_port;
    __u32 family = skb->family;

    if (family != AF_INET)
        return 1;  // pass

    // Pod identity from cgroup id — allowed helper, not a RAM read.
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Existing should_filter_traffic / dedup logic, unchanged.
    if (should_filter_traffic(src_ip, dst_ip))
        return 1;

    struct network_event_data *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->cgroup_id = cgroup_id;   // <-- new field; replaces inum
    event->saddr     = src_ip;
    event->daddr     = dst_ip;
    event->sport     = sport;
    event->dport     = bpf_ntohs(dport);
    event->kind      = 1;  // Egress

    bpf_ringbuf_submit(event, 0);
    return 1;
}
```

Same shape on ingress. No `bpf_probe_read_kernel` in the data path.

### Userspace side

The current `pod_watcher.rs` already runs a Kubernetes informer for
pod events. Two changes:

1. Resolve each pod's cgroup ID from the cgroup hierarchy
   (`/sys/fs/cgroup/kubepods/...`) at pod-create time. Already
   approximately what the existing inum-based filter does for netns.
2. Maintain a `cgroup_to_pod` BPF map keyed on cgroup ID, value
   being the pod identity already used downstream. Replaces the
   existing `inode_num` map.

Flow events now carry `cgroup_id` to the broker; the broker resolves
to pod identity by cross-referencing the userspace-maintained table
(unchanged from how it resolves inums today; just a different key).

### Trade-offs

- We lose the `TCP_ESTABLISHED`-only filter that comes from attaching
  to `tcp_set_state`. `cgroup_skb/egress` fires per packet on the
  egress side, not per state transition. The dedup logic in
  `is_new_connection` already handles this — it keys on the 4-tuple,
  not on syscall context — so the rate of events going to userspace
  stays roughly the same. Worth measuring before we ship.
- We lose syscall-context PID. Currently the controller calls
  `bpf_get_current_pid_tgid()` to dedup per-thread state. Cgroup-attached
  programs run in softirq context for incoming packets, so PID is
  meaningless there. Dedup logic moves to (cgroup_id, 4-tuple) instead
  of (pid, 4-tuple). Same cardinality bounds.
- The attach mechanism is different. We currently bpf-link to fentry
  via libbpf's auto-attach; cgroup attach needs a cgroup file
  descriptor and explicit `BPF_PROG_ATTACH` syscall. The
  `pod_reconciler.rs` watches pod create/delete already and is the
  natural place to do the per-pod attach.

### What does not change

- Ringbuffer to userspace. Same path.
- Broker-side processing. Same fields, plus `cgroup_id` instead of
  `inum`. Schema change is one column rename / addition; broker code
  treats it as opaque.
- Frontend behaviour. Doesn't touch this layer.
- Audit-mode evaluator. Same flow shape arrives at the evaluator.

### What's deliberately not in this proposal

- BPF program signing. Linux 6.18 added the kernel infrastructure for
  signed BPF programs (which would let signed programs bypass
  lockdown's restrictions); the userspace tooling and distro signing
  pipelines aren't deployable end-to-end yet. Worth tracking as the
  long-term answer; not an option now.
- Detect-and-degrade behaviour. We could try the old fentry path
  first and fall back. There's no scenario where fentry beats
  cgroup-attach for our use case, and dual program loads add
  verification cost on every cluster. Just switch.
- Lockdown=integrity support. Integrity mode doesn't block any of
  this — `LOCKDOWN_BPF_READ_KERNEL` only fires under confidentiality
  (per `include/linux/security.h`'s `lockdown_reason` enum, where
  `LOCKDOWN_INTEGRITY_MAX` is the boundary marker). Mainstream
  distro defaults stay on integrity under Secure Boot and aren't
  affected. The break is specifically confidentiality.

## Where this matters in practice

Talos with Secure Boot defaults to `lockdown=confidentiality`. This is
opinionated harder than mainstream distros. RHEL, Ubuntu, Debian, and
Fedora all default to integrity under Secure Boot, which doesn't block
this code path.

A typical Talos cluster mixes Secure Boot bare-metal nodes with VM
nodes that boot normally; a 50–80% SB split is common. NodeSelector to
the VM-only subset works as a per-cluster opt-out but it hides the
controller from most of the cluster, which isn't a tenable default.

## Implementation plan

Three landings, in order:

1. **Lockdown detection at startup.** Controller reads
   `/sys/kernel/security/lockdown` on init. If `[confidentiality]` is
   active, log a clear error message naming this proposal and exit
   non-zero. Beats a verifier log dump for users. ~30 lines. Ships
   before the redesign so anyone hitting the existing breakage gets a
   useful message and a forward pointer.
2. **Documentation.** `docs/installation.mdx` calls out
   Talos+SecureBoot specifically. Includes the diagnostic command
   (`talosctl read /sys/kernel/security/lockdown` /
   `cat /sys/kernel/security/lockdown`), the integrity-vs-confidentiality
   distinction so RHEL/Ubuntu/Debian/Fedora users don't think they're
   affected, and a temporary nodeSelector workaround. Ships with (1).
3. **The redesign.** Cgroup-attached BPF programs. New attach plumbing
   in `pod_reconciler.rs`. cgroup_id as the new pod-identity key
   replacing the netns inum throughout the controller and broker.
   Validation: integration test on a non-locked-down kernel to confirm
   no regression; build for someone running Talos+SecureBoot to confirm
   the load actually succeeds under confidentiality.

(1) and (2) are session-sized. (3) is a sprint. (3) does not depend on
(1) and (2); they ship in parallel branches.

## References

- `include/linux/security.h` — `lockdown_reason` enum and the
  integrity/confidentiality boundary markers
  (`LOCKDOWN_INTEGRITY_MAX`, `LOCKDOWN_CONFIDENTIALITY_MAX`)
- `kernel/bpf/helpers.c` and `kernel/trace/bpf_trace.c` —
  `bpf_probe_read_kernel` checks `security_locked_down(LOCKDOWN_BPF_READ_KERNEL)`
- `kernel/bpf/cgroup.c` — `cgroup_skb` program-type attach surface
- `man kernel_lockdown.7`
- Cilium datapath docs — `cgroup_skb`/`tc` attach patterns
- LWN: "Signed BPF programs" (Linux 6.18, Nov 2025) — eventual
  upstream answer; not deployable end-to-end yet
