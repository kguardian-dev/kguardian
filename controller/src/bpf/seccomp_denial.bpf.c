// Seccomp denial capture: the kernel's own seccomp verdict, aggregated
// in-kernel and read back by controller/src/seccomp_denial.rs.
//
// ## The hook
//
// kprobe on `void audit_seccomp(unsigned long syscall, long signr,
// int code)` (kernel/auditsc.c). `seccomp_log()` in kernel/seccomp.c
// calls it exactly once per LOGGABLE verdict:
//
//   * SECCOMP_RET_LOG        — unconditionally, subject only to
//                              /proc/sys/kernel/seccomp/actions_logged
//                              (which lists `log` by default). This is
//                              the action kguardian's own generated
//                              profiles use, so it is the case that
//                              matters.
//   * SECCOMP_RET_ERRNO,
//     TRAP, TRACE, USER_NOTIF — when the filter was loaded with
//                              SECCOMP_FILTER_FLAG_LOG.
//   * SECCOMP_RET_KILL_*     — always.
//
// SECCOMP_RET_ALLOW never reaches it, so nothing here counts a call
// that seccomp permitted. `audit_seccomp` deliberately does not gate on
// `audit_enabled` (see its kernel-doc), so a node with auditd stopped
// still produces these calls — we are hooking the producer, not reading
// the audit log.
//
// `code` is the action AFTER `__seccomp_filter` masked it with
// SECCOMP_RET_ACTION_FULL, i.e. the bare SECCOMP_RET_* constant with the
// 16-bit data field (the errno, the trap number) already cleared.
//
// ## Why kprobe, not fentry
//
// fentry resolves its target through BTF; a kprobe resolves by symbol
// name through the kprobe subsystem and needs nothing but the symbol
// being present and not blacklisted. The rest of this tree already has
// to tolerate kernels with thin or missing module BTF (see
// kernel_can_fentry in controller/src/bpf.rs), and there is no reason to
// inherit that exposure for a probe that does not need it.
//
// ## Graceful degradation is mandatory
//
// `audit_seccomp` only exists as a real symbol with CONFIG_AUDITSYSCALL=y
// (the contract says CONFIG_AUDIT; CONFIG_AUDITSYSCALL is the option that
// actually decides it, and it depends on CONFIG_AUDIT plus arch support).
// Without it, include/linux/audit.h supplies an empty `static inline` and
// there is no symbol to attach to. A kernel built with CONFIG_LTO_CLANG
// could also inline the real one away. Both cases look identical from
// userspace — no kallsyms entry — and userspace checks for that BEFORE
// loading this object (bpf::kernel_can_kprobe), then treats a load or
// attach failure as "skip this probe" rather than an error. A node
// without audit support is a supported node; it must lose this one
// signal, never the Controller.
//
// ## Aggregation, not a ring buffer
//
// Unlike the syscall probe there is no ringbuffer here. A compromised or
// merely broken workload can drive seccomp verdicts at syscall rate, and
// one event per verdict would turn an attack into a second, self-inflicted
// incident in the Controller. Everything is counted in place in an LRU
// hash and userspace reads-and-clears it on a timer, which bounds the
// cost of a denial storm to one hash update per verdict and gives real
// counts rather than a sample.
//
// ## Portability of the atomics
//
// build.rs compiles this file with -mcpu=v2, exactly as it does
// sched_contention.bpf.c: recent clang defaults the BPF target to cpu v3
// and lowers __sync_fetch_and_add to BPF_ATOMIC|BPF_FETCH, which the
// verifier rejects before 5.12 and the arm64 JIT before 5.18. On v2 it
// lowers to the legacy BPF_XADD every supported kernel accepts. Nothing
// below uses the value the add returns — that is what makes the v2
// lowering possible; keep it that way.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"

// Mask the kernel applies to a filter return before it decides an action
// (SECCOMP_RET_ACTION_FULL in include/uapi/linux/seccomp.h). `code` is
// already masked by the time seccomp_log() hands it over, so applying it
// again changes nothing today. It is here as a key guard: if a future
// kernel ever passed an unmasked value, SECCOMP_RET_ERRNO would arrive
// as a different number for every errno a filter returns, and this map
// would grow one row per (syscall, errno) instead of one per (syscall,
// action) — turning a bounded aggregate into the firehose the design
// exists to avoid. Userspace reports the masked value as `actionRaw`,
// which is the SECCOMP_RET_* constant it means to report anyway.
#define KG_SECCOMP_RET_ACTION_FULL 0xffff0000U

// One row per (netns, generation, syscall, action).
//
// The generation is part of the key for the reason KG_GEN_SHIFT in
// helper.h spells out: the kernel recycles netns inode numbers, so a
// replacement pod can land on a dead pod's inode. Without it, a pod that
// died mid-interval and one that took its inode would have their counts
// summed into a single row and attributed wholesale to the survivor.
// With it they stay separate, and userspace drops any row whose
// generation no longer matches the pod registered on that inode — a
// denial attributed to the wrong pod is worse than one not reported.
//
// `pad` is explicit because this is a map key and the kernel compares
// keys byte-for-byte: a compiler-inserted tail padding byte holding
// stack garbage would split one logical row into several.
struct seccomp_denial_key
{
    __u64 netns;
    __u32 generation;
    __u32 syscall_nr;
    __u32 action; // raw SECCOMP_RET_*, masked with ACTION_FULL
    __u32 pad;    // always 0
};

struct seccomp_denial_value
{
    __u64 count;
    __u64 first_seen_ns; // bpf_ktime_get_ns at the first verdict in this row
    __u64 last_seen_ns;  // bpf_ktime_get_ns at the most recent one
};

// Sizes are the wire format between this file and
// controller/src/seccomp_denial.rs, which reads the bytes back at the
// offsets this layout implies. Change a field and the Rust parsers
// (`denial_key_from_bytes`, `denial_value_from_bytes`) must change with
// it.
_Static_assert(sizeof(struct seccomp_denial_key) == 24, "denial key is 24 bytes on the wire");
_Static_assert(sizeof(struct seccomp_denial_value) == 24, "denial value is 24 bytes on the wire");

// LRU, sized like `seen_syscalls` in syscall.bpf.c. Nothing in the
// kernel frees a row when a pod dies, and userspace clears the map on
// each drain, so steady-state occupancy is "distinct denials seen in the
// last interval". LRU rather than a plain hash so that a storm from one
// workload evicts old rows instead of failing every insert node-wide —
// under attack we would rather lose the oldest counts than stop
// recording new pods entirely. Userspace reports occupancy so that
// eviction pressure is a number on a dashboard rather than a quietly
// short list.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct seccomp_denial_key);
    __type(value, struct seccomp_denial_value);
} seccomp_denials SEC(".maps");

// [0] verdicts this probe saw for a tracked pod but could not record.
//     LRU eviction itself never fails, so this only moves when the LRU
//     cannot evict (every row hot on the same CPU) — but a silently
//     dropped denial is the one failure mode that makes "no denials"
//     mean the wrong thing, so it is counted rather than assumed away.
#define KG_STAT_DENIAL_UPDATE_FAILURES 0
#define KG_STAT_COUNT 1

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KG_STAT_COUNT);
    __type(key, u32);
    __type(value, u64);
} denial_stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
    u64 *v = bpf_map_lookup_elem(&denial_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// Count one verdict into `key`, creating the row if it is not there yet.
//
// The lookup-then-insert is not a single atomic step, so two CPUs can
// both miss and both try to create the row. BPF_NOEXIST makes exactly
// one of them win with -EEXIST for the loser, which then falls back to
// the in-place increment — no verdict is lost to that race and no row is
// clobbered back to count=1.
static __always_inline void record_denial(struct seccomp_denial_key *key, __u64 now)
{
    struct seccomp_denial_value *val = bpf_map_lookup_elem(&seccomp_denials, key);
    if (val)
    {
        __sync_fetch_and_add(&val->count, 1);
        // Plain stores, not atomics. Concurrent writers race, and the
        // loser's timestamp is at most a few hundred nanoseconds from
        // the winner's — the value is used to render a second-precision
        // "last seen", so the race is below the resolution of anything
        // that reads it. first_seen_ns is never rewritten after the row
        // is created, so it cannot drift forward.
        val->last_seen_ns = now;
        return;
    }

    struct seccomp_denial_value fresh = {
        .count = 1,
        .first_seen_ns = now,
        .last_seen_ns = now,
    };
    if (bpf_map_update_elem(&seccomp_denials, key, &fresh, BPF_NOEXIST) == 0)
        return;

    val = bpf_map_lookup_elem(&seccomp_denials, key);
    if (val)
    {
        __sync_fetch_and_add(&val->count, 1);
        val->last_seen_ns = now;
        return;
    }

    stat_inc(KG_STAT_DENIAL_UPDATE_FAILURES);
}

SEC("kprobe/audit_seccomp")
int BPF_KPROBE(trace_audit_seccomp, unsigned long syscall, long signr, int code)
{
    // Attribution is the syscall probe's, unchanged: the current task's
    // network namespace inode, looked up in the tracked-pod map this
    // object gets its own instance of (helper.h). A verdict from a host
    // process or from a pod kguardian does not track resolves to no
    // entry and costs one hash lookup.
    //
    // `nsproxy` is NULL for a task past exit_task_namespaces(); the
    // CO-RE read then leaves net_ns at 0, which matches no tracked
    // netns, so the early return covers it. The kill actions are not
    // affected: seccomp_log() runs before do_exit(), while the task
    // still has its namespaces.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    __u32 *flags = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!flags)
        return 0;

    // The capture tier in `flags` is deliberately NOT consulted. The
    // tiers exist to bound how much of a pod's ORDINARY syscall traffic
    // is recorded; a seccomp verdict is not ordinary traffic, it is the
    // kernel acting on a profile kguardian generated, and a workload
    // dropped to the `low` tier to save overhead must not thereby go
    // silent about its own denials.
    struct seccomp_denial_key key = {
        .netns = net_ns,
        .generation = KG_GEN_OF(*flags),
        // Truncation is safe: Linux syscall numbers are three digits on
        // every supported arch, and `syscall` here is the number the
        // filter was evaluated against, not a pointer.
        .syscall_nr = (__u32)syscall,
        .action = (__u32)code & KG_SECCOMP_RET_ACTION_FULL,
        .pad = 0,
    };

    // bpf_ktime_get_ns is CLOCK_MONOTONIC — nanoseconds since boot, not
    // wall clock. Userspace converts with a CLOCK_MONOTONIC/wall anchor
    // it reads right after the drain (seccomp_denial.rs, ClockAnchor).
    // bpf_ktime_get_boot_ns would survive suspend but needs 5.7+; nodes
    // do not suspend, and this probe should not carry a kernel floor it
    // does not need.
    record_denial(&key, bpf_ktime_get_ns());
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
