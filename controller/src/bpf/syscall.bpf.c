#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024); // 128KB ring buffer
} syscall_events SEC(".maps");

// One allowlist per non-full capture tier, keyed by syscall number for
// THIS architecture. Userspace (controller/src/bpf.rs) resolves the tier
// name lists in controller/src/capture_tiers.rs through libseccomp at
// startup and fills these; the probe picks the map by the tier index in
// the netns's inode_num value. Tier 0 (full) has no map and no filter.
//
// A tier map that is empty drops everything for that tier — there is
// deliberately no "empty means unfiltered" fallback any more, because
// full capture is now an explicit tier of its own.
#define KG_ALLOWLIST(name, size) \
    struct                       \
    {                            \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, size);       \
        __type(key, u32);                \
        __type(value, u8);               \
    } name SEC(".maps")

// high = every syscall on the arch minus ~30 hot-path exclusions, so
// it needs room for the whole table (x86_64 is in the 460s).
KG_ALLOWLIST(allowlist_high, 1024);
KG_ALLOWLIST(allowlist_medium, 512);
KG_ALLOWLIST(allowlist_low, 512);
KG_ALLOWLIST(allowlist_custom, 1024);

// Per-netns dedup. The controller only ever needs the SET of syscalls
// a pod has made, not every occurrence, so the first sighting of
// (netns, generation, syscall) is the only one that reaches userspace.
// This is what makes the full tier affordable: after warm-up a pod
// costs one hash lookup per syscall and no ring-buffer traffic.
//
// LRU_HASH sized for ~65k live (netns, syscall) pairs — a few hundred
// pods times a couple of hundred distinct syscalls each. Entries for a
// pod that has gone are simply aged out under pressure; nothing has to
// clean them up on pod removal. If pressure does evict a live entry the
// only cost is one duplicate event, which userspace dedups again
// (controller/src/syscall.rs SYSCALL_CACHE).
//
// The generation is part of the key on purpose — see KG_GEN_SHIFT in
// helper.h for why a bare (netns, syscall) key is not safe.
struct seen_syscall_key
{
    __u64 netns;
    __u32 generation;
    __u32 syscall;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct seen_syscall_key);
    __type(value, u8);
} seen_syscalls SEC(".maps");

struct data_t
{
    __u64 inum;
    __u64 sysnbr;
};

// True when `syscall_id` passes the allowlist for `tier`. Full (and any
// tier index userspace does not emit) is unfiltered so a bad value can
// never silently blind capture.
static __always_inline bool tier_allows(u32 tier, u32 syscall_id)
{
    u8 *hit;
    switch (tier)
    {
    case KG_TIER_HIGH:
        hit = bpf_map_lookup_elem(&allowlist_high, &syscall_id);
        break;
    case KG_TIER_MEDIUM:
        hit = bpf_map_lookup_elem(&allowlist_medium, &syscall_id);
        break;
    case KG_TIER_LOW:
        hit = bpf_map_lookup_elem(&allowlist_low, &syscall_id);
        break;
    case KG_TIER_CUSTOM:
        hit = bpf_map_lookup_elem(&allowlist_custom, &syscall_id);
        break;
    default:
        return true;
    }
    return hit != NULL;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    u32 *flags = 0;

    task = (struct task_struct *)bpf_get_current_task();
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // Early exit if not in tracked namespace
    flags = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!flags)
        return 0;

    u32 syscall_id = (__u32)ctx->id;

    // Tier filter first: cheap, and keeps the dedup map from filling
    // with syscalls nobody asked to see.
    if (!tier_allows(KG_TIER_OF(*flags), syscall_id))
        return 0;

    // Dedup: only the first sighting per (netns, generation, syscall)
    // is submitted. BPF_NOEXIST fails with -EEXIST when the key is
    // already there, which is exactly the "seen before" signal.
    struct seen_syscall_key seen = {
        .netns = net_ns,
        .generation = KG_GEN_OF(*flags),
        .syscall = syscall_id,
    };
    u8 one = 1;
    if (bpf_map_update_elem(&seen_syscalls, &seen, &one, BPF_NOEXIST) != 0)
        return 0;

    // Reserve space in ring buffer
    struct data_t *data;
    data = bpf_ringbuf_reserve(&syscall_events, sizeof(*data), 0);
    if (!data)
    {
        // Buffer full: drop the event, but ALSO forget we saw it, or
        // this syscall would never be reported for this pod again
        // (until LRU pressure evicted the entry) — a hole in the
        // seccomp profile caused by nothing but a busy moment.
        bpf_map_delete_elem(&seen_syscalls, &seen);
        return 0;
    }

    // Fill event data
    data->sysnbr = ctx->id;
    data->inum = net_ns;

    // Submit to userspace
    bpf_ringbuf_submit(data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
