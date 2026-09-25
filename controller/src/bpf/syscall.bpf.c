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

// Keep in sync with `SyscallEventData` in controller/src/syscall.rs.
//
// `kind` says which path produced the event:
//   KG_SYSCALL_EVENT_REGISTERED  the netns is in inode_num; userspace
//                                attributes by `inum`, as it always has.
//   KG_SYSCALL_EVENT_PENDING     the netns is NOT registered yet, but the
//                                calling task sits in a kubepods cgroup
//                                created since the controller started
//                                (pending_cgroups). Userspace buffers it
//                                by `cgroup_id` until the pod watcher has
//                                registered the pod, then attributes it
//                                (controller/src/early_capture.rs).
// `cgroup_id` is filled on both paths: it names the container, where
// `inum` only names the pod.
#define KG_SYSCALL_EVENT_REGISTERED 0
#define KG_SYSCALL_EVENT_PENDING    1

struct data_t
{
    __u64 inum;
    __u32 sysnbr;
    __u32 kind;
    __u64 cgroup_id;
};

// ---- Startup capture (closes the seccomp startup-capture gap) ----------
//
// The pod watcher can only register a pod's netns once an app container
// is running (it needs a containerID out of the pod status and a pid out
// of containerd). Everything before that — runc's container setup and
// the app's first instructions — used to fall through the inode_num gate
// and was never seen, so a profile recorded from a fresh pod was missing
// its startup syscalls and crashlooped on the next restart once it was
// enforced with SCMP_ACT_ERRNO.
//
// The fix keys capture on the one identity that exists before the
// container runs: its cgroup. The runtime creates a container's cgroup
// before runc moves the init process into it, so the cgroup_mkdir probe
// below sees it first, marks it pending, and tells userspace its path
// (which carries the pod UID and container id). From then on, any
// syscall from a task in that cgroup whose netns is not registered is
// captured, deduplicated per (cgroup, syscall), and attributed by
// userspace once the pod watcher has registered the pod. There is no
// race window: the mark is set in the kernel, synchronously, before any
// task can run in the cgroup, so nothing depends on how fast userspace
// reacts.
//
// Kernfs cgroup ids are 64-bit and not recycled, so unlike the netns
// keys no generation is needed in these keys.
#define KG_CGROUP_PATH_MAX 256
// "kubepods" must start within this many bytes of the path. Every
// layout seen in practice has it in the first or second segment:
//   /kubepods/burstable/pod<uid>/<cid>                        (cgroupfs)
//   /kubepods.slice/kubepods-burstable.slice/...              (systemd)
//   /kubelet.slice/kubelet-kubepods.slice/...                 (kind)
#define KG_KUBEPODS_SCAN 96

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);   // cgroup id
    __type(value, u64); // bpf_ktime_get_ns() at mkdir
} pending_cgroups SEC(".maps");

// Hot-path gate for the pending path. Every syscall from a task whose
// netns is not registered (host daemons, excluded namespaces) reaches
// capture_pending; without this gate each one paid a helper call and an
// LRU miss even when nothing was pending, which is the steady state.
//
//   [KG_GATE_CREATED]  pending marks set, incremented here by the mkdir
//                      program (atomically; mkdirs can race on CPUs)
//   [KG_GATE_RETIRED]  pending marks deleted, written only by userspace
//                      (controller/src/bpf.rs) after a successful delete
//
// created == retired means nothing is pending and the pending path is two
// array reads. A mark lost to LRU eviction is never counted as retired,
// which leaves the gate open: the old per-syscall cost, never lost data.
#define KG_GATE_CREATED 0
#define KG_GATE_RETIRED 1
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} pending_gate SEC(".maps");

// Syscalls the container runtime makes BEFORE it installs the container's
// seccomp filter, and so never need to be in the profile: the rootfs,
// hostname, keyring and namespace setup runc performs ahead of
// syncParentReady. Indexed by syscall number, filled by userspace from
// `early_capture::RUNTIME_PREFILTER_SYSCALLS` for this arch.
//
// Deliberately NOT "everything runc init does": with NoNewPrivileges
// unset (the Kubernetes default, allowPrivilegeEscalation: true) runc
// installs the filter BEFORE finalizeNamespace, so its capset, prctl,
// setgroups, setresuid/gid, close_range, chdir, the exec-fifo
// openat/write/close and its Go runtime's own syscalls all run UNDER the
// profile. Dropping those would make an enforced profile fail the
// container at create time.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} runtime_prefilter SEC(".maps");

// runc names its init stages "runc:[0:PARENT]", "runc:[1:CHILD]",
// "runc:[2:INIT]" (comm is at most 15 bytes). True for a task in one of
// them making a syscall runc only makes before the filter exists.
static __always_inline bool runtime_prefilter_skip(u32 syscall_id)
{
    u8 *pre = bpf_map_lookup_elem(&runtime_prefilter, &syscall_id);
    if (!pre || !*pre)
        return false;
    char comm[16];
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return false;
    return comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c' &&
           comm[4] == ':' && comm[5] == '[';
}

struct pending_syscall_key
{
    __u64 cgroup_id;
    __u32 syscall;
    __u32 _pad;
};

// Dedup for the pending path, mirroring seen_syscalls. The pending path
// captures at FULL tier because the pod's tier is not known until it is
// registered; userspace applies the tier when it attributes. Bounded by
// (containers starting) x (distinct syscalls during startup).
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pending_syscall_key);
    __type(value, u8);
} pending_seen SEC(".maps");

// Keep in sync with `CgroupEventData` in controller/src/early_capture.rs.
struct cgroup_event_t
{
    __u64 cgroup_id;
    __u32 level;
    __u32 _pad;
    char path[KG_CGROUP_PATH_MAX];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // ~240 events; cgroup mkdir is rare
} cgroup_events SEC(".maps");

// True when the NUL-terminated `p` contains "kubepods" starting within
// the first KG_KUBEPODS_SCAN bytes. `p` points at a KG_CGROUP_PATH_MAX
// buffer, so every index read here stays in bounds.
static __always_inline bool path_has_kubepods(const char *p)
{
    for (int i = 0; i < KG_KUBEPODS_SCAN; i++)
    {
        if (p[i] == 0)
            return false;
        if (p[i] == 'k' && p[i + 1] == 'u' && p[i + 2] == 'b' && p[i + 3] == 'e' &&
            p[i + 4] == 'p' && p[i + 5] == 'o' && p[i + 6] == 'd' && p[i + 7] == 's')
            return true;
    }
    return false;
}

SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(trace_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
    struct cgroup_event_t *ev;

    // Default (v2) hierarchy only. On a hybrid v1+v2 host every container
    // also gets a directory in each v1 hierarchy, whose ids can never
    // match bpf_get_current_cgroup_id() (always the v2 id). The task
    // doing the mkdir sits in some v2 cgroup, so its dfl_cgrp->root IS
    // the default hierarchy root.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(cgrp, root) != BPF_CORE_READ(task, cgroups, dfl_cgrp, root))
        return 0;

    // Reserve first: a cgroup is only marked pending if userspace is
    // also told what it is. A pending mark userspace never hears about
    // would capture into a buffer nothing can attribute (it would still
    // expire, but it is wasted work).
    ev = bpf_ringbuf_reserve(&cgroup_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    if (bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path) < 0 ||
        !path_has_kubepods(ev->path))
    {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    __u64 id = BPF_CORE_READ(cgrp, kn, id);
    ev->cgroup_id = id;
    ev->level = BPF_CORE_READ(cgrp, level);
    ev->_pad = 0;

    __u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&pending_cgroups, &id, &now, BPF_NOEXIST) != 0)
    {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    u32 created_key = KG_GATE_CREATED;
    __u64 *created = bpf_map_lookup_elem(&pending_gate, &created_key);
    if (created)
        __sync_fetch_and_add(created, 1);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// Pending path of the syscall probe: the netns is not registered, so
// look the task's cgroup up in pending_cgroups instead. Cost for every
// untracked task on the node while nothing is pending: two array reads
// (pending_gate). While something is pending: plus one helper call and
// one hash lookup.
static __always_inline int capture_pending(__u64 net_ns, u32 syscall_id)
{
    u32 created_key = KG_GATE_CREATED, retired_key = KG_GATE_RETIRED;
    __u64 *created = bpf_map_lookup_elem(&pending_gate, &created_key);
    __u64 *retired = bpf_map_lookup_elem(&pending_gate, &retired_key);
    if (!created || !retired || *created == *retired)
        return 0;

    if (runtime_prefilter_skip(syscall_id))
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&pending_cgroups, &cgroup_id))
        return 0;

    struct pending_syscall_key key = {
        .cgroup_id = cgroup_id,
        .syscall = syscall_id,
        ._pad = 0,
    };
    u8 one = 1;
    if (bpf_map_update_elem(&pending_seen, &key, &one, BPF_NOEXIST) != 0)
        return 0;

    struct data_t *data = bpf_ringbuf_reserve(&syscall_events, sizeof(*data), 0);
    if (!data)
    {
        // Same reasoning as the registered path: forget the sighting so
        // the next occurrence is reported instead of never.
        bpf_map_delete_elem(&pending_seen, &key);
        return 0;
    }
    data->inum = net_ns;
    data->sysnbr = syscall_id;
    data->kind = KG_SYSCALL_EVENT_PENDING;
    data->cgroup_id = cgroup_id;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

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

    u32 syscall_id = (__u32)ctx->id;

    // Not a registered netns: either nothing kube-guardian tracks, or a
    // container that is not registered YET (startup). The pending path
    // tells the two apart by cgroup.
    //
    // TODO(1533): a hostNetwork pod's netns is the node's, so once any
    // hostNetwork pod on the node is registered, a starting hostNetwork
    // container takes the registered path below (never the pending one)
    // and its syscalls go to whichever pod holds the node netns key in the
    // ContainerMap. The fix is attribution by cgroup id, which lands with
    // the per-container keying of P1-2.
    flags = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!flags)
        return capture_pending(net_ns, syscall_id);

    // Tier filter first: cheap, and keeps the dedup map from filling
    // with syscalls nobody asked to see.
    if (!tier_allows(KG_TIER_OF(*flags), syscall_id))
        return 0;

    // A container (re)starting in an already-registered netns: skip the
    // runtime's pre-filter setup syscalls here too, or the profile would
    // depend on whether a restart happened to be observed.
    if (runtime_prefilter_skip(syscall_id))
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
    data->sysnbr = syscall_id;
    data->kind = KG_SYSCALL_EVENT_REGISTERED;
    data->inum = net_ns;
    data->cgroup_id = bpf_get_current_cgroup_id();

    // Submit to userspace
    bpf_ringbuf_submit(data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
