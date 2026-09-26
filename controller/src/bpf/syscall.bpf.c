#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"
#include "pod_cgroup.h"

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
    // Registered path: the generation of the pod whose cgroup the task is
    // in (see task_pod_generation). Userspace attributes by it, which is
    // what separates hostNetwork pods sharing the node's netns. 0 on the
    // pending path.
    __u32 generation;
    __u32 _pad;
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
// "runc:[2:INIT]"; before nsexec renames it the process is plain "runc",
// and runc 1.2's exec helper is "runc-dmz". Matching the "runc" prefix
// covers all of them (comm is at most 15 bytes). True for such a task
// making a syscall runc only makes before the filter exists. The app
// itself is never matched unless its binary is named runc*, and then only
// for this short list.
static __always_inline bool runtime_prefilter_skip(u32 syscall_id)
{
    u8 *pre = bpf_map_lookup_elem(&runtime_prefilter, &syscall_id);
    if (!pre || !*pre)
        return false;
    char comm[16];
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return false;
    return comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c';
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

// Pending path of the syscall probe. Returns true when the calling task
// sits in a pending cgroup, i.e. the event is this path's to handle (or to
// drop) and the registered path must NOT see it; false otherwise.
//
// This runs BEFORE the inode_num lookup, not only when the netns is
// unregistered. The kernel hands netns inode numbers out lowest-free
// first, so a new pod almost always gets the number of a pod that died
// recently, and inode_num still holds the dead pod's entry (nothing
// deletes it on pod death; it only ages out of the LRU). Gating on the
// netns first sent every such new pod down the registered path with the
// DEAD pod's generation: its startup syscalls were deduplicated against
// the dead pod's set and the rest were credited to the dead pod by
// userspace, and the pending path never saw the new pod at all
// (cluster-00, 2026-09-26: new nginx pods got no syscall row; an nginx
// pod's row gained the musl-only syscalls of a curl pod that had reused
// its netns inode). The cgroup is new per container and never reused, so
// it is the identity to trust while the container is pending.
//
// Cost for every task while nothing is pending: two array reads
// (pending_gate). While something is pending: plus one helper call and
// one hash lookup.
static __always_inline bool capture_pending(__u64 net_ns, u32 syscall_id)
{
    u32 created_key = KG_GATE_CREATED, retired_key = KG_GATE_RETIRED;
    __u64 *created = bpf_map_lookup_elem(&pending_gate, &created_key);
    __u64 *retired = bpf_map_lookup_elem(&pending_gate, &retired_key);
    if (!created || !retired || *created == *retired)
        return false;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&pending_cgroups, &cgroup_id))
        return false;

    // From here on the event belongs to the pending path, captured or not.
    if (runtime_prefilter_skip(syscall_id))
        return true;

    struct pending_syscall_key key = {
        .cgroup_id = cgroup_id,
        .syscall = syscall_id,
        ._pad = 0,
    };
    u8 one = 1;
    if (bpf_map_update_elem(&pending_seen, &key, &one, BPF_NOEXIST) != 0)
        return true;

    struct data_t *data = bpf_ringbuf_reserve(&syscall_events, sizeof(*data), 0);
    if (!data)
    {
        // Same reasoning as the registered path: forget the sighting so
        // the next occurrence is reported instead of never.
        bpf_map_delete_elem(&pending_seen, &key);
        return true;
    }
    data->inum = net_ns;
    data->sysnbr = syscall_id;
    data->kind = KG_SYSCALL_EVENT_PENDING;
    data->cgroup_id = cgroup_id;
    data->generation = 0;
    data->_pad = 0;
    bpf_ringbuf_submit(data, 0);
    return true;
}

// ---- Who owns the calling task (registered path) -----------------------
//
// The registered path is keyed by netns, and a netns is not a pod: host
// processes enter pod network namespaces all the time. containerd pins a
// new netns with a bind mount from a thread inside it and unmounts it at
// teardown; CNI ADD/DEL plugins setns() in; anything else that does
// setns() lands there too. Keyed by netns alone, all of it was credited to
// the pod: 83% of the pod_syscalls rows written by v1.15.1 on cluster-00
// contained mount and umount2, so nearly every generated profile allowed
// them. A task is now credited to a pod only when its cgroup is that
// pod's: the kernfs name of the pod-level cgroup carries the pod UID,
// hashed to the same generation the inode_num entry names.
//
// cgroup id -> KG_CG_POD|generation, or 0 for "not a pod cgroup". Kernfs
// cgroup ids are never reused, so an entry never goes stale; the LRU only
// bounds memory.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, u32);
} cgroup_pod_gen SEC(".maps");

// Static pods: the cgroup carries the config hash, the registered (mirror)
// pod a different UID. generation(config hash) -> generation(mirror uid),
// written by userspace at registration.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} gen_alias SEC(".maps");

// Generations of registered hostNetwork pods. They all share the node's
// netns, whose inode_num entry names only the last one registered; a task
// of any of them is credited to its own pod by generation.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} hostnet_gens SEC(".maps");

// Ownership gate switch. Userspace clears it (before load) when the
// object with the gate enabled does not load on this kernel: with it
// false the verifier sees the whole walk below as dead code, so a CO-RE
// relocation that cannot be resolved here (poisoned by libbpf) is never
// reached, and the registered path falls back to crediting by netns
// alone, as before the gate existed. See bpf.rs (syscall load variants).
const volatile bool kg_ownership_gate = true;

// kernfs_node.parent became the RCU-protected __parent in Linux 6.15
// (include/linux/kernfs.h). Both spellings, chosen at load time; the
// branch for the absent one is dead code the verifier never reaches.
struct kernfs_node___pre615
{
    struct kernfs_node *parent;
} __attribute__((preserve_access_index));

struct kernfs_node___615
{
    struct kernfs_node *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kn_parent(struct kernfs_node *kn)
{
    if (bpf_core_field_exists(struct kernfs_node___615, __parent))
        return BPF_CORE_READ((struct kernfs_node___615 *)kn, __parent);
    return BPF_CORE_READ((struct kernfs_node___pre615 *)kn, parent);
}

// The name parser runs as a GLOBAL function: the verifier checks a global
// function once, on its own, instead of re-walking its loops for every
// state the caller can be in. Inlined into the 4-level walk, the parser's
// data-dependent loops pushed trace_execve past the verifier's 1M
// instruction budget (E2BIG) on every kernel tried.
//
// All parser state lives in a per-CPU map value; the loop context on the
// stack holds only a pointer to it (bpf_loop accepts nothing but a stack
// pointer as its context). Verifiers before Linux 6.7 check a bpf_loop
// callback as if it ran once, so state kept on the stack was tracked as
// the constants of that single iteration, and the branches on it
// (prev == '-', the UID length and dash count) were removed as dead code:
// at runtime every cgroup name parsed as "not a pod" and the ownership
// gate dropped every syscall. Map value contents are never tracked, so
// nothing is hard-wired. It also keeps the 192-byte name off the stack.
struct kg_parse_state
{
    char n[KG_CG_NAME_BUF];
    int at;
    char prev;
    __u32 s;
    struct kg_uid u;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct kg_parse_state);
} kg_parse_state SEC(".maps");

struct kg_parse_ctx
{
    struct kg_parse_state *p;
};

static long kg_scan_cb(__u64 i, void *ctx)
{
    struct kg_parse_state *p = ((struct kg_parse_ctx *)ctx)->p;
    if (!p)
        return 1;
    return kg_scan_step(p->n, (__u32)i, &p->at, &p->prev);
}

static long kg_uid_cb(__u64 k, void *ctx)
{
    struct kg_parse_state *p = ((struct kg_parse_ctx *)ctx)->p;
    if (!p)
        return 1;
    return kg_uid_step(p->n, p->s, (__u32)k, &p->u);
}

// KG_CG_POD|generation when the kernfs name at `kn_name` (a kernel
// address, passed as a scalar) is a pod-level cgroup's, else 0.
__noinline __u32 kg_name_generation(__u64 kn_name)
{
    __u32 zero = 0;
    struct kg_parse_state *p = bpf_map_lookup_elem(&kg_parse_state, &zero);
    if (!p)
        return 0;
    if (bpf_probe_read_kernel_str(p->n, sizeof(p->n), (const void *)kn_name) < 0)
        return 0;
    struct kg_parse_ctx c = {.p = p};
    p->at = -1;
    p->prev = 0;
    bpf_loop(KG_CG_NAME_SCAN, kg_scan_cb, &c, 0);
    int at = p->at;
    if (at < 0 || at >= KG_CG_NAME_SCAN)
        return 0;
    p->s = (__u32)at;
    kg_uid_init(&p->u);
    bpf_loop(KG_CG_UID_MAX, kg_uid_cb, &c, 0);
    return kg_uid_finish(p->n, p->s, &p->u);
}

// Pod-level cgroup at most this many levels above the task's: the
// container's own cgroup is one below it, and a container managing its own
// sub-cgroups adds a level or two.
#define KG_CG_LEVELS 4

// KG_CG_POD|generation of the pod owning the calling task's cgroup, or 0.
// Cached per cgroup: after the first syscall from a cgroup this is one
// hash lookup.
static __always_inline __u32 task_pod_generation(void)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u32 *cached = bpf_map_lookup_elem(&cgroup_pod_gen, &cgid);
    if (cached)
        return *cached;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    __u32 gen = 0;
    for (int lvl = 0; lvl < KG_CG_LEVELS; lvl++)
    {
        if (!kn)
            break;
        gen = kg_name_generation((__u64)BPF_CORE_READ(kn, name));
        if (gen)
            break;
        kn = kn_parent(kn);
    }
    bpf_map_update_elem(&cgroup_pod_gen, &cgid, &gen, BPF_ANY);
    return gen;
}

// The generation to credit the calling task to, given the netns entry's
// generation, or 0 to drop the syscall:
//   - not in a pod cgroup (a host process in the pod's netns): 0
//   - the netns's own pod (static pods via gen_alias): that generation
//   - a registered hostNetwork pod sharing the node netns: its own
//   - any other pod (a stale entry on a recycled inode): 0
static __always_inline __u32 credit_generation(__u32 netns_gen)
{
    if (!kg_ownership_gate)
        return netns_gen;
    __u32 owner = task_pod_generation();
    if (!(owner & KG_CG_POD))
        return 0;
    __u32 gen = owner & KG_CG_GEN_MASK;
    if (gen == netns_gen)
        return gen;
    __u32 *alias = bpf_map_lookup_elem(&gen_alias, &gen);
    if (alias)
        gen = *alias;
    if (gen == netns_gen)
        return gen;
    if (bpf_map_lookup_elem(&hostnet_gens, &gen))
        return gen;
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

    // A container that started after the controller and is not yet
    // attributed is captured by cgroup, whatever inode_num says about its
    // netns (see capture_pending for why the netns cannot be trusted yet).
    if (capture_pending(net_ns, syscall_id))
        return 0;

    flags = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!flags)
        return 0;

    // Credit only tasks in a pod's own cgroup (see task_pod_generation).
    // This also resolves hostNetwork pods, which share the node's netns,
    // and a stale entry on a recycled inode, whose generation no live
    // task's cgroup carries.
    __u32 gen = credit_generation(KG_GEN_OF(*flags));
    if (!gen)
        return 0;

    // Tier filter first: cheap, and keeps the dedup map from filling
    // with syscalls nobody asked to see.
    if (!tier_allows(KG_TIER_OF(*flags), syscall_id))
        return 0;

    // A container that started before the controller (no pending mark)
    // and is restarted in place still runs runc here: skip its pre-filter
    // setup syscalls too, so the profile does not depend on which path
    // happened to see a restart.
    if (runtime_prefilter_skip(syscall_id))
        return 0;

    // Dedup: only the first sighting per (netns, generation, syscall)
    // is submitted. BPF_NOEXIST fails with -EEXIST when the key is
    // already there, which is exactly the "seen before" signal.
    struct seen_syscall_key seen = {
        .netns = net_ns,
        .generation = gen,
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
    data->generation = gen;
    data->_pad = 0;

    // Submit to userspace
    bpf_ringbuf_submit(data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
