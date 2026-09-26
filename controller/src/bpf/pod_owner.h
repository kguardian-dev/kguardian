// Which pod owns the calling task, from its cgroup (shared by the syscall
// and runtime-inventory objects; each object gets its own cache map).
//
// The pod-level cgroup's kernfs name carries the pod UID (see
// pod_cgroup.h); its generation is the same 28-bit hash userspace gives
// the pod's inode_num entry (pod_flags::generation_for_uid).
//
// Include after vmlinux.h, bpf_helpers.h, bpf_core_read.h and
// pod_cgroup.h.

#ifndef KG_POD_OWNER_H
#define KG_POD_OWNER_H

// Task storage (Linux 5.11) is newer than the bundled vmlinux.h, so its
// UAPI values are spelled out: enum bpf_map_type BPF_MAP_TYPE_TASK_STORAGE
// and BPF_LOCAL_STORAGE_GET_F_CREATE (include/uapi/linux/bpf.h).
#define KG_MAP_TYPE_TASK_STORAGE 29
#define KG_LOCAL_STORAGE_GET_F_CREATE 1

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
// All parser state lives in a map value, and the loop context on the
// stack holds only a pointer to it (bpf_loop takes a stack pointer and
// nothing else: "R3 type=map_value expected=fp"). Two reasons:
//  - Verifiers before Linux 6.7 check a bpf_loop callback as if it ran
//    once. State kept on the stack is tracked as the constants of that
//    one iteration, and branches on it (prev == '-', the UID length and
//    dash count) are hard-wired as dead code, so at runtime every name
//    parsed as "not a pod" (seen on 6.1). Map value contents are never
//    tracked, so nothing is hard-wired.
//  - It keeps the 192-byte name off the stack (the combined stack of the
//    caller and this global function is capped at 512 bytes).
//
// Which map, per object (each object has its own copy; none is shared):
//  - Default, per-CPU (the syscall object): its classic tracepoint runs
//    with preemption disabled, so nothing else runs on the CPU mid-parse,
//    and the lookup cannot fail. This is #1685's proven design.
//  - KG_OWNER_TASK_STORAGE (the runtime inventory object): its library
//    probe (fentry) runs preemptible, so another task on the same CPU
//    could run the parser mid-parse and clobber a per-CPU slot, and the
//    wrong answer would be cached for the cgroup. Task storage is never
//    touched by another task; a use the helper refuses (nested, busy,
//    allocation failure) returns KG_OWNER_UNKNOWN, which is never cached
//    and which the runtime probe counts as a lost event. The entry is
//    deleted after each parse.
struct kg_parse_state
{
    char n[KG_CG_NAME_BUF];
    int at;
    char prev;
    __u32 s;
    struct kg_uid u;
};

#ifdef KG_OWNER_TASK_STORAGE
struct
{
    __uint(type, KG_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kg_parse_state);
} kg_parse_state SEC(".maps");
#else
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct kg_parse_state);
} kg_parse_state SEC(".maps");
#endif

// The parse could not run: not an answer, never cached.
#define KG_OWNER_UNKNOWN (1u << 30)

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
// address, passed as a scalar) is a pod-level cgroup's, 0 when it is not,
// KG_OWNER_UNKNOWN when the parse could not run.
__noinline __u32 kg_name_generation(__u64 kn_name)
{
#ifdef KG_OWNER_TASK_STORAGE
    struct task_struct *task = bpf_get_current_task_btf();
    struct kg_parse_state *p = bpf_task_storage_get(&kg_parse_state, task, 0,
                                                    KG_LOCAL_STORAGE_GET_F_CREATE);
#else
    __u32 zero = 0;
    struct kg_parse_state *p = bpf_map_lookup_elem(&kg_parse_state, &zero);
#endif
    if (!p)
        return KG_OWNER_UNKNOWN;
    __u32 gen = 0;
    if (bpf_probe_read_kernel_str(p->n, sizeof(p->n), (const void *)kn_name) < 0)
        goto out;
    struct kg_parse_ctx c = {.p = p};
    p->at = -1;
    p->prev = 0;
    bpf_loop(KG_CG_NAME_SCAN, kg_scan_cb, &c, 0);
    int at = p->at;
    if (at < 0 || at >= KG_CG_NAME_SCAN)
        goto out;
    p->s = (__u32)at;
    kg_uid_init(&p->u);
    bpf_loop(KG_CG_UID_MAX, kg_uid_cb, &c, 0);
    gen = kg_uid_finish(p->n, p->s, &p->u);
out:
#ifdef KG_OWNER_TASK_STORAGE
    bpf_task_storage_delete(&kg_parse_state, task);
#endif
    return gen;
}

// Pod-level cgroup at most this many levels above the task's: the
// container's own cgroup is one below it, and a container managing its own
// sub-cgroups adds a level or two.
#define KG_CG_LEVELS 4

// KG_CG_POD|generation of the pod owning the calling task's cgroup, 0 when
// it is not a pod's, or KG_OWNER_UNKNOWN (not cached) when it could not be
// worked out.
// Cached per cgroup: after the first syscall from a cgroup this is one
// hash lookup.
static __always_inline __u32 task_pod_generation_of(struct task_struct *task)
{
    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    // The cgroup id bpf_get_current_cgroup_id() returns for the task.
    __u64 cgid = BPF_CORE_READ(kn, id);
    __u32 *cached = bpf_map_lookup_elem(&cgroup_pod_gen, &cgid);
    if (cached)
        return *cached;

    __u32 gen = 0;
    for (int lvl = 0; lvl < KG_CG_LEVELS; lvl++)
    {
        if (!kn)
            break;
        gen = kg_name_generation((__u64)BPF_CORE_READ(kn, name));
        // Could not parse: answer "unknown" and cache nothing, so the
        // next call tries again instead of inheriting a wrong answer.
        if (gen == KG_OWNER_UNKNOWN)
            return KG_OWNER_UNKNOWN;
        if (gen)
            break;
        kn = kn_parent(kn);
    }
    bpf_map_update_elem(&cgroup_pod_gen, &cgid, &gen, BPF_ANY);
    return gen;
}

static __always_inline __u32 task_pod_generation(void)
{
    return task_pod_generation_of((struct task_struct *)bpf_get_current_task());
}

#endif
