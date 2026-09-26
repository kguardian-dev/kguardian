// Runtime inventory (#1533 P1-2): which binaries each container executes
// and which files it maps executable (shared libraries, the dynamic
// loader). Joined later against image SBOMs, this is the "in use" signal
// for a vulnerable package.
//
// Its own object, so a kernel that refuses anything here costs this
// feature and nothing else (bpf.rs loads it optionally).
//
// Volume is bounded the same way the syscall probe's is: each (cgroup,
// file, kind) is reported once (runtime_seen), so after warm-up a
// container costs one hash lookup per exec or executable mmap and no
// ring-buffer traffic. Only tasks in a pod cgroup reach the dedup.
//
// Deliberately no "is this pod tracked" gate here: the pod watcher learns
// about a pod asynchronously, and gating on it would miss exactly the
// execs that matter most, a container's entrypoint. Userspace drops
// events for pods it does not track (excluded namespaces, opted-out
// pods); the dedup bounds what that costs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "pod_cgroup.h"
// Preemptible fentry program: parse state must be task-local (pod_owner.h).
#define KG_OWNER_TASK_STORAGE 1
#include "pod_owner.h"

#define KG_RT_EXEC 1
#define KG_RT_LIB 2

#define KG_PROT_EXEC 0x4

#define KG_OVERLAYFS_MAGIC 0x794c7630
#define KG_UPPER_UNKNOWN 0
#define KG_UPPER_NO 1
#define KG_UPPER_YES 2

// Path buffer: components are written leaf first, each NUL-terminated,
// starting at offsets below KG_PATH_OFF_MAX; a name is read with at most
// KG_PATH_NAME_MAX bytes, so every write stays inside the buffer.
#define KG_PATH_OFF_MAX 1024
#define KG_PATH_NAME_MAX 256
#define KG_PATH_BUF (KG_PATH_OFF_MAX + KG_PATH_NAME_MAX)
#define KG_PATH_DEPTH 48
#define KG_CONTAINER_NAME 128

// Keep in sync with RuntimeEventData in controller/src/runtime_inventory.rs.
struct runtime_event
{
    __u64 cgroup_id;
    __u64 ino;
    __u32 dev;
    __u32 generation;
    __u32 kind;
    __u32 ncomp;
    __u32 complete;
    __u32 pid;
    // Where the file lives, for drift (a binary the image did not ship):
    // the superblock magic, the link count (0 = deleted, or a memfd) and,
    // on overlayfs, whether the file is in the container's writable upper
    // layer (KG_UPPER_*).
    __u32 fs_magic;
    __u32 nlink;
    __u32 upper;
    // Bytes of `path` in use.
    __u32 path_len;
    // kernfs name of the cgroup directly below the pod-level one: the
    // container's (cri-containerd-<id>.scope, or the bare id).
    char container[KG_CONTAINER_NAME];
    char path[KG_PATH_BUF];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} runtime_events SEC(".maps");

// Events lost because the ring buffer was full. Any increase is a
// coverage gap for every container on the node (a one-off exec that was
// dropped is never seen again); userspace reports it with the heartbeat.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} runtime_drops SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 zero = 0;
    __u64 *drops = bpf_map_lookup_elem(&runtime_drops, &zero);
    if (drops)
        __sync_fetch_and_add(drops, 1);
}

// Scratch for building one event (too big for the 512-byte stack). Task
// storage, not per-CPU: the library probe (fentry) runs preemptible, and
// another task on the same CPU building its own event in a shared per-CPU
// slot would overwrite this one mid-build (a wrong path or container in
// the event). Deleted once the event is out.
struct
{
    __uint(type, KG_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct runtime_event);
} runtime_scratch SEC(".maps");

struct runtime_seen_key
{
    __u64 cgroup_id;
    __u64 ino;
    __u32 dev;
    __u32 kind;
    // The file's state, so a change re-reports it: KG_UPPER_* in the low
    // bits and KG_STATE_UNLINKED. An overlay copy-up (a file of the image
    // overwritten in place) or an exec of an unlinked file keeps the
    // inode but must not stay reported as the image's.
    __u32 state;
    __u32 _pad;
};

#define KG_STATE_UNLINKED (1u << 2)

// Report-once dedup. Kernfs cgroup ids are never reused, so no generation
// is needed in the key; a container restart gets a new cgroup and is
// reported afresh.
// When the LRU is full it evicts the oldest entry; that file is reported
// again on its next use, so a full map costs duplicates, never a lost
// sighting.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct runtime_seen_key);
    __type(value, u8);
} runtime_seen SEC(".maps");

// struct mount is internal to fs/, but in BTF on every supported kernel.
// Only the fields read here.
struct mount___kg
{
    struct mount___kg *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
} __attribute__((preserve_access_index));

static __always_inline struct mount___kg *real_mount(struct vfsmount *vfsmnt)
{
    return (struct mount___kg *)((void *)vfsmnt -
                                 bpf_core_field_offset(struct mount___kg, mnt));
}

// The walk's position. Its counters (bytes used, components, done) live
// in the event, a map value, not here: a pre-6.7 verifier checks the
// callback as if it ran once, and would treat stack-held counters as the
// constants of that iteration and drop the bounds check on them as dead
// code (see pod_owner.h).
struct kg_path_ctx
{
    struct dentry *d;
    struct mount___kg *mnt;
};

// One path component per call: append d's name, or cross to the parent
// mount at a mount root, or stop at the mount namespace root (a mount
// that is its own parent: the container's rootfs after pivot_root).
static long kg_path_step(__u64 i, void *vctx)
{
    struct kg_path_ctx *c = vctx;
    __u32 key = 0;
    struct runtime_event *ev =
        bpf_task_storage_get(&runtime_scratch, bpf_get_current_task_btf(), 0, 0);
    if (!ev)
        return 1;
    // Copy out of the (local, non-kernel) context struct before any CO-RE
    // read: BPF_CORE_READ(c->mnt, ...) would record a relocation against
    // kg_path_ctx itself, which no kernel BTF has.
    struct dentry *d = c->d;
    struct mount___kg *m = c->mnt;
    struct dentry *parent = BPF_CORE_READ(d, d_parent);
    struct dentry *mnt_root = BPF_CORE_READ(m, mnt.mnt_root);

    if (d == mnt_root)
    {
        struct mount___kg *up = BPF_CORE_READ(m, mnt_parent);
        if (up == m || !up)
        {
            ev->complete = 1;
            return 1;
        }
        c->d = BPF_CORE_READ(m, mnt_mountpoint);
        c->mnt = up;
        return 0;
    }
    // A dentry that is its own parent and not a mount root: a filesystem
    // root with nothing above it ("/"), or a pseudo file such as a memfd
    // ("memfd:<name>" on the kernel's internal shmem mount). The pseudo
    // file's name is the whole path; a real root adds nothing.
    bool top = d == parent;

    __u32 off = ev->path_len;
    if (off >= KG_PATH_OFF_MAX)
        return 1;
    off &= KG_PATH_OFF_MAX - 1;
    const unsigned char *name = BPF_CORE_READ(d, d_name.name);
    long n = bpf_probe_read_kernel_str(&ev->path[off], KG_PATH_NAME_MAX, name);
    if (n <= 0)
        return 1;
    if (top)
    {
        if (ev->path[off] != '/')
        {
            ev->path_len = off + (__u32)n;
            ev->ncomp++;
        }
        ev->complete = 1;
        return 1;
    }
    ev->path_len = off + (__u32)n;
    ev->ncomp++;
    c->d = parent;
    return 0;
}

// overlayfs's inode (fs/overlayfs/ovl_entry.h). overlay is usually a
// module, so the type may only be in module BTF, or absent when overlay is
// not loaded; bpf_core_type_exists keeps the read dead code then.
// __upperdentry is set once the file exists in the upper (writable) layer:
// created there, or copied up by a write or metadata change.
struct ovl_inode___kg
{
    struct inode vfs_inode;
    struct dentry *__upperdentry;
} __attribute__((preserve_access_index));

static __always_inline __u32 overlay_upper(struct inode *inode)
{
    if (!bpf_core_type_exists(struct ovl_inode___kg))
        return KG_UPPER_UNKNOWN;
    struct ovl_inode___kg *oi = (struct ovl_inode___kg *)((void *)inode -
        bpf_core_field_offset(struct ovl_inode___kg, vfs_inode));
    struct dentry *upper = BPF_CORE_READ(oi, __upperdentry);
    return upper ? KG_UPPER_YES : KG_UPPER_NO;
}

// Fill ev->container with the kernfs name of the cgroup below the pod's.
// Test hook (VM tests only; never set in production): make the container
// lookup fail as an "unknown" parse would, to exercise the lost-event path.
volatile bool kg_test_container_unknown = false;

// Fill ev->container with the kernfs name of the cgroup below the pod's.
// False when it could not be worked out (a parse that could not run, or
// no container cgroup under the pod): the caller must treat the event as
// lost, not send it without a container.
static __always_inline bool container_cgroup_name(char *out)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    struct kernfs_node *below = 0;
    out[0] = 0;
    if (kg_test_container_unknown)
        return false;
    for (int lvl = 0; lvl < KG_CG_LEVELS; lvl++)
    {
        if (!kn)
            return false;
        __u32 g = kg_name_generation((__u64)BPF_CORE_READ(kn, name));
        if (g == KG_OWNER_UNKNOWN)
            return false;
        if (g & KG_CG_POD)
        {
            if (!below)
                return false;
            return bpf_probe_read_kernel_str(out, KG_CONTAINER_NAME,
                                             BPF_CORE_READ(below, name)) > 1;
        }
        below = kn;
        kn = kn_parent(kn);
    }
    return false;
}

static __always_inline int report_file(struct file *file, __u32 kind)
{
    if (!file)
        return 0;
    __u32 owner = task_pod_generation();
    if (owner == KG_OWNER_UNKNOWN)
    {
        // Could not tell whose it is: a sighting possibly lost.
        count_drop();
        return 0;
    }
    if (!(owner & KG_CG_POD))
        return 0;
    __u32 gen = owner & KG_CG_GEN_MASK;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    __u32 fs_magic = (__u32)BPF_CORE_READ(inode, i_sb, s_magic);
    __u32 nlink = BPF_CORE_READ(inode, i_nlink);
    __u32 upper = KG_UPPER_UNKNOWN;
    if (fs_magic == KG_OVERLAYFS_MAGIC)
        upper = overlay_upper(inode);

    struct runtime_seen_key key = {
        .cgroup_id = bpf_get_current_cgroup_id(),
        .ino = BPF_CORE_READ(inode, i_ino),
        .dev = BPF_CORE_READ(inode, i_sb, s_dev),
        .kind = kind,
        .state = upper | (nlink == 0 ? KG_STATE_UNLINKED : 0),
    };
    __u8 one = 1;
    if (bpf_map_update_elem(&runtime_seen, &key, &one, BPF_NOEXIST) != 0)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    struct runtime_event *ev =
        bpf_task_storage_get(&runtime_scratch, task, 0, KG_LOCAL_STORAGE_GET_F_CREATE);
    if (!ev)
    {
        bpf_map_delete_elem(&runtime_seen, &key);
        count_drop();
        return 0;
    }
    ev->cgroup_id = key.cgroup_id;
    ev->ino = key.ino;
    ev->dev = key.dev;
    ev->generation = gen;
    ev->kind = kind;
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->fs_magic = fs_magic;
    ev->nlink = nlink;
    ev->upper = upper;
    if (!container_cgroup_name(ev->container))
    {
        // Whose container it was is unknown: the sighting is lost. Forget
        // it so the file is reported again on its next use, and count it
        // so coverage is not claimed for this window.
        bpf_map_delete_elem(&runtime_seen, &key);
        count_drop();
        bpf_task_storage_delete(&runtime_scratch, task);
        return 0;
    }

    struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
    struct kg_path_ctx c = {
        .d = BPF_CORE_READ(file, f_path.dentry),
        .mnt = real_mount(vfsmnt),
    };
    ev->path_len = 0;
    ev->ncomp = 0;
    ev->complete = 0;
    bpf_loop(KG_PATH_DEPTH, kg_path_step, &c, 0);

    if (bpf_ringbuf_output(&runtime_events, ev, sizeof(*ev), 0) != 0)
    {
        // Forget the sighting so the next one is reported, not never.
        bpf_map_delete_elem(&runtime_seen, &key);
        count_drop();
    }
    bpf_task_storage_delete(&runtime_scratch, task);
    return 0;
}

// The file a process ends up running after exec (for a script, its
// interpreter).
SEC("tp_btf/sched_process_exec")
int BPF_PROG(trace_runtime_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    return report_file(BPF_CORE_READ(bprm, file), KG_RT_EXEC);
}

// Executable file mappings: shared libraries and the dynamic loader. The
// main executable is mapped through here too; it is skipped, being
// reported as the exec.
SEC("fentry/security_mmap_file")
int BPF_PROG(trace_runtime_mmap, struct file *file, unsigned long prot, unsigned long flags)
{
    if (!file || !(prot & KG_PROT_EXEC))
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct inode *exe = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (exe && exe == BPF_CORE_READ(file, f_inode))
        return 0;
    return report_file(file, KG_RT_LIB);
}

// ---- Capabilities (#1533 P2-7) -------------------------------------------
//
// Every capability check a container's task makes, and whether it was
// granted, from the commoncap check cap_capable (fexit, for the verdict):
// it sees every check security_capable does plus those commoncap makes
// directly (capset's SETPCAP test, xattr and prctl checks), and its
// verdict is the capability bits alone. security_capable is the fallback
// where cap_capable cannot be traced (bpf.rs picks). Counted per
// (container cgroup, capability, verdict) in the kernel; the first
// sighting of each is also sent as an event (which carries the container
// identity), later ones only bump the count userspace reads from the map.
//
// Not counted:
//  - CAP_OPT_NOAUDIT checks (ns_capable_noaudit, has_capability_noaudit):
//    the kernel asking "would this task be privileged?" without the task
//    needing it (e.g. picking a code path). They are probes, not uses.
//  - runc's own setup: runc init runs in the container's cgroup before
//    the container starts and uses privileges the container itself never
//    gets (mount, setuid, ...). Same comm test as the syscall probe.

// include/linux/security.h
#define KG_CAP_OPT_NOAUDIT (1u << 1)

struct cap_seen_key
{
    __u64 cgroup_id;
    __u32 cap;
    __u32 granted;
};

struct cap_seen_val
{
    __u64 count;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cap_seen_key);
    __type(value, struct cap_seen_val);
} cap_seen SEC(".maps");

// Keep in sync with CapEventData in controller/src/runtime_inventory.rs.
struct cap_event
{
    __u64 cgroup_id;
    __u32 generation;
    __u32 cap;
    __u32 granted;
    __u32 pid;
    char container[KG_CONTAINER_NAME];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} cap_events SEC(".maps");

static __always_inline bool is_runc_init(void)
{
    char comm[8] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    return comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c' &&
           comm[4] == ':' && comm[5] == '[';
}

static __always_inline int report_capable(int cap, unsigned int opts, int ret)
{
    if (opts & KG_CAP_OPT_NOAUDIT)
        return 0;
    if (cap < 0 || cap > 63)
        return 0;
    __u32 owner = task_pod_generation();
    if (owner == KG_OWNER_UNKNOWN)
    {
        count_drop();
        return 0;
    }
    if (!(owner & KG_CG_POD))
        return 0;
    if (is_runc_init())
        return 0;

    struct cap_seen_key key = {
        .cgroup_id = bpf_get_current_cgroup_id(),
        .cap = (__u32)cap,
        .granted = ret == 0,
    };
    struct cap_seen_val *seen = bpf_map_lookup_elem(&cap_seen, &key);
    if (seen)
    {
        __sync_fetch_and_add(&seen->count, 1);
        return 0;
    }
    struct cap_seen_val one = {.count = 1};
    if (bpf_map_update_elem(&cap_seen, &key, &one, BPF_NOEXIST) != 0)
    {
        // Another task inserted it first: count this one there.
        seen = bpf_map_lookup_elem(&cap_seen, &key);
        if (seen)
            __sync_fetch_and_add(&seen->count, 1);
        return 0;
    }

    // First sighting: send who it was. On the stack, so preemption cannot
    // mix it with another task's.
    struct cap_event ev = {
        .cgroup_id = key.cgroup_id,
        .generation = owner & KG_CG_GEN_MASK,
        .cap = key.cap,
        .granted = key.granted,
        .pid = bpf_get_current_pid_tgid() >> 32,
    };
    if (!container_cgroup_name(ev.container) ||
        bpf_ringbuf_output(&cap_events, &ev, sizeof(ev), 0) != 0)
    {
        // Lost: forget it so the next check is reported, and count it.
        bpf_map_delete_elem(&cap_seen, &key);
        count_drop();
    }
    return 0;
}

// Fallback hook (see RUNTIME_CAP_SYMBOLS in bpf.rs).
SEC("fexit/security_capable")
int BPF_PROG(trace_runtime_capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts, int ret)
{
    return report_capable(cap, opts, ret);
}

// Preferred hook.
SEC("fexit/cap_capable")
int BPF_PROG(trace_runtime_cap_capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts, int ret)
{
    return report_capable(cap, opts, ret);
}

char LICENSE[] SEC("license") = "GPL";
