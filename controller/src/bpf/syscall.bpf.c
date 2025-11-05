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

struct data_t
{
    __u64 inum;
    __u64 sysnbr;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    u32 *inum = 0;

    task = (struct task_struct *)bpf_get_current_task();
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // Early exit if not in tracked namespace
    inum = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!inum)
        return 0;

    // Filter syscalls using allowlist if populated
    // If allowlist is empty (no entries), trace all syscalls (backward compatible)
    u32 syscall_id = (__u32)ctx->id;
    u32 *allowed = bpf_map_lookup_elem(&allowed_syscalls, &syscall_id);

    // If allowlist has entries, only trace allowed syscalls
    // Check if map is populated by testing a known syscall (0)
    u32 zero = 0;
    u32 *test = bpf_map_lookup_elem(&allowed_syscalls, &zero);

    // If allowlist is populated (test returns non-NULL) but current syscall not found, skip
    if (test && !allowed)
        return 0;

    // Reserve space in ring buffer
    struct data_t *data;
    data = bpf_ringbuf_reserve(&syscall_events, sizeof(*data), 0);
    if (!data)
        return 0; // Buffer full, drop event

    // Fill event data
    data->sysnbr = ctx->id;
    data->inum = net_ns;

    // Submit to userspace
    bpf_ringbuf_submit(data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
