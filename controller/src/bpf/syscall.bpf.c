#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} syscall_events SEC(".maps");

struct data_t
{
    __u64 inum;
    __u64 sysnbr;
};


SEC("tracepoint/raw_syscalls/sys_enter")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    u32 *inum = 0;

    task = (struct task_struct *)bpf_get_current_task();
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    inum = bpf_map_lookup_elem(&inode_num, &net_ns);

    if (inum)
    {
        data.sysnbr = ctx->id;
        data.inum = net_ns;
        // For perf event array:
        bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
