#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>




struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct data_t {
    __u32 pid;
    __u64 inum;
    __u64 sysnbr;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
  
    task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

if (pid_ns == 4026533546 ) {
    data.sysnbr = ctx->id;
    data.inum = pid_ns;
    // For perf event array:
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
}

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

