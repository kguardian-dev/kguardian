#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

struct tcp_event_data {
    __u64 inum;
    __u32 saddr;
    __u32 daddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tracept_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u32);
} inode_num SEC(".maps");

/**
    1: TCP_ESTABLISHED
    2: TCP_SYN_SENT
    3: TCP_SYN_RECV
    4: TCP_FIN_WAIT1
    5: TCP_FIN_WAIT2
    6: TCP_TIME_WAIT
    7: TCP_CLOSE
    8: TCP_CLOSE_WAIT
 */

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_connect(struct trace_event_raw_inet_sock_set_state *ctx) {
    struct task_struct *task;
    struct tcp_event_data tcp_event = {};
    task = (struct task_struct *)bpf_get_current_task();
      __u64 pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    u32 *inum  = 0;

    inum = bpf_map_lookup_elem(&inode_num, &pid_ns);
 
    if (inum){

        bpf_printk("%u---%u\n",
                   ctx->oldstate,ctx->newstate);

        tcp_event.inum = pid_ns;

        struct sock *sk = (struct sock *)ctx->skaddr;
 
        __u16 family = ctx->family;

        // IPv4 address handling
        if (family == 2) {
           bpf_probe_read_kernel(&tcp_event.saddr, sizeof(tcp_event.saddr), &sk->__sk_common.skc_rcv_saddr);
           bpf_probe_read_kernel(&tcp_event.daddr, sizeof(tcp_event.daddr), &sk->__sk_common.skc_daddr);
        }

// Egress 
old (1) -> new(4)
//Ingress
old (4) -> new (5)
    // char saddr[28];
    // char daddr[28];
    // struct sockaddr_in *ipv4_addr;

    // ipv4_addr = (struct sockaddr_in *)ctx->saddr;
    // saddr=  ipv4_addr->sin_addr->s_addr;
    // ipv4_addr = (struct sockaddr_in *)ctx->daddr;
    // tcp_event.dst_ip = &ipv4_addr->sin_addr;

     bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &tcp_event, sizeof(tcp_event));
    }
    return 0;    
}


char LICENSE[] SEC("license") = "GPL";