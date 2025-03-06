#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

struct network_event_data
{
    __u64 inum;
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u16 old_state;
    __u16 new_state;
    __u16 kind; // 1-> Ingress, 2- Egress
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tracept_events SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u32);
} inode_num SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} ignore_ips SEC(".maps");

/**
    1: TCP_ESTABLISHED
    2: TCP_SYN_SENT
    3: TCP_SYN_RECV
    4: TCP_FIN_WAIT1
    5: TCP_FIN_WAIT2
    6: TCP_TIME_WAIT
    7: TCP_CLOSE
    8: TCP_CLOSE_WAIT
    https://brendangregg.com/blog/2018-03-22/tcp-tracepoints.html
 */

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct task_struct *task;
    struct network_event_data tcp_event = {};
    task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    u32 *inum = 0;

    tcp_event.kind = 0;

    inum = bpf_map_lookup_elem(&inode_num, &pid_ns);

    if (inum)
    {
        bpf_printk("%u---%u\n",
                   ctx->oldstate, ctx->newstate);
        tcp_event.inum = pid_ns;
        struct sock *sk = (struct sock *)ctx->skaddr;
        __u16 family = ctx->family;
        __u16 old_state = ctx->oldstate;
        __u16 new_state = ctx->newstate;
         u16 lport, dport;

        // IPv4 address handling
        if (family == 2)
        
        {
            bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
            bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
            bpf_probe_read_kernel(&tcp_event.saddr, sizeof(tcp_event.saddr), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&tcp_event.daddr, sizeof(tcp_event.daddr), &sk->__sk_common.skc_daddr);

            // Check for loopback destination (127.0.0.1 in network byte order)
            if (tcp_event.daddr == bpf_htonl(0x7F000001)) {
                return 0;
            }

            // if the source or destination IP is in the ignore list, return
            if (bpf_map_lookup_elem(&ignore_ips, &tcp_event.saddr) || bpf_map_lookup_elem(&ignore_ips, &tcp_event.daddr)) {
                return 0;
            }


            // Ignore if source and destination IP are the same
            if (tcp_event.saddr == tcp_event.daddr) {
                return 0;
            }

            tcp_event.sport = lport;
            tcp_event.dport = bpf_ntohs(dport);
            tcp_event.old_state = old_state;
            tcp_event.new_state = new_state;
         
            if ((old_state == 1) && (new_state == 4))
            {
                // egress
                tcp_event.kind = 2;
            }
            else if ((old_state == 8) && (new_state == 9))
            {
                // ingress
                tcp_event.kind = 1;
            };
        }

        if ((tcp_event.kind == 1) || (tcp_event.kind == 2))
        {
            bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &tcp_event, sizeof(tcp_event));
        }
    }
    return 0;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {


     struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    u32 *inum = 0;
    inum = bpf_map_lookup_elem(&inode_num, &pid_ns);
     u16 lport, dport;

    if (inum)
    {
        struct network_event_data event = {};
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        event.inum = pid_ns;
        bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
        if (event.daddr == bpf_htonl(0x7F000001) || event.daddr == bpf_htonl(0x00000000)) {
            return 0;   
        }


        // if the source or destination IP is in the ignore list, return
        if (bpf_map_lookup_elem(&ignore_ips, &event.saddr) || bpf_map_lookup_elem(&ignore_ips, &event.daddr)) {
            return 0;
        }


        // Ignore if source and destination IP are the same
        if (event.saddr == event.daddr) {
            return 0;
        }

        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        event.kind = 3;
        event.sport = lport;
        event.dport = bpf_ntohs(dport);
        bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
