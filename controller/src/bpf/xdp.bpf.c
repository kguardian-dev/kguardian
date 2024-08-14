#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} xdp_events SEC(".maps");

struct data_t {
    __u64 inum;
    __u32 src_ip;
    __u16 syn;
    __u16 ack;
    __u32 ingress_if_index;
};


//  this is xdp
SEC("xdp")
int xdp_trace_packets(struct xdp_md *ctx) {

    struct data_t xdp_data = {};
    struct task_struct *task;
    xdp_data.ingress_if_index = ctx->ingress_ifindex;
  

    // Start of the packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure we can access the Ethernet header
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    // Check if it's an IP packet
    // if (eth->h_proto == bpf_htons("0x0800")) {
        struct iphdr *ip = data + sizeof(*eth);

        // Ensure we can access the IP header
        if (ip + 1 > data_end) {
            return XDP_DROP;
        }

        // struct tcphdr *tcp = data + sizeof(*eth)+ sizeof(*ip);
        struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;        
        }


        if (tcp) {
            __u16 syn = tcp->syn;
            __u16 ack = tcp->ack; 
        // Log the source and destination IP addresses
        // bpf_printk("XDP Packet: src_ip=%x, dst_ip=%x, proto=%x\n",
        //            ip->saddr, ip->daddr, ip->protocol);

            task = (struct task_struct *)bpf_get_current_task();
            __u64 pid_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
            xdp_data.inum = pid_ns;
            xdp_data.src_ip = ip->saddr;
            xdp_data.syn = ack;
            xdp_data.ack = syn;

            bpf_perf_event_output(ctx, &xdp_events, BPF_F_CURRENT_CPU, &xdp_data, sizeof(xdp_data));
        }

    // }
    //  bpf_printk("XDP Packet:\n");

    // Pass the packet to the next step in the processing pipeline
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";