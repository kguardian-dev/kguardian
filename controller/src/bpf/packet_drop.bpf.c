#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "helper.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline __u16 ntohs_manual(__u16 val)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(val);
#else
    return val;
#endif
}

struct drop_event {
    __u64 timestamp;
    __u64 inum;
    __u32 saddr;          // Source IP
    __u32 daddr;          // Dest IP
    __u16 sport;          // Source port
    __u16 dport;          // Dest port
    __u8 protocol;        // TCP/UDP/etc
    __u64 drop_location;  // Kernel function that dropped packet
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} drop_events SEC(".maps");

// Helper to read TCP header
static __always_inline int read_tcp_ports(unsigned char *head,
                                          __u16 transport_header,
                                          __u16 *sport, 
                                          __u16 *dport)
{
    struct tcphdr tcp;
    if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) != 0)
        return -1;
    
    // Read the port values and convert from network to host byte order
    *sport = ntohs_manual(tcp.source);
    *dport = ntohs_manual(tcp.dest);
    return 0;
}

// Helper to read UDP header
static __always_inline int read_udp_ports(unsigned char *head,
                                          __u16 transport_header,
                                          __u16 *sport,
                                          __u16 *dport)
{
    struct udphdr udp;
    if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) != 0)
        return -1;
    
    // Read the port values and convert from network to host byte order
    *sport = ntohs_manual(udp.source);
    *dport = ntohs_manual(udp.dest);
    return 0;
}

// Main tracepoint for packet drops
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

     u32 *exists = bpf_map_lookup_elem(&inode_num, &net_ns);
    if (!exists)
       return 0;
    
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    void *location = (void *)ctx->location;
    
    if (!skb)
        return 0;
    
    struct drop_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.drop_location = (__u64)location;
     
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    
    // Check if network_header is set (0xFFFF means not set)
    if (network_header == 0xFFFF) {
        return 0;
    }
    
    // Read IP header
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) != 0)
        return 0;
    
    // Only process IPv4
    if (ip.version != 4)
        return 0;

   // Check if destination is in 127.0.0.0/8 (loopback) range
    __u32 daddr = ntohs_manual(ip.daddr);  // Convert to host byte order
    if ((daddr & 0xFF000000) == 0x7F000000)  // Check if first byte is 127
        return 0;

    // Also ignore 0.0.0.0
    if (ip.daddr == 0)
        return 0;

    // Ignore if IP is in ignore list
    if (bpf_map_lookup_elem(&ignore_ips, &ip.saddr) || bpf_map_lookup_elem(&ignore_ips, &ip.daddr))
        return 0;

    // Ignore if source and dest IPs are the same
    if (ip.saddr == ip.daddr)
        return 0;
    
    evt.saddr = ip.saddr;
    evt.daddr = ip.daddr;
    evt.protocol = ip.protocol;
    evt.inum = net_ns;
    
    // Check if transport_header is set
    if (transport_header != 0xFFFF) {
        // Read transport layer ports
        if (ip.protocol == IPPROTO_TCP) {
            read_tcp_ports(head, transport_header, &evt.sport, &evt.dport);
        } else if (ip.protocol == IPPROTO_UDP) {
            read_udp_ports(head, transport_header, &evt.sport, &evt.dport);
        }
    }
    
    bpf_perf_event_output(ctx, &drop_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}