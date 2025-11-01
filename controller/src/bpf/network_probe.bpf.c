#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

struct network_event_data
{
    __u64 inum;
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u16 kind; // 2-> Ingress, 1- Egress
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
    __type(key, __u32);
    __type(value, struct sock *);
} sockets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sock *);
} accepted_sockets SEC(".maps");

static __always_inline __u32 *get_user_space_inum_ptr(struct sock *sk, __u64 *key)
{
    __u32 inum = 0;
    __u32 *user_space_inum_ptr = NULL;

    BPF_CORE_READ_INTO(&inum, sk, __sk_common.skc_net.net, ns.inum);
    *key = (__u64)inum;
    user_space_inum_ptr = bpf_map_lookup_elem(&inode_num, key);

    return user_space_inum_ptr;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx)
{
    struct network_event_data event = {};
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);
    if (!user_space_inum_ptr)
        return 0;

    event.inum = key;


    event.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    if (event.daddr == bpf_htonl(0x7F000001) || event.daddr == bpf_htonl(0x00000000))
        return 0;

    // Ignore if IP is in ignore list
    if (bpf_map_lookup_elem(&ignore_ips, &event.saddr) || bpf_map_lookup_elem(&ignore_ips, &event.daddr))
        return 0;

    // Ignore if source and dest IPs are the same
    if (event.saddr == event.daddr)
        return 0;

    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    event.kind = 3;
    event.sport = lport;
    event.dport = bpf_ntohs(dport);

    bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk)
{
    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);

    if (!user_space_inum_ptr)
        return 0;

    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sockets, &tid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&sockets, &tid);
    if (!skpp)
        return 0;

    struct sock *sk = *skpp;

    bpf_map_delete_elem(&sockets, &tid);

    if (!sk || ret)
        return 0; // Ignore failed connections

    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);

    if (!user_space_inum_ptr)
        return 0;

    struct network_event_data tcp_event = {};
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;

    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    sport = __bpf_ntohs(sport);
    dport = __bpf_ntohs(dport);

    // if the source or destination IP is in the ignore list, return
    if (bpf_map_lookup_elem(&ignore_ips, &saddr) || bpf_map_lookup_elem(&ignore_ips, &daddr))
    {
        return 0;
    }

    if (saddr == 0 || daddr == 0)
    {
        bpf_printk("Warning: Source or destination address is 0\n");
        return 0;
    }

    // Ignore if source and destination IP are the same
    if (saddr == daddr)
    {
        return 0;
    }

    tcp_event.saddr = saddr;
    tcp_event.daddr = daddr;
    tcp_event.sport = sport;
    tcp_event.dport = dport;
    tcp_event.inum = key;
    tcp_event.kind = 1; // egress

    // bpf_printk("TCP Connect (ret): Src %pI4:%d -> Dst %pI4:%d\n", &saddr, sport, &daddr, dport);
    bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &tcp_event, sizeof(tcp_event));

    return 0;
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(tcp_accept_entry, struct sock *sk)
{
    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);

    if (!user_space_inum_ptr)
        return 0;

    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&accepted_sockets, &tid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(tcp_accept_exit, struct sock *new_sk)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&accepted_sockets, &tid);
    if (!skpp)
        return 0;

    struct sock *sk = *skpp;
    bpf_map_delete_elem(&accepted_sockets, &tid); // Cleanup

    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);

    if (!user_space_inum_ptr)
        return 0;

    if (!new_sk)
        return 0; // Failed accept

    struct network_event_data accept_event = {};
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;

    BPF_CORE_READ_INTO(&saddr, new_sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, new_sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&sport, new_sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, new_sk, __sk_common.skc_dport);

    // if the source or destination IP is in the ignore list, return
    if (bpf_map_lookup_elem(&ignore_ips, &saddr) || bpf_map_lookup_elem(&ignore_ips, &daddr))
    {
        return 0;
    }

    // Ignore if source and destination IP are the same
    if (saddr == daddr)
    {
        return 0;
    }
    // Convert ports to host byte order
    dport = __bpf_ntohs(dport);

    accept_event.saddr = saddr;
    accept_event.daddr = daddr;
    accept_event.sport = sport;
    accept_event.dport = dport;
    accept_event.inum = key;
    accept_event.kind = 2; // Ingress

    // bpf_printk("TCP Accept: Src %pI4:%d -> Dst %pI4:%d\n", &saddr, sport, &daddr, dport);
    bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &accept_event, sizeof(accept_event));

    return 0;
}

char _license[] SEC("license") = "GPL";
