#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"

// Wire struct shared with userspace (controller/src/network.rs,
// NetworkEventData). The ring-buffer callback in controller/src/bpf.rs
// reinterprets the raw bytes with a pointer cast, so ANY change to
// field order, width or padding here is silent memory corruption unless
// the Rust mirror changes with it. The _Static_asserts below and the
// layout tests in network.rs pin both sides to the same numbers.
//
// Addresses are 16 bytes, IPv4 carried v4-mapped — see IPV6_ADDR_LEN in
// helper.h. Fields are ordered so the struct has no implicit padding;
// `_pad` is explicit and named so designated initialisers zero it
// (unnamed padding bytes are not guaranteed zeroed, and would leak
// uninitialised ring-buffer memory to userspace).
struct network_event_data
{
    __u64 inum;                  // 0
    __u8 saddr[IPV6_ADDR_LEN];   // 8
    __u8 daddr[IPV6_ADDR_LEN];   // 24
    __u16 sport;                 // 40
    __u16 dport;                 // 42
    __u16 kind;                  // 44 - 2-> Ingress, 1- Egress, 3-> UDP
    __u16 _pad;                  // 46
};

_Static_assert(sizeof(struct network_event_data) == 48,
               "network_event_data layout changed; update NetworkEventData in network.rs");
_Static_assert(__builtin_offsetof(struct network_event_data, saddr) == 8, "saddr offset");
_Static_assert(__builtin_offsetof(struct network_event_data, daddr) == 24, "daddr offset");
_Static_assert(__builtin_offsetof(struct network_event_data, kind) == 44, "kind offset");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // 512KB ring buffer. Bumped from 256KB when addresses widened to 16
    // bytes: events doubled 24 -> 48 bytes, so the old size held half as
    // many in-flight events and dropped them under burst.
    __uint(max_entries, 512 * 1024);
} network_events SEC(".maps");

// Connection tracking to reduce duplicate events
// Uses 4-tuple (no source port) to handle ephemeral port rotation
struct conn_key {
    __u64 inum;                  // Network namespace inode
    __u8 saddr[IPV6_ADDR_LEN];   // Source IP (v4-mapped when IPv4)
    __u8 daddr[IPV6_ADDR_LEN];   // Destination IP (v4-mapped when IPv4)
    __u16 dport;                 // Destination port
    __u8 protocol;               // 1=TCP, 2=UDP
    __u8 direction;              // 1=Egress, 2=Ingress
    __u32 _pad;                  // Explicit tail padding: hash map keys are
                                 // compared byte-wise, and only *named*
                                 // members are guaranteed zeroed by a
                                 // designated initialiser.
    // NOTE: sport (source port) intentionally omitted to handle ephemeral ports
};

_Static_assert(sizeof(struct conn_key) == 48, "conn_key must have no implicit padding");

struct conn_state {
    __u64 first_seen;
    __u64 last_seen;
    __u32 event_count;
};

// LRU map automatically evicts old connections
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // Track up to 64K active connections
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} connections SEC(".maps");

// Helper to check if this is a new connection
static __always_inline bool is_new_connection(struct conn_key *key)
{
    struct conn_state *state = bpf_map_lookup_elem(&connections, key);
    __u64 now = bpf_ktime_get_ns();

    if (!state) {
        // New connection - add to map
        struct conn_state new_state = {
            .first_seen = now,
            .last_seen = now,
            .event_count = 1,
        };
        bpf_map_update_elem(&connections, key, &new_state, BPF_ANY);
        return true;
    }

    // Existing connection - update timestamps
    state->last_seen = now;
    state->event_count++;

    // Don't send duplicate event
    return false;
}

// Context for TCP connect/accept kprobe/kretprobe pairs
struct tcp_connect_ctx {
    struct sock *sk;
    __u64 inum;
};

// Use LRU map to automatically evict stale entries if thread dies
// Use PER_CPU to eliminate lock contention on multi-core systems
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct tcp_connect_ctx);
} tcp_ctx SEC(".maps");

// Shared body for the two UDP egress entry points below.
//
// udp_sendmsg only ever sees AF_INET sockets plus the v4-mapped sends
// udpv6_sendmsg delegates back to it; native IPv6 UDP — most
// importantly a DNS query to an IPv6 CoreDNS clusterIP — goes through
// udpv6_sendmsg and never reaches the v4 hook. Both hooks funnel here.
//
// skip_v4_mapped is set by the v6 hook: a v4-mapped destination is
// about to be handed to udp_sendmsg by the kernel, where the v4 hook
// records it, so skipping here keeps each send tracked exactly once.
static __always_inline int handle_udp_send(struct sock *sk, bool skip_v4_mapped)
{

    // Validate socket and get inode - single lookup
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Read socket common structure once (batch read) - ports only; the
    // addresses come from read_sock_addrs, which relocates the v6 fields
    // properly. See helper.h.
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses and reject unsupported families. This path had
    // NO family check before IPv6 support: an AF_INET6 socket leaves
    // skc_rcv_saddr/skc_daddr zeroed, so its traffic was silently
    // discarded by the zero-address filter rather than deliberately.
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // See the contract above: the v6 entry point leaves v4-mapped sends
    // to the v4 hook the kernel is about to invoke.
    if (skip_v4_mapped && addr_is_v4_mapped(daddr))
        return 0;

    // Apply common filtering helper
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Check if this is a new connection (reduces duplicate events by 80-90%)
    // Uses 4-tuple to handle ephemeral source port rotation
    struct conn_key conn = {
        .inum = inum,
        .dport = bpf_ntohs(skc.skc_dport),
        .protocol = 2, // UDP
        .direction = 1, // Egress
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (!is_new_connection(&conn))
        return 0; // Existing connection, skip duplicate event

    // Reserve space in ring buffer
    struct network_event_data *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0; // Buffer full, drop event

    // Fill event data
    event->inum = inum;
    __builtin_memcpy(event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(event->daddr, daddr, IPV6_ADDR_LEN);
    event->sport = skc.skc_num;
    event->dport = bpf_ntohs(skc.skc_dport);
    event->kind = 3; // UDP
    event->_pad = 0; // ring-buffer memory is not zeroed on reserve

    // Submit to userspace
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// Use fentry instead of kprobe for better performance (lower overhead)
SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_send(sk, /* skip_v4_mapped = */ false);
}

// Twin entry point for native IPv6 UDP. Without it, AF_INET6 UDP egress
// produced zero events and generated policies silently omitted DNS on
// IPv6-primary clusters. Autoload is turned off in bpf.rs when the
// running kernel has no udpv6_sendmsg (CONFIG_IPV6=n, or the ipv6
// module not loaded) so the controller still starts there.
SEC("fentry/udpv6_sendmsg")
int BPF_PROG(trace_udpv6_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_send(sk, /* skip_v4_mapped = */ true);
}

// Hook into tcp_set_state to detect ESTABLISHED connections (outbound)
// This ensures we only record successful connections, not failed attempts
SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_state_change, struct sock *sk, int state)
{
    if (!sk)
        return 0;

    // TCP_ESTABLISHED = 1 - only record when connection succeeds
    if (state != 1)
        return 0;

    // Read socket common structure once (batch read) for the ports
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses; also acts as the family check that used to be
    // an explicit `skc_family != AF_INET` bail here (which is what made
    // IPv6 flows invisible).
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // Get network namespace inode
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Apply common filtering helper
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Determine direction: if the source address is our pod IP, it's egress
    // For established connections from tcp_set_state, we need to determine direction
    // We'll consider it egress if skc_num (local port) is ephemeral (>1024)
    __u16 sport = skc.skc_num;
    __u16 dport = bpf_ntohs(skc.skc_dport);

    // Assume egress if local port > 1024 (ephemeral), otherwise ingress
    // This is a heuristic - most client connections use ephemeral ports
    __u8 direction = (sport > 1024) ? 1 : 2; // 1=Egress, 2=Ingress

    // Check if this is a new connection (reduces duplicate events)
    struct conn_key conn = {
        .inum = inum,
        .dport = dport,
        .protocol = 1, // TCP
        .direction = direction,
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (!is_new_connection(&conn))
        return 0; // Existing connection, skip duplicate event

    // Reserve space in ring buffer
    struct network_event_data *tcp_event;
    tcp_event = bpf_ringbuf_reserve(&network_events, sizeof(*tcp_event), 0);
    if (!tcp_event)
        return 0; // Buffer full, drop event

    // Fill event data
    tcp_event->inum = inum;
    __builtin_memcpy(tcp_event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(tcp_event->daddr, daddr, IPV6_ADDR_LEN);
    tcp_event->sport = sport;
    tcp_event->dport = dport;
    tcp_event->kind = direction; // 1=Egress or 2=Ingress
    tcp_event->_pad = 0;

    // Submit to userspace
    bpf_ringbuf_submit(tcp_event, 0);

    return 0;
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(tcp_accept_entry, struct sock *sk)
{
    // Early validation - only store context if socket is in tracked namespace
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Store both listening socket and inum for kretprobe
    // Note: We store the listening socket's inum, the accepted socket comes from kretprobe
    struct tcp_connect_ctx ctx_data = {
        .sk = NULL, // Will use new_sk from kretprobe
        .inum = inum,
    };

    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_ctx, &tid, &ctx_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(tcp_accept_exit, struct sock *new_sk)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct tcp_connect_ctx *ctx_data = bpf_map_lookup_elem(&tcp_ctx, &tid);

    // Always cleanup
    if (!ctx_data)
        return 0;

    __u64 inum = ctx_data->inum;
    bpf_map_delete_elem(&tcp_ctx, &tid);

    // Check for failed accept
    if (!new_sk)
        return 0;

    // Read socket common structure once (batch read) for the ports
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, new_sk, __sk_common);

    // Resolve addresses and reject unsupported families. Like
    // udp_sendmsg, this path had no family check before IPv6 support.
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(new_sk, saddr, daddr))
        return 0;

    // Apply common filtering helper
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Check if this is a new connection (reduces duplicate events by 80-90%)
    // Uses 4-tuple to handle ephemeral source port rotation
    __u16 dport = __bpf_ntohs(skc.skc_dport);

    struct conn_key conn = {
        .inum = inum,
        .dport = dport,
        .protocol = 1, // TCP
        .direction = 2, // Ingress
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (!is_new_connection(&conn))
        return 0; // Existing connection, skip duplicate event

    // Reserve space in ring buffer
    struct network_event_data *accept_event;
    accept_event = bpf_ringbuf_reserve(&network_events, sizeof(*accept_event), 0);
    if (!accept_event)
        return 0; // Buffer full, drop event

    // Fill event data
    accept_event->inum = inum;
    __builtin_memcpy(accept_event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(accept_event->daddr, daddr, IPV6_ADDR_LEN);
    accept_event->sport = skc.skc_num;
    accept_event->dport = dport;
    accept_event->kind = 2; // TCP Ingress
    accept_event->_pad = 0;

    // Submit to userspace
    bpf_ringbuf_submit(accept_event, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
