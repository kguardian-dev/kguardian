#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "helper.h"

char LICENSE[] SEC("license") = "GPL";

// TCP connection states (from include/net/tcp_states.h)
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2

// Track outgoing connection attempts.
//
// Addresses are 16 bytes with IPv4 carried v4-mapped (see IPV6_ADDR_LEN
// in helper.h). Field order is chosen so the struct has no implicit
// padding: this is a hash-map key, compared byte-wise, and only *named*
// members are guaranteed zeroed by a designated initialiser.
struct conn_attempt {
    __u64 inum;                  // 0  Network namespace inode
    __u8 saddr[IPV6_ADDR_LEN];   // 8  Source IP (v4-mapped when IPv4)
    __u8 daddr[IPV6_ADDR_LEN];   // 24 Dest IP (v4-mapped when IPv4)
    __u16 sport;                 // 40 Source port
    __u16 dport;                 // 42 Dest port
    __u8 protocol;               // 44 TCP/UDP
    __u8 _pad[3];                // 45 Explicit padding for alignment
};

_Static_assert(sizeof(struct conn_attempt) == 48,
               "conn_attempt must have no implicit padding");

// Connection state tracking
struct conn_state {
    __u64 first_syn_time;    // When first SYN was sent
    __u64 last_syn_time;     // Last SYN retransmission
    __u32 syn_count;         // Number of SYN attempts
    __u8 established;        // 1 if connection succeeded
};

// Wire struct shared with userspace (controller/src/network.rs,
// PolicyDropEvent). The ring-buffer callback in controller/src/bpf.rs
// reinterprets the raw bytes with a pointer cast, so ANY change to field
// order, width or padding here is silent memory corruption unless the
// Rust mirror changes with it. The _Static_asserts below and the layout
// tests in network.rs pin both sides to the same numbers.
struct policy_drop_event {
    __u64 timestamp;             // 0
    __u64 inum;                  // 8
    __u8 saddr[IPV6_ADDR_LEN];   // 16
    __u8 daddr[IPV6_ADDR_LEN];   // 32
    __u16 sport;                 // 48
    __u16 dport;                 // 50
    __u32 syn_retries;           // 52 SYN retransmissions before giving up
    __u8 protocol;               // 56
    __u8 _pad[7];                // 57 explicit: ring-buffer memory is not
                                 //    zeroed on reserve, so unnamed padding
                                 //    would leak kernel bytes to userspace
};

_Static_assert(sizeof(struct policy_drop_event) == 64,
               "policy_drop_event layout changed; update PolicyDropEvent in network.rs");
_Static_assert(__builtin_offsetof(struct policy_drop_event, saddr) == 16, "saddr offset");
_Static_assert(__builtin_offsetof(struct policy_drop_event, daddr) == 32, "daddr offset");
_Static_assert(__builtin_offsetof(struct policy_drop_event, syn_retries) == 52, "syn_retries offset");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn_attempt);
    __type(value, struct conn_state);
} connection_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // 512KB ring buffer. Bumped from 256KB when addresses widened to 16
    // bytes: events grew 24 -> 64 bytes, so the old size held far fewer
    // in-flight events and dropped them under burst.
    __uint(max_entries, 512 * 1024);
} policy_drop_events SEC(".maps");

// Hook into tcp_retransmit_skb to detect SYN retransmissions
// This fires when TCP retransmits a packet (including SYN)
SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(trace_tcp_retransmit, struct sock *sk, struct sk_buff *skb, int segs)
{
    if (!sk)
        return 0;

    // Get network namespace inode
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Read socket info - ports only; addresses come from
    // read_sock_addrs, which relocates the v6 fields properly (helper.h)
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses; also rejects address families we don't track
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // Apply filtering
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Get TCP state - we only care about SYN_SENT state (retransmitting SYN)
    __u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);

    // Only track retransmits during connection attempt phase
    if (state == TCP_SYN_SENT) {
        struct conn_attempt key = {
            .inum = inum,
            .sport = skc.skc_num,
            .dport = bpf_ntohs(skc.skc_dport),
            .protocol = 6, // TCP
        };
        __builtin_memcpy(key.saddr, saddr, IPV6_ADDR_LEN);
        __builtin_memcpy(key.daddr, daddr, IPV6_ADDR_LEN);

        struct conn_state *state_ptr = bpf_map_lookup_elem(&connection_tracking, &key);
        __u64 now = bpf_ktime_get_ns();

        if (!state_ptr) {
            // First SYN retransmission (2nd attempt total)
            struct conn_state new_state = {
                .first_syn_time = now,
                .last_syn_time = now,
                .syn_count = 2,  // Original SYN + this retry
                .established = 0,
            };
            bpf_map_update_elem(&connection_tracking, &key, &new_state, BPF_ANY);
        } else {
            // Subsequent retransmission
            state_ptr->last_syn_time = now;
            state_ptr->syn_count++;

            // After 3 SYN retries (4 total attempts), consider it blocked
            // This is typical Linux behavior before timeout
            if (state_ptr->syn_count >= 4 && !state_ptr->established) {
                // Reserve space in ring buffer
                struct policy_drop_event *evt;
                evt = bpf_ringbuf_reserve(&policy_drop_events, sizeof(*evt), 0);
                if (!evt)
                    return 0;

                // Fill event data
                evt->timestamp = now;
                evt->inum = inum;
                __builtin_memcpy(evt->saddr, key.saddr, IPV6_ADDR_LEN);
                __builtin_memcpy(evt->daddr, key.daddr, IPV6_ADDR_LEN);
                evt->sport = key.sport;
                evt->dport = key.dport;
                evt->protocol = 6;
                evt->syn_retries = state_ptr->syn_count;
                // ring-buffer memory is not zeroed on reserve
                __builtin_memset(evt->_pad, 0, sizeof(evt->_pad));

                // Submit to userspace
                bpf_ringbuf_submit(evt, 0);

                // Mark as reported to avoid duplicates
                state_ptr->established = 1;
            }
        }
    }

    return 0;
}

// Hook into tcp_v4_connect to track initial connection attempts
SEC("fentry/tcp_v4_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (!sk)
        return 0;

    // Get network namespace inode
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Read socket info - ports only; addresses come from read_sock_addrs
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses; also rejects address families we don't track
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // Apply filtering
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Track this connection attempt
    struct conn_attempt key = {
        .inum = inum,
        .sport = skc.skc_num,
        .dport = bpf_ntohs(skc.skc_dport),
        .protocol = 6, // TCP
    };
    __builtin_memcpy(key.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(key.daddr, daddr, IPV6_ADDR_LEN);

    struct conn_state initial_state = {
        .first_syn_time = bpf_ktime_get_ns(),
        .last_syn_time = 0,
        .syn_count = 1,  // Initial SYN
        .established = 0,
    };

    bpf_map_update_elem(&connection_tracking, &key, &initial_state, BPF_ANY);

    return 0;
}

// Hook into tcp_set_state to detect successful connections
SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_state_change, struct sock *sk, int state)
{
    if (!sk)
        return 0;

    // Only process when connection becomes established
    if (state == TCP_ESTABLISHED) {
        // Get network namespace inode
        __u64 inum = 0;
        if (!get_and_validate_inum(sk, &inum))
            return 0;

        // Read socket info - ports only; addresses come from read_sock_addrs
        struct sock_common skc;
        BPF_CORE_READ_INTO(&skc, sk, __sk_common);

        // Resolve addresses; also rejects address families we don't track.
        // The key built here must match the one trace_tcp_connect /
        // trace_tcp_retransmit built byte-for-byte, or an established
        // connection never clears its pending drop record.
        __u8 saddr[IPV6_ADDR_LEN];
        __u8 daddr[IPV6_ADDR_LEN];
        if (!read_sock_addrs(sk, saddr, daddr))
            return 0;

        struct conn_attempt key = {
            .inum = inum,
            .sport = skc.skc_num,
            .dport = bpf_ntohs(skc.skc_dport),
            .protocol = 6,
        };
        __builtin_memcpy(key.saddr, saddr, IPV6_ADDR_LEN);
        __builtin_memcpy(key.daddr, daddr, IPV6_ADDR_LEN);

        // Mark connection as established (don't report as drop)
        struct conn_state *state_ptr = bpf_map_lookup_elem(&connection_tracking, &key);
        if (state_ptr) {
            state_ptr->established = 1;
        }
    }

    return 0;
}

// Track UDP sendmsg to detect repeated send attempts (application-level retries)
SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    // Get network namespace inode
    __u64 inum = 0;
    if (!get_and_validate_inum(sk, &inum))
        return 0;

    // Read socket info - ports only; addresses come from read_sock_addrs
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses; also the family check this path never had
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // Apply filtering
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Track UDP send attempts (useful for detecting patterns)
    struct conn_attempt key = {
        .inum = inum,
        .sport = skc.skc_num,
        .dport = bpf_ntohs(skc.skc_dport),
        .protocol = 17, // UDP
    };
    __builtin_memcpy(key.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(key.daddr, daddr, IPV6_ADDR_LEN);

    struct conn_state *state_ptr = bpf_map_lookup_elem(&connection_tracking, &key);
    __u64 now = bpf_ktime_get_ns();

    if (!state_ptr) {
        struct conn_state new_state = {
            .first_syn_time = now,
            .last_syn_time = now,
            .syn_count = 1,
            .established = 0,
        };
        bpf_map_update_elem(&connection_tracking, &key, &new_state, BPF_ANY);
    } else {
        state_ptr->last_syn_time = now;
        state_ptr->syn_count++;

        // If application retries UDP many times, it might indicate blocking
        // But we rely on netfilter hook for actual drop detection
    }

    return 0;
}