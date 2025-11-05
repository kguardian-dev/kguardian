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

// Track outgoing connection attempts
struct conn_attempt {
    __u64 inum;           // Network namespace inode
    __u32 saddr;          // Source IP
    __u32 daddr;          // Dest IP
    __u16 sport;          // Source port
    __u16 dport;          // Dest port
    __u8 protocol;        // TCP/UDP
    __u8 _pad;            // Explicit padding for alignment
};

// Connection state tracking
struct conn_state {
    __u64 first_syn_time;    // When first SYN was sent
    __u64 last_syn_time;     // Last SYN retransmission
    __u32 syn_count;         // Number of SYN attempts
    __u8 established;        // 1 if connection succeeded
};

struct policy_drop_event {
    __u64 timestamp;
    __u64 inum;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 _pad;
    __u32 syn_retries;       // Number of SYN retransmissions before giving up
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn_attempt);
    __type(value, struct conn_state);
} connection_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
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

    // Read socket info
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Apply filtering
    if (should_filter_traffic(skc.skc_rcv_saddr, skc.skc_daddr))
        return 0;

    // Get TCP state - we only care about SYN_SENT state (retransmitting SYN)
    __u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);

    // Only track retransmits during connection attempt phase
    if (state == TCP_SYN_SENT) {
        struct conn_attempt key = {
            .inum = inum,
            .saddr = skc.skc_rcv_saddr,
            .daddr = skc.skc_daddr,
            .sport = skc.skc_num,
            .dport = bpf_ntohs(skc.skc_dport),
            .protocol = 6, // TCP
        };

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
                evt->saddr = key.saddr;
                evt->daddr = key.daddr;
                evt->sport = key.sport;
                evt->dport = key.dport;
                evt->protocol = 6;
                evt->syn_retries = state_ptr->syn_count;

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

    // Read socket info
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Apply filtering
    if (should_filter_traffic(skc.skc_rcv_saddr, skc.skc_daddr))
        return 0;

    // Track this connection attempt
    struct conn_attempt key = {
        .inum = inum,
        .saddr = skc.skc_rcv_saddr,
        .daddr = skc.skc_daddr,
        .sport = skc.skc_num,
        .dport = bpf_ntohs(skc.skc_dport),
        .protocol = 6, // TCP
    };

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

        // Read socket info
        struct sock_common skc;
        BPF_CORE_READ_INTO(&skc, sk, __sk_common);

        struct conn_attempt key = {
            .inum = inum,
            .saddr = skc.skc_rcv_saddr,
            .daddr = skc.skc_daddr,
            .sport = skc.skc_num,
            .dport = bpf_ntohs(skc.skc_dport),
            .protocol = 6,
        };

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

    // Read socket info
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Apply filtering
    if (should_filter_traffic(skc.skc_rcv_saddr, skc.skc_daddr))
        return 0;

    // Track UDP send attempts (useful for detecting patterns)
    struct conn_attempt key = {
        .inum = inum,
        .saddr = skc.skc_rcv_saddr,
        .daddr = skc.skc_daddr,
        .sport = skc.skc_num,
        .dport = bpf_ntohs(skc.skc_dport),
        .protocol = 17, // UDP
    };

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