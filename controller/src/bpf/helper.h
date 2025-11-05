#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Use LRU_HASH for automatic eviction of stale entries
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u32);
} inode_num SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} ignore_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u32);
} allowed_syscalls SEC(".maps");

// Common filtering helper to avoid code duplication
// Optimized to check cheap conditions first before map lookups
static __always_inline bool should_filter_traffic(__u32 saddr, __u32 daddr)
{
    // Fast path: check cheap conditions first (no map lookups)

    // Filter same source and destination
    if (saddr == daddr)
        return true;

    // Filter localhost (127.0.0.1) - 0x7F000001 in network byte order is 0x0100007F
    __u32 localhost = 0x0100007F;
    if (saddr == localhost || daddr == localhost)
        return true;

    // Filter zero addresses
    if (saddr == 0 || daddr == 0)
        return true;

    // Slow path: map lookups only if cheap checks passed
    // Check ignore list (typically empty or small, so lookups are rare)
    if (bpf_map_lookup_elem(&ignore_ips, &saddr))
        return true;

    if (bpf_map_lookup_elem(&ignore_ips, &daddr))
        return true;

    return false;
}

// Helper to get user space inode and validate it exists
static __always_inline bool get_and_validate_inum(struct sock *sk, __u64 *inum_out)
{
    if (!sk)
        return false;

    __u32 net_ns_inum = 0;
    BPF_CORE_READ_INTO(&net_ns_inum, sk, __sk_common.skc_net.net, ns.inum);

    __u64 key = (__u64)net_ns_inum;
    __u32 *user_space_inum_ptr = bpf_map_lookup_elem(&inode_num, &key);

    if (!user_space_inum_ptr)
        return false;

    *inum_out = key;
    return true;
}