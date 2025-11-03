#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u32);
} allowed_syscalls SEC(".maps");

// Common filtering helper to avoid code duplication
static __always_inline bool should_filter_traffic(__u32 saddr, __u32 daddr)
{
    // Filter same source and destination
    if (saddr == daddr)
        return true;

    // Filter localhost (127.0.0.1) and zero addresses
    if (daddr == bpf_htonl(0x7F000001) || daddr == bpf_htonl(0x00000000))
        return true;

    // Filter if either IP is in ignore list
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