#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Address families we track. Anything else (AF_UNIX, AF_NETLINK, ...)
// is dropped by read_sock_addrs below.
#define AF_INET  2
#define AF_INET6 10

// Every address on the wire between these probes and userspace is a
// fixed 16 bytes. IPv4 is carried v4-mapped (::ffff:a.b.c.d) inside
// those 16 bytes, so the kernel side has exactly ONE code path and one
// representation — there is no family discriminator in any event or map
// key. Userspace (controller/src/network.rs, wire_addr_to_ip) un-maps
// it back to a real Ipv4Addr exactly once. Do not add a second un-map
// anywhere else: the pod-correlation lookups downstream match on plain
// dotted-quad strings, so an address that reaches the broker still
// spelled "::ffff:10.0.0.1" matches no pod and silently degrades to an
// ipBlock rule.
#define IPV6_ADDR_LEN 16

// The value stored in inode_num is a bitfield, not a bare "present"
// marker. Userspace (controller/src/bpf.rs) writes it from the
// PodRegistration flags the pod watcher computes; the network and
// netpolicy probes only test the key for presence, but the syscall
// probe reads the capture tier out of it to pick an allowlist map (or
// none). Keep these bit positions in sync with `mod pod_flags` in
// controller/src/models.rs and `CaptureLevel::tier_index` in
// controller/src/capture_tiers.rs.
//
//   bit 0      netns belongs to a pod kube-guardian tracks (always set)
//   bits 1-3   capture tier: 0=full 1=high 2=medium 3=low 4=custom
//   bits 4-31  registration generation (see KG_GEN_SHIFT)
#define KG_FLAG_POD_TRACKED  (1u << 0)
#define KG_TIER_SHIFT        1
#define KG_TIER_MASK         0x7u
#define KG_TIER_FULL         0
#define KG_TIER_HIGH         1
#define KG_TIER_MEDIUM       2
#define KG_TIER_LOW          3
#define KG_TIER_CUSTOM       4
// Generation: a per-registration value derived from the pod UID. The
// kernel hands out netns inode numbers from an IDA, so a pod that dies
// frees its number for the next pod on the node to reuse. The syscall
// probe's per-netns dedup would then suppress, for the NEW pod, every
// syscall the OLD pod had already reported — silently punching holes
// in a seccomp profile. Folding the generation into the dedup key
// makes a reused inode start from a clean slate.
#define KG_GEN_SHIFT         4
#define KG_TIER_OF(flags)    (((flags) >> KG_TIER_SHIFT) & KG_TIER_MASK)
#define KG_GEN_OF(flags)     ((flags) >> KG_GEN_SHIFT)

// Use LRU_HASH for automatic eviction of stale entries
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u32);
} inode_num SEC(".maps");

// Operator-supplied ignore list (IGNORE_DAEMONSET_TRAFFIC), keyed on the
// same 16-byte v4-mapped representation the probes compare against.
// Userspace writes the key in controller/src/bpf.rs via
// network::ip_to_wire_addr — both sides must agree byte-for-byte or the
// lookup silently never matches.
//
// Scope, so nobody reads more into this than is true: this header is
// included by BOTH network_probe.bpf.c and netpolicy_drop.bpf.c, and
// each object therefore gets its OWN independent instance of the map.
// Userspace populates only the network_probe instance, so
// netpolicy_drop's lookups always miss and its drop events are not
// filtered by the ignore list. That gap predates the widening to 16
// bytes and is unchanged by it — the two maps were equally separate
// when the key was a u32. Fixing it means populating both instances in
// bpf.rs (or moving the map to a shared pinned object); until then,
// treat the ignore list as covering observed traffic only, not drops.
struct ignore_ip_key
{
    __u8 addr[IPV6_ADDR_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ignore_ip_key);
    __type(value, u32);
} ignore_ips SEC(".maps");

// Compare two 16-byte addresses.
//
// Deliberately byte-wise. __builtin_memcmp can be lowered by clang to an
// out-of-line memcmp call, which does not exist in BPF, and casting the
// __u8[16] fields to __u32 * would assume an alignment the array type
// does not carry. Sixteen unrolled byte compares with an early exit is a
// handful of register operations — still far cheaper than the map
// lookups it guards.
static __always_inline bool addr_eq(const __u8 *a, const __u8 *b)
{
#pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

// True when the address names no host: the IPv6 unspecified address
// (::) or the v4-mapped IPv4 unspecified address (::ffff:0.0.0.0).
//
// The pre-IPv6 code filtered `saddr == 0` on the raw __be32. After
// widening, an unbound or not-yet-connected IPv4 socket arrives here as
// ::ffff:0.0.0.0 — NOT as all-zero — so both forms have to be caught.
// Checking only for all-zero would let every unbound socket through and
// flood the broker with 0.0.0.0 events.
static __always_inline bool addr_is_unspecified(const __u8 *a)
{
    // Low 32 bits hold the IPv4 quad when v4-mapped and the tail of a
    // native v6 address otherwise; non-zero here means specified either way.
    if (a[12] || a[13] || a[14] || a[15])
        return false;

#pragma unroll
    for (int i = 0; i < 10; i++)
    {
        if (a[i])
            return false;
    }

    // Leading 80 bits are zero, so this is either :: (bytes 10-11 zero)
    // or ::ffff:0.0.0.0 (bytes 10-11 == 0xffff).
    return (a[10] == 0 && a[11] == 0) || (a[10] == 0xff && a[11] == 0xff);
}

// True for ::1 and for v4-mapped 127.0.0.1. Matches the exact addresses
// the pre-IPv6 code filtered (it compared against 0x7F000001 only), so
// the rest of 127.0.0.0/8 is deliberately still let through.
static __always_inline bool addr_is_loopback(const __u8 *a)
{
#pragma unroll
    for (int i = 0; i < 10; i++)
    {
        if (a[i])
            return false;
    }

    if (a[10] == 0 && a[11] == 0) // ::1
        return a[12] == 0 && a[13] == 0 && a[14] == 0 && a[15] == 1;

    if (a[10] == 0xff && a[11] == 0xff) // ::ffff:127.0.0.1
        return a[12] == 127 && a[13] == 0 && a[14] == 0 && a[15] == 1;

    return false;
}

// Common filtering helper to avoid code duplication
// Optimized to check cheap conditions first before map lookups
static __always_inline bool should_filter_traffic(const __u8 *saddr, const __u8 *daddr)
{
    // Fast path: check cheap conditions first (no map lookups)

    // Filter same source and destination
    if (addr_eq(saddr, daddr))
        return true;

    // Filter unspecified addresses (:: and ::ffff:0.0.0.0)
    if (addr_is_unspecified(saddr) || addr_is_unspecified(daddr))
        return true;

    // Filter localhost (::1 and ::ffff:127.0.0.1)
    if (addr_is_loopback(saddr) || addr_is_loopback(daddr))
        return true;

    // Slow path: map lookups only if cheap checks passed
    // Check ignore list (typically empty or small, so lookups are rare)
    if (bpf_map_lookup_elem(&ignore_ips, saddr))
        return true;

    if (bpf_map_lookup_elem(&ignore_ips, daddr))
        return true;

    return false;
}

// Write an IPv4 address (network byte order, as it sits in
// skc_rcv_saddr / skc_daddr) into the 16-byte v4-mapped form
// ::ffff:a.b.c.d.
static __always_inline void ipv4_to_v4_mapped(__u8 *out, __be32 v4)
{
    __builtin_memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    __builtin_memcpy(out + 12, &v4, 4);
}

// True for the v4-mapped form ::ffff:a.b.c.d — the spelling
// ipv4_to_v4_mapped produces and the one an AF_INET6 socket carrying a
// v4 peer holds in skc_v6_daddr.
static __always_inline bool addr_is_v4_mapped(const __u8 *a)
{
    for (int i = 0; i < 10; i++)
    {
        if (a[i])
            return false;
    }
    return a[10] == 0xff && a[11] == 0xff;
}

// Read a socket's local and peer addresses into the widened 16-byte
// representation. Returns false — caller must bail — for any address
// family we do not track.
//
// Two things here are load-bearing:
//
//  1. bpf_core_field_exists() on skc_v6_rcv_saddr is NOT optional. Those
//     fields sit behind `#if IS_ENABLED(CONFIG_IPV6)` in the kernel, so
//     on a CONFIG_IPV6=n node the CO-RE relocation cannot be resolved
//     and libbpf poisons the instruction. Guarding it keeps the poisoned
//     instruction in a branch the verifier proves dead, so the program
//     still LOADS. Drop the guard and the whole controller fails to
//     start on such a node — not a degraded feature, a dead pod.
//
//  2. The v6 fields are read with a dedicated CO-RE read rather than
//     off a batch-read `struct sock_common` copy. A batch read applies
//     one relocation to the offset of __sk_common and then trusts our
//     local vmlinux.h layout for everything inside it; skc_v6_* sit
//     after skc_net (which is an empty struct when CONFIG_NET_NS=n) and
//     are themselves config-dependent, so those offsets can and do
//     differ from the running kernel's. Ports and family are read from
//     the batch copy because they live in the first 24 bytes of
//     sock_common, ahead of anything configurable.
//
//  3. A v4-mapped connection on an AF_INET6 socket already has
//     ::ffff:a.b.c.d in skc_v6_*, which is exactly the wire form we
//     want, so it is copied straight through. Do not "helpfully"
//     re-derive it from skc_rcv_saddr — un-mapping happens once, in
//     Rust.
static __always_inline bool read_sock_addrs(struct sock *sk, __u8 *saddr, __u8 *daddr)
{
    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    if (family == AF_INET)
    {
        __be32 v4_saddr = 0;
        __be32 v4_daddr = 0;

        BPF_CORE_READ_INTO(&v4_saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&v4_daddr, sk, __sk_common.skc_daddr);

        ipv4_to_v4_mapped(saddr, v4_saddr);
        ipv4_to_v4_mapped(daddr, v4_daddr);
        return true;
    }

    if (family == AF_INET6)
    {
        if (!bpf_core_field_exists(sk->__sk_common.skc_v6_rcv_saddr))
            return false;

        // bpf_core_read with an EXPLICIT size, not BPF_CORE_READ_INTO.
        // BPF_CORE_READ_INTO derives the read length from
        // `sizeof(*(dst))`, and dst here is a `__u8 *` — so it would
        // quietly read ONE byte and leave the other fifteen holding
        // whatever the previous invocation left on the stack. That
        // failure is invisible in a compile or a load: the program
        // verifies and runs, it just emits addresses whose first byte
        // is right and whose tail is the last connection's. Both calls
        // still carry the CO-RE relocation (bpf_core_read applies
        // __builtin_preserve_access_index to the field reference), so
        // this is only a length fix, not an escape from CO-RE.
        bpf_core_read(saddr, IPV6_ADDR_LEN, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(daddr, IPV6_ADDR_LEN, &sk->__sk_common.skc_v6_daddr);
        return true;
    }

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
