// Which pod a cgroup belongs to, from its kernfs name alone.
//
// Plain C with no BPF helpers so the SAME step functions are compiled into
// the probe and into a host-side harness by the unit tests
// (early_capture::tests::the_c_pod_cgroup_parser_matches_the_rust_one).
// The includer provides __u32 and __always_inline.
//
// A pod's containers live under a pod-level cgroup whose name carries the
// pod UID:
//   cgroupfs:  pod<uid>                                 (uid with '-')
//   systemd:   kubepods[-<qos>]-pod<uid>.slice          (uid with '_')
//   kind:      kubelet-kubepods[-<qos>]-pod<uid>.slice
// A static pod's "uid" there is its 32-hex config hash.
//
// The parse yields the registration generation that UID hashes to (the
// same 28-bit FNV-1a as pod_flags::generation_for_uid in
// controller/src/models.rs) with KG_CG_POD set, or 0 when the name names
// no pod.
//
// The logic is split into per-index STEP functions. The probe drives them
// with bpf_loop(), so the verifier checks each step once instead of every
// iteration of every data-dependent path (driving them with plain loops
// inlined into the probe exceeded the verifier's 1M instruction budget).
// The host harness drives them with plain loops (kg_pod_gen_from_name).

#ifndef KG_POD_CGROUP_H
#define KG_POD_CGROUP_H

// Buffer the name is read into. The "pod" marker is looked for within
// KG_CG_NAME_SCAN bytes, and the UID after it may extend 36 bytes past
// that, so the buffer covers both without further checks.
#define KG_CG_NAME_BUF 192
#define KG_CG_NAME_SCAN 128
#define KG_CG_UID_MAX 36
#define KG_CG_POD (1u << 31)
#define KG_CG_GEN_MASK 0x0fffffffu

// Hide a value from the optimiser so a bounds check on it is kept, and
// kept on the very register the access uses. Without it clang proves the
// check redundant from earlier ones and drops it, and the verifier, which
// does not track that proof, rejects the access.
#define KG_OPAQUE(x) __asm__ __volatile__("" : "+r"(x))

static __always_inline int kg_is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

// Marker scan, one index. Records in *at the index just past the last
// "pod" that starts the name or follows a '-'. *prev carries the previous
// character (0 before the first) so no step reads behind its own index.
// Returns 1 to stop.
static __always_inline int kg_scan_step(const char *n, __u32 i, int *at, char *prev)
{
    if (i >= KG_CG_NAME_SCAN - 3)
        return 1;
    char c = n[i];
    if (c == 0)
        return 1;
    if (c == 'p' && n[i + 1] == 'o' && n[i + 2] == 'd' && (i == 0 || *prev == '-'))
        *at = (int)i + 3;
    *prev = c;
    return 0;
}

struct kg_uid
{
    __u32 hash;
    __u32 len;
    __u32 dashes;
    __u32 bad;
};

// UID hash, one character: n[s + k]. Returns 1 at the end of the UID.
static __always_inline int kg_uid_step(const char *n, __u32 s, __u32 k, struct kg_uid *u)
{
    if (s >= KG_CG_NAME_SCAN || k >= KG_CG_UID_MAX)
        return 1;
    // Bound the index itself: the verifier tracks the sum, not the two
    // checks above (the compiler is free to reorder those).
    __u32 idx = s + k;
    KG_OPAQUE(idx);
    if (idx >= KG_CG_NAME_BUF)
        return 1;
    char c = n[idx];
    if (c == 0 || c == '.')
        return 1;
    if (c == '_')
        c = '-';
    if (c == '-')
    {
        if (k != 8 && k != 13 && k != 18 && k != 23)
            u->bad = 1;
        u->dashes++;
    }
    else if (!kg_is_hex(c))
    {
        u->bad = 1;
    }
    u->hash ^= (__u32)(unsigned char)c;
    u->hash *= 0x01000193u;
    u->len++;
    return 0;
}

static __always_inline void kg_uid_init(struct kg_uid *u)
{
    u->hash = 0x811c9dc5u;
    u->len = 0;
    u->dashes = 0;
    u->bad = 0;
}

// Validate the UID that started at n[s] and produce the result.
static __always_inline __u32 kg_uid_finish(const char *n, __u32 s, const struct kg_uid *u)
{
    __u32 len = u->len;
    if (u->bad || s >= KG_CG_NAME_SCAN || len > KG_CG_UID_MAX)
        return 0;
    // Must end right after the UID.
    __u32 idx = s + len;
    KG_OPAQUE(idx);
    if (idx >= KG_CG_NAME_BUF)
        return 0;
    char end = n[idx];
    if (end != 0 && end != '.')
        return 0;
    if (!((len == 36 && u->dashes == 4) || (len == 32 && u->dashes == 0)))
        return 0;
    return (u->hash & KG_CG_GEN_MASK) | KG_CG_POD;
}

#ifndef __bpf__
// Host driver (tests). `n` is NUL-terminated in a KG_CG_NAME_BUF buffer.
static __always_inline __u32 kg_pod_gen_from_name(const char *n)
{
    int at = -1;
    char prev = 0;
    for (__u32 i = 0; i < KG_CG_NAME_SCAN; i++)
        if (kg_scan_step(n, i, &at, &prev))
            break;
    if (at < 0)
        return 0;
    struct kg_uid u;
    kg_uid_init(&u);
    for (__u32 k = 0; k < KG_CG_UID_MAX; k++)
        if (kg_uid_step(n, (__u32)at, k, &u))
            break;
    return kg_uid_finish(n, (__u32)at, &u);
}
#endif

#endif
