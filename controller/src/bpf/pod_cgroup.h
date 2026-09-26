// Which pod a cgroup belongs to, from its kernfs name alone.
//
// Plain C with no BPF helpers so the SAME code is compiled into the probe
// and into a host-side harness by the unit tests
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
// kg_pod_gen_from_name returns the registration generation that UID hashes
// to — the same 28-bit FNV-1a as pod_flags::generation_for_uid in
// controller/src/models.rs — with KG_CG_POD set, or 0 when the name names
// no pod.

#ifndef KG_POD_CGROUP_H
#define KG_POD_CGROUP_H

// Buffer the name is read into. Names are scanned for the "pod" marker
// within KG_CG_NAME_SCAN bytes, and the UID after it may extend 36 bytes
// past that, so the buffer covers both without an index check.
#define KG_CG_NAME_BUF 192
#define KG_CG_NAME_SCAN 128
#define KG_CG_POD (1u << 31)
#define KG_CG_GEN_MASK 0x0fffffffu

static __always_inline int kg_is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

// Hash the UID starting at n[s]. `s` must be < KG_CG_NAME_SCAN.
static __always_inline __u32 kg_uid_gen(const char *n, int s)
{
    __u32 h = 0x811c9dc5u;
    int len = 0, dashes = 0, bad = 0;
    for (int k = 0; k < 36; k++)
    {
        char c = n[s + k];
        if (c == 0 || c == '.')
            break;
        if (c == '_')
            c = '-';
        if (c == '-')
        {
            if (k != 8 && k != 13 && k != 18 && k != 23)
                bad = 1;
            dashes++;
        }
        else if (!kg_is_hex(c))
        {
            bad = 1;
        }
        h ^= (__u32)(unsigned char)c;
        h *= 0x01000193u;
        len++;
    }
    if (bad)
        return 0;
    // Must end right after the UID.
    char end = n[s + len];
    if (end != 0 && end != '.')
        return 0;
    if (!((len == 36 && dashes == 4) || (len == 32 && dashes == 0)))
        return 0;
    return (h & KG_CG_GEN_MASK) | KG_CG_POD;
}

// `n` is a NUL-terminated name in a KG_CG_NAME_BUF buffer.
static __always_inline __u32 kg_pod_gen_from_name(const char *n)
{
    int at = -1;
    for (int i = 0; i < KG_CG_NAME_SCAN - 3; i++)
    {
        if (n[i] == 0)
            break;
        if (n[i] == 'p' && n[i + 1] == 'o' && n[i + 2] == 'd' && (i == 0 || n[i - 1] == '-'))
            at = i + 3;
    }
    if (at < 0 || at >= KG_CG_NAME_SCAN)
        return 0;
    return kg_uid_gen(n, at);
}

#endif
