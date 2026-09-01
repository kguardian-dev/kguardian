//! Canonical textual form for IP addresses crossing the broker's wire
//! and storage boundaries.
//!
//! Every IP the broker stores or looks up is a `VARCHAR`, matched with
//! `=` (or JSONB containment). That is fine for IPv4, whose textual
//! form is effectively unique, but an IPv6 address has many spellings
//! of the same value: `FD00::1`, `fd00:0:0:0:0:0:0:1` and `fd00::1`
//! are one address written three ways, and a string equality filter
//! matches none of the others. Left unnormalised, a dual-stack peer
//! whose address the eBPF probe rendered one way and the pod watcher
//! rendered another simply never resolves — `/pod/ip/<ip>` 404s and
//! the advisor silently degrades that flow from a podSelector to a
//! raw ipBlock, which is a weaker policy that nobody notices is wrong.
//!
//! The canonical form is `std::net::IpAddr`'s `Display` applied after
//! IPv4-mapped forms are un-mapped: lowercase hex with the longest
//! zero-run compressed to `::` for IPv6, and a plain dotted quad for
//! IPv4 however it arrived. `::ffff:10.0.0.1` is an IPv4 address
//! wearing an IPv6 coat, and canonicalises to `10.0.0.1`.
//!
//! The un-mapping is a cross-component contract, not a local
//! preference. Every other side already un-maps:
//!
//!   * the controller (Rust, like the broker — the Go components are
//!     the advisor and evaluator) routes every outbound address
//!     through `network::canonicalize_ip`, whose `wire_addr_to_ip` is
//!     marked as the single un-mapping step for the whole eBPF
//!     pipeline: the kernel side carries IPv4 v4-mapped so there is
//!     one code path in BPF and no family discriminator on the wire;
//!   * the advisor's `common.HostCIDR` renders through `addr.To4()`,
//!     because `::ffff:10.0.0.1/32` parses as the IPv6 prefix `::/32`
//!     — a single-host rule silently widened to 2^96 addresses.
//!
//! A broker that stored the mapped spelling would be the lone holdout
//! and would write rows that no lookup — its own or anyone else's —
//! can find, which is precisely the failure this module exists to
//! prevent.
//!
//! Only IPv4-*mapped* (`::ffff:a.b.c.d`) is un-mapped, never
//! IPv4-*compatible* (`::a.b.c.d`). `IpAddr::to_canonical()` and the
//! controller's `to_ipv4_mapped()` agree on this, and the distinction
//! is load-bearing: the looser `to_ipv4()` would also convert
//! compatible addresses and turn `::1` into `0.0.0.1`.
//!
//! Applied on both sides of the boundary — writes (so stored values
//! are canonical) and reads (so lookups are canonical) — the two
//! agree regardless of which spelling the source emitted.

use std::net::IpAddr;

/// Normalise `s` to the canonical textual form of the IP address it
/// denotes; return it unchanged if it does not parse as one.
///
/// The passthrough is deliberate rather than an error path. This
/// function sits on the ingest hot path and on every lookup, and it
/// receives values the broker does not fully control: the headless
/// Service sentinel `"None"` (see [`crate::add::is_routable_svc_ip`]),
/// zone-scoped link-locals like `fe80::1%eth0` (which Rust's parser
/// rejects), empty strings from a degenerate caller, and whatever a
/// future writer POSTs by hand. Those already have defined behaviour
/// further down — the routability guard rejects `"None"`, an unknown
/// string simply fails to match any row — and rewriting this function
/// to fail loudly would turn a benign 404 into a 500. Non-IP input
/// therefore behaves exactly as it did before canonicalisation
/// existed.
pub(crate) fn canonical_ip(s: &str) -> String {
    match s.parse::<IpAddr>() {
        Ok(addr) => addr.to_canonical().to_string(),
        Err(_) => s.to_string(),
    }
}

/// [`canonical_ip`] over an optional column value, in place.
///
/// `PodTraffic`'s IP columns are `Option<String>` (nullable in the
/// schema), and the ingest path needs to normalise them without
/// disturbing `None`.
pub(crate) fn canonicalise_opt(v: &mut Option<String>) {
    if let Some(s) = v.as_mut() {
        let canonical = canonical_ip(s);
        if canonical != *s {
            *s = canonical;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_unchanged() {
        // IPv4 has one spelling in practice; canonicalisation must be
        // a no-op so existing rows written before this function
        // existed still match lookups made through it.
        for ip in ["10.0.0.1", "192.168.1.100", "172.20.0.10", "0.0.0.0"] {
            assert_eq!(canonical_ip(ip), ip, "IPv4 {ip} must round-trip unchanged");
        }
    }

    #[test]
    fn ipv6_textual_variants_collapse_to_one_form() {
        // The actual bug: three spellings of one address that an
        // exact-match filter treats as three different addresses.
        let expected = "fd00::1";
        for spelling in [
            "FD00::1",
            "fd00:0:0:0:0:0:0:1",
            "fd00::1",
            "fd00:0000:0000:0000:0000:0000:0000:0001",
        ] {
            assert_eq!(
                canonical_ip(spelling),
                expected,
                "{spelling} must canonicalise to {expected}"
            );
        }
    }

    #[test]
    fn ipv6_compresses_longest_zero_run_and_lowercases() {
        assert_eq!(
            canonical_ip("2001:0DB8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(canonical_ip("0:0:0:0:0:0:0:0"), "::");
        assert_eq!(canonical_ip("::"), "::");
    }

    #[test]
    fn ipv4_mapped_is_unmapped_to_bare_ipv4() {
        // Contract check, not a formatting check. The controller
        // un-maps at source and the advisor un-maps when rendering
        // CIDRs, so a broker that stored "::ffff:10.0.0.1" would write
        // a row that no lookup can find.
        assert_eq!(canonical_ip("::ffff:10.0.0.1"), "10.0.0.1");
        assert_eq!(canonical_ip("::FFFF:10.0.0.1"), "10.0.0.1");
        // The all-hex spelling of the same mapped address too.
        assert_eq!(canonical_ip("::ffff:0a00:0001"), "10.0.0.1");
        // The point of all of it: a v4-mapped observation and a native
        // IPv4 observation of one host must land on one string.
        assert_eq!(canonical_ip("::ffff:10.0.0.1"), canonical_ip("10.0.0.1"));
    }

    #[test]
    fn ipv4_compatible_and_loopback_are_not_unmapped() {
        // Only IPv4-MAPPED is un-mapped. `to_ipv4()` would also convert
        // IPv4-COMPATIBLE addresses, turning "::1" into "0.0.0.1" —
        // the broker would then answer a loopback lookup with whatever
        // pod happens to hold 0.0.0.1. `to_canonical()` (and the
        // controller's `to_ipv4_mapped()`) do not. Guard the
        // distinction; it is an easy thing to "simplify" away.
        assert_eq!(canonical_ip("::1"), "::1");
        assert_eq!(canonical_ip("::"), "::");
        assert_eq!(canonical_ip("::10.0.0.1"), "::a00:1");
    }

    #[test]
    fn unparseable_input_passes_through_untouched() {
        // Everything here must behave exactly as it did before
        // canonicalisation existed — see the fn doc comment.
        for garbage in [
            "",
            "None",         // headless Service sentinel
            "fe80::1%eth0", // zone id: rejected by Rust's parser
            "10.0.0.1/32",  // CIDR, not an address
            "010.0.0.1",    // leading zeros: rejected by Rust's parser
            "not-an-ip",
            "10.0.0.256",
            "fd00::1::2",
            " fd00::1", // leading space
            "fd00::1 ", // trailing space
        ] {
            assert_eq!(
                canonical_ip(garbage),
                garbage,
                "{garbage:?} must pass through unchanged"
            );
        }
    }

    #[test]
    fn canonicalisation_is_idempotent() {
        // Rows are re-upserted on every controller watch event, so the
        // write path canonicalises values that are already canonical.
        for ip in [
            "fd00::1",
            "10.0.0.1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
            "None",
        ] {
            let once = canonical_ip(ip);
            assert_eq!(
                canonical_ip(&once),
                once,
                "{ip} must be stable under reapplication"
            );
        }
    }

    #[test]
    fn canonicalise_opt_leaves_none_alone() {
        let mut v: Option<String> = None;
        canonicalise_opt(&mut v);
        assert_eq!(v, None);
    }

    #[test]
    fn canonicalise_opt_normalises_some() {
        let mut v = Some("FD00:0:0:0:0:0:0:1".to_string());
        canonicalise_opt(&mut v);
        assert_eq!(v.as_deref(), Some("fd00::1"));
    }
}
