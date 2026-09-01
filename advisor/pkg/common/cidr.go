package common

import (
	"fmt"
	"net"
)

// HostCIDR renders a single observed IP address as the single-host CIDR
// that a NetworkPolicy ipBlock (or a Cilium to/fromCIDR entry) expects:
// /32 for IPv4, /128 for IPv6.
//
// The prefix used to be hardcoded as "%s/32" at three call sites — the
// standard generator, the Cilium generator, and the k8s peer-resolution
// helper. On a dual-stack cluster that silently produced `fd00::1/32`: a
// syntactically valid CIDR that Kubernetes accepts and that means "the
// whole fd00::/32 block", roughly 2^96 addresses. A generator whose whole
// job is proposing a least-privilege policy must not widen a single-host
// rule into a /32 of IPv6 space, so the family is now decided from the
// parsed address instead of assumed.
//
// The family test is To4(), not a length check: net.ParseIP returns a
// 16-byte slice for dotted-quad input too, so len(addr) == net.IPv4len is
// false for most IPv4 addresses and would misclassify them as v6.
//
// The emitted address is the canonical text of the *parsed* address
// rather than the caller's raw string. That matters for the IPv4-in-IPv6
// forms a dual-stack node can report: "::ffff:10.0.0.1" is an IPv4
// address wearing an IPv6 coat, and pasting "/32" onto the input verbatim
// gives "::ffff:10.0.0.1/32", which net.ParseCIDR reads as the IPv6
// prefix ::/32 — the same catastrophic widening by another route. Routing
// through the parsed value emits "10.0.0.1/32". As a bonus it normalises
// case and zero-compression ("FD00::0:1" -> "fd00::1"), so regenerating a
// policy from equivalent-but-differently-spelled input does not churn the
// YAML.
//
// An unparseable input is an error, not a best-effort string. Callers
// resolving a peer treat that as "skip this peer": a malformed ipBlock is
// worse than a missing one, because it either fails admission and takes
// the entire generated policy down with it — leaving the operator with
// nothing — or lands as a rule nobody can reason about. Dropping the one
// peer we could not parse keeps every other rule reviewable.
func HostCIDR(ip string) (string, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return "", fmt.Errorf("cannot build host CIDR: %q is not a valid IP address", ip)
	}
	if v4 := addr.To4(); v4 != nil {
		return v4.String() + "/32", nil
	}
	return addr.String() + "/128", nil
}
