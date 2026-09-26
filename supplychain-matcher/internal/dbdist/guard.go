// Package dbdist downloads the Grype vulnerability database without
// go-getter. Grype's own distribution client hands URLs to go-getter,
// which also speaks git, hg, s3, gcs and file, honours X-Terraform-Get and
// follows redirects unchecked. This client implements grype's
// distribution.Client interface with plain HTTP(S) only:
//
//   - https only, or http when the operator configured an http:// URL;
//   - every connection, including each redirect hop, goes through an
//     address guard that always refuses loopback, link-local (incl. cloud
//     metadata), unspecified and multicast addresses. Private addresses are
//     allowed: DB mirrors are often internal;
//   - the archive's sha256 is checked against the listing before anything
//     is unpacked, and unpacking accepts only regular files at the archive
//     root, with size limits.
//
// The sha256 comes from the same listing as the archive URL, so it proves
// integrity (the archive the listing named), not authenticity. Anchore
// publishes no signature; TLS to the configured URL is the trust anchor.
package dbdist

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// BlockedError is returned for a refused destination.
type BlockedError struct{ Target string }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("refused DB download destination %s (loopback, link-local, unspecified or multicast)", e.Target)
}

// guard refuses destinations a DB download must never reach.
type guard struct {
	allowLoopbackForTest bool
}

func (g guard) checkIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if g.allowLoopbackForTest && ip.IsLoopback() {
		return nil
	}
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return &BlockedError{Target: ip.String()}
	}
	return nil
}

// control is the dialer hook: it sees the resolved address of every
// connection, so a name that (re)binds to a refused address is caught.
func (g guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &BlockedError{Target: address}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return &BlockedError{Target: address}
	}
	return g.checkIP(ip)
}
