package registry

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Skip reasons, used as the metric label.
const (
	ReasonBlockedAddress = "blocked_address" // loopback, link-local, unspecified, multicast
	ReasonPrivateAddress = "private_address" // RFC1918, CGNAT, ULA, when private registries are not allowed
	ReasonLocalHostname  = "local_hostname"  // localhost, *.local, *.localhost, single-label names
	// ReasonBlockedRealm: go-containerregistry itself refused a token
	// realm pointing at a private or link-local IP literal.
	ReasonBlockedRealm = "blocked_realm"
)

// BlockedError is returned when the guard refuses a destination.
type BlockedError struct {
	Reason string
	Target string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("registry lookup refused (%s): %s", e.Reason, e.Target)
}

// Guard decides which destinations registry lookups may reach. The image
// reference comes from a pod spec, i.e. from anyone who can create a pod,
// so the lookup must not become a way to probe the node, the cluster
// network or a cloud metadata endpoint.
type Guard struct {
	// AllowPrivate admits RFC1918, CGNAT (100.64.0.0/10), ULA (fc00::/7)
	// addresses and .local names, for LAN registries. Loopback, link-local
	// (including 169.254.169.254), unspecified and multicast are refused
	// regardless.
	AllowPrivate bool

	// allowLoopbackForTest lets tests reach an httptest server. Never set
	// outside tests.
	allowLoopbackForTest bool
}

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")

	// Always refused IPv4 ranges not covered by the netip predicates.
	alwaysBlocked = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
		netip.MustParsePrefix("240.0.0.0/4"),   // reserved, incl. 255.255.255.255
	}

	// IPv6 ranges that embed an IPv4 address a gateway may forward to.
	nat64      = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052 well-known prefix
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215 local-use
	sixToFour  = netip.MustParsePrefix("2002::/16")      // 6to4: IPv4 in bits 16-47
	v4Compat   = netip.MustParsePrefix("::/96")          // deprecated IPv4-compatible ::a.b.c.d
)

// embeddedIPv4 returns the IPv4 address carried inside a NAT64, 6to4 or
// IPv4-compatible IPv6 address.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip), nat64Local.Contains(ip), v4Compat.Contains(ip):
		// The IPv4 address is the last 32 bits (for 64:ff9b:1::/48 this is
		// the /96 embedding, the form NAT64 gateways use).
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// CheckIP classifies one resolved address. It returns nil when allowed.
// An IPv6 address embedding an IPv4 one (NAT64, 6to4, IPv4-compatible) is
// classified by that IPv4 address as well, so 64:ff9b::a9fe:a9fe is
// refused as 169.254.169.254.
func (g Guard) CheckIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if g.allowLoopbackForTest && ip.IsLoopback() {
		return nil
	}
	if v4, ok := embeddedIPv4(ip); ok {
		if err := g.CheckIP(v4); err != nil {
			var be *BlockedError
			if errors.As(err, &be) {
				return &BlockedError{Reason: be.Reason, Target: ip.String() + " (embeds " + v4.String() + ")"}
			}
			return err
		}
	}
	for _, p := range alwaysBlocked {
		if p.Contains(ip) {
			return &BlockedError{Reason: ReasonBlockedAddress, Target: ip.String()}
		}
	}
	switch {
	case !ip.IsValid(),
		ip.IsLoopback(),
		ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), // 169.254.0.0/16 (cloud metadata), fe80::/10
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return &BlockedError{Reason: ReasonBlockedAddress, Target: ip.String()}
	case ip.IsPrivate() || cgnat.Contains(ip): // IsPrivate: RFC1918 + fc00::/7
		if !g.AllowPrivate {
			return &BlockedError{Reason: ReasonPrivateAddress, Target: ip.String()}
		}
	}
	return nil
}

// CheckHost refuses host names that only make sense on a local network,
// before any resolution. IP literals are checked with CheckIP.
func (g Guard) CheckHost(host string) error {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return g.CheckIP(ip)
	}
	switch {
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return &BlockedError{Reason: ReasonBlockedAddress, Target: host}
	case strings.HasSuffix(h, ".local") || !strings.Contains(h, "."):
		// mDNS names and bare single-label names (in-cluster short
		// service names) are LAN destinations.
		if !g.AllowPrivate {
			return &BlockedError{Reason: ReasonLocalHostname, Target: host}
		}
	}
	return nil
}

// control runs after DNS resolution, on the exact address about to be
// dialled, for every connection: the registry, the token realm and any
// redirect. That is what defeats DNS rebinding - a name that resolved to a
// public address during a pre-check but to 169.254.169.254 now is refused
// here.
func (g Guard) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &BlockedError{Reason: ReasonBlockedAddress, Target: address}
	}
	return g.CheckIP(ap.Addr())
}

// Transport returns an HTTP transport whose every request and every dial is
// checked by the guard. It ignores proxy environment variables: with a
// proxy the dial check would only see the proxy's address.
func (g Guard) Transport(timeout time.Duration) http.RoundTripper {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: g.control}
	base := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &guardedRoundTripper{g: g, base: base}
}

type guardedRoundTripper struct {
	g    Guard
	base http.RoundTripper
}

// RoundTrip checks the host name of every request, including token-realm
// requests and redirects, which go-containerregistry issues through this
// same transport.
func (rt *guardedRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := rt.g.CheckHost(r.URL.Hostname()); err != nil {
		return nil, err
	}
	return rt.base.RoundTrip(r)
}

// blockedReason extracts the guard's reason from a wrapped error.
func blockedReason(err error) (string, bool) {
	var be *BlockedError
	if errors.As(err, &be) {
		return be.Reason, true
	}
	// Some layers flatten errors to strings; fall back to the message.
	msg := err.Error()
	if strings.Contains(msg, "invalid realm") {
		return ReasonBlockedRealm, true
	}
	for _, r := range []string{ReasonBlockedAddress, ReasonPrivateAddress, ReasonLocalHostname} {
		if strings.Contains(msg, "registry lookup refused ("+r+")") {
			return r, true
		}
	}
	return "", false
}
