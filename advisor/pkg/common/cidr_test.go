package common

import (
	"net"
	"testing"
)

func TestHostCIDR(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		want    string
		wantErr bool
	}{
		{name: "ipv4 pod ip", ip: "10.0.0.1", want: "10.0.0.1/32"},
		{name: "ipv4 service ip", ip: "10.96.0.10", want: "10.96.0.10/32"},
		{name: "ipv4 loopback", ip: "127.0.0.1", want: "127.0.0.1/32"},
		{name: "ipv6 ula pod ip", ip: "fd00::1", want: "fd00::1/128"},
		{name: "ipv6 ula service ip", ip: "fd00:96::a", want: "fd00:96::a/128"},
		{name: "ipv6 documentation range", ip: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "ipv6 loopback", ip: "::1", want: "::1/128"},
		{name: "ipv6 fully expanded is compressed", ip: "fd00:0000:0000:0000:0000:0000:0000:0001", want: "fd00::1/128"},
		{name: "ipv6 uppercase is lowercased", ip: "FD00::AB", want: "fd00::ab/128"},

		// The IPv4-in-IPv6 form is the trap this helper exists to close:
		// naive "%s/32" concatenation yields "::ffff:10.0.0.1/32", which
		// parses as the IPv6 prefix ::/32 rather than one host.
		{name: "ipv4-mapped ipv6 collapses to dotted quad", ip: "::ffff:10.0.0.1", want: "10.0.0.1/32"},

		// Everything below must be rejected so no caller can emit it.
		{name: "empty string", ip: "", wantErr: true},
		{name: "hostname", ip: "db.prod.svc.cluster.local", wantErr: true},
		{name: "already a cidr", ip: "10.0.0.0/8", wantErr: true},
		{name: "ipv4 with port", ip: "10.0.0.1:8080", wantErr: true},
		{name: "ipv6 with zone", ip: "fe80::1%eth0", wantErr: true},
		{name: "octet out of range", ip: "10.0.0.256", wantErr: true},
		{name: "truncated ipv4", ip: "10.0.0", wantErr: true},
		{name: "garbage", ip: "not-an-ip", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HostCIDR(tc.ip)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("HostCIDR(%q): want error, got %q", tc.ip, got)
				}
				if got != "" {
					t.Errorf("HostCIDR(%q): want empty string alongside error, got %q", tc.ip, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("HostCIDR(%q): unexpected error: %v", tc.ip, err)
			}
			if got != tc.want {
				t.Errorf("HostCIDR(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

// The output is fed straight into an ipBlock / toCIDR field, so every
// success case must survive a round trip through net.ParseCIDR and still
// describe exactly one host. This is the property that "%s/32" on an IPv6
// address violated: fd00::1/32 parses fine but covers 2^96 addresses.
func TestHostCIDR_DescribesExactlyOneHost(t *testing.T) {
	for _, ip := range []string{
		"10.0.0.1", "10.96.0.10", "fd00::1", "fd00:96::a", "2001:db8::1", "::ffff:10.0.0.1",
	} {
		t.Run(ip, func(t *testing.T) {
			cidr, err := HostCIDR(ip)
			if err != nil {
				t.Fatalf("HostCIDR(%q): %v", ip, err)
			}
			addr, network, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("HostCIDR(%q) = %q which is not a parseable CIDR: %v", ip, cidr, err)
			}
			ones, bits := network.Mask.Size()
			if ones != bits {
				t.Errorf("HostCIDR(%q) = %q is a /%d of %d bits; want a full-length host prefix", ip, cidr, ones, bits)
			}
			if !network.Contains(addr) {
				t.Errorf("HostCIDR(%q) = %q does not contain its own address", ip, cidr)
			}
		})
	}
}
