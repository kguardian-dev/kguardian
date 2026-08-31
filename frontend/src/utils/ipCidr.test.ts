import { describe, it, expect } from 'vitest';
import { peerCIDR } from './ipCidr';

// The UI cannot use node:net (it is browser code), so ipCidr hand-rolls both the
// address validation and the canonical serialization. These cases pin that
// parser to the semantics of the advisor's Go reference, common.HostCIDR
// (net.ParseIP -> To4 -> String): the mask must follow the address family, the
// emitted text must be RFC 5952 canonical rather than whatever was observed, and
// anything that is not a clean address literal must come back null so the
// generators drop the peer instead of emitting a CIDR the API server would
// reject outright.

describe('peerCIDR', () => {
  it('gives IPv4 peers a /32 host mask', () => {
    expect(peerCIDR('10.0.0.7')).toBe('10.0.0.7/32');
    expect(peerCIDR('0.0.0.0')).toBe('0.0.0.0/32');
    expect(peerCIDR('255.255.255.255')).toBe('255.255.255.255/32');
  });

  it('gives IPv6 peers a /128 host mask, not /32', () => {
    expect(peerCIDR('fd00::1')).toBe('fd00::1/128');
    expect(peerCIDR('fd00:96::a')).toBe('fd00:96::a/128');
    expect(peerCIDR('fe80::1')).toBe('fe80::1/128');
  });

  // Canonical form is the cross-component contract: Go's net.IP.String() and
  // Rust's IpAddr::to_string() both produce it, and the Controller and Broker
  // already emit it. Passing the observed text through would satisfy goldens
  // written in canonical form and then disagree on a live cluster.
  it('lowercases hex', () => {
    expect(peerCIDR('FD00::7')).toBe('fd00::7/128');
    expect(peerCIDR('2001:DB8::1')).toBe('2001:db8::1/128');
  });

  it('compresses the longest run of zero groups', () => {
    expect(peerCIDR('fd00:0:0:0:0:0:0:7')).toBe('fd00::7/128');
    expect(peerCIDR('2001:db8:0:0:0:0:0:1')).toBe('2001:db8::1/128');
    expect(peerCIDR('0:0:0:0:0:0:0:0')).toBe('::/128');
    // Longest run wins over an earlier shorter one...
    expect(peerCIDR('1:0:0:2:0:0:0:3')).toBe('1:0:0:2::3/128');
    // ...and the leftmost wins when two runs tie.
    expect(peerCIDR('1:0:0:2:0:0:3:4')).toBe('1::2:0:0:3:4/128');
    // A single zero group is never collapsed (RFC 5952).
    expect(peerCIDR('1:2:3:4:5:6:0:8')).toBe('1:2:3:4:5:6:0:8/128');
  });

  it('strips leading zeros within a group', () => {
    expect(peerCIDR('fd00:0000::0007')).toBe('fd00::7/128');
    expect(peerCIDR('2001:0db8:0000:0000:0000:ff00:0042:8329'))
      .toBe('2001:db8::ff00:42:8329/128');
  });

  it('leaves an already-canonical address untouched', () => {
    expect(peerCIDR('fd00::7')).toBe('fd00::7/128');
    expect(peerCIDR('::1')).toBe('::1/128');
    expect(peerCIDR('::')).toBe('::/128');
    expect(peerCIDR('1:2:3:4:5:6:7:8')).toBe('1:2:3:4:5:6:7:8/128');
  });

  // Go's To4() unwraps an IPv4-mapped address, so HostCIDR gives it a /32 and
  // prints it as a dotted quad - in both the dotted and the all-hex spelling.
  it('unwraps IPv4-mapped addresses to a dotted-quad /32', () => {
    expect(peerCIDR('::ffff:10.0.0.1')).toBe('10.0.0.1/32');
    expect(peerCIDR('::FFFF:10.0.0.1')).toBe('10.0.0.1/32');
    expect(peerCIDR('::ffff:0a00:0001')).toBe('10.0.0.1/32');
    expect(peerCIDR('0:0:0:0:0:ffff:10.0.0.1')).toBe('10.0.0.1/32');
  });

  // An IPv4-COMPATIBLE address (no ffff marker) is not unwrapped by To4(), so it
  // stays IPv6 and keeps its /128.
  it('does not unwrap IPv4-compatible addresses', () => {
    expect(peerCIDR('::10.0.0.1')).toBe('::a00:1/128');
  });

  it('returns null for malformed addresses rather than a malformed CIDR', () => {
    expect(peerCIDR('')).toBeNull();
    expect(peerCIDR('not-an-ip')).toBeNull();
    expect(peerCIDR('10.0.0')).toBeNull();            // too few octets
    expect(peerCIDR('10.0.0.1.5')).toBeNull();        // too many octets
    expect(peerCIDR('10.0.0.256')).toBeNull();        // octet out of range
    expect(peerCIDR('01.2.3.4')).toBeNull();          // leading zero is octal-ambiguous
    expect(peerCIDR('fd00::1::2')).toBeNull();        // more than one "::"
    expect(peerCIDR('fd00:::1')).toBeNull();
    expect(peerCIDR('fd00::xyz')).toBeNull();         // non-hex group
    expect(peerCIDR('fd00::12345')).toBeNull();       // group wider than 16 bits
    expect(peerCIDR('1:2:3:4:5:6:7')).toBeNull();     // too few groups, uncompressed
    expect(peerCIDR('1:2:3:4:5:6:7:8:9')).toBeNull(); // too many groups
    expect(peerCIDR('10.0.0.1::ffff')).toBeNull();    // dotted quad outside the last group
  });

  it('returns null for a zone-scoped address, which is not reachable from a peer', () => {
    expect(peerCIDR('fe80::1%eth0')).toBeNull();
  });

  it('returns null for an address that already carries a prefix', () => {
    expect(peerCIDR('10.0.0.0/24')).toBeNull();
    expect(peerCIDR('fd00::/64')).toBeNull();
  });
});
