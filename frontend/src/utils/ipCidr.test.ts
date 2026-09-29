import { describe, it, expect } from 'vitest';
import { isPrivateAddress, isValidCidr, peerCIDR } from './ipCidr';

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

// The map must not call a VPC address "Internet" just because no record holds
// it: on the dev cluster 18 of argocd's 69 "Internet" IPs were 10.62.0.0/16.
describe('isPrivateAddress', () => {
  it('RFC 1918, CGNAT and link-local IPv4 are private', () => {
    expect(isPrivateAddress('10.62.139.244')).toBe(true);
    expect(isPrivateAddress('10.0.0.1')).toBe(true);
    expect(isPrivateAddress('172.16.0.1')).toBe(true);
    expect(isPrivateAddress('172.31.255.254')).toBe(true);
    expect(isPrivateAddress('192.168.1.9')).toBe(true);
    expect(isPrivateAddress('100.64.0.1')).toBe(true);
    expect(isPrivateAddress('100.127.255.255')).toBe(true);
    expect(isPrivateAddress('169.254.169.254')).toBe(true);
  });

  it('the neighbours of those ranges are public', () => {
    expect(isPrivateAddress('11.0.0.1')).toBe(false);
    expect(isPrivateAddress('172.15.255.255')).toBe(false);
    expect(isPrivateAddress('172.32.0.1')).toBe(false);
    expect(isPrivateAddress('192.169.0.1')).toBe(false);
    expect(isPrivateAddress('100.63.255.255')).toBe(false);
    expect(isPrivateAddress('100.128.0.1')).toBe(false);
    expect(isPrivateAddress('169.253.0.1')).toBe(false);
    expect(isPrivateAddress('140.82.121.4')).toBe(false);
    expect(isPrivateAddress('8.8.8.8')).toBe(false);
  });

  it('loopback, unspecified, multicast and broadcast are not Internet either', () => {
    // A real row: DHCPv6 all-agents multicast from a host-network datadog-agent pod.
    expect(isPrivateAddress('ff02::1:2')).toBe(true);
    expect(isPrivateAddress('ff05::1:3')).toBe(true);
    expect(isPrivateAddress('::1')).toBe(true);
    expect(isPrivateAddress('::')).toBe(true);
    expect(isPrivateAddress('0.0.0.0')).toBe(true);
    expect(isPrivateAddress('0.255.255.255')).toBe(true);
    expect(isPrivateAddress('127.0.0.1')).toBe(true);
    expect(isPrivateAddress('224.0.0.251')).toBe(true);
    expect(isPrivateAddress('239.255.255.250')).toBe(true);
    expect(isPrivateAddress('240.0.0.1')).toBe(true);
    expect(isPrivateAddress('255.255.255.255')).toBe(true);
    expect(isPrivateAddress('::ffff:127.0.0.1')).toBe(true);
    // Neighbours stay public.
    expect(isPrivateAddress('1.0.0.1')).toBe(false);
    expect(isPrivateAddress('126.255.255.255')).toBe(false);
    expect(isPrivateAddress('128.0.0.1')).toBe(false);
    expect(isPrivateAddress('223.255.255.255')).toBe(false);
    expect(isPrivateAddress('::2')).toBe(false);
    expect(isPrivateAddress('fe00::1')).toBe(false);
  });

  it('IPv6: ULA and link-local are private, global unicast is not', () => {
    expect(isPrivateAddress('fd00::1')).toBe(true);
    expect(isPrivateAddress('fc00::')).toBe(true);
    expect(isPrivateAddress('fdff:ffff::1')).toBe(true);
    expect(isPrivateAddress('fe80::1')).toBe(true);
    expect(isPrivateAddress('FE80::1')).toBe(true);
    expect(isPrivateAddress('febf::1')).toBe(true);
    expect(isPrivateAddress('fec0::1')).toBe(false);
    expect(isPrivateAddress('fb00::1')).toBe(false);
    expect(isPrivateAddress('2001:db8::1')).toBe(false);
    expect(isPrivateAddress('2606:4700::1111')).toBe(false);
  });

  it('an IPv4-mapped address is judged as its IPv4', () => {
    expect(isPrivateAddress('::ffff:10.0.0.1')).toBe(true);
    expect(isPrivateAddress('::ffff:a00:1')).toBe(true);
    expect(isPrivateAddress('::ffff:8.8.8.8')).toBe(false);
  });

  it('anything that is not an address literal is not private', () => {
    expect(isPrivateAddress('')).toBe(false);
    expect(isPrivateAddress('10.0.0')).toBe(false);
    expect(isPrivateAddress('10.0.0.256')).toBe(false);
    expect(isPrivateAddress('fe80::1%eth0')).toBe(false);
    expect(isPrivateAddress('example.com')).toBe(false);
  });
});

// A CIDR typed into the editor's ipBlock / fromCIDR field. The API server
// rejects the whole policy for one that does not parse, `""` included.
describe('isValidCidr', () => {
  it.each([['10.0.0.0/8'], ['0.0.0.0/0'], ['10.0.0.1/32'], ['fd00::/64'], ['::/0'], ['2001:db8::1/128'], ['10.1.2.3/24']])('accepts %s', (cidr) => {
    expect(isValidCidr(cidr)).toBe(true);
  });

  it.each([[''], ['10.0.0.0'], ['10.0.0.0/'], ['10.0.0.0/33'], ['10.0.0.0/08'], ['fd00::/129'], ['10.0.0.256/8'], ['010.0.0.0/8'], ['fd00::%eth0/64'], [' 10.0.0.0/8'], ['10.0.0.0/8/8'], ['/8']])('rejects %j', (cidr) => {
    expect(isValidCidr(cidr)).toBe(false);
  });
});
