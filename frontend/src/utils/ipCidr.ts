// Single-host CIDR conversion for observed peer IPs, shared by the standard
// (networkPolicyGenerator) and Cilium (ciliumPolicyGenerator) policy builders.
//
// Two invariants, both of which must agree with the advisor's Go reference
// (common.HostCIDR) because the generators are compared against the same
// goldens:
//
//  1. The host mask follows the address family. /32 pins exactly one IPv4
//     address, but the same /32 on an IPv6 address leaves 96 host bits free -
//     it would widen a rule meant for one peer into one covering 2^96
//     addresses. IPv6 peers are emitted as /128.
//
//  2. The emitted address is CANONICAL, not the observed text. Go returns
//     addr.String(); Rust returns IpAddr::to_string(); the Controller and
//     Broker already hold to that form. Canonical means lowercase hex, no
//     leading zeros in a group, and the longest run of two or more zero groups
//     collapsed to "::" (leftmost wins a tie) - RFC 5952. Emitting the raw
//     observed string instead would pass goldens written in canonical form and
//     then disagree with every other component on a real cluster.
//
// The UI is browser code, so node:net is unavailable; parsing is done here.
// Note this file is deliberately kept logically identical to the peerCIDR
// helper in llm-bridge/src/tools/generators/networkpolicy.ts - the two packages
// cannot share a module, so they share semantics instead.

// Strict dotted quad. Leading zeros are rejected as octal-ambiguous, matching
// Go's net.ParseIP (which has rejected them since 1.17).
const IPV4_OCTET_RE = /^(0|[1-9]\d{0,2})$/;
const IPV6_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;

/** Parse a dotted quad into its four octets, or null. */
function parseIPv4(ip: string): number[] | null {
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  const out: number[] = [];
  for (const octet of octets) {
    if (!IPV4_OCTET_RE.test(octet)) return null;
    const n = Number(octet);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** Parse an IPv6 literal into its eight 16-bit groups, or null. */
function parseIPv6(ip: string): number[] | null {
  // A zone ID scopes an address to one interface; it is not addressable from
  // another host and so is never a valid policy peer.
  if (ip.includes('%')) return null;

  const halves = ip.split('::');
  if (halves.length > 2) return null; // "::" may appear at most once
  const compressed = halves.length === 2;

  // Groups written out explicitly, split across the two sides of any "::".
  const sides: number[][] = [[], []];
  for (let i = 0; i < halves.length; i++) {
    if (halves[i] === '') continue; // the empty side of a leading/trailing "::"
    const segments = halves[i].split(':');
    for (let j = 0; j < segments.length; j++) {
      const segment = segments[j];
      if (segment.includes('.')) {
        // A dotted quad is only legal as the very last group of the address,
        // where it occupies the final two 16-bit groups.
        if (i !== halves.length - 1 || j !== segments.length - 1) return null;
        const quad = parseIPv4(segment);
        if (quad === null) return null;
        sides[i].push((quad[0] << 8) | quad[1], (quad[2] << 8) | quad[3]);
        continue;
      }
      if (!IPV6_GROUP_RE.test(segment)) return null;
      sides[i].push(parseInt(segment, 16));
    }
  }

  const [head, tail] = sides;
  if (!compressed) return head.length === 8 ? head : null;
  // "::" must stand in for at least one omitted group.
  const omitted = 8 - head.length - tail.length;
  if (omitted < 1) return null;
  return [...head, ...new Array<number>(omitted).fill(0), ...tail];
}

/**
 * Serialize eight groups to the RFC 5952 canonical form, matching Go's
 * net.IP.String(): lowercase, no leading zeros, and the longest run of two or
 * more zero groups collapsed to "::". A single zero group is never collapsed.
 */
function formatIPv6(groups: number[]): string {
  let bestStart = -1;
  let bestLen = 1; // a run must exceed one group to be worth collapsing
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    // Strictly greater, so the leftmost of two equal-length runs wins.
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }

  const hex = (g: number) => g.toString(16);
  if (bestStart === -1) return groups.map(hex).join(':');
  const head = groups.slice(0, bestStart).map(hex).join(':');
  const tail = groups.slice(bestStart + bestLen).map(hex).join(':');
  return `${head}::${tail}`;
}

/**
 * An IPv4-mapped address (::ffff:a.b.c.d, equivalently ::ffff:XXXX:XXXX) is an
 * IPv4 address in IPv6 clothing. Go's To4() unwraps it, so HostCIDR gives it a
 * /32 and prints it as a dotted quad; we match that. In practice the Controller
 * un-maps these before they reach the database, so this is defence in depth -
 * but defence in depth that disagreed with the reference would be worthless.
 */
function mappedIPv4(groups: number[]): string | null {
  for (let i = 0; i < 5; i++) if (groups[i] !== 0) return null;
  if (groups[5] !== 0xffff) return null;
  return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join('.');
}

/**
 * peerCIDR - the canonical single-host CIDR for `ip`: `/32` for an IPv4 (or
 * IPv4-mapped) address, `/128` for an IPv6 one, or null when `ip` is not a
 * valid address literal.
 *
 * Callers must drop the peer when this returns null rather than fall back to a
 * malformed CIDR. kube-apiserver validates every ipBlock and rejects the whole
 * policy if one of them fails to parse, so a single unparseable observed row
 * would otherwise take every legitimate rule in the policy down with it.
 * Dropping fails closed: the peer we could not describe is simply not allowed.
 */
export function peerCIDR(ip: string): string | null {
  const v4 = parseIPv4(ip);
  if (v4 !== null) return `${v4.join('.')}/32`;

  const groups = parseIPv6(ip);
  if (groups === null) return null;

  const mapped = mappedIPv4(groups);
  if (mapped !== null) return `${mapped}/32`;
  return `${formatIPv6(groups)}/128`;
}
