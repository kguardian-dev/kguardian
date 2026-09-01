import { stringify } from "yaml";

// In-process NetworkPolicy / CiliumNetworkPolicy generation. A faithful
// TypeScript port of the advisor's Go generators (pkg/network standard_policy.go,
// cilium_policy.go, types.go) so the assistant produces the same policy the
// advisor did — letting the advisor Deployment be retired. Parity is proven
// against the shared G2 netpol goldens (compared as parsed objects, since YAML
// serialization differs harmlessly between the Go and TS emitters).
//
// Peer identity is resolved through an injected resolver (broker /svc/ip,
// /pod/ip) — the same seam the advisor uses (BrokerData) and the frontend uses
// (resolveTrafficIdentity).

export interface PeerIdentity {
  // Service selector (priority 1) or pod labels (priority 2); null → external CIDR.
  selector?: Record<string, string>;
  namespace?: string;
}

// resolvePeer(ip) → identity, or null for an unresolvable/external IP.
export type PeerResolver = (ip: string) => Promise<PeerIdentity | null>;

export interface TrafficRow {
  traffic_type?: string;   // INGRESS | EGRESS
  pod_port?: string;       // our pod's port (ingress)
  traffic_in_out_ip?: string;   // peer IP
  traffic_in_out_port?: string; // peer port (egress)
  ip_protocol?: string;    // TCP | UDP
}

export interface PodInfo {
  name: string;
  namespace: string;
  ip: string;
  labels: Record<string, string>;
}

interface Port { port: number; protocol: string }
interface Rule { peerIP: string; ports: Port[] }

function parsePort(p: string): number | null {
  const n = Number(p);
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return null;
  return n;
}

// mergeOrAppendRule — group by peer IP, dedup (port,protocol). Mirrors types.go.
function mergeOrAppend(rules: Rule[], peer: string, port: number, protocol: string): void {
  for (const r of rules) {
    if (r.peerIP === peer) {
      if (r.ports.some((p) => p.port === port && p.protocol === protocol)) return;
      r.ports.push({ port, protocol });
      return;
    }
  }
  rules.push({ peerIP: peer, ports: [{ port, protocol }] });
}

// deduplicatePorts — sort by port asc then protocol asc, drop dups. Mirrors the
// Go helper that keeps regenerated YAML diff-stable.
function dedupePorts(ports: Port[]): Port[] {
  const seen = new Set<string>();
  const out: Port[] = [];
  for (const p of [...ports].sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol))) {
    const k = `${p.port}/${p.protocol}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(p);
  }
  return out;
}

const standardLabels = (pod: string, resourceType: string) => ({
  "app.kubernetes.io/name": pod,
  "app.kubernetes.io/component": resourceType,
  "app.kubernetes.io/part-of": "kguardian",
});

// processTrafficRules — split observed flows into ingress/egress peer rules.
// Ingress peer = traffic_in_out_ip, port = our pod_port. Egress peer =
// traffic_in_out_ip, port = traffic_in_out_port. Self-traffic + empty peers
// dropped. Mirrors the Go generators (shared by standard + cilium).
function processTrafficRules(traffic: TrafficRow[], pod: PodInfo): { ingress: Rule[]; egress: Rule[] } {
  const ingress: Rule[] = [];
  const egress: Rule[] = [];
  for (const t of traffic) {
    const peer = t.traffic_in_out_ip ?? "";
    if (!peer || peer === pod.ip) continue;
    const protocol = (t.ip_protocol ?? "TCP").toUpperCase();
    const type = (t.traffic_type ?? "").toUpperCase();
    if (type === "INGRESS") {
      const port = parsePort(t.pod_port ?? "");
      if (port === null) continue;
      mergeOrAppend(ingress, peer, port, protocol);
    } else if (type === "EGRESS") {
      const port = parsePort(t.traffic_in_out_port ?? "");
      if (port === null) continue;
      mergeOrAppend(egress, peer, port, protocol);
    }
  }
  return { ingress, egress };
}

// Peers are ordered by the RAW observed IP string, byte for byte, because that
// is what the advisor's sort.Strings does — not family-grouped, not numeric, and
// deliberately not canonicalized first. Canonicalization happens later, in
// peerCIDR at emit time; normalizing before the sort would reorder any peer
// whose observed text differs from its canonical form and silently desync the
// rule order from the goldens.
//
// The comparison must be bytewise. localeCompare (used here previously) is
// collation-aware: it treats ":" as ignorable punctuation and orders case
// before byte value, so it disagrees with Go on ordinary input — given
// 10.96.0.10, fd00::7 and fd00:96::a it yields fd00::7 before fd00:96::a, where
// Go yields the reverse. For ASCII, comparing UTF-16 code units as below is
// identical to Go comparing UTF-8 bytes.
function sortedPeers(rules: Rule[]): Rule[] {
  return [...rules].sort((a, b) => (a.peerIP < b.peerIP ? -1 : a.peerIP > b.peerIP ? 1 : 0));
}

// ---- Peer CIDR ---------------------------------------------------------------
//
// Two invariants, both of which must agree with the advisor's Go reference
// (common.HostCIDR) since both are compared against the same goldens:
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
//     observed string would pass goldens written in canonical form and then
//     disagree with every other component on a real cluster.
//
// node:net's isIP() can validate but cannot canonicalize, so the address is
// parsed here. This is deliberately kept logically identical to the peerCIDR
// helper in frontend/src/utils/ipCidr.ts - the two packages cannot share a
// module, so they share semantics instead.

// Strict dotted quad. Leading zeros are rejected as octal-ambiguous, matching
// Go's net.ParseIP (which has rejected them since 1.17).
const IPV4_OCTET_RE = /^(0|[1-9]\d{0,2})$/;
const IPV6_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;

/** Parse a dotted quad into its four octets, or null. */
function parseIPv4(ip: string): number[] | null {
  const octets = ip.split(".");
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
  if (ip.includes("%")) return null;

  const halves = ip.split("::");
  if (halves.length > 2) return null; // "::" may appear at most once
  const compressed = halves.length === 2;

  // Groups written out explicitly, split across the two sides of any "::".
  const sides: number[][] = [[], []];
  for (let i = 0; i < halves.length; i++) {
    if (halves[i] === "") continue; // the empty side of a leading/trailing "::"
    const segments = halves[i].split(":");
    for (let j = 0; j < segments.length; j++) {
      const segment = segments[j];
      if (segment.includes(".")) {
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

// Serialize eight groups to the RFC 5952 canonical form, matching Go's
// net.IP.String(): lowercase, no leading zeros, longest run of two or more zero
// groups collapsed to "::". A single zero group is never collapsed.
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
  if (bestStart === -1) return groups.map(hex).join(":");
  const head = groups.slice(0, bestStart).map(hex).join(":");
  const tail = groups.slice(bestStart + bestLen).map(hex).join(":");
  return `${head}::${tail}`;
}

// An IPv4-mapped address (::ffff:a.b.c.d) is an IPv4 address in IPv6 clothing.
// Go's To4() unwraps it, so HostCIDR gives it a /32 and prints it as a dotted
// quad; we match that. The Controller un-maps these before they reach the
// database, so this is defence in depth - but defence in depth that disagreed
// with the reference implementation would be worthless.
function mappedIPv4(groups: number[]): string | null {
  for (let i = 0; i < 5; i++) if (groups[i] !== 0) return null;
  if (groups[5] !== 0xffff) return null;
  return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(".");
}

// peerCIDR - the canonical single-host CIDR for an observed peer, or null when
// the address does not parse. Callers DROP the rule on null rather than fall
// back to a malformed CIDR: kube-apiserver validates every ipBlock and rejects
// the whole policy if one fails to parse, so a single bad observed row would
// otherwise take every legitimate rule down with it. Dropping fails closed -
// the peer we could not describe is simply not allowed.
function peerCIDR(ip: string): string | null {
  const v4 = parseIPv4(ip);
  if (v4 !== null) return `${v4.join(".")}/32`;

  const groups = parseIPv6(ip);
  if (groups === null) return null;

  const mapped = mappedIPv4(groups);
  if (mapped !== null) return `${mapped}/32`;
  return `${formatIPv6(groups)}/128`;
}

// ---- Standard NetworkPolicy --------------------------------------------------

async function standardPeer(ip: string, resolve: PeerResolver): Promise<Record<string, unknown> | null> {
  const id = await resolve(ip);
  if (id && id.selector && Object.keys(id.selector).length > 0) {
    return {
      podSelector: { matchLabels: id.selector },
      namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": id.namespace ?? "" } },
    };
  }
  const cidr = peerCIDR(ip);
  return cidr === null ? null : { ipBlock: { cidr } };
}

async function standardRules(rules: Rule[], resolve: PeerResolver, key: "from" | "to"): Promise<unknown[]> {
  const out: unknown[] = [];
  for (const r of sortedPeers(rules)) {
    const peer = await standardPeer(r.peerIP, resolve);
    if (peer === null) continue; // unparseable peer IP - see peerCIDR
    out.push({
      [key]: [peer],
      ports: dedupePorts(r.ports).map((p) => ({ protocol: p.protocol, port: p.port })),
    });
  }
  return out;
}

export async function generateNetworkPolicy(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<Record<string, unknown>> {
  const { ingress, egress } = processTrafficRules(traffic, pod);

  if (ingress.length === 0 && egress.length === 0) {
    return {
      apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
      metadata: { name: `${pod.name}-standard-policy-deny-all`, namespace: pod.namespace, labels: standardLabels(pod.name, "standard-policy-deny-all") },
      // No empty ingress/egress arrays: the advisor's Go type omitempties them,
      // so the emitted YAML carries only policyTypes for a default-deny.
      spec: { podSelector: { matchLabels: pod.labels }, policyTypes: ["Ingress", "Egress"] },
    };
  }

  const spec: Record<string, unknown> = { podSelector: { matchLabels: pod.labels }, policyTypes: [] as string[] };
  const types: string[] = [];
  // The policyType is driven by the direction being OBSERVED, not by the rule
  // list surviving: if every peer in a direction dropped out (unparseable IPs),
  // the direction stays default-denied and the empty list is omitted, matching
  // the advisor's omitempty serialization.
  if (ingress.length > 0) {
    types.push("Ingress");
    const rules = await standardRules(ingress, resolve, "from");
    if (rules.length > 0) spec.ingress = rules;
  }
  if (egress.length > 0) {
    types.push("Egress");
    const rules = await standardRules(egress, resolve, "to");
    if (rules.length > 0) spec.egress = rules;
  }
  spec.policyTypes = types;

  return {
    apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
    metadata: { name: `${pod.name}-standard-policy`, namespace: pod.namespace, labels: standardLabels(pod.name, "standard-policy") },
    spec,
  };
}

// ---- Cilium NetworkPolicy ----------------------------------------------------

const k8sPrefixed = (labels: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(labels).map(([k, v]) => [`k8s:${k}`, v]));

async function ciliumPeer(ip: string, resolve: PeerResolver): Promise<{ endpoints?: unknown[]; cidr?: string[] }> {
  const id = await resolve(ip);
  if (id && id.selector && Object.keys(id.selector).length > 0) {
    return { endpoints: [{ matchLabels: k8sPrefixed(id.selector) }] };
  }
  // Neither key set when the IP is unparseable; ciliumRules drops the rule,
  // since a Cilium rule with no peer field selects ALL peers.
  const cidr = peerCIDR(ip);
  return cidr === null ? {} : { cidr: [cidr] };
}

async function ciliumRules(rules: Rule[], resolve: PeerResolver, dir: "ingress" | "egress"): Promise<unknown[]> {
  const out: unknown[] = [];
  for (const r of sortedPeers(rules)) {
    const peer = await ciliumPeer(r.peerIP, resolve);
    const rule: Record<string, unknown> = {};
    const epKey = dir === "ingress" ? "fromEndpoints" : "toEndpoints";
    const cidrKey = dir === "ingress" ? "fromCIDR" : "toCIDR";
    if (peer.endpoints) rule[epKey] = peer.endpoints;
    else if (peer.cidr) rule[cidrKey] = peer.cidr;
    else continue;
    rule.toPorts = [{ ports: dedupePorts(r.ports).map((p) => ({ port: String(p.port), protocol: p.protocol })) }];
    out.push(rule);
  }
  return out;
}

export async function generateCiliumPolicy(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<Record<string, unknown>> {
  const { ingress, egress } = processTrafficRules(traffic, pod);
  const endpointSelector = { matchLabels: k8sPrefixed(pod.labels) };

  if (ingress.length === 0 && egress.length === 0) {
    return {
      apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy",
      metadata: { name: `${pod.name}-cilium-policy-deny-all`, namespace: pod.namespace, labels: standardLabels(pod.name, "cilium-policy-deny-all") },
      spec: { endpointSelector, description: `Default-deny Cilium network policy for pod ${pod.name}`, enableDefaultDeny: { ingress: true, egress: true } },
      status: {},
    };
  }

  const spec: Record<string, unknown> = {
    endpointSelector,
    description: `Cilium network policy for pod ${pod.name} generated by kguardian`,
  };
  // As above, an empty list is omitted rather than emitted - only reachable
  // when every peer in the direction had an unparseable IP.
  if (ingress.length > 0) {
    const rules = await ciliumRules(ingress, resolve, "ingress");
    if (rules.length > 0) spec.ingress = rules;
  }
  if (egress.length > 0) {
    const rules = await ciliumRules(egress, resolve, "egress");
    if (rules.length > 0) spec.egress = rules;
  }

  return { apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy", metadata: { name: `${pod.name}-cilium-policy`, namespace: pod.namespace, labels: standardLabels(pod.name, "cilium-policy") }, spec, status: {} };
}

/** Serialize a generated policy object to YAML for the tool response. */
export function policyToYAML(policy: Record<string, unknown>): string {
  return stringify(policy);
}
