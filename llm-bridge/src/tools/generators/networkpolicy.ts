import { Document, stringify, isNode } from "yaml";
import { log } from "../../logger.js";

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
  // Host-network pod (broker host_network === true). Takes precedence over
  // selector: its labels select nothing the CNI can see, so the peer is
  // rendered as the observed node IP (NetworkPolicy ipBlock) or the host
  // entities (Cilium) with an explanatory comment. false/undefined ⇒ normal.
  hostNetwork?: boolean;
  // Identity for the comment: workload_name (falls back to podName) and
  // node_name (falls back to the observed IP). For a Service whose backing
  // pods are host-network, `service` is the Service name (rendered as
  // "<ns>/svc/<name>") and `node` the sorted, deduped node list of those pods.
  podName?: string;
  workload?: string;
  node?: string;
  service?: string;
  // Service case only: distinct backend pod IPs (= node IPs), sorted bytewise.
  // NetworkPolicy is evaluated post-DNAT, so these — never the ClusterIP —
  // are the ipBlock peers. Cilium ignores them (entities cover every node).
  backendIPs?: string[];
}

// The broker /pod/info record fields consulted when deciding whether a
// Service fronts host-network pods.
export interface BrokerPodListEntry {
  pod_name?: string; pod_namespace?: string; pod_ip?: string; host_network?: boolean | null;
  node_name?: string; is_dead?: boolean;
  pod_obj?: { metadata?: { labels?: Record<string, string> }; spec?: { nodeName?: string } };
}

function labelsContain(labels: Record<string, string> | undefined, selector: Record<string, string>): boolean {
  return Object.entries(selector).every(([k, v]) => labels?.[k] === v);
}

/**
 * Host-network identity for a Service, or null when none of its alive,
 * selector-matching backing pods (same namespace) is host_network === true.
 * Mirrors advisor hostNetworkServiceBackends/hostNetworkServiceComment: the
 * node is the sorted, deduplicated node list (node_name, then
 * pod_obj.spec.nodeName) of the host-network backends; empty ⇒ the generator
 * falls back to the observed IP.
 */
export function hostNetworkServiceIdentity(
  svc: { svc_name?: string; svc_namespace?: string; selector: Record<string, string> },
  pods: BrokerPodListEntry[],
): PeerIdentity | null {
  if (!svc.svc_name || Object.keys(svc.selector).length === 0) return null;
  const backends = pods.filter((p) =>
    p && !p.is_dead && p.pod_namespace === svc.svc_namespace && p.host_network === true
    && labelsContain(p.pod_obj?.metadata?.labels, svc.selector));
  if (backends.length === 0) return null;
  const nodes = [...new Set(backends.map((p) => p.node_name || p.pod_obj?.spec?.nodeName || "").filter(Boolean))].sort();
  const backendIPs = [...new Set(backends.map((p) => p.pod_ip || "").filter(Boolean))].sort();
  return { hostNetwork: true, namespace: svc.svc_namespace, service: svc.svc_name, selector: svc.selector, node: nodes.join(","), backendIPs };
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
  // broker host_network for the TARGET pod: true ⇒ the policy is headed by a
  // WARNING (no selector can select a host-network pod). null/undefined/false
  // ⇒ unchanged output.
  hostNetwork?: boolean | null;
  workload?: string;
}

// YAML comments emitted beside a policy. The policy object cannot carry them,
// so generators return them separately and policyToYAML splices them in.
// Lines are stored without the leading "# ". Rule comments are keyed by the
// index of the emitted rule in spec.ingress / spec.egress.
export interface PolicyComments {
  header: string[];
  ingress: Record<number, string[]>;
  egress: Record<number, string[]>;
}

export interface GeneratedPolicy {
  policy: Record<string, unknown>;
  comments: PolicyComments;
}

const newComments = (): PolicyComments => ({ header: [], ingress: {}, egress: {} });

function addRuleComment(bucket: Record<number, string[]>, idx: number, line: string): void {
  if (!line) return;
  (bucket[idx] ??= []).push(line);
}

export function hasComments(c: PolicyComments | undefined): boolean {
  return !!c && (c.header.length > 0 || Object.keys(c.ingress).length > 0 || Object.keys(c.egress).length > 0);
}

// ---- Host-network peers and targets ------------------------------------------
//
// Mirrors advisor pkg/network/hostnetwork.go: identical wording, identical
// fallbacks, because the goldens pin the comment lines too.

const hostWorkloadName = (workload: string | undefined, name: string | undefined): string => workload || name || "";

function hostPeerComment(id: PeerIdentity, peerIP: string, selector: string): string {
  const who = `${id.namespace ?? ""}/${id.service ? `svc/${id.service}` : hostWorkloadName(id.workload, id.podName)}`;
  return `host-network peer ${who} on node ${id.node || peerIP} — ${selector} cannot match host traffic`;
}

function hostTargetWarning(pod: PodInfo, kind: string, selector: string): string[] {
  return [
    `WARNING: ${pod.namespace}/${hostWorkloadName(pod.workload, pod.name)} runs with hostNetwork: true. A ${kind} ${selector} cannot select`,
    "host-network pods; this policy will have no effect. Use a CiliumClusterwideNetworkPolicy",
    "with a nodeSelector (host firewall) instead.",
  ];
}

// Both entities: `host` is the local node, `remote-node` every other node,
// and the peer may sit on either.
const HOST_ENTITIES = ["host", "remote-node"];

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

// standardPeer resolves one observed peer IP to its NetworkPolicy peer set.
// Every path yields exactly one peer except a Service backed by host-network
// pods, which yields one ipBlock per backend node IP (the post-DNAT
// destinations — never the ClusterIP). null ⇒ drop the rule. `comment` is
// non-empty only for host-network peers, which are pinned by node IP (no
// namespaceSelector) because no podSelector can match them.
async function standardPeer(ip: string, resolve: PeerResolver): Promise<{ peers: Record<string, unknown>[]; comment: string } | null> {
  const id = await resolve(ip);
  if (id?.hostNetwork === true) {
    const comment = hostPeerComment(id, ip, "podSelector");
    if (id.service) {
      const cidrs = (id.backendIPs ?? []).map(peerCIDR).filter((c): c is string => c !== null);
      return cidrs.length === 0 ? null : { peers: cidrs.map((cidr) => ({ ipBlock: { cidr } })), comment };
    }
    const cidr = peerCIDR(ip);
    return cidr === null ? null : { peers: [{ ipBlock: { cidr } }], comment };
  }
  if (id && id.selector && Object.keys(id.selector).length > 0) {
    return {
      peers: [{
        podSelector: { matchLabels: id.selector },
        namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": id.namespace ?? "" } },
      }],
      comment: "",
    };
  }
  const cidr = peerCIDR(ip);
  return cidr === null ? null : { peers: [{ ipBlock: { cidr } }], comment: "" };
}

async function standardRules(
  rules: Rule[], resolve: PeerResolver, key: "from" | "to", comments: Record<number, string[]>,
): Promise<unknown[]> {
  const out: unknown[] = [];
  for (const r of sortedPeers(rules)) {
    const resolved = await standardPeer(r.peerIP, resolve);
    if (resolved === null) continue; // unparseable peer IP - see peerCIDR
    addRuleComment(comments, out.length, resolved.comment);
    out.push({
      [key]: resolved.peers,
      ports: dedupePorts(r.ports).map((p) => ({ protocol: p.protocol, port: p.port })),
    });
  }
  return out;
}

/** generateNetworkPolicy without the comments — kept for existing callers. */
export async function generateNetworkPolicy(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<Record<string, unknown>> {
  return (await generateNetworkPolicyWithComments(pod, traffic, resolve)).policy;
}

export async function generateNetworkPolicyWithComments(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<GeneratedPolicy> {
  const { ingress, egress } = processTrafficRules(traffic, pod);
  const comments = newComments();
  if (pod.hostNetwork === true) comments.header.push(...hostTargetWarning(pod, "NetworkPolicy", "podSelector"));

  if (ingress.length === 0 && egress.length === 0) {
    return {
      policy: {
        apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
        metadata: { name: `${pod.name}-standard-policy-deny-all`, namespace: pod.namespace, labels: standardLabels(pod.name, "standard-policy-deny-all") },
        // No empty ingress/egress arrays: the advisor's Go type omitempties them,
        // so the emitted YAML carries only policyTypes for a default-deny.
        spec: { podSelector: { matchLabels: pod.labels }, policyTypes: ["Ingress", "Egress"] },
      },
      comments,
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
    const rules = await standardRules(ingress, resolve, "from", comments.ingress);
    if (rules.length > 0) spec.ingress = rules;
  }
  if (egress.length > 0) {
    types.push("Egress");
    const rules = await standardRules(egress, resolve, "to", comments.egress);
    if (rules.length > 0) spec.egress = rules;
  }
  spec.policyTypes = types;

  return {
    policy: {
      apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
      metadata: { name: `${pod.name}-standard-policy`, namespace: pod.namespace, labels: standardLabels(pod.name, "standard-policy") },
      spec,
    },
    comments,
  };
}

// ---- Cilium NetworkPolicy ----------------------------------------------------

const k8sPrefixed = (labels: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(labels).map(([k, v]) => [`k8s:${k}`, v]));

// Exactly one of endpoints / entities / cidr is set; none when the IP is
// unparseable (ciliumRules drops the rule, since a Cilium rule with no peer
// field selects ALL peers). `comment` is set only for host-network peers.
interface CiliumPeer { endpoints?: unknown[]; entities?: string[]; cidr?: string[]; comment: string }

// Cilium attaches every pod endpoint's namespace as this (source-prefixed)
// label. An endpoint selector WITHOUT it is scoped to the policy's own
// namespace, so a cross-namespace peer rendered from its labels alone matches
// nothing and the flow is denied (media/maintainerr → downloads/sonarr).
const CILIUM_NAMESPACE_LABEL = "k8s:io.kubernetes.pod.namespace";

// peerEndpointSelector — the from/toEndpoints selector for a peer with the
// given labels living in peerNamespace, relative to the policy's namespace.
// Same-namespace peers are unchanged; an unknown peer namespace cannot be
// fixed here and is logged. Mirrors advisor createPeerEndpointSelector.
function peerEndpointSelector(labels: Record<string, string>, peerNamespace: string | undefined, policyNamespace: string): Record<string, string> {
  const matchLabels = k8sPrefixed(labels);
  if (!peerNamespace) {
    log.warn(`peer namespace unknown for labels ${JSON.stringify(labels)}; Cilium endpoint selector is scoped to namespace ${policyNamespace} and will not match a cross-namespace peer`);
    return matchLabels;
  }
  if (peerNamespace !== policyNamespace) matchLabels[CILIUM_NAMESPACE_LABEL] = peerNamespace;
  return matchLabels;
}

async function ciliumPeer(ip: string, resolve: PeerResolver, policyNamespace: string): Promise<CiliumPeer> {
  const id = await resolve(ip);
  if (id?.hostNetwork === true) {
    // A host-network pod is not a Cilium endpoint; it carries the node's
    // identity. Select that identity rather than labels nothing will match.
    return { entities: [...HOST_ENTITIES], comment: hostPeerComment(id, ip, "endpointSelector") };
  }
  if (id && id.selector && Object.keys(id.selector).length > 0) {
    return { endpoints: [{ matchLabels: peerEndpointSelector(id.selector, id.namespace, policyNamespace) }], comment: "" };
  }
  const cidr = peerCIDR(ip);
  return cidr === null ? { comment: "" } : { cidr: [cidr], comment: "" };
}

const portsKey = (ports: Port[]): string => ports.map((p) => `${p.port}/${p.protocol}`).join(",");

// Host-network peers collapse into ONE entities rule per distinct port list
// (the entities already cover every node): the rule sits where the first such
// peer fell in sorted-IP order, and later same-port peers only add their
// comment line to it. Mirrors transformToCilium{Ingress,Egress}Rules in Go.
async function ciliumRules(
  rules: Rule[], resolve: PeerResolver, dir: "ingress" | "egress", comments: Record<number, string[]>, policyNamespace: string,
): Promise<unknown[]> {
  const out: unknown[] = [];
  const entityRuleByPorts = new Map<string, number>();
  for (const r of sortedPeers(rules)) {
    const peer = await ciliumPeer(r.peerIP, resolve, policyNamespace);
    const rule: Record<string, unknown> = {};
    const epKey = dir === "ingress" ? "fromEndpoints" : "toEndpoints";
    const entKey = dir === "ingress" ? "fromEntities" : "toEntities";
    const cidrKey = dir === "ingress" ? "fromCIDR" : "toCIDR";
    const ports = dedupePorts(r.ports);
    if (peer.endpoints) rule[epKey] = peer.endpoints;
    else if (peer.entities) {
      const key = portsKey(ports);
      const existing = entityRuleByPorts.get(key);
      if (existing !== undefined) { addRuleComment(comments, existing, peer.comment); continue; }
      entityRuleByPorts.set(key, out.length);
      rule[entKey] = peer.entities;
    }
    else if (peer.cidr) rule[cidrKey] = peer.cidr;
    else continue;
    rule.toPorts = [{ ports: ports.map((p) => ({ port: String(p.port), protocol: p.protocol })) }];
    addRuleComment(comments, out.length, peer.comment);
    out.push(rule);
  }
  return out;
}

/** generateCiliumPolicy without the comments — kept for existing callers. */
export async function generateCiliumPolicy(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<Record<string, unknown>> {
  return (await generateCiliumPolicyWithComments(pod, traffic, resolve)).policy;
}

export async function generateCiliumPolicyWithComments(
  pod: PodInfo, traffic: TrafficRow[], resolve: PeerResolver,
): Promise<GeneratedPolicy> {
  const { ingress, egress } = processTrafficRules(traffic, pod);
  const endpointSelector = { matchLabels: k8sPrefixed(pod.labels) };
  const comments = newComments();
  if (pod.hostNetwork === true) comments.header.push(...hostTargetWarning(pod, "CiliumNetworkPolicy", "endpointSelector"));

  if (ingress.length === 0 && egress.length === 0) {
    return {
      policy: {
        apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy",
        metadata: { name: `${pod.name}-cilium-policy-deny-all`, namespace: pod.namespace, labels: standardLabels(pod.name, "cilium-policy-deny-all") },
        spec: { endpointSelector, description: `Default-deny Cilium network policy for pod ${pod.name}`, enableDefaultDeny: { ingress: true, egress: true } },
        status: {},
      },
      comments,
    };
  }

  const spec: Record<string, unknown> = {
    endpointSelector,
    description: `Cilium network policy for pod ${pod.name} generated by kguardian`,
  };
  // As above, an empty list is omitted rather than emitted - only reachable
  // when every peer in the direction had an unparseable IP.
  if (ingress.length > 0) {
    const rules = await ciliumRules(ingress, resolve, "ingress", comments.ingress, pod.namespace);
    if (rules.length > 0) spec.ingress = rules;
  }
  if (egress.length > 0) {
    const rules = await ciliumRules(egress, resolve, "egress", comments.egress, pod.namespace);
    if (rules.length > 0) spec.egress = rules;
  }

  return {
    policy: { apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy", metadata: { name: `${pod.name}-cilium-policy`, namespace: pod.namespace, labels: standardLabels(pod.name, "cilium-policy") }, spec, status: {} },
    comments,
  };
}

/**
 * Serialize a generated policy object to YAML for the tool response. With no
 * comments this is exactly `stringify(policy)` (the pre-existing output);
 * otherwise the comments are attached to the document / rule nodes so the
 * emitter renders them as `# ...` lines above the header / rule.
 */
export function policyToYAML(policy: Record<string, unknown>, comments?: PolicyComments): string {
  if (!hasComments(comments)) return stringify(policy);
  const c = comments as PolicyComments;
  const doc = new Document(policy);
  const asComment = (lines: string[]) => lines.map((l) => ` ${l}`).join("\n");
  if (c.header.length > 0) doc.commentBefore = asComment(c.header);
  for (const dir of ["ingress", "egress"] as const) {
    for (const [idx, lines] of Object.entries(c[dir])) {
      const node = doc.getIn(["spec", dir, Number(idx)], true);
      if (isNode(node)) node.commentBefore = asComment(lines);
    }
  }
  return doc.toString();
}
