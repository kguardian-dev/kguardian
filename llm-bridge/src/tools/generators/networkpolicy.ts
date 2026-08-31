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

function sortedPeers(rules: Rule[]): Rule[] {
  return [...rules].sort((a, b) => a.peerIP.localeCompare(b.peerIP));
}

// ---- Standard NetworkPolicy --------------------------------------------------

async function standardPeer(ip: string, resolve: PeerResolver): Promise<Record<string, unknown>> {
  const id = await resolve(ip);
  if (id && id.selector && Object.keys(id.selector).length > 0) {
    return {
      podSelector: { matchLabels: id.selector },
      namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": id.namespace ?? "" } },
    };
  }
  return { ipBlock: { cidr: `${ip}/32` } };
}

async function standardRules(rules: Rule[], resolve: PeerResolver, key: "from" | "to"): Promise<unknown[]> {
  const out: unknown[] = [];
  for (const r of sortedPeers(rules)) {
    const peer = await standardPeer(r.peerIP, resolve);
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
  if (ingress.length > 0) { types.push("Ingress"); spec.ingress = await standardRules(ingress, resolve, "from"); }
  if (egress.length > 0) { types.push("Egress"); spec.egress = await standardRules(egress, resolve, "to"); }
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
  return { cidr: [`${ip}/32`] };
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
  if (ingress.length > 0) spec.ingress = await ciliumRules(ingress, resolve, "ingress");
  if (egress.length > 0) spec.egress = await ciliumRules(egress, resolve, "egress");

  return { apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy", metadata: { name: `${pod.name}-cilium-policy`, namespace: pod.namespace, labels: standardLabels(pod.name, "cilium-policy") }, spec, status: {} };
}

/** Serialize a generated policy object to YAML for the tool response. */
export function policyToYAML(policy: Record<string, unknown>): string {
  return stringify(policy);
}
