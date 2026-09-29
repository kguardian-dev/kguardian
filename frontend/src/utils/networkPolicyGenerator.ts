import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPeer, NetworkPolicyPort } from '../types/networkPolicy';
import { apiClient } from '../services/api';
import { createRowIdentityResolver, type IdentitySources, type TrafficIdentity } from './trafficIdentity';
import { isValidCidr, peerCIDR } from './ipCidr';
import { collapseToServiceIdentity, identityKey, newerRow, selectorlessServiceComment, unattributedPeerComment } from './peerComments';
import { mapServicePort, servicePortsByRow, unmappedServicePortComments } from './serviceTargetPort';
import {
  hostNetworkPeerComment,
  hostNetworkServiceBackends,
  hostNetworkServiceComment,
  hostNetworkTargetName,
  hostNetworkTargetWarning,
  isHostNetworkTarget,
  specNodeName,
  yamlComments,
} from './hostNetwork';

/**
 * The port of an observed row, or null when it has none NetworkPolicy can
 * express: missing, not a decimal number, or outside 1-65535 (ICMP rows carry
 * "0"). The row is then skipped, as the advisor's parsePort skips it
 * (standard_policy.go), rather than rendered as a port the API server rejects.
 * Shared with the Cilium generator so both skip the same rows.
 */
export function observedPort(port: string | null | undefined): string | null {
  if (!port || !/^[0-9]+$/.test(port)) return null;
  const n = Number(port);
  return n >= 1 && n <= 65535 ? String(n) : null;
}

/** The protocol of an observed row: TCP, UDP or SCTP, anything else TCP, as
 *  the advisor's protocolPtr maps it. */
export function observedProtocol(protocol: string | null | undefined): string {
  const p = (protocol ?? '').toUpperCase();
  return p === 'UDP' || p === 'SCTP' ? p : 'TCP';
}

/**
 * `sources` are the listings the caller already holds (the map's pods and
 * Services); without them the resolver downloads `/pod/info` again.
 */
export async function generateNetworkPolicy(pod: PodNodeData, sources: IdentitySources = {}): Promise<NetworkPolicy> {
  const ingressRules: NetworkPolicyRule[] = [];
  const egressRules: NetworkPolicyRule[] = [];

  // Create one rule per unique peer with all its ports
  interface PeerInfo {
    ip: string;
    identity: TrafficIdentity;
  }
  // `unmapped`: observed Service ports (`PROTOCOL:port`) that spec.ports
  // could not map to a targetPort; each gets a comment above the rule.
  const ingressMap = new Map<string, { peer: PeerInfo; ports: Set<string>; unmapped?: Set<string> }>();
  const egressMap = new Map<string, { peer: PeerInfo; ports: Set<string>; unmapped?: Set<string> }>();

  // Resolve every ROW to an identity — not every IP. Pod IPs are recycled,
  // so two rows from one IP months apart can be two different peers. The
  // row's stored `peer_*` (resolved by the broker at ingest) wins; a row
  // without one falls back to a by-IP lookup guarded by the flow time
  // (utils/peerResolution).
  const resolver = await createRowIdentityResolver(sources);
  const rows: NetworkTraffic[] = pod.traffic ?? [];
  const identities = await Promise.all(rows.map((t) => resolver.resolve(t)));
  const rowIdentity = new Map<NetworkTraffic, TrafficIdentity>();
  rows.forEach((t, i) => rowIdentity.set(t, identities[i]));

  // Egress to a Service is observed pre-DNAT, on the Service port; the rule
  // must allow the backend targetPort (utils/serviceTargetPort). Read before
  // the collapse below: a pod row redirected to its Service was observed
  // post-DNAT and already carries the container port.
  const svcPorts = await servicePortsByRow(rows, rowIdentity, resolver, sources);

  // Deduplicate: a pod peer that is selected by a Service peer also present
  // is redirected to the Service identity, collapsing traffic to both the
  // ClusterIP and its backing pod IP into one rule.
  collapseToServiceIdentity(rowIdentity);

  // Process traffic rules
  rows.forEach((traffic) => {
    const protocol = observedProtocol(traffic.ip_protocol);
    const remoteIP = traffic.traffic_in_out_ip;

    if (!remoteIP) {
      return; // Skip if no remote IP
    }

    // Get the resolved identity for this row
    const identity = rowIdentity.get(traffic) || { isExternal: true };

    const trafficType = traffic.traffic_type?.toLowerCase();

    // Create a unique key for this peer. An unattributed peer shares the
    // external key for its IP: both render the same ipBlock.
    let key: string;
    if (identity.svcName) {
      key = `svc-${identity.svcNamespace || 'default'}-${identity.svcName}`;
    } else if (identity.podName) {
      key = `pod-${identity.podNamespace || 'default'}-${identity.podName}`;
    } else if (identity.unattributed) {
      key = `unattributed-${remoteIP}`;
    } else {
      key = `ip-${remoteIP}`;
    }

    const map = trafficType === 'ingress' ? ingressMap : trafficType === 'egress' ? egressMap : null;
    if (!map) return;
    // For ingress: allow traffic FROM remote IP TO this pod's port.
    // For egress: allow traffic TO remote IP:port.
    const observed = observedPort(trafficType === 'ingress' ? traffic.pod_port : traffic.traffic_in_out_port);
    // No usable port (ICMP rows carry "0"): skip the row, as the advisor does.
    if (observed === null) return;
    const rowSvcPorts = svcPorts.get(traffic);
    const mapped = rowSvcPorts ? mapServicePort(rowSvcPorts, observed, protocol) : { ports: [observed], mapped: true };

    let entry = map.get(key);
    if (!entry) {
      entry = { peer: { ip: remoteIP, identity }, ports: new Set() };
      map.set(key, entry);
    }
    for (const port of mapped.ports) entry.ports.add(`${protocol}:${port}`);
    if (!mapped.mapped) (entry.unmapped ??= new Set()).add(`${protocol}:${observed}`);
    // The group's comment quotes the NEWEST unattributed flow.
    if (identity.unattributed && entry.peer.identity.unattributed && newerRow(identity.unattributed.at, entry.peer.identity.unattributed.at)) {
      entry.peer = { ip: remoteIP, identity };
    }
  });

  // What the by-name pod lookup tells us about a peer: its selector labels
  // (workload labels preferred over pod labels) plus the host-network facts
  // needed to decide whether a podSelector can match it at all.
  interface PeerPodFacts {
    labels: Record<string, string> | null;
    hostNetwork: boolean | undefined;
    nodeName?: string;
    workloadName?: string;
    namespace?: string;
  }

  // One pod listing per generation, fetched lazily and only when a Service
  // peer needs its backends inspected. null = listing failed (unknown).
  let allPods: Promise<readonly PodInfo[] | null> | undefined;
  const listPods = (): Promise<readonly PodInfo[] | null> => {
    if (resolver.pods) return Promise.resolve(resolver.pods);
    if (!allPods) {
      allPods = (async () => {
        try {
          const pods = await apiClient.getAllPods();
          return Array.isArray(pods) ? pods : null;
        } catch {
          return null;
        }
      })();
    }
    return allPods;
  };

  const getPeerPodFacts = async (podName: string): Promise<PeerPodFacts> => {
    const facts: PeerPodFacts = { labels: null, hostNetwork: undefined };
    try {
      // The listing keys pods by name exactly as `/pod/name/{name}` does.
      const podInfo = resolver.index?.podsByName.get(podName) ?? (await apiClient.getPodDetailsByName(podName));
      if (!podInfo) return facts;

      // First try workload selector labels
      if (podInfo.workload_selector_labels && Object.keys(podInfo.workload_selector_labels).length > 0) {
        facts.labels = podInfo.workload_selector_labels;
      } else if (podInfo.pod_obj?.metadata?.labels && Object.keys(podInfo.pod_obj.metadata.labels).length > 0) {
        // Fall back to pod labels from pod spec
        facts.labels = podInfo.pod_obj.metadata.labels;
      }
      // null/absent host_network (old broker) stays undefined ⇒ legacy rendering.
      if (typeof podInfo.host_network === 'boolean') facts.hostNetwork = podInfo.host_network;
      facts.nodeName = podInfo.node_name || specNodeName(podInfo) || undefined;
      facts.workloadName = podInfo.workload_name || undefined;
      facts.namespace = podInfo.pod_namespace || undefined;
    } catch {
      // If we can't fetch the pod, fall back to name-derived labels
    }
    return facts;
  };

  interface ResolvedPeer {
    // Usually one peer; a Service backed by host-network pods yields one
    // ipBlock per backend node IP in a single rule.
    peers: NetworkPolicyPeer[];
    // Set only for a host-network peer: the explanatory comment line.
    hostNetworkComment?: string;
    // Any other explanatory comment (unattributed peer, gone stored peer).
    comment?: string;
  }

  // A host-network pod shares the node's IP and network identity, so a
  // podSelector on its labels never matches its traffic. Pin the observed
  // node IP instead (no namespaceSelector — an ipBlock may not be combined
  // with selectors in one peer) and say why in a comment above the rule.
  const hostNetworkPeer = (
    peerInfo: PeerInfo,
    namespace: string,
    name: string,
    node: string,
  ): ResolvedPeer | null => {
    const cidr = peerCIDR(peerInfo.ip);
    if (cidr === null) return null;
    return {
      peers: [{ ipBlock: { cidr } }],
      hostNetworkComment: hostNetworkPeerComment('standard', namespace, name, node),
    };
  };

  // Helper function to create peer based on identity type
  // Returns null when the peer is an external IP that does not parse as an
  // address literal - see peerCIDR; the caller drops the rule in that case.
  const createPeer = async (peerInfo: PeerInfo): Promise<ResolvedPeer | null> => {
    const { identity } = peerInfo;

    if (identity.svcName) {
      // No selector means no backend labels, and the ClusterIP is gone after
      // DNAT: pin the observed address with a comment saying so, rather than
      // a guessed `{app: <svc>}` selector that matches nothing silently.
      if (identity.svcNoSelector) {
        const cidr = peerCIDR(peerInfo.ip);
        if (cidr === null) return null;
        return {
          peers: [{ ipBlock: { cidr } }],
          comment: selectorlessServiceComment(identity.svcNamespace || 'default', identity.svcName, peerInfo.ip, 'ipBlock'),
        };
      }

      // A Service fronting host-network pods fronts node IPs: its selector
      // matches labels no policy can see. NetworkPolicy is evaluated after
      // the Service DNAT, so the ClusterIP never appears on the wire either —
      // pin the backends' node IPs, one ipBlock each, in a single rule.
      const backends = hostNetworkServiceBackends(await listPods(), identity.svcNamespace, identity.svcSelector);
      if (backends.length > 0) {
        const cidrs = Array.from(new Set(backends.map((b) => b.pod_ip)))
          .sort()
          .map((ip) => peerCIDR(ip))
          .filter((c): c is string => c !== null);
        // Never fall back to the ClusterIP: a rule for it would be inert.
        if (cidrs.length === 0) return null;
        return {
          peers: cidrs.map((cidr) => ({ ipBlock: { cidr } })),
          hostNetworkComment: hostNetworkServiceComment(
            'standard', identity.svcNamespace || 'default', identity.svcName, backends, peerInfo.ip,
          ),
        };
      }

      // The Service's own selector picks its backends, as the advisor renders
      // it; kube-dns selects `k8s-app: kube-dns`, not `app: kube-dns`. The
      // resolver turns a Service with an unknown spec into an unattributed
      // peer, so a missing selector here is never guessed from the name.
      if (!identity.svcSelector) {
        const cidr = peerCIDR(peerInfo.ip);
        if (cidr === null) return null;
        return { peers: [{ ipBlock: { cidr } }], comment: unattributedPeerComment(peerInfo.ip, undefined, `${identity.svcNamespace || 'default'}/${identity.svcName}`) };
      }

      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: identity.svcSelector,
        },
      };

      // If the service is in a different namespace, add namespace selector
      if (identity.svcNamespace && identity.svcNamespace !== pod.pod.pod_namespace) {
        peer.namespaceSelector = {
          matchLabels: {
            'kubernetes.io/metadata.name': identity.svcNamespace,
          },
        };
      }

      return { peers: [peer] };
    } else if (identity.podName) {
      // Pod - use labels (workload selector labels or pod labels)
      const facts = await getPeerPodFacts(identity.podName);

      // The by-IP lookup (resolveTrafficIdentity) already carries
      // host_network; the by-name lookup is the fallback for a broker that
      // reported it on one route but not the other.
      const hostNetwork = identity.hostNetwork ?? facts.hostNetwork;
      if (hostNetwork === true) {
        return hostNetworkPeer(
          peerInfo,
          identity.podNamespace || facts.namespace || 'default',
          identity.workloadName || facts.workloadName || identity.podName,
          identity.nodeName || facts.nodeName || peerInfo.ip,
        );
      }

      // A stored peer whose record carries no labels has no selector to
      // build: pin the observed IP rather than guess `{app: <pod-name>}`.
      const labels = facts.labels || identity.podLabels || null;
      if (!labels && identity.stored) {
        const cidr = peerCIDR(peerInfo.ip);
        return cidr === null ? null : { peers: [{ ipBlock: { cidr } }] };
      }

      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: labels || { app: identity.podName },
        },
      };

      // If the pod is in a different namespace, add namespace selector
      if (identity.podNamespace && identity.podNamespace !== pod.pod.pod_namespace) {
        peer.namespaceSelector = {
          matchLabels: {
            'kubernetes.io/metadata.name': identity.podNamespace,
          },
        };
      }

      return { peers: [peer] };
    } else {
      // External IP - use IP block. The host mask follows the address family:
      // /32 for IPv4, /128 for IPv6 (a /32 on a v6 address would cover 2^96
      // hosts rather than the single peer we observed).
      const cidr = peerCIDR(peerInfo.ip);
      if (cidr === null) return null;
      // A guarded-out peer (the flow predates every pod that held the IP)
      // is the same ipBlock, with a comment saying no pod could be matched.
      if (identity.unattributed) {
        return { peers: [{ ipBlock: { cidr } }], comment: unattributedPeerComment(identity.unattributed.ip, identity.unattributed.at, identity.unattributed.service, identity.unattributed.reason) };
      }
      return { peers: [{ ipBlock: { cidr } }] };
    }
  };

  // Rules are emitted in bytewise peer-IP order, the same order the advisor
  // and llm-bridge use, so the three generators agree on rule position.
  // Two rules for one IP (it changed hands between flows) order by identity key.
  const sortedByPeerIP = <T extends { peer: PeerInfo }>(map: Map<string, T>): T[] =>
    Array.from(map.values()).sort((a, b) => {
      if (a.peer.ip !== b.peer.ip) return a.peer.ip < b.peer.ip ? -1 : 1;
      const ka = identityKey(a.peer.identity);
      const kb = identityKey(b.peer.identity);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });

  const parsePorts = (ports: Set<string>): NetworkPolicyPort[] =>
    Array.from(ports).map((portStr) => {
      const [protocol, port] = portStr.split(':');
      return {
        protocol: protocol.toUpperCase(),
        // Digits only are a number; a name stays a name, even a digit-led
        // one (`8080-tcp`), which parseInt would truncate to 8080.
        port: /^[0-9]+$/.test(port) ? Number(port) : port,
      };
    });

  // Build rules - one rule per peer with all its ports. Host-network peers
  // are the exception: several of them can share one node IP (every
  // host-network pod on a node does), and they collapse into a single ipBlock
  // rule carrying the union of their ports and one comment line per peer.
  const buildRules = async (
    map: Map<string, { peer: PeerInfo; ports: Set<string>; unmapped?: Set<string> }>,
    direction: 'ingress' | 'egress',
  ): Promise<NetworkPolicyRule[]> => {
    const rules: NetworkPolicyRule[] = [];
    const hostRuleByCidr = new Map<string, NetworkPolicyRule>();
    for (const { peer, ports, unmapped } of sortedByPeerIP(map)) {
      const resolved = await createPeer(peer);
      // An unparseable peer IP drops the whole rule rather than emitting a
      // malformed CIDR, which would make the API server reject the entire policy.
      if (resolved === null) continue;
      const rulePorts = parsePorts(ports);

      // Host-network rules collapse on their ipBlock set (one node IP for a
      // pod peer, the backends' node IPs for a Service peer).
      const cidr = resolved.hostNetworkComment
        ? resolved.peers.map((p) => p.ipBlock?.cidr).filter(Boolean).join(',') || undefined
        : undefined;
      const existing = cidr ? hostRuleByCidr.get(cidr) : undefined;
      const peerComment = resolved.hostNetworkComment ?? resolved.comment;
      const lines = [...(peerComment ? [peerComment] : []), ...unmappedServicePortComments(peer.identity, unmapped)];
      if (existing && resolved.hostNetworkComment) {
        const seen = new Set(existing.ports.map((p) => `${p.protocol}:${p.port}`));
        for (const p of rulePorts) {
          if (!seen.has(`${p.protocol}:${p.port}`)) existing.ports.push(p);
        }
        for (const line of lines) {
          if (!existing.comments!.includes(line)) existing.comments!.push(line);
        }
        continue;
      }

      const rule: NetworkPolicyRule = {
        id: `${direction}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        peers: resolved.peers,
        ports: rulePorts,
        ...(lines.length > 0 && { comments: lines }),
      };
      if (cidr) hostRuleByCidr.set(cidr, rule);
      rules.push(rule);
    }
    return rules;
  };

  ingressRules.push(...(await buildRules(ingressMap, 'ingress')));
  egressRules.push(...(await buildRules(egressMap, 'egress')));

  // Create policy
  // Use pod identity for resource name, fallback to pod name if not available
  const resourceName = pod.pod.pod_identity || pod.pod.pod_name;

  // Get labels for the target pod (workload selector labels or pod labels)
  let targetPodLabels: Record<string, string> = { app: pod.pod.pod_name };

  if (pod.pod.workload_selector_labels && Object.keys(pod.pod.workload_selector_labels).length > 0) {
    targetPodLabels = pod.pod.workload_selector_labels;
  } else if (pod.pod.pod_obj?.metadata?.labels && Object.keys(pod.pod.pod_obj.metadata.labels).length > 0) {
    targetPodLabels = pod.pod.pod_obj.metadata.labels;
  }

  const policy: NetworkPolicy = {
    // A host-network target cannot be selected by any namespaced
    // NetworkPolicy. Emit the policy anyway — the rules are still the right
    // shape for a host-firewall rewrite — but lead with a warning so nobody
    // applies it expecting enforcement.
    ...(isHostNetworkTarget(pod) && { warnings: hostNetworkTargetWarning('standard', pod.pod.pod_namespace || 'default', hostNetworkTargetName(pod)) }),
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: `${resourceName}-policy`,
      namespace: pod.pod.pod_namespace || 'default',
    },
    spec: {
      podSelector: {
        matchLabels: targetPodLabels,
      },
      policyTypes: [],
      ...(ingressRules.length > 0 && { ingress: ingressRules }),
      ...(egressRules.length > 0 && { egress: egressRules }),
    },
  };

  // The policyType is driven by the direction being OBSERVED, not by the rule
  // list surviving. Those were the same thing until unparseable peers began
  // being dropped above: if every peer in a direction fails to resolve, the
  // rule list is empty, and gating the policyType on it would omit the
  // direction entirely — which does not mean "deny", it means the policy stops
  // restricting that direction at all. Keeping the type with an empty rule list
  // is the default-deny form, and matches the advisor (standard_policy.go) and
  // llm-bridge, both of which key off the observed direction for this reason.
  if (ingressMap.size > 0) {
    policy.spec.policyTypes.push('Ingress');
  }
  if (egressMap.size > 0) {
    policy.spec.policyTypes.push('Egress');
  }
  // Nothing observed in either direction is the reference deny-all (advisor,
  // llm-bridge, standard_default_deny golden). Left empty, the API server
  // defaults policyTypes to [Ingress]: deny-all ingress, said nowhere.
  if (policy.spec.policyTypes.length === 0) {
    policy.spec.policyTypes.push('Ingress', 'Egress');
  }

  return policy;
}

// YAML special characters that require quoting a value
/** Characters that force quoting. Retained from the original rule. */
const YAML_SPECIAL_RE = /[:#'"{}[\],&*?|<>=!%@`\n\r-]/;

/**
 * Values YAML 1.1 resolves to a non-string even though they contain no
 * punctuation. kubectl converts YAML to JSON through a YAML 1.1 parser,
 * and `matchLabels` is `map[string]string`, so an unquoted one is a type
 * error at apply time. All are legal Kubernetes label values.
 */
const YAML11_KEYWORDS = new Set([
  'y', 'yes', 'n', 'no', 'true', 'false', 'on', 'off', 'null', '~',
]);

// Deliberately absent: `.inf`, `-.inf` and `.nan`, which YAML 1.1 also
// resolves to floats. Every form starts with a dot or a sign, and
// Kubernetes requires a label key or value to begin and end
// alphanumeric, so none of them is reachable through this function.
// Recorded so the next reader does not have to re-derive it.

/**
 * Every form YAML 1.1 resolves as a number: decimal, binary, octal
 * (both `0o` and bare-leading-zero), hex, float, exponent, and the
 * sexagesimal `1:30` form. Underscores are digit separators in YAML 1.1.
 *
 * A closed set is why this one can be matched positively rather than
 * guessed at: unlike "all YAML special syntax", the numeric grammar is
 * finite and specified. An IP or CIDR like `10.0.0.20/32` matches none
 * of it — two dots and a slash — so it stays unquoted as before.
 */
const YAML11_NUMERIC_RE =
  /^[-+]?(0b[01_]+|0o[0-7_]+|0[0-7_]+|0x[0-9a-fA-F_]+|[0-9][0-9_]*(\.[0-9_]*)?([eE][-+]?[0-9]+)?|\.[0-9_]+([eE][-+]?[0-9]+)?|[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?)$/;

/**
 * A value safe to emit as a plain (unquoted) YAML scalar.
 *
 * Only the type resolvers are its business: the caller has already
 * applied the punctuation rule, and this answers the separate question
 * of whether YAML would read the text as something other than a string.
 *
 * Both halves are positive matches against closed, specified sets — the
 * YAML 1.1 numeric grammar and its boolean/null keywords — rather than
 * an attempt to enumerate everything YAML can reinterpret. That is the
 * mistake the original punctuation-only rule made, and it missed every
 * resolver: `2`, `1.2`, `0x1f` and `1e5` became numbers, `true`, `no`
 * and `null` became booleans and null. Eleven escapes on the first pass.
 */
function isSafePlainScalar(value: string): boolean {
  if (value === '') return false;
  // A backslash is literal in a plain scalar, so this is legal
  // unquoted — but quoting is the predictable direction and no
  // Kubernetes label value contains one, so nothing is lost.
  if (value.includes('\\')) return false;
  if (YAML11_NUMERIC_RE.test(value)) return false;
  return !YAML11_KEYWORDS.has(value.toLowerCase());
}

export function quoteYamlValue(value: string): string {
  // Both checks, and deliberately additive rather than a replacement.
  // The punctuation test is what already quotes hyphenated names like
  // `deployment-web`, and the allowlist alone would permit those —
  // loosening quoting is an output change, and this fix should only
  // ever tighten it. So: quote if the old rule said to, and also quote
  // anything the allowlist does not vouch for.
  if (!YAML_SPECIAL_RE.test(value) && isSafePlainScalar(value)) {
    return value;
  }
  // Double quotes with backslashes escaped before quotes — the other
  // order would double the backslashes the second pass adds.
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * Whether a rule renders. An empty `from` / `to` matches every peer, so a rule
 * the editor holds with no peers (just added, or its last source removed) is
 * left out of the YAML rather than exported as allow-all; the editor says so
 * on the rule. A direction left with no rendered rules keeps its policyType,
 * which is the deny form.
 */
export function ruleHasPeers(rule: NetworkPolicyRule): boolean {
  return rule.peers.length > 0;
}

/** An IANA service name, the form of a named container port: 1-15 lowercase
 *  letters, digits and inner single hyphens, with at least one letter. */
const PORT_NAME_RE = /^(?=.{1,15}$)(?=.*[a-z])[a-z0-9]+(-[a-z0-9]+)*$/;

/**
 * What `NetworkPolicyPort.port` accepts: a number 1-65535 (or its decimal
 * string, as the editor holds it) or a named port. Anything else, including
 * the empty string a cleared field leaves, makes the API server reject the
 * whole policy.
 */
export function isValidPolicyPort(port: string | number): boolean {
  if (typeof port === 'number') return Number.isInteger(port) && port >= 1 && port <= 65535;
  if (/^[0-9]+$/.test(port)) return isValidPolicyPort(Number(port));
  return PORT_NAME_RE.test(port);
}

/** Every invalid port in the rules that render, as `<direction> rule <n>: port "<value>"`. */
export function invalidPolicyPorts(policy: NetworkPolicy): string[] {
  const out: string[] = [];
  (['ingress', 'egress'] as const).forEach((dir) => {
    (policy.spec[dir] ?? []).forEach((rule, i) => {
      if (!ruleHasPeers(rule)) return;
      rule.ports.filter((p) => !isValidPolicyPort(p.port)).forEach((p) => out.push(`${dir} rule ${i + 1}: port "${p.port}"`));
    });
  });
  return out;
}

/** Every malformed ipBlock CIDR (or `except` entry) in the rules that render,
 *  as `<direction> rule <n>: cidr "<value>"`. Typed values only: the
 *  generators emit peerCIDR output, which always parses. */
export function invalidPolicyCidrs(policy: NetworkPolicy): string[] {
  const out: string[] = [];
  (['ingress', 'egress'] as const).forEach((dir) => {
    (policy.spec[dir] ?? []).forEach((rule, i) => {
      if (!ruleHasPeers(rule)) return;
      rule.peers.forEach(({ ipBlock }) => {
        if (!ipBlock) return;
        if (!isValidCidr(ipBlock.cidr)) out.push(`${dir} rule ${i + 1}: cidr "${ipBlock.cidr}"`);
        (ipBlock.except ?? []).filter((e) => !isValidCidr(e)).forEach((e) => out.push(`${dir} rule ${i + 1}: except "${e}"`));
      });
    });
  });
  return out;
}

/** A port number is written as a plain decimal: a digit string with a leading
 *  zero, bare, is octal to a YAML 1.1 decoder (`0100` reads as 64). A named
 *  port is a string, quoted when YAML would read it as something else (`no`). */
const portValue = (port: string | number): string =>
  typeof port === 'number' || /^[0-9]+$/.test(port) ? String(Number(port)) : quoteYamlValue(port);

/** A peer's selector. No labels is written `{}`, the API's "select all"
 *  (every pod in the namespace, or every namespace), rather than a bare
 *  `matchLabels:` that reads as if something were missing. */
function peerSelectorLines(field: 'podSelector' | 'namespaceSelector', labels: Record<string, string>): string[] {
  const entries = Object.entries(labels);
  if (entries.length === 0) return [`      ${field}: {}`];
  return [
    `      ${field}:`,
    '        matchLabels:',
    ...entries.map(([key, value]) => `          ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`),
  ];
}

export function policyToYAML(policy: NetworkPolicy): string {
  const yaml: string[] = [];

  yaml.push(...yamlComments(policy.warnings));
  yaml.push(`apiVersion: ${quoteYamlValue(policy.apiVersion)}`);
  yaml.push(`kind: ${quoteYamlValue(policy.kind)}`);
  yaml.push('metadata:');
  yaml.push(`  name: ${quoteYamlValue(policy.metadata.name)}`);
  yaml.push(`  namespace: ${quoteYamlValue(policy.metadata.namespace)}`);
  yaml.push('spec:');
  yaml.push('  podSelector:');
  yaml.push('    matchLabels:');
  Object.entries(policy.spec.podSelector.matchLabels).forEach(([key, value]) => {
    yaml.push(`      ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
  });

  if (policy.spec.policyTypes.length > 0) {
    yaml.push('  policyTypes:');
    policy.spec.policyTypes.forEach(type => {
      yaml.push(`  - ${type}`);
    });
  }

  const ingress = (policy.spec.ingress ?? []).filter(ruleHasPeers);
  if (ingress.length > 0) {
    yaml.push('  ingress:');
    ingress.forEach((rule) => {
      yaml.push(...yamlComments(rule.comments, '  '));
      yaml.push('  - from:');
      rule.peers.forEach((peer) => {
        yaml.push('    -');
        if (peer.ipBlock) {
          yaml.push('      ipBlock:');
          yaml.push(`        cidr: ${quoteYamlValue(peer.ipBlock.cidr)}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${quoteYamlValue(e)}`));
          }
        }
        if (peer.podSelector) yaml.push(...peerSelectorLines('podSelector', peer.podSelector.matchLabels));
        if (peer.namespaceSelector) yaml.push(...peerSelectorLines('namespaceSelector', peer.namespaceSelector.matchLabels));
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${quoteYamlValue(port.protocol)}`);
          yaml.push(`      port: ${portValue(port.port)}`);
        });
      }
    });
  }

  const egress = (policy.spec.egress ?? []).filter(ruleHasPeers);
  if (egress.length > 0) {
    yaml.push('  egress:');
    egress.forEach((rule) => {
      yaml.push(...yamlComments(rule.comments, '  '));
      yaml.push('  - to:');
      rule.peers.forEach((peer) => {
        yaml.push('    -');
        if (peer.ipBlock) {
          yaml.push('      ipBlock:');
          yaml.push(`        cidr: ${quoteYamlValue(peer.ipBlock.cidr)}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${quoteYamlValue(e)}`));
          }
        }
        if (peer.podSelector) yaml.push(...peerSelectorLines('podSelector', peer.podSelector.matchLabels));
        if (peer.namespaceSelector) yaml.push(...peerSelectorLines('namespaceSelector', peer.namespaceSelector.matchLabels));
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${quoteYamlValue(port.protocol)}`);
          yaml.push(`      port: ${portValue(port.port)}`);
        });
      }
    });
  }

  return yaml.join('\n');
}
