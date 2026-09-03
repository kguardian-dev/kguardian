import type { PodInfo, PodNodeData } from '../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPeer, NetworkPolicyPort } from '../types/networkPolicy';
import { apiClient } from '../services/api';
import { resolveTrafficIdentity, type TrafficIdentity } from './trafficIdentity';
import { peerCIDR } from './ipCidr';
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

export async function generateNetworkPolicy(pod: PodNodeData): Promise<NetworkPolicy> {
  const ingressRules: NetworkPolicyRule[] = [];
  const egressRules: NetworkPolicyRule[] = [];

  // Create one rule per unique peer with all its ports
  interface PeerInfo {
    ip: string;
    identity: TrafficIdentity;
  }
  const ingressMap = new Map<string, { peer: PeerInfo; ports: Set<string> }>();
  const egressMap = new Map<string, { peer: PeerInfo; ports: Set<string> }>();

  // Resolve all unique IPs to identities
  const uniqueIPs = new Set<string>();
  pod.traffic?.forEach((traffic) => {
    if (traffic.traffic_in_out_ip) {
      uniqueIPs.add(traffic.traffic_in_out_ip);
    }
  });

  const uniqueIPArray = Array.from(uniqueIPs);
  const identities = await Promise.all(uniqueIPArray.map(ip => resolveTrafficIdentity(ip)));
  const identityMap = new Map<string, TrafficIdentity>();
  uniqueIPArray.forEach((ip, i) => {
    identityMap.set(ip, identities[i]);
  });

  // Deduplicate: if a pod IP resolves to a pod that is selected by a service identity
  // already present in identityMap, redirect the pod IP to use the service identity.
  // This collapses traffic to both the service ClusterIP and its backing pod IP into one rule.
  uniqueIPArray.forEach((ip) => {
    const identity = identityMap.get(ip)!;
    if (!identity.podName || !identity.podNamespace || !identity.podLabels) return;

    for (const [otherIp, svcIdentity] of identityMap) {
      if (otherIp === ip) continue;
      if (!svcIdentity.svcName || svcIdentity.svcNamespace !== identity.podNamespace) continue;
      if (!svcIdentity.svcSelector) continue;

      const matches = Object.entries(svcIdentity.svcSelector).every(
        ([k, v]) => identity.podLabels![k] === v
      );
      if (matches) {
        identityMap.set(ip, svcIdentity);
        break;
      }
    }
  });

  // Process traffic rules
  pod.traffic?.forEach((traffic) => {
    const protocol = traffic.ip_protocol || 'TCP';
    const remoteIP = traffic.traffic_in_out_ip;

    if (!remoteIP) {
      return; // Skip if no remote IP
    }

    // Get the resolved identity for this IP
    const identity = identityMap.get(remoteIP) || { isExternal: true };

    const trafficType = traffic.traffic_type?.toLowerCase();

    // Create a unique key for this peer
    let key: string;
    if (identity.svcName) {
      key = `svc-${identity.svcNamespace || 'default'}-${identity.svcName}`;
    } else if (identity.podName) {
      key = `pod-${identity.podNamespace || 'default'}-${identity.podName}`;
    } else {
      key = `ip-${remoteIP}`;
    }

    if (trafficType === 'ingress') {
      // For ingress: allow traffic FROM remote IP TO this pod's port
      const port = traffic.pod_port || '80';

      if (!ingressMap.has(key)) {
        ingressMap.set(key, {
          peer: { ip: remoteIP, identity },
          ports: new Set()
        });
      }
      ingressMap.get(key)?.ports.add(`${protocol}:${port}`);
    } else if (trafficType === 'egress') {
      // For egress: allow traffic TO remote IP:port
      const port = traffic.traffic_in_out_port || '80';

      if (!egressMap.has(key)) {
        egressMap.set(key, {
          peer: { ip: remoteIP, identity },
          ports: new Set()
        });
      }
      egressMap.get(key)?.ports.add(`${protocol}:${port}`);
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
  let allPods: Promise<PodInfo[] | null> | undefined;
  const listPods = (): Promise<PodInfo[] | null> => {
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
      const podInfo = await apiClient.getPodDetailsByName(podName);
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
      // Service - use podSelector with service label
      // Try to get labels (workload or pod labels) for pods behind this service
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

      const facts = await getPeerPodFacts(identity.svcName);

      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: facts.labels || { app: identity.svcName },
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

      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: facts.labels || { app: identity.podName },
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
      return { peers: [{ ipBlock: { cidr } }] };
    }
  };

  // Rules are emitted in bytewise peer-IP order, the same order the advisor
  // and llm-bridge use, so the three generators agree on rule position.
  const sortedByPeerIP = <T extends { peer: PeerInfo }>(map: Map<string, T>): T[] =>
    Array.from(map.values()).sort((a, b) => (a.peer.ip < b.peer.ip ? -1 : a.peer.ip > b.peer.ip ? 1 : 0));

  const parsePorts = (ports: Set<string>): NetworkPolicyPort[] =>
    Array.from(ports).map((portStr) => {
      const [protocol, port] = portStr.split(':');
      return {
        protocol: protocol.toUpperCase(),
        port: parseInt(port) || port,
      };
    });

  // Build rules - one rule per peer with all its ports. Host-network peers
  // are the exception: several of them can share one node IP (every
  // host-network pod on a node does), and they collapse into a single ipBlock
  // rule carrying the union of their ports and one comment line per peer.
  const buildRules = async (
    map: Map<string, { peer: PeerInfo; ports: Set<string> }>,
    direction: 'ingress' | 'egress',
  ): Promise<NetworkPolicyRule[]> => {
    const rules: NetworkPolicyRule[] = [];
    const hostRuleByCidr = new Map<string, NetworkPolicyRule>();
    for (const { peer, ports } of sortedByPeerIP(map)) {
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
      if (existing && resolved.hostNetworkComment) {
        const seen = new Set(existing.ports.map((p) => `${p.protocol}:${p.port}`));
        for (const p of rulePorts) {
          if (!seen.has(`${p.protocol}:${p.port}`)) existing.ports.push(p);
        }
        if (!existing.comments!.includes(resolved.hostNetworkComment)) {
          existing.comments!.push(resolved.hostNetworkComment);
        }
        continue;
      }

      const rule: NetworkPolicyRule = {
        id: `${direction}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        peers: resolved.peers,
        ports: rulePorts,
        ...(resolved.hostNetworkComment && { comments: [resolved.hostNetworkComment] }),
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

  return policy;
}

// YAML special characters that require quoting a value
const YAML_SPECIAL_RE = /[:#'"{}[\],&*?|<>=!%@`\n\r-]/;

export function quoteYamlValue(value: string): string {
  if (YAML_SPECIAL_RE.test(value)) {
    // Use double quotes with internal double-quotes escaped
    return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return value;
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

  if (policy.spec.ingress && policy.spec.ingress.length > 0) {
    yaml.push('  ingress:');
    policy.spec.ingress.forEach((rule) => {
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
        if (peer.podSelector) {
          yaml.push('      podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('      namespaceSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.namespaceSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        }
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${quoteYamlValue(port.protocol)}`);
          yaml.push(`      port: ${port.port}`);
        });
      }
    });
  }

  if (policy.spec.egress && policy.spec.egress.length > 0) {
    yaml.push('  egress:');
    policy.spec.egress.forEach((rule) => {
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
        if (peer.podSelector) {
          yaml.push('      podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('      namespaceSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.namespaceSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        }
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${quoteYamlValue(port.protocol)}`);
          yaml.push(`      port: ${port.port}`);
        });
      }
    });
  }

  return yaml.join('\n');
}
