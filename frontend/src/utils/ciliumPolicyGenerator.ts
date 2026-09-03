import type { PodInfo, PodNodeData } from '../types';
import {
  CILIUM_NAMESPACE_LABEL,
  type CiliumNetworkPolicy,
  type CiliumIngressRule,
  type CiliumEgressRule,
  type EndpointSelector,
  type PortProtocol,
  type CiliumPortRule,
} from '../types/ciliumPolicy';
import { apiClient } from '../services/api';
import { resolveTrafficIdentity, type TrafficIdentity } from './trafficIdentity';
import { quoteYamlValue } from './networkPolicyGenerator';
import { peerCIDR } from './ipCidr';
import { specNodeName } from './hostNetwork';
import {
  HOST_NETWORK_ENTITIES,
  hostNetworkPeerComment,
  hostNetworkServiceBackends,
  hostNetworkServiceComment,
  hostNetworkTargetName,
  hostNetworkTargetWarning,
  isHostNetworkTarget,
  yamlComments,
} from './hostNetwork';

interface PeerInfo {
  ip: string;
  identity: TrafficIdentity;
}

export async function generateCiliumNetworkPolicy(pod: PodNodeData): Promise<CiliumNetworkPolicy> {
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

    if (!remoteIP) return;

    const identity = identityMap.get(remoteIP) || { isExternal: true };
    const trafficType = traffic.traffic_type?.toLowerCase();

    let key: string;
    if (identity.svcName) {
      key = `svc-${identity.svcNamespace || 'default'}-${identity.svcName}`;
    } else if (identity.podName) {
      key = `pod-${identity.podNamespace || 'default'}-${identity.podName}`;
    } else {
      key = `ip-${remoteIP}`;
    }

    if (trafficType === 'ingress') {
      const port = traffic.pod_port || '80';
      if (!ingressMap.has(key)) {
        ingressMap.set(key, { peer: { ip: remoteIP, identity }, ports: new Set() });
      }
      ingressMap.get(key)?.ports.add(`${protocol}:${port}`);
    } else if (trafficType === 'egress') {
      const port = traffic.traffic_in_out_port || '80';
      if (!egressMap.has(key)) {
        egressMap.set(key, { peer: { ip: remoteIP, identity }, ports: new Set() });
      }
      egressMap.get(key)?.ports.add(`${protocol}:${port}`);
    }
  });

  // What the by-name pod lookup tells us about a peer: selector labels plus
  // the host-network facts (see hostNetwork.ts).
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
      if (podInfo.workload_selector_labels && Object.keys(podInfo.workload_selector_labels).length > 0) {
        facts.labels = podInfo.workload_selector_labels;
      } else if (podInfo.pod_obj?.metadata?.labels && Object.keys(podInfo.pod_obj.metadata.labels).length > 0) {
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

  // A resolved Cilium peer: exactly one of selector / cidr / entities is set.
  // `entities` marks a host-network peer — its traffic carries the node's
  // identity, which no endpointSelector matches. `host` covers a peer on the
  // local node and `remote-node` one on any other node; we cannot tell which
  // from the observed IP, so both are emitted.
  interface ResolvedPeer {
    selector?: EndpointSelector;
    cidr?: string;
    entities?: string[];
    hostNetworkComment?: string;
  }

  // Cilium scopes an endpoint selector to the POLICY's namespace unless the
  // selector names one, so a cross-namespace peer must carry the namespace
  // label or it matches nothing (the standard generator's namespaceSelector
  // equivalent). Same-namespace and unknown-namespace peers are unchanged.
  const withPeerNamespace = (labels: Record<string, string>, peerNamespace: string | undefined): Record<string, string> => {
    if (!peerNamespace) {
      // Unknown namespace: emit the bare selector (scoped to the policy's own
      // namespace) rather than guess, but say so — a cross-namespace peer
      // rendered this way matches nothing.
      console.warn(`Cilium peer ${JSON.stringify(labels)} has no namespace; selector is scoped to ${pod.pod.pod_namespace || 'default'}`);
      return labels;
    }
    if (peerNamespace === (pod.pod.pod_namespace || 'default')) return labels;
    return { ...labels, [CILIUM_NAMESPACE_LABEL]: peerNamespace };
  };

  const hostNetworkPeer = (namespace: string, name: string, node: string): ResolvedPeer => ({
    entities: [...HOST_NETWORK_ENTITIES],
    hostNetworkComment: hostNetworkPeerComment('cilium', namespace, name, node),
  });

  // Helper to create Cilium peer fields
  const resolvePeerLabels = async (peerInfo: PeerInfo): Promise<ResolvedPeer> => {
    const { identity } = peerInfo;

    if (identity.svcName) {
      // A Service fronting host-network pods fronts node IPs — entities, not
      // an endpointSelector built from the Service selector.
      const backends = hostNetworkServiceBackends(await listPods(), identity.svcNamespace, identity.svcSelector);
      if (backends.length > 0) {
        return {
          entities: [...HOST_NETWORK_ENTITIES],
          hostNetworkComment: hostNetworkServiceComment(
            'cilium', identity.svcNamespace || 'default', identity.svcName, backends, peerInfo.ip,
          ),
        };
      }
      const facts = await getPeerPodFacts(identity.svcName);
      return { selector: { matchLabels: withPeerNamespace(facts.labels || { app: identity.svcName }, identity.svcNamespace) } };
    } else if (identity.podName) {
      const facts = await getPeerPodFacts(identity.podName);
      const hostNetwork = identity.hostNetwork ?? facts.hostNetwork;
      if (hostNetwork === true) {
        return hostNetworkPeer(
          identity.podNamespace || facts.namespace || 'default',
          identity.workloadName || facts.workloadName || identity.podName,
          identity.nodeName || facts.nodeName || peerInfo.ip,
        );
      }
      return {
        selector: {
          matchLabels: withPeerNamespace(facts.labels || { app: identity.podName }, identity.podNamespace || facts.namespace),
        },
      };
    } else {
      // External IP - the host mask follows the address family: /32 for IPv4,
      // /128 for IPv6 (a /32 on a v6 address would cover 2^96 hosts rather than
      // the single peer we observed). An unparseable IP resolves to neither a
      // selector nor a CIDR, and the caller drops the rule.
      const cidr = peerCIDR(peerInfo.ip);
      return cidr === null ? {} : { cidr };
    }
  };

  // Rules are emitted in bytewise peer-IP order, matching advisor/llm-bridge.
  const sortedByPeerIP = <T extends { peer: PeerInfo }>(map: Map<string, T>): T[] =>
    Array.from(map.values()).sort((a, b) => (a.peer.ip < b.peer.ip ? -1 : a.peer.ip > b.peer.ip ? 1 : 0));

  const parsePorts = (ports: Set<string>): CiliumPortRule[] => {
    const portProtocols: PortProtocol[] = Array.from(ports).map((portStr) => {
      const [protocol, port] = portStr.split(':');
      return { port, protocol: protocol.toUpperCase() };
    });
    return portProtocols.length > 0 ? [{ ports: portProtocols }] : [];
  };

  // Every host-network peer renders to the same `[host, remote-node]`
  // entities, so peers with the same port list would be pure duplicates.
  // One entities rule per distinct (direction, port list); later peers with
  // the same ports only add their comment line. Keyed the way the advisor and
  // llm-bridge key it so all three emit the same rule count.
  const hostPortKey = (ports: Set<string>): string =>
    Array.from(ports)
      .map((p) => { const [protocol, port] = p.split(':'); return `${port}/${protocol.toUpperCase()}`; })
      .sort()
      .join(',');
  const addHostComment = (rule: { comments?: string[] }, comment: string) => {
    rule.comments = rule.comments ?? [];
    if (!rule.comments.includes(comment)) rule.comments.push(comment);
  };

  // Build ingress rules
  const ingressRules: CiliumIngressRule[] = [];
  const ingressHostRules = new Map<string, CiliumIngressRule>();
  for (const { peer, ports } of sortedByPeerIP(ingressMap)) {
    const resolved = await resolvePeerLabels(peer);
    // A Cilium rule with neither fromEndpoints nor fromCIDR nor fromEntities selects
    // ALL peers, so an unparseable IP must drop the rule rather than silently widen it.
    if (!resolved.selector && !resolved.cidr && !resolved.entities) continue;
    if (resolved.entities && resolved.hostNetworkComment) {
      const key = hostPortKey(ports);
      let hostRule = ingressHostRules.get(key);
      if (!hostRule) {
        hostRule = {
          id: `ingress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          fromEntities: resolved.entities,
          toPorts: parsePorts(ports),
        };
        ingressHostRules.set(key, hostRule);
        ingressRules.push(hostRule);
      }
      addHostComment(hostRule, resolved.hostNetworkComment);
      continue;
    }
    const rule: CiliumIngressRule = {
      id: `ingress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      toPorts: parsePorts(ports),
    };
    if (resolved.selector) {
      rule.fromEndpoints = [resolved.selector];
    } else if (resolved.cidr) {
      rule.fromCIDR = [resolved.cidr];
    }
    ingressRules.push(rule);
  }

  // Build egress rules
  const egressRules: CiliumEgressRule[] = [];
  const egressHostRules = new Map<string, CiliumEgressRule>();
  for (const { peer, ports } of sortedByPeerIP(egressMap)) {
    const resolved = await resolvePeerLabels(peer);
    // A Cilium rule with neither toEndpoints nor toCIDR nor toEntities selects
    // ALL peers, so an unparseable IP must drop the rule rather than silently widen it.
    if (!resolved.selector && !resolved.cidr && !resolved.entities) continue;
    if (resolved.entities && resolved.hostNetworkComment) {
      const key = hostPortKey(ports);
      let hostRule = egressHostRules.get(key);
      if (!hostRule) {
        hostRule = {
          id: `egress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          toEntities: resolved.entities,
          toPorts: parsePorts(ports),
        };
        egressHostRules.set(key, hostRule);
        egressRules.push(hostRule);
      }
      addHostComment(hostRule, resolved.hostNetworkComment);
      continue;
    }
    const rule: CiliumEgressRule = {
      id: `egress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      toPorts: parsePorts(ports),
    };
    if (resolved.selector) {
      rule.toEndpoints = [resolved.selector];
    } else if (resolved.cidr) {
      rule.toCIDR = [resolved.cidr];
    }
    egressRules.push(rule);
  }

  // Target pod labels
  const resourceName = pod.pod.pod_identity || pod.pod.pod_name;
  let targetPodLabels: Record<string, string> = { app: pod.pod.pod_name };

  if (pod.pod.workload_selector_labels && Object.keys(pod.pod.workload_selector_labels).length > 0) {
    targetPodLabels = pod.pod.workload_selector_labels;
  } else if (pod.pod.pod_obj?.metadata?.labels && Object.keys(pod.pod.pod_obj.metadata.labels).length > 0) {
    targetPodLabels = pod.pod.pod_obj.metadata.labels;
  }

  const policy: CiliumNetworkPolicy = {
    // Same caveat as the standard generator: a host-network target is not an
    // endpoint Cilium can select with a namespaced endpointSelector. Warn,
    // do not silently hand over an inert policy. (A CCNP + nodeSelector is the
    // real answer and is deliberately not generated here.)
    ...(isHostNetworkTarget(pod) && { warnings: hostNetworkTargetWarning('cilium', pod.pod.pod_namespace || 'default', hostNetworkTargetName(pod)) }),
    apiVersion: 'cilium.io/v2',
    kind: 'CiliumNetworkPolicy',
    metadata: {
      name: `${resourceName}-cilium-policy`,
      namespace: pod.pod.pod_namespace || 'default',
    },
    spec: {
      endpointSelector: { matchLabels: targetPodLabels },
      // Keyed off the direction being OBSERVED, not off the rule list
      // surviving — see the sibling comment in networkPolicyGenerator. Since
      // unparseable peers are now dropped, a direction can observe traffic and
      // still end with no rules, and flipping defaultDeny to false there would
      // turn "deny everything not listed" into "restrict nothing".
      defaultDeny: {
        ingress: ingressMap.size > 0,
        egress: egressMap.size > 0,
      },
      ...(ingressRules.length > 0 && { ingress: ingressRules }),
      ...(egressRules.length > 0 && { egress: egressRules }),
    },
  };

  return policy;
}

export function ciliumPolicyToYAML(policy: CiliumNetworkPolicy): string {
  const yaml: string[] = [];

  yaml.push(...yamlComments(policy.warnings));
  yaml.push(`apiVersion: ${quoteYamlValue(policy.apiVersion)}`);
  yaml.push(`kind: ${quoteYamlValue(policy.kind)}`);
  yaml.push('metadata:');
  yaml.push(`  name: ${quoteYamlValue(policy.metadata.name)}`);
  yaml.push(`  namespace: ${quoteYamlValue(policy.metadata.namespace)}`);
  yaml.push('spec:');

  // Endpoint selector
  yaml.push('  endpointSelector:');
  yaml.push('    matchLabels:');
  Object.entries(policy.spec.endpointSelector.matchLabels).forEach(([key, value]) => {
    yaml.push(`      ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
  });

  // Default deny
  if (policy.spec.defaultDeny.ingress || policy.spec.defaultDeny.egress) {
    yaml.push('  enableDefaultDeny:');
    yaml.push(`    ingress: ${policy.spec.defaultDeny.ingress}`);
    yaml.push(`    egress: ${policy.spec.defaultDeny.egress}`);
  }

  // Ingress rules
  if (policy.spec.ingress && policy.spec.ingress.length > 0) {
    yaml.push('  ingress:');
    policy.spec.ingress.forEach((rule) => {
      yaml.push(...yamlComments(rule.comments, '  '));
      yaml.push('  -');
      if (rule.fromEntities && rule.fromEntities.length > 0) {
        yaml.push('    fromEntities:');
        // Entity names are a fixed lowercase/hyphen vocabulary; quoteYamlValue
        // would needlessly quote the hyphen in remote-node.
        rule.fromEntities.forEach((entity) => {
          yaml.push(`    - ${entity}`);
        });
      }
      if (rule.fromEndpoints && rule.fromEndpoints.length > 0) {
        yaml.push('    fromEndpoints:');
        rule.fromEndpoints.forEach((ep) => {
          yaml.push('    - matchLabels:');
          Object.entries(ep.matchLabels).forEach(([key, value]) => {
            yaml.push(`        ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        });
      }
      if (rule.fromCIDR && rule.fromCIDR.length > 0) {
        yaml.push('    fromCIDR:');
        rule.fromCIDR.forEach((cidr) => {
          yaml.push(`    - ${quoteYamlValue(cidr)}`);
        });
      }
      if (rule.toPorts && rule.toPorts.length > 0) {
        yaml.push('    toPorts:');
        rule.toPorts.forEach((portRule) => {
          yaml.push('    - ports:');
          portRule.ports.forEach((pp) => {
            yaml.push(`      - port: "${pp.port}"`);
            yaml.push(`        protocol: ${pp.protocol}`);
          });
        });
      }
    });
  }

  // Egress rules
  if (policy.spec.egress && policy.spec.egress.length > 0) {
    yaml.push('  egress:');
    policy.spec.egress.forEach((rule) => {
      yaml.push(...yamlComments(rule.comments, '  '));
      yaml.push('  -');
      if (rule.toEntities && rule.toEntities.length > 0) {
        yaml.push('    toEntities:');
        // Entity names are a fixed lowercase/hyphen vocabulary; quoteYamlValue
        // would needlessly quote the hyphen in remote-node.
        rule.toEntities.forEach((entity) => {
          yaml.push(`    - ${entity}`);
        });
      }
      if (rule.toEndpoints && rule.toEndpoints.length > 0) {
        yaml.push('    toEndpoints:');
        rule.toEndpoints.forEach((ep) => {
          yaml.push('    - matchLabels:');
          Object.entries(ep.matchLabels).forEach(([key, value]) => {
            yaml.push(`        ${quoteYamlValue(key)}: ${quoteYamlValue(value)}`);
          });
        });
      }
      if (rule.toCIDR && rule.toCIDR.length > 0) {
        yaml.push('    toCIDR:');
        rule.toCIDR.forEach((cidr) => {
          yaml.push(`    - ${quoteYamlValue(cidr)}`);
        });
      }
      if (rule.toPorts && rule.toPorts.length > 0) {
        yaml.push('    toPorts:');
        rule.toPorts.forEach((portRule) => {
          yaml.push('    - ports:');
          portRule.ports.forEach((pp) => {
            yaml.push(`      - port: "${pp.port}"`);
            yaml.push(`        protocol: ${pp.protocol}`);
          });
        });
      }
    });
  }

  return yaml.join('\n');
}
