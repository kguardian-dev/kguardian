import type { PodNodeData } from '../types';
import type {
  CiliumNetworkPolicy,
  CiliumIngressRule,
  CiliumEgressRule,
  EndpointSelector,
  PortProtocol,
  CiliumPortRule,
} from '../types/ciliumPolicy';
import { apiClient } from '../services/api';
import { resolveTrafficIdentity, type TrafficIdentity } from './trafficIdentity';
import { quoteYamlValue } from './networkPolicyGenerator';

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

  // Helper to get labels for a pod
  const getLabelsForPod = async (podName: string): Promise<Record<string, string> | null> => {
    try {
      const podInfo = await apiClient.getPodDetailsByName(podName);
      if (podInfo?.workload_selector_labels && Object.keys(podInfo.workload_selector_labels).length > 0) {
        return podInfo.workload_selector_labels;
      }
      if (podInfo?.pod_obj?.metadata?.labels) {
        const labels = podInfo.pod_obj.metadata.labels;
        if (Object.keys(labels).length > 0) {
          return labels;
        }
      }
    } catch {
      // If we can't fetch labels, return null
    }
    return null;
  };

  // Helper to create Cilium peer fields
  const resolvePeerLabels = async (peerInfo: PeerInfo): Promise<{ selector?: EndpointSelector; cidr?: string }> => {
    const { identity } = peerInfo;

    if (identity.svcName) {
      const labels = await getLabelsForPod(identity.svcName);
      return { selector: { matchLabels: labels || { app: identity.svcName } } };
    } else if (identity.podName) {
      const labels = await getLabelsForPod(identity.podName);
      return { selector: { matchLabels: labels || { app: identity.podName } } };
    } else {
      return { cidr: `${peerInfo.ip}/32` };
    }
  };

  const parsePorts = (ports: Set<string>): CiliumPortRule[] => {
    const portProtocols: PortProtocol[] = Array.from(ports).map((portStr) => {
      const [protocol, port] = portStr.split(':');
      return { port, protocol: protocol.toUpperCase() };
    });
    return portProtocols.length > 0 ? [{ ports: portProtocols }] : [];
  };

  // Build ingress rules
  const ingressRules: CiliumIngressRule[] = [];
  for (const { peer, ports } of ingressMap.values()) {
    const resolved = await resolvePeerLabels(peer);
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
  for (const { peer, ports } of egressMap.values()) {
    const resolved = await resolvePeerLabels(peer);
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
    apiVersion: 'cilium.io/v2',
    kind: 'CiliumNetworkPolicy',
    metadata: {
      name: `${resourceName}-cilium-policy`,
      namespace: pod.pod.pod_namespace || 'default',
    },
    spec: {
      endpointSelector: { matchLabels: targetPodLabels },
      defaultDeny: {
        ingress: ingressRules.length > 0,
        egress: egressRules.length > 0,
      },
      ...(ingressRules.length > 0 && { ingress: ingressRules }),
      ...(egressRules.length > 0 && { egress: egressRules }),
    },
  };

  return policy;
}

export function ciliumPolicyToYAML(policy: CiliumNetworkPolicy): string {
  const yaml: string[] = [];

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
      yaml.push('  -');
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
      yaml.push('  -');
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
