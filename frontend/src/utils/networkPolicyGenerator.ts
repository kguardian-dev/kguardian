import type { PodNodeData } from '../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPeer } from '../types/networkPolicy';
import { apiClient } from '../services/api';

interface TrafficIdentity {
  podName?: string;
  podNamespace?: string;
  svcName?: string;
  svcNamespace?: string;
  isExternal: boolean;
}

// Helper to resolve traffic identity following advisor priority
async function resolveTrafficIdentity(ip: string): Promise<TrafficIdentity> {
  if (!ip) {
    return { isExternal: true };
  }

  // Priority 1: Try to get service info from API
  try {
    const serviceInfo = await apiClient.getServiceByIP(ip);
    if (serviceInfo && serviceInfo.svc_name) {
      return {
        svcName: serviceInfo.svc_name,
        svcNamespace: serviceInfo.svc_namespace || undefined,
        isExternal: false,
      };
    }
  } catch (error) {
    // Service lookup failed, continue to pod lookup
  }

  // Priority 2: Try to get pod info from API (checks all namespaces)
  try {
    const podInfo = await apiClient.getPodDetailsByIP(ip);
    if (podInfo && podInfo.pod_name) {
      return {
        podName: podInfo.pod_name,
        podNamespace: podInfo.pod_namespace || undefined,
        isExternal: false,
      };
    }
  } catch (error) {
    // Pod lookup failed, continue to external
  }

  // Priority 3: External traffic
  return { isExternal: true };
}

export async function generateNetworkPolicy(pod: PodNodeData, _allPods: PodNodeData[] = []): Promise<NetworkPolicy> {
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

  const identityMap = new Map<string, TrafficIdentity>();
  for (const ip of uniqueIPs) {
    const identity = await resolveTrafficIdentity(ip);
    identityMap.set(ip, identity);
  }

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

  // Helper function to get labels for a pod (workload labels or pod labels)
  const getLabelsForPod = async (podName: string): Promise<Record<string, string> | null> => {
    try {
      const podInfo = await apiClient.getPodDetailsByName(podName);

      // First try workload selector labels
      if (podInfo?.workload_selector_labels && Object.keys(podInfo.workload_selector_labels).length > 0) {
        return podInfo.workload_selector_labels;
      }

      // Fall back to pod labels from pod spec
      if (podInfo?.pod_obj?.metadata?.labels) {
        const labels = podInfo.pod_obj.metadata.labels;
        if (Object.keys(labels).length > 0) {
          return labels;
        }
      }
    } catch (error) {
      // If we can't fetch labels, return null
    }
    return null;
  };

  // Helper function to create peer based on identity type
  const createPeer = async (peerInfo: PeerInfo): Promise<NetworkPolicyPeer> => {
    const { identity } = peerInfo;

    if (identity.svcName) {
      // Service - use podSelector with service label
      // Try to get labels (workload or pod labels) for pods behind this service
      const labels = await getLabelsForPod(identity.svcName);

      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: labels || { app: identity.svcName },
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

      return peer;
    } else if (identity.podName) {
      // Pod - use labels (workload selector labels or pod labels)
      const labels = await getLabelsForPod(identity.podName);

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

      return peer;
    } else {
      // External IP - use IP block
      return {
        ipBlock: {
          cidr: `${peerInfo.ip}/32`,
        },
      };
    }
  };

  // Build ingress rules - one rule per peer with all its ports
  for (const { peer, ports } of ingressMap.values()) {
    const rule: NetworkPolicyRule = {
      id: `ingress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      peers: [await createPeer(peer)],
      ports: Array.from(ports).map((portStr) => {
        const [protocol, port] = portStr.split(':');
        return {
          protocol: protocol.toUpperCase(),
          port: parseInt(port) || port,
        };
      }),
    };
    ingressRules.push(rule);
  }

  // Build egress rules - one rule per peer with all its ports
  for (const { peer, ports } of egressMap.values()) {
    const rule: NetworkPolicyRule = {
      id: `egress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      peers: [await createPeer(peer)],
      ports: Array.from(ports).map((portStr) => {
        const [protocol, port] = portStr.split(':');
        return {
          protocol: protocol.toUpperCase(),
          port: parseInt(port) || port,
        };
      }),
    };
    egressRules.push(rule);
  }

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

  // Add policy types
  if (ingressRules.length > 0) {
    policy.spec.policyTypes.push('Ingress');
  }
  if (egressRules.length > 0) {
    policy.spec.policyTypes.push('Egress');
  }

  return policy;
}

export function policyToYAML(policy: NetworkPolicy): string {
  const yaml: string[] = [];

  yaml.push(`apiVersion: ${policy.apiVersion}`);
  yaml.push(`kind: ${policy.kind}`);
  yaml.push('metadata:');
  yaml.push(`  name: ${policy.metadata.name}`);
  yaml.push(`  namespace: ${policy.metadata.namespace}`);
  yaml.push('spec:');
  yaml.push('  podSelector:');
  yaml.push('    matchLabels:');
  Object.entries(policy.spec.podSelector.matchLabels).forEach(([key, value]) => {
    yaml.push(`      ${key}: ${value}`);
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
      yaml.push('  - from:');
      rule.peers.forEach((peer) => {
        yaml.push('    -');
        if (peer.ipBlock) {
          yaml.push('      ipBlock:');
          yaml.push(`        cidr: ${peer.ipBlock.cidr}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${e}`));
          }
        }
        if (peer.podSelector) {
          yaml.push('      podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('      namespaceSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.namespaceSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${port.protocol}`);
          yaml.push(`      port: ${port.port}`);
        });
      }
    });
  }

  if (policy.spec.egress && policy.spec.egress.length > 0) {
    yaml.push('  egress:');
    policy.spec.egress.forEach((rule) => {
      yaml.push('  - to:');
      rule.peers.forEach((peer) => {
        yaml.push('    -');
        if (peer.ipBlock) {
          yaml.push('      ipBlock:');
          yaml.push(`        cidr: ${peer.ipBlock.cidr}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${e}`));
          }
        }
        if (peer.podSelector) {
          yaml.push('      podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('      namespaceSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.namespaceSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
      });
      if (rule.ports.length > 0) {
        yaml.push('    ports:');
        rule.ports.forEach((port) => {
          yaml.push(`    - protocol: ${port.protocol}`);
          yaml.push(`      port: ${port.port}`);
        });
      }
    });
  }

  return yaml.join('\n');
}
