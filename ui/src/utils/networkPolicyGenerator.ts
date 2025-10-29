import type { PodNodeData } from '../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPeer } from '../types/networkPolicy';

export function generateNetworkPolicy(pod: PodNodeData, allPods: PodNodeData[] = []): NetworkPolicy {
  const ingressRules: NetworkPolicyRule[] = [];
  const egressRules: NetworkPolicyRule[] = [];

  // Create a map of IP -> Pod for quick lookups
  const podByIP = new Map<string, PodNodeData>();
  allPods.forEach(p => {
    if (p.pod.pod_ip) {
      podByIP.set(p.pod.pod_ip, p);
    }
  });

  // Create one rule per unique peer (IP or pod) with all its ports
  interface PeerInfo {
    ip: string;
    matchedPod?: PodNodeData;
  }
  const ingressMap = new Map<string, { peer: PeerInfo; ports: Set<string> }>();
  const egressMap = new Map<string, { peer: PeerInfo; ports: Set<string> }>();

  console.log('Generating policy for pod:', pod.pod.pod_name);
  console.log('Traffic entries:', pod.traffic?.length || 0);

  pod.traffic?.forEach((traffic, idx) => {
    console.log(`Traffic ${idx}:`, {
      type: traffic.traffic_type,
      type_typeof: typeof traffic.traffic_type,
      pod_ip: traffic.pod_ip,
      pod_port: traffic.pod_port,
      remote_ip: traffic.traffic_in_out_ip,
      remote_port: traffic.traffic_in_out_port,
      protocol: traffic.ip_protocol
    });

    const protocol = traffic.ip_protocol || 'TCP';
    const remoteIP = traffic.traffic_in_out_ip;

    if (!remoteIP) {
      console.log(`Skipping traffic ${idx}: no remote IP`);
      return; // Skip if no remote IP
    }

    // Check if this IP belongs to a pod in the cluster
    const matchedPod = podByIP.get(remoteIP);
    console.log(`Traffic ${idx} matched pod:`, matchedPod ? matchedPod.pod.pod_name : 'none (external)');

    const trafficType = traffic.traffic_type?.toLowerCase();
    console.log(`Traffic ${idx} type check:`, {
      original: traffic.traffic_type,
      normalized: trafficType,
      isIngress: trafficType === 'ingress',
      isEgress: trafficType === 'egress'
    });

    if (trafficType === 'ingress') {
      // For ingress: allow traffic FROM remote IP TO this pod's port
      const port = traffic.pod_port || '80';
      const key = matchedPod ? `pod-${matchedPod.pod.pod_name}` : `ip-${remoteIP}`;

      if (!ingressMap.has(key)) {
        ingressMap.set(key, {
          peer: { ip: remoteIP, matchedPod },
          ports: new Set()
        });
      }
      ingressMap.get(key)?.ports.add(`${protocol}:${port}`);
      console.log(`Added ingress rule: ${key} -> ${protocol}:${port}`);
    } else if (trafficType === 'egress') {
      // For egress: allow traffic TO remote IP:port
      const port = traffic.traffic_in_out_port || '80';
      const key = matchedPod ? `pod-${matchedPod.pod.pod_name}` : `ip-${remoteIP}`;

      if (!egressMap.has(key)) {
        egressMap.set(key, {
          peer: { ip: remoteIP, matchedPod },
          ports: new Set()
        });
      }
      egressMap.get(key)?.ports.add(`${protocol}:${port}`);
      console.log(`Added egress rule: ${key} -> ${protocol}:${port}`);
    }
  });

  console.log('Ingress rules count:', ingressMap.size);
  console.log('Egress rules count:', egressMap.size);

  // Helper function to create peer based on whether it's a pod or external IP
  const createPeer = (peerInfo: PeerInfo): NetworkPolicyPeer => {
    if (peerInfo.matchedPod) {
      // This is an in-cluster pod - use pod selector
      const targetPod = peerInfo.matchedPod;
      const peer: NetworkPolicyPeer = {
        podSelector: {
          matchLabels: {
            app: targetPod.pod.pod_name,
          },
        },
      };

      // If the pod is in a different namespace, add namespace selector
      if (targetPod.pod.pod_namespace !== pod.pod.pod_namespace) {
        peer.namespaceSelector = {
          matchLabels: {
            'kubernetes.io/metadata.name': targetPod.pod.pod_namespace || 'default',
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
  ingressMap.forEach(({ peer, ports }) => {
    const rule: NetworkPolicyRule = {
      id: `ingress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      peers: [createPeer(peer)],
      ports: Array.from(ports).map((portStr) => {
        const [protocol, port] = portStr.split(':');
        return {
          protocol: protocol.toUpperCase(),
          port: parseInt(port) || port,
        };
      }),
    };
    ingressRules.push(rule);
  });

  // Build egress rules - one rule per peer with all its ports
  egressMap.forEach(({ peer, ports }) => {
    const rule: NetworkPolicyRule = {
      id: `egress-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      peers: [createPeer(peer)],
      ports: Array.from(ports).map((portStr) => {
        const [protocol, port] = portStr.split(':');
        return {
          protocol: protocol.toUpperCase(),
          port: parseInt(port) || port,
        };
      }),
    };
    egressRules.push(rule);
  });

  // Create policy
  const policy: NetworkPolicy = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: `${pod.pod.pod_name}-policy`,
      namespace: pod.pod.pod_namespace || 'default',
    },
    spec: {
      podSelector: {
        matchLabels: {
          app: pod.pod.pod_name,
        },
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
        if (peer.ipBlock) {
          yaml.push('    - ipBlock:');
          yaml.push(`        cidr: ${peer.ipBlock.cidr}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${e}`));
          }
        }
        if (peer.podSelector) {
          yaml.push('    - podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('    - namespaceSelector:');
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
        if (peer.ipBlock) {
          yaml.push('    - ipBlock:');
          yaml.push(`        cidr: ${peer.ipBlock.cidr}`);
          if (peer.ipBlock.except) {
            yaml.push('        except:');
            peer.ipBlock.except.forEach(e => yaml.push(`        - ${e}`));
          }
        }
        if (peer.podSelector) {
          yaml.push('    - podSelector:');
          yaml.push('        matchLabels:');
          Object.entries(peer.podSelector.matchLabels).forEach(([key, value]) => {
            yaml.push(`          ${key}: ${value}`);
          });
        }
        if (peer.namespaceSelector) {
          yaml.push('    - namespaceSelector:');
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
