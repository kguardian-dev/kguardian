export interface NetworkPolicyPort {
  protocol: string;
  port: string | number;
}

export interface PodSelector {
  matchLabels: Record<string, string>;
}

export interface NamespaceSelector {
  matchLabels: Record<string, string>;
}

export interface IPBlock {
  cidr: string;
  except?: string[];
}

export interface NetworkPolicyPeer {
  podSelector?: PodSelector;
  namespaceSelector?: NamespaceSelector;
  ipBlock?: IPBlock;
}

export interface NetworkPolicyRule {
  id: string;
  peers: NetworkPolicyPeer[];
  ports: NetworkPolicyPort[];
}

export interface NetworkPolicy {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace: string;
  };
  spec: {
    podSelector: PodSelector;
    policyTypes: string[];
    ingress?: NetworkPolicyRule[];
    egress?: NetworkPolicyRule[];
  };
}
