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
  /** Free-text notes emitted as `# ...` comment lines directly above the rule
   *  in YAML (one per entry). Used to explain why a host-network peer is an
   *  ipBlock rather than a podSelector. */
  comments?: string[];
}

export interface NetworkPolicy {
  /** Leading `# ...` comment block emitted before `apiVersion` — e.g. the
   *  hostNetwork-target warning. Not part of the Kubernetes object. */
  warnings?: string[];
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
