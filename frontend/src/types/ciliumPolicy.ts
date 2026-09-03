/** The label Cilium derives from a pod's namespace; naming it in an endpoint
 *  selector is how a CiliumNetworkPolicy selects peers in ANOTHER namespace. */
export const CILIUM_NAMESPACE_LABEL = 'k8s:io.kubernetes.pod.namespace';

export interface EndpointSelector {
  matchLabels: Record<string, string>;
}

export interface PortProtocol {
  port: string;
  protocol: string;
}

export interface CiliumPortRule {
  ports: PortProtocol[];
}

/** Cilium entity names accepted in fromEntities / toEntities. Only the two the
 *  generators emit are listed; the field itself is `string[]`. */
export type CiliumEntity = 'host' | 'remote-node' | (string & {});

export interface CiliumPeer {
  fromEndpoints?: EndpointSelector[];
  fromCIDR?: string[];
  fromEntities?: CiliumEntity[];
  toEndpoints?: EndpointSelector[];
  toCIDR?: string[];
  toEntities?: CiliumEntity[];
}

export interface CiliumIngressRule {
  id: string;
  fromEndpoints?: EndpointSelector[];
  fromCIDR?: string[];
  /** Host-network peers: `[host, remote-node]` — a rule-level field, a sibling
   *  of fromEndpoints, never nested under a selector. */
  fromEntities?: CiliumEntity[];
  toPorts?: CiliumPortRule[];
  /** `# ...` comment lines emitted above the rule in YAML. */
  comments?: string[];
}

export interface CiliumEgressRule {
  id: string;
  toEndpoints?: EndpointSelector[];
  toCIDR?: string[];
  toEntities?: CiliumEntity[];
  toPorts?: CiliumPortRule[];
  comments?: string[];
}

export interface DefaultDenyConfig {
  ingress: boolean;
  egress: boolean;
}

export interface CiliumNetworkPolicy {
  /** Leading `# ...` comment block emitted before `apiVersion`. */
  warnings?: string[];
  apiVersion: 'cilium.io/v2';
  kind: 'CiliumNetworkPolicy';
  metadata: {
    name: string;
    namespace: string;
  };
  spec: {
    endpointSelector: EndpointSelector;
    ingress?: CiliumIngressRule[];
    egress?: CiliumEgressRule[];
    defaultDeny: DefaultDenyConfig;
  };
}
