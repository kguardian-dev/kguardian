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

export interface CiliumPeer {
  fromEndpoints?: EndpointSelector[];
  fromCIDR?: string[];
  toEndpoints?: EndpointSelector[];
  toCIDR?: string[];
}

export interface CiliumIngressRule {
  id: string;
  fromEndpoints?: EndpointSelector[];
  fromCIDR?: string[];
  toPorts?: CiliumPortRule[];
}

export interface CiliumEgressRule {
  id: string;
  toEndpoints?: EndpointSelector[];
  toCIDR?: string[];
  toPorts?: CiliumPortRule[];
}

export interface DefaultDenyConfig {
  ingress: boolean;
  egress: boolean;
}

export interface CiliumNetworkPolicy {
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
