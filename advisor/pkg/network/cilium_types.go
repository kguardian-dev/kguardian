package network

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hand-rolled CiliumNetworkPolicy types. These replace the heavy
// github.com/cilium/cilium dependency — pulled in transitively hive, statedb,
// gopacket, otel, azure-sdk, etc. — which the advisor imported solely to build
// and marshal a CiliumNetworkPolicy YAML. The structs below reproduce exactly
// the YAML the library emitted; the G2 golden fixtures
// (test/fixtures/generators/networkpolicy/cilium_*.golden.yaml) pin every
// output path (CIDR peers, endpoint-resolved peers, default-deny) byte-for-byte.
//
// Field ordering in the emitted YAML is alphabetical because sigs.k8s.io/yaml
// marshals through encoding/json (which sorts map keys) then to YAML — the same
// path the library used, so ordering matches without extra effort.

// CiliumNetworkPolicy mirrors cilium.io/v2 CiliumNetworkPolicy for the subset
// the generator produces. Status is a non-omitempty empty object so the YAML
// carries `status: {}`, matching the library output.
type CiliumNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              *CiliumRule  `json:"spec,omitempty"`
	Status            CiliumStatus `json:"status"`
}

// CiliumStatus is intentionally empty — the generator never sets status, and
// the library emitted a bare `status: {}`.
type CiliumStatus struct{}

// CiliumRule is the policy spec (cilium policy/api Rule subset).
type CiliumRule struct {
	EndpointSelector  CiliumEndpointSelector `json:"endpointSelector,omitempty"`
	Description       string                 `json:"description,omitempty"`
	Ingress           []CiliumIngressRule    `json:"ingress,omitempty"`
	Egress            []CiliumEgressRule     `json:"egress,omitempty"`
	EnableDefaultDeny *CiliumDefaultDeny     `json:"enableDefaultDeny,omitempty"`
}

// CiliumEndpointSelector selects endpoints by label. Cilium serializes labels
// with their source prefix, so keys are "k8s:<key>" (see newCiliumEndpointSelector).
type CiliumEndpointSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// CiliumIngressRule allows traffic from endpoints or CIDRs on given ports.
type CiliumIngressRule struct {
	FromEndpoints []CiliumEndpointSelector `json:"fromEndpoints,omitempty"`
	FromCIDR      []string                 `json:"fromCIDR,omitempty"`
	ToPorts       []CiliumPortRule         `json:"toPorts,omitempty"`
}

// CiliumEgressRule allows traffic to endpoints or CIDRs on given ports.
type CiliumEgressRule struct {
	ToEndpoints []CiliumEndpointSelector `json:"toEndpoints,omitempty"`
	ToCIDR      []string                 `json:"toCIDR,omitempty"`
	ToPorts     []CiliumPortRule         `json:"toPorts,omitempty"`
}

// CiliumPortRule is a set of L4 ports.
type CiliumPortRule struct {
	Ports []CiliumPortProtocol `json:"ports,omitempty"`
}

// CiliumPortProtocol is a single port/protocol pair. Port is a string to match
// the library (it accepts named or numeric ports).
type CiliumPortProtocol struct {
	Port     string `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// CiliumDefaultDeny toggles Cilium's default-deny per direction.
type CiliumDefaultDeny struct {
	Ingress *bool `json:"ingress,omitempty"`
	Egress  *bool `json:"egress,omitempty"`
}

// newCiliumEndpointSelector builds a selector from pod/service labels, applying
// Cilium's "k8s:" label-source prefix so the emitted matchLabels match what
// NewESFromLabels(...LabelSourceK8s) produced.
func newCiliumEndpointSelector(labels map[string]string) CiliumEndpointSelector {
	if len(labels) == 0 {
		return CiliumEndpointSelector{}
	}
	m := make(map[string]string, len(labels))
	for k, v := range labels {
		m["k8s:"+k] = v
	}
	return CiliumEndpointSelector{MatchLabels: m}
}
