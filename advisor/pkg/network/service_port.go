package network

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Service ports and backend target ports.
//
// The controller records an egress flow from the socket (tcp_set_state /
// udp_sendmsg). Under kube-proxy the socket still holds the ClusterIP and the
// Service port: the DNAT to a backend pod happens later, in conntrack. So a
// row whose peer resolves to a Service carries the Service `port`.
//
// NetworkPolicy and Cilium evaluate the destination AFTER service
// translation, i.e. the backend pod and its `targetPort`. A rule to the
// Service's selector (or, for host-network backends, to their node IPs) that
// allowed the Service port would drop the very traffic it was generated from
// whenever port != targetPort. The observed port is therefore mapped through
// spec.ports[] (matched on port AND protocol) to its targetPort:
//
//   - a numeric targetPort is emitted as that number;
//   - a named targetPort is emitted as the name (NetworkPolicy and Cilium
//     both accept named ports and resolve them on the selected pods);
//   - an omitted targetPort defaults to the port, as the API server does.
//
// When the spec has no ports or no entry matches, the observed port is kept
// (the pre-existing behaviour) and the rule carries a comment saying the port
// could not be mapped. Only egress rows are mapped: the ingress port is the
// target pod's own port, already post-translation.

// servicePortFor returns the port a rule must allow for an egress flow to
// peer on port/protocol, and false when peer is a Service whose spec could
// not map it. A non-Service peer returns the port unchanged and true.
func servicePortFor(peer resolvedPeer, port int, protocol string) (intstr.IntOrString, bool) {
	observed := intstr.FromInt(port)
	if peer.Svc == nil {
		return observed, true
	}
	proto := *protocolPtr(protocol)
	for _, sp := range peer.Svc.Service.Spec.Ports {
		spProto := sp.Protocol
		if spProto == "" {
			spProto = corev1.ProtocolTCP
		}
		if int(sp.Port) != port || spProto != proto {
			continue
		}
		switch {
		case sp.TargetPort.Type == intstr.String && sp.TargetPort.StrVal != "":
			return intstr.FromString(sp.TargetPort.StrVal), true
		case sp.TargetPort.Type == intstr.Int && sp.TargetPort.IntVal >= 1 && sp.TargetPort.IntVal <= 65535:
			return intstr.FromInt(int(sp.TargetPort.IntVal)), true
		default:
			// Omitted (or unusable) targetPort: Kubernetes defaults it to port.
			return observed, true
		}
	}
	return observed, false
}

// unmappedServicePortComments is one comment line per Service port that
// could not be mapped to a targetPort, in port order (numeric ASC, then
// protocol), deduplicated. Empty for a non-Service peer.
func unmappedServicePortComments(peer resolvedPeer, unmapped []networkingv1.NetworkPolicyPort) []string {
	if peer.Svc == nil || len(unmapped) == 0 {
		return nil
	}
	var lines []string
	for _, p := range deduplicatePorts(unmapped) {
		lines = append(lines, fmt.Sprintf("service %s/svc/%s: port %s/%s could not be mapped to a targetPort; allowing the Service port as observed",
			peer.Svc.SvcNamespace, peer.Svc.SvcName, p.Port.String(), string(*p.Protocol)))
	}
	return lines
}
