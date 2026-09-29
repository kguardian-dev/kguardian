package network

import (
	"fmt"
	"sort"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
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
//   - a named targetPort is emitted as the name when the Service selects
//     ordinary pods (NetworkPolicy and Cilium resolve named ports against the
//     containerPort names of the selected pods);
//   - a named targetPort on a Service backed by host-network pods is resolved
//     here, through the backends' containers[].ports[] (name AND protocol),
//     to the number(s): the rule's peer is then an ipBlock / host entities,
//     which have no endpoints to resolve a name against, and a host-network
//     containerPort is the host port. Backends that disagree yield every
//     distinct number;
//   - an omitted targetPort defaults to the port, as the API server does.
//
// When the spec has no ports, no entry matches, or a host-network backend
// name cannot be resolved, the observed port is kept (the pre-existing
// behaviour) and the rule carries a comment saying the port could not be
// mapped. Only egress rows are mapped: the ingress port is the target pod's
// own port, already post-translation.

// servicePortFor returns the port(s) a rule must allow for an egress flow to
// peer on port/protocol, and false when peer is a Service whose spec could
// not map it (the observed port is then returned). A non-Service peer returns
// the port unchanged and true.
func servicePortFor(peer resolvedPeer, port int, protocol string) ([]intstr.IntOrString, bool) {
	observed := []intstr.IntOrString{intstr.FromInt(port)}
	if peer.Svc == nil {
		return observed, true
	}
	proto := *protocolPtr(protocol)
	for _, sp := range peer.Svc.Service.Spec.Ports {
		if int(sp.Port) != port || protocolOrTCP(sp.Protocol) != proto {
			continue
		}
		switch {
		case sp.TargetPort.Type == intstr.String && sp.TargetPort.StrVal != "":
			if len(peer.Backends) == 0 {
				return []intstr.IntOrString{intstr.FromString(sp.TargetPort.StrVal)}, true
			}
			if nums := hostBackendPortNumbers(peer.Backends, sp.TargetPort.StrVal, proto); len(nums) > 0 {
				return nums, true
			}
			return observed, false
		case sp.TargetPort.Type == intstr.Int && sp.TargetPort.IntVal >= 1 && sp.TargetPort.IntVal <= 65535:
			return []intstr.IntOrString{intstr.FromInt(int(sp.TargetPort.IntVal))}, true
		default:
			// Omitted (or unusable) targetPort: Kubernetes defaults it to port.
			return observed, true
		}
	}
	return observed, false
}

func protocolOrTCP(p corev1.Protocol) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return p
}

// hostBackendPortNumbers resolves a named targetPort against the containers
// of a Service's host-network backends: every distinct containerPort
// (1-65535) whose name and protocol match, ascending. Empty when none does.
func hostBackendPortNumbers(backends []api.PodDetail, name string, proto corev1.Protocol) []intstr.IntOrString {
	seen := map[int32]bool{}
	var nums []int
	for _, b := range backends {
		for _, c := range b.Pod.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name != name || protocolOrTCP(cp.Protocol) != proto || cp.ContainerPort < 1 || cp.ContainerPort > 65535 || seen[cp.ContainerPort] {
					continue
				}
				seen[cp.ContainerPort] = true
				nums = append(nums, int(cp.ContainerPort))
			}
		}
	}
	sort.Ints(nums)
	out := make([]intstr.IntOrString, 0, len(nums))
	for _, n := range nums {
		out = append(out, intstr.FromInt(n))
	}
	return out
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
