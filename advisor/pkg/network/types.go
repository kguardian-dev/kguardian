package network

import (
	"fmt"
	"strings"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyType represents the type of network policy
type PolicyType string

const (
	// StandardPolicy is the standard Kubernetes NetworkPolicy
	StandardPolicy PolicyType = "standard"
	// CiliumPolicy is the Cilium NetworkPolicy
	CiliumPolicy PolicyType = "cilium"
)

// NetworkPolicyRule represents a network policy rule: the ports one peer was
// observed on. Peer is the peer's attributed identity (see peer.go); a nil
// Peer means "resolve PeerIP with no row context" — the pre-v4 behaviour,
// kept for callers that build rules from bare IPs. Stamps are the
// time_stamps of the rows folded into the rule (the newest is quoted in the
// unattributed-peer comment).
type NetworkPolicyRule struct {
	PeerIP string
	Peer   *resolvedPeer
	Ports  []networkingv1.NetworkPolicyPort
	Stamps []string
}

// identityKey is the rule's grouping key beside PeerIP ("" for a rule with
// no resolved peer, which groups by IP alone like before).
func (r NetworkPolicyRule) identityKey() string {
	if r.Peer == nil {
		return ""
	}
	return r.Peer.identityKey()
}

// mergeOrAppendResolvedRule is mergeOrAppendRule keyed on (peer IP, resolved
// identity) rather than the IP alone, so flows from two different peers that
// held the same IP at different times never merge into one rule — the
// stored/guarded identity would otherwise be lost at exactly the point it
// matters. It also records the row's time_stamp.
func mergeOrAppendResolvedRule(
	rules []NetworkPolicyRule,
	peer resolvedPeer,
	port intstr.IntOrString,
	protocolStr string,
	timeStamp string,
) []NetworkPolicyRule {
	key := peer.identityKey()
	for i := range rules {
		if rules[i].PeerIP != peer.IP || rules[i].identityKey() != key {
			continue
		}
		rules[i].Stamps = appendStamp(rules[i].Stamps, timeStamp)
		merged := mergeOrAppendRule([]NetworkPolicyRule{rules[i]}, peer.IP, port, protocolStr)
		rules[i].Ports = merged[0].Ports
		return rules
	}
	p := peer
	return append(rules, NetworkPolicyRule{
		PeerIP: peer.IP,
		Peer:   &p,
		Ports:  []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: protocolPtr(protocolStr)}},
		Stamps: appendStamp(nil, timeStamp),
	})
}

func appendStamp(stamps []string, s string) []string {
	if s == "" {
		return stamps
	}
	return append(stamps, s)
}

// mergeOrAppendRule merges a (port, protocol) into an existing
// NetworkPolicyRule for `peer` if one already exists in `rules`, or
// appends a new rule otherwise. Identical (peer, port, protocol)
// triples are no-ops; same peer + same port + different protocol
// (e.g. DNS over TCP/UDP) coexist as separate port entries on the
// same rule.
//
// Shared between StandardPolicyGenerator and CiliumPolicyGenerator,
// which previously had byte-identical copies that drifted apart only
// in a stray comment. Keeping a single implementation prevents one
// generator developing dedup behaviour the other lacks.
func mergeOrAppendRule(
	rules []NetworkPolicyRule,
	peer string,
	port intstr.IntOrString,
	protocolStr string,
) []NetworkPolicyRule {
	protocol := protocolPtr(protocolStr)

	for i := range rules {
		if rules[i].PeerIP == peer {
			for _, existingPort := range rules[i].Ports {
				if existingPort.Port != nil && existingPort.Port.String() == port.String() &&
					existingPort.Protocol != nil && *existingPort.Protocol == *protocol {
					return rules
				}
			}
			rules[i].Ports = append(rules[i].Ports, networkingv1.NetworkPolicyPort{
				Port:     &port,
				Protocol: protocol,
			})
			return rules
		}
	}

	return append(rules, NetworkPolicyRule{
		PeerIP: peer,
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port, Protocol: protocol},
		},
	})
}

// PolicyGenerator is the interface for network policy generators
type PolicyGenerator interface {
	// Generate creates a network policy for the given pod
	Generate(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, error)
	// GetType returns the policy type
	GetType() PolicyType
}

// PolicyOutput represents the output of policy generation
type PolicyOutput struct {
	Policy interface{}
	// Comments are the YAML comments already spliced into YAML (nil when
	// the generator had nothing to explain). Kept for callers that render
	// the policy themselves.
	Comments  *PolicyComments
	YAML      []byte
	PodName   string
	Namespace string
	Type      PolicyType
}

// ConfigProvider provides configuration for policy generation
type ConfigProvider interface {
	// GetClientset returns the Kubernetes clientset
	GetClientset() interface{}
	// IsDryRun returns whether we're in dry run mode
	IsDryRun() bool
	// GetOutputDir returns the output directory
	GetOutputDir() string
}

// GetPolicyName returns a name for the policy
func GetPolicyName(podName, policyType string) string {
	return fmt.Sprintf("%s-%s", podName, policyType)
}

// CreateStandardLabels creates standard labels for a resource
func CreateStandardLabels(podName, resourceType string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      podName,
		"app.kubernetes.io/component": resourceType,
		"app.kubernetes.io/part-of":   "kguardian",
	}
}

// CreateTypeMeta creates a TypeMeta for a resource
func CreateTypeMeta(kind, apiVersion string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: apiVersion,
	}
}

// CreateObjectMeta creates an ObjectMeta for a resource
func CreateObjectMeta(name, namespace string, labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

// IsIngressTraffic checks if traffic is ingress to the pod.
// Case-insensitive on the wire field to match the sibling
// cilium_networkpolicies.go (strings.ToUpper before compare) — guards
// against a future writer emitting mixed-case rather than the broker's
// canonical UPPERCASE convention. Same defensive pattern that caught
// the recent mcp-server case-mismatch.
func IsIngressTraffic(traffic api.PodTraffic, podDetail *api.PodDetail) bool {
	return strings.EqualFold(traffic.TrafficType, "INGRESS")
}

// IsEgressTraffic checks if traffic is egress from the pod.
// See IsIngressTraffic for the case-insensitive rationale.
func IsEgressTraffic(traffic api.PodTraffic, podDetail *api.PodDetail) bool {
	return strings.EqualFold(traffic.TrafficType, "EGRESS")
}
