package network

import (
	"fmt"

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

// NetworkPolicyRule represents a network policy rule
type NetworkPolicyRule struct {
	PeerIP string
	Ports  []networkingv1.NetworkPolicyPort
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
	Policy    interface{}
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

// IsIngressTraffic checks if traffic is ingress to the pod
func IsIngressTraffic(traffic api.PodTraffic, podDetail *api.PodDetail) bool {
	return traffic.TrafficType == "INGRESS"
}

// IsEgressTraffic checks if traffic is egress from the pod
func IsEgressTraffic(traffic api.PodTraffic, podDetail *api.PodDetail) bool {
	return traffic.TrafficType == "EGRESS"
}
