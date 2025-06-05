package network

import (
	"fmt"

	log "github.com/rs/zerolog/log"
	"github.com/xentra-ai/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// StandardPolicyGenerator generates standard Kubernetes NetworkPolicy resources
type StandardPolicyGenerator struct{}

// NewStandardPolicyGenerator creates a new generator for standard NetworkPolicy resources
func NewStandardPolicyGenerator() *StandardPolicyGenerator {
	return &StandardPolicyGenerator{}
}

// GetType returns the policy type
func (g *StandardPolicyGenerator) GetType() PolicyType {
	return StandardPolicy
}

// Generate creates a NetworkPolicy for the specified pod
func (g *StandardPolicyGenerator) Generate(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, error) {
	log.Info().Msgf("Generating standard network policy for pod %s", podName)

	if podDetail == nil {
		return nil, fmt.Errorf("pod detail is nil for pod %s", podName)
	}
	if len(podTraffic) == 0 {
		// If there's no traffic, generate a default-deny policy
		log.Warn().Msgf("No traffic data available for pod %s. Generating a default-deny policy.", podName)
		return g.generateDefaultDenyPolicy(podDetail), nil
	}

	// Group traffic by ingress/egress
	ingressRules, egressRules := g.processTrafficRules(podTraffic, podDetail)

	// Create the NetworkPolicy object
	policy := &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy"), // Use standard-policy for clarity
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels, // Use actual pod labels
			},
			PolicyTypes: []networkingv1.PolicyType{},
		},
	}

	// Add ingress rules if any
	if len(ingressRules) > 0 {
		policy.Spec.PolicyTypes = append(policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
		policy.Spec.Ingress = g.transformToNetworkPolicyIngressRules(ingressRules)
	}

	// Add egress rules if any
	if len(egressRules) > 0 {
		policy.Spec.PolicyTypes = append(policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
		policy.Spec.Egress = g.transformToNetworkPolicyEgressRules(egressRules)
	}

	// If no rules were added (e.g., only traffic to self or unidentifiable IPs), make it default deny
	if len(policy.Spec.PolicyTypes) == 0 {
		log.Warn().Msgf("No valid ingress or egress rules generated for pod %s. Applying default-deny.", podName)
		return g.generateDefaultDenyPolicy(podDetail), nil
	}

	return policy, nil
}

// generateDefaultDenyPolicy creates a policy that denies all ingress and egress traffic
func (g *StandardPolicyGenerator) generateDefaultDenyPolicy(podDetail *api.PodDetail) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy-deny-all"),
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy-deny-all"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels,
			},
			// An empty PolicyTypes slice makes it default-deny for both ingress and egress
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			// Explicitly empty Ingress and Egress rules further clarify the deny-all stance
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	}
}

// processTrafficRules groups traffic rules by direction
func (g *StandardPolicyGenerator) processTrafficRules(podTraffic []api.PodTraffic, podDetail *api.PodDetail) ([]NetworkPolicyRule, []NetworkPolicyRule) {
	var ingressRules, egressRules []NetworkPolicyRule

	for _, traffic := range podTraffic {
		// Convert string port to int, handle potential errors
		portInt, err := parsePort(traffic.DstPort)
		if err != nil {
			log.Warn().Err(err).Msgf("Skipping traffic record due to invalid port: %s", traffic.DstPort)
			continue
		}
		port := intstr.FromInt(portInt)
		protocolStr := string(traffic.Protocol)

		if IsIngressTraffic(traffic, podDetail) {
			peer := traffic.SrcIP
			ingressRules = g.addOrUpdateRule(ingressRules, peer, port, protocolStr)
		} else if IsEgressTraffic(traffic, podDetail) {
			peer := traffic.DstIP
			egressRules = g.addOrUpdateRule(egressRules, peer, port, protocolStr)
		}
		// else: Traffic is neither ingress nor egress for this pod (e.g., traffic between other pods)
	}

	return ingressRules, egressRules
}

// addOrUpdateRule adds a port to an existing rule for a peer or creates a new rule.
func (g *StandardPolicyGenerator) addOrUpdateRule(rules []NetworkPolicyRule, peer string, port intstr.IntOrString, protocolStr string) []NetworkPolicyRule {
	protocol := protocolPtr(protocolStr) // Get protocol pointer once

	for i := range rules {
		if rules[i].PeerIP == peer {
			// Found rule for the peer, check if port/protocol combo exists
			portExists := false
			for _, existingPort := range rules[i].Ports {
				if existingPort.Port != nil && existingPort.Port.String() == port.String() &&
					existingPort.Protocol != nil && *existingPort.Protocol == *protocol {
					portExists = true
					break
				}
			}
			if !portExists {
				// Add port to existing rule
				rules[i].Ports = append(rules[i].Ports, networkingv1.NetworkPolicyPort{
					Port:     &port,
					Protocol: protocol,
				})
			}
			return rules // Rule updated or port already existed
		}
	}

	// No rule found for this peer, create a new one
	newRule := NetworkPolicyRule{
		PeerIP: peer,
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Port:     &port,
				Protocol: protocol,
			},
		},
	}
	return append(rules, newRule)
}

// transformToNetworkPolicyIngressRules converts our internal rules to K8s NetworkPolicyIngressRule
func (g *StandardPolicyGenerator) transformToNetworkPolicyIngressRules(rules []NetworkPolicyRule) []networkingv1.NetworkPolicyIngressRule {
	var ingressRules []networkingv1.NetworkPolicyIngressRule

	// Group rules by peer IP
	peerRules := make(map[string][]networkingv1.NetworkPolicyPort)
	for _, rule := range rules {
		peerRules[rule.PeerIP] = append(peerRules[rule.PeerIP], rule.Ports...)
	}

	// Create ingress rules
	for peerIP, ports := range peerRules {
		peerPolicy := g.createNetworkPolicyPeer(peerIP)
		if peerPolicy == nil { // Skip if peer could not be determined (e.g., internal error)
			continue
		}
		ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
			From:  []networkingv1.NetworkPolicyPeer{*peerPolicy},
			Ports: deduplicatePorts(ports),
		})
	}

	return ingressRules
}

// transformToNetworkPolicyEgressRules converts our internal rules to K8s NetworkPolicyEgressRule
func (g *StandardPolicyGenerator) transformToNetworkPolicyEgressRules(rules []NetworkPolicyRule) []networkingv1.NetworkPolicyEgressRule {
	var egressRules []networkingv1.NetworkPolicyEgressRule

	// Group rules by peer IP
	peerRules := make(map[string][]networkingv1.NetworkPolicyPort)
	for _, rule := range rules {
		peerRules[rule.PeerIP] = append(peerRules[rule.PeerIP], rule.Ports...)
	}

	// Create egress rules
	for peerIP, ports := range peerRules {
		peerPolicy := g.createNetworkPolicyPeer(peerIP)
		if peerPolicy == nil { // Skip if peer could not be determined
			continue
		}

		egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{*peerPolicy},
			Ports: deduplicatePorts(ports),
		})
	}

	return egressRules
}

// createNetworkPolicyPeer determines the NetworkPolicyPeer based on the IP address.
// It prioritizes Service selectors, then Pod selectors, then falls back to IPBlock.
func (g *StandardPolicyGenerator) createNetworkPolicyPeer(peerIP string) *networkingv1.NetworkPolicyPeer {
	// Try to get Service info first
	svcSpec, err := api.GetSvcSpec(peerIP)
	if err == nil && svcSpec != nil && len(svcSpec.Service.Spec.Selector) > 0 {
		log.Debug().Msgf("Using service selector for peer %s: %v in namespace %s",
			peerIP, svcSpec.Service.Spec.Selector, svcSpec.SvcNamespace)
		return &networkingv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: svcSpec.Service.Spec.Selector,
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": svcSpec.SvcNamespace,
				},
			},
		}
	}
	// If error or no service found, log it and try Pod info
	if err != nil {
		log.Debug().Err(err).Msgf("Error fetching service spec for IP %s, trying pod spec.", peerIP)
	} else if svcSpec == nil {
		log.Debug().Msgf("No service found for IP %s, trying pod spec.", peerIP)
	} else { // Service found but no selector
		log.Debug().Msgf("Service %s/%s found for IP %s, but it has no selector. Trying pod spec.", svcSpec.SvcNamespace, svcSpec.SvcName, peerIP)
	}

	// Try to get Pod info
	podSpec, err := api.GetPodSpec(peerIP)
	if err == nil && podSpec != nil && len(podSpec.Pod.Labels) > 0 {
		log.Debug().Msgf("Using pod selector for peer %s: %v in namespace %s",
			peerIP, podSpec.Pod.Labels, podSpec.Namespace)
		return &networkingv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: podSpec.Pod.Labels,
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": podSpec.Namespace,
				},
			},
		}
	}
	// If error or no pod found, log it and fall back to IPBlock
	if err != nil {
		log.Debug().Err(err).Msgf("Error fetching pod spec for IP %s, falling back to IPBlock.", peerIP)
	} else if podSpec == nil {
		log.Debug().Msgf("No pod found for IP %s, falling back to IPBlock.", peerIP)
	} else { // Pod found but no labels
		log.Debug().Msgf("Pod %s/%s found for IP %s, but it has no labels. Falling back to IPBlock.", podSpec.Namespace, podSpec.Name, peerIP)
	}

	// Fall back to IPBlock
	log.Debug().Msgf("Using IP block for peer %s", peerIP)
	ipBlock := &networkingv1.IPBlock{
		CIDR: fmt.Sprintf("%s/32", peerIP),
	}
	return &networkingv1.NetworkPolicyPeer{IPBlock: ipBlock}
}

// Helper functions

// parsePort converts a string port to an integer.
func parsePort(portStr string) (int, error) {
	var portInt int
	_, err := fmt.Sscanf(portStr, "%d", &portInt)
	if err != nil {
		return 0, fmt.Errorf("invalid port format '%s': %w", portStr, err)
	}
	if portInt <= 0 || portInt > 65535 {
		return 0, fmt.Errorf("port number '%d' out of range", portInt)
	}
	return portInt, nil
}

// protocolPtr returns a pointer to the protocol type.
func protocolPtr(protocol string) *corev1.Protocol {
	var p corev1.Protocol
	switch protocol {
	case "TCP":
		p = corev1.ProtocolTCP
	case "UDP":
		p = corev1.ProtocolUDP
	case "SCTP":
		p = corev1.ProtocolSCTP
	default:
		log.Warn().Msgf("Unknown protocol '%s', defaulting to TCP.", protocol)
		p = corev1.ProtocolTCP // Default to TCP for unknown protocols
	}
	return &p
}

// deduplicatePorts removes duplicate ports from a slice.
func deduplicatePorts(ports []networkingv1.NetworkPolicyPort) []networkingv1.NetworkPolicyPort {
	uniquePorts := make(map[string]networkingv1.NetworkPolicyPort)
	var result []networkingv1.NetworkPolicyPort

	for _, port := range ports {
		if port.Port == nil || port.Protocol == nil {
			log.Warn().Msg("Skipping port with nil port or protocol during deduplication.")
			continue // Skip ports with nil values
		}
		key := fmt.Sprintf("%s-%s", port.Port.String(), string(*port.Protocol))
		if _, exists := uniquePorts[key]; !exists {
			uniquePorts[key] = port
			result = append(result, port)
		}
	}

	return result
}
