package k8s

import (
	"encoding/json"
	"fmt"

	log "github.com/rs/zerolog/log"
	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// API function variables are now defined in the api package

// Function variables to make mocking easier in tests
//
//nolint:unused // Reserved for future testing/mocking use
var (
	processIngressRulesFunc  = processIngressRules
	processEgressRulesFunc   = processEgressRules
	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return detectSelectorLabels(clientset, origin)
	}
	determinePeerForTrafficFunc = determinePeerForTraffic

	// Pod fetch function variables have been removed and logic moved to pods.go
)

type NetworkPolicyRule struct {
	Ports  []networkingv1.NetworkPolicyPort
	FromTo []networkingv1.NetworkPolicyPeer
}

type NetworkPolicySpec struct {
	PodSelector metav1.LabelSelector
	PolicyTypes []networkingv1.PolicyType
	Ingress     []NetworkPolicyRule
	Egress      []NetworkPolicyRule
}

type RuleSets struct {
	Ingress []networkingv1.NetworkPolicyIngressRule
	Egress  []networkingv1.NetworkPolicyEgressRule
}

// transformToNetworkPolicy transforms pod traffic data into Kubernetes NetworkPolicy rules.
//
//nolint:unused // Reserved for future refactoring
func transformToNetworkPolicy(pod *corev1.Pod, podTraffic []api.PodTraffic, podDetail *api.PodDetail, config *Config) ([]networkingv1.NetworkPolicyIngressRule, []networkingv1.NetworkPolicyEgressRule, error) {
	ruleSets := RuleSets{}

	for _, traffic := range podTraffic {
		var err error
		isIngress := traffic.TrafficType == "INGRESS"
		isEgress := traffic.TrafficType == "EGRESS"

		if isIngress {
			rule, err := processIngressRulesFunc(traffic, config)
			if err != nil {
				log.Debug().Err(err).Msg("Error processing ingress rule")
				continue
			}
			if rule != nil {
				ruleSets.Ingress = append(ruleSets.Ingress, *rule)
			}
		} else if isEgress {
			rule, err := processEgressRulesFunc(traffic, config)
			if err != nil {
				log.Debug().Err(err).Msg("Error processing egress rule")
				continue
			}
			if rule != nil {
				ruleSets.Egress = append(ruleSets.Egress, *rule)
			}
		} else {
			log.Warn().Msgf("Traffic doesn't match pod IP %s. Src: %s, Dst: %s", podDetail.PodIP, traffic.SrcIP, traffic.DstIP)
		}

		if err != nil {
			log.Error().Err(err).Msg("Error processing traffic record")
			continue // Skip this traffic record and continue with the next
		}
	}

	// Deduplicate rules
	deduplicatedIngress := deduplicateIngressRules(ruleSets.Ingress)
	deduplicatedEgress := deduplicateEgressRules(ruleSets.Egress)

	return deduplicatedIngress, deduplicatedEgress, nil
}

//nolint:unused // Reserved for future refactoring
func processIngressRules(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyIngressRule, error) {
	peer, err := determinePeerForTrafficFunc(traffic.DstIP, config)
	if err != nil {
		return nil, fmt.Errorf("error determining peer for ingress traffic from %s: %w", traffic.DstIP, err)
	}

	portInt := 0
	_, _ = fmt.Sscanf(traffic.SrcPodPort, "%d", &portInt)
	port := intstr.FromInt(portInt)
	protocol := traffic.Protocol

	rule := &networkingv1.NetworkPolicyIngressRule{
		From: []networkingv1.NetworkPolicyPeer{peer},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Port:     &port,
				Protocol: &protocol,
			},
		},
	}

	return rule, nil
}

//nolint:unused // Reserved for future refactoring
func processEgressRules(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyEgressRule, error) {
	peer, err := determinePeerForTrafficFunc(traffic.DstIP, config)
	if err != nil {
		return nil, fmt.Errorf("error determining peer for egress traffic to %s: %w", traffic.DstIP, err)
	}

	portInt := 0
	_, _ = fmt.Sscanf(traffic.DstPort, "%d", &portInt)
	port := intstr.FromInt(portInt)
	protocol := traffic.Protocol

	rule := &networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{peer},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Port:     &port,
				Protocol: &protocol,
			},
		},
	}

	return rule, nil
}

//nolint:unused // Reserved for future refactoring
func determinePeerForTraffic(ip string, config *Config) (networkingv1.NetworkPolicyPeer, error) {
	// Check if the IP corresponds to a known service or pod
	origin, err := api.GetSvcSpec(ip) // Try service first
	if err != nil || origin == nil {
		log.Debug().Msgf("No service found for IP %s, checking for pods...", ip)
		podOrigin, podErr := api.GetPodSpec(ip)
		if podErr != nil || podOrigin == nil {
			log.Debug().Msgf("No pod found for IP %s, assuming external IP.", ip)
			// Assume external IP if no service or pod found
			ipBlock := &networkingv1.IPBlock{
				CIDR: fmt.Sprintf("%s/32", ip),
			}
			return networkingv1.NetworkPolicyPeer{IPBlock: ipBlock}, nil
		}
		// Found a pod
		log.Debug().Msgf("Found pod %s/%s for IP %s", podOrigin.Namespace, podOrigin.Name, ip)
		return networkingv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: podOrigin.Pod.Labels,
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": podOrigin.Namespace,
				},
			},
		}, nil
	}

	// Found a service
	log.Debug().Msgf("Found service %s/%s for IP %s", origin.SvcNamespace, origin.SvcName, ip)
	return networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: origin.Service.Spec.Selector,
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": origin.SvcNamespace,
			},
		},
	}, nil
}

// Deduplicate ingress rules based on From and Ports
//
//nolint:unused // Reserved for future refactoring
func deduplicateIngressRules(rules []networkingv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyIngressRule {
	seen := make(map[string]bool)
	deduplicated := []networkingv1.NetworkPolicyIngressRule{}
	for _, rule := range rules {
		ruleStr, err := json.Marshal(rule)
		if err != nil {
			log.Warn().Err(err).Msg("Error marshaling ingress rule for deduplication")
			continue
		}
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}

// Deduplicate egress rules based on To and Ports
//
//nolint:unused // Reserved for future refactoring
func deduplicateEgressRules(rules []networkingv1.NetworkPolicyEgressRule) []networkingv1.NetworkPolicyEgressRule {
	seen := make(map[string]bool)
	deduplicated := []networkingv1.NetworkPolicyEgressRule{}
	for _, rule := range rules {
		ruleStr, err := json.Marshal(rule)
		if err != nil {
			log.Warn().Err(err).Msg("Error marshaling egress rule for deduplication")
			continue
		}
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}

// Policy generator interface
type PolicyGenerator interface {
	GeneratePolicy(podTraffic []api.PodTraffic, podDetail *api.PodDetail, config *Config) (interface{}, error)
	CreateMockPolicy(podName, namespace string) interface{}
}

// Mock factory
func CreateMockPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app": name,
			},
		},
		// ...other fields
	}
}
