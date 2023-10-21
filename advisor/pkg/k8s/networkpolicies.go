package k8s

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/rs/zerolog/log"
	api "github.com/xentra-ai/advisor/pkg/api"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
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

func GenerateNetworkPolicy(podName string, config *Config) {
	podTraffic, err := api.GetPodTraffic(podName)
	if err != nil {
		log.Fatal().Err(err).Msg("Error retrieving pod traffic")
	}

	if podTraffic == nil {
		log.Fatal().Msgf("No pod traffic found for pod %s\n", podName)
	}

	podDetail, err := api.GetPodSpec(podTraffic[0].SrcIP)
	if err != nil {
		log.Fatal().Err(err).Msg("Error retrieving pod spec")
	}

	if podDetail == nil {
		log.Fatal().Msgf("No pod spec found for pod %s\n", podTraffic[0].SrcIP)
	}

	policy, err := transformToNetworkPolicy(podTraffic, podDetail, config)
	if err != nil {
		log.Error().Err(err).Msg("Error transforming policy")
	}

	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		log.Error().Err(err).Msg("Error converting policy to YAML")
	}
	log.Info().Msgf("Generated policy for pod %s:\n%s", podName, string(policyYAML))
}

func transformToNetworkPolicy(podTraffic []api.PodTraffic, podDetail *api.PodDetail, config *Config) (*networkingv1.NetworkPolicy, error) {
	ingressRulesRaw := processTrafficRules(podTraffic, "INGRESS", config)
	egressRulesRaw := processTrafficRules(podTraffic, "EGRESS", config)

	ingressRules := deduplicateRules(ingressRulesRaw).([]networkingv1.NetworkPolicyIngressRule)
	egressRules := deduplicateRules(egressRulesRaw).([]networkingv1.NetworkPolicyEgressRule)

	podSelectorLabels, err := detectSelectorLabels(config.Clientset, &podDetail.Pod)
	if err != nil {
		return nil, fmt.Errorf("error detecting selector labels: %w", err)
	}

	networkPolicy := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      podDetail.Name,
			Namespace: podDetail.Namespace,
			Labels: map[string]string{
				"advisor.xentra.ai/managed-by": "xentra",
				"advisor.xentra.ai/version":    "0.0.1",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: ingressRules,
			Egress:  egressRules,
		},
	}

	return networkPolicy, nil
}

func processTrafficRules(podTraffic []api.PodTraffic, trafficType string, config *Config) interface{} {
	var rules interface{}

	for _, traffic := range podTraffic {
		if strings.ToUpper(traffic.TrafficType) != trafficType {
			continue
		}
		peer := determinePeerForTraffic(traffic, config)
		protocol := traffic.Protocol
		portIntOrString := intstr.Parse(traffic.SrcPodPort) // Adjusted this line
		portPtr := &portIntOrString                         // Adjusted this line

		switch trafficType {
		case "INGRESS":
			rules = append(rules.([]networkingv1.NetworkPolicyIngressRule), networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
						Port:     portPtr,
					},
				},
				From: []networkingv1.NetworkPolicyPeer{*peer},
			})

		case "EGRESS":
			portIntOrString := intstr.Parse(traffic.DstPort) // Adjusted this line for destination port
			portPtr := &portIntOrString                      // Adjusted this line for destination port
			rules = append(rules.([]networkingv1.NetworkPolicyEgressRule), networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
						Port:     portPtr,
					},
				},
				To: []networkingv1.NetworkPolicyPeer{*peer},
			})
		}
	}
	return rules
}

func determinePeerForTraffic(traffic api.PodTraffic, config *Config) *networkingv1.NetworkPolicyPeer {
	var origin interface{}

	podOrigin, err := api.GetPodSpec(traffic.DstIP)
	if err == nil && podOrigin != nil {
		origin = podOrigin
	}

	if origin == nil {
		svcOrigin, _ := api.GetSvcSpec(traffic.DstIP) // Error handling can be enhanced.
		if svcOrigin != nil {
			origin = svcOrigin
		}
	}

	if origin == nil {
		log.Debug().Msgf("Could not find details for origin assuming IP is external %s", traffic.DstIP)
		return &networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: traffic.DstIP + "/32",
			},
		}
	}

	peerSelectorLabels, _ := detectSelectorLabels(config.Clientset, origin) // error handling was done internally within the function.
	var metadata metav1.ObjectMeta

	switch o := origin.(type) {
	case *api.PodDetail:
		metadata = o.Pod.ObjectMeta
	case *api.SvcDetail:
		metadata = o.Service.ObjectMeta
	}

	return &networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: peerSelectorLabels,
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": metadata.Namespace},
		},
	}
}

func deduplicateRules(rules interface{}) interface{} {
	seen := make(map[string]bool)

	switch v := rules.(type) {
	case []networkingv1.NetworkPolicyIngressRule:
		var deduplicated []networkingv1.NetworkPolicyIngressRule
		for _, rule := range v {
			ruleStr, _ := json.Marshal(rule)
			if !seen[string(ruleStr)] {
				seen[string(ruleStr)] = true
				deduplicated = append(deduplicated, rule)
			}
		}
		return deduplicated

	case []networkingv1.NetworkPolicyEgressRule:
		var deduplicated []networkingv1.NetworkPolicyEgressRule
		for _, rule := range v {
			ruleStr, _ := json.Marshal(rule)
			if !seen[string(ruleStr)] {
				seen[string(ruleStr)] = true
				deduplicated = append(deduplicated, rule)
			}
		}
		return deduplicated
	}

	return nil
}
