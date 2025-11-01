package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	log "github.com/rs/zerolog/log"
	apiapi "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// GenerateCiliumNetworkPolicy generates Cilium network policies for the provided options
func GenerateCiliumNetworkPolicy(options GenerateOptions, config *Config) {
	// Safety check for nil config
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	// Check for dry run mode
	if config.DryRun {
		log.Info().Msgf("Dry run: Would generate Cilium network policy for pod(s) in namespace %s", options.Namespace)
	}

	// Setup output directory if specified
	if config.OutputDir != "" {
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			log.Error().Err(err).Msgf("Failed to create output directory %s", config.OutputDir)
			return
		}
		log.Info().Msgf("Cilium network policies will be saved to %s", config.OutputDir)
	}

	// Fetch pods based on options
	pods := GetResource(options, config)

	if len(pods) == 0 {
		log.Info().Msg("No pods found with the specified criteria")
		return
	}

	// Generate Cilium network policies for each pod in pods
	for _, pod := range pods {
		if pod.Name == "" {
			log.Warn().Msg("Found pod with empty name, skipping")
			continue
		}

		log.Debug().Msgf("Generating Cilium network policy for pod %s", pod.Name)

		podTraffic, err := apiapi.GetPodTraffic(pod.Name)
		if err != nil {
			log.Debug().Err(err).Msgf("Error retrieving %s pod traffic", pod.Name)
			continue
		}

		if len(podTraffic) == 0 {
			log.Info().Msgf("No traffic data found for pod %s", pod.Name)
			continue
		}

		podDetail, err := apiapi.GetPodSpec(podTraffic[0].SrcIP)
		if err != nil {
			log.Error().Err(err).Msgf("Error retrieving %s pod spec", pod.Name)
			continue
		}

		if podDetail == nil {
			log.Error().Msgf("Pod details not found for %s", pod.Name)
			continue
		}

		policy, err := transformToCiliumNetworkPolicy(podTraffic, podDetail, config)
		if err != nil {
			log.Error().Err(err).Msg("Error transforming to Cilium policy")
			continue
		}

		policyYAML, err := yaml.Marshal(policy)
		if err != nil {
			log.Error().Err(err).Msg("Error converting Cilium policy to YAML")
			continue
		}

		// Save policy to file if output directory is specified
		if config.OutputDir != "" {
			filename := filepath.Join(config.OutputDir, fmt.Sprintf("%s-%s-cilium-networkpolicy.yaml", podDetail.Namespace, podDetail.Name))
			if err := os.WriteFile(filename, policyYAML, 0644); err != nil {
				log.Error().Err(err).Msgf("Failed to write Cilium policy for pod %s to file %s", pod.Name, filename)
			} else {
				log.Info().Msgf("Generated Cilium network policy for pod %s saved to %s", pod.Name, filename)
			}
		}

		if config.DryRun {
			// Only print the policy to console if we're not saving to file
			if config.OutputDir == "" {
				log.Info().Msgf("Dry run: Generated Cilium policy for pod %s (not applied)\n%s", pod.Name, string(policyYAML))
			}
		} else {
			// Apply the policy to the cluster
			log.Info().Msgf("Applying Cilium network policy for pod %s", pod.Name)

			// TODO: Implement applying the policy to the cluster
			// For now, just log it
			log.Warn().Msg("Applying Cilium network policies is not yet implemented - only saving to files")
		}
	}
}

// Helper function to create a mock Cilium NetworkPolicy for test mode
func createMockCiliumNetworkPolicy(podName, namespace string) *ciliumv2.CiliumNetworkPolicy {
	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CiliumNetworkPolicy",
			APIVersion: "cilium.io/v2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-policy", podName),
			Namespace: namespace,
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": podName,
					},
				},
			},
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							{
								LabelSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "example-client",
									},
								},
							},
						},
					},
					ToPorts: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{
									Port:     "80",
									Protocol: "TCP",
								},
							},
						},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							{
								LabelSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "example-service",
									},
								},
							},
						},
					},
					ToPorts: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{
									Port:     "443",
									Protocol: "TCP",
								},
							},
						},
					},
				},
			},
		},
	}
}

// transformToCiliumNetworkPolicy converts pod traffic data to a Cilium network policy
func transformToCiliumNetworkPolicy(podTraffic []apiapi.PodTraffic, podDetail *apiapi.PodDetail, config *Config) (*ciliumv2.CiliumNetworkPolicy, error) {
	if config == nil {
		return nil, fmt.Errorf("kubernetes configuration is nil")
	}

	if podDetail == nil {
		return nil, fmt.Errorf("pod detail is nil")
	}

	// Process ingress rules
	ingressRules, err := processCiliumIngressRules(podTraffic, config)
	if err != nil {
		return nil, err
	}

	// Process egress rules
	egressRules, err := processCiliumEgressRules(podTraffic, config)
	if err != nil {
		return nil, err
	}

	podSelectorLabels, err := detectSelectorLabels(config.Clientset, &podDetail.Pod)
	if err != nil {
		return nil, err
	}

	// Ensure we have selector labels
	if podSelectorLabels == nil || len(podSelectorLabels) == 0 {
		log.Warn().Msg("No selector labels found, using default labels")
		podSelectorLabels = map[string]string{
			"app": podDetail.Name,
		}
	}

	// Create endpoint selector
	endpointSelector := api.EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels: podSelectorLabels,
		},
	}

	// Create the rule with ingress and egress rules
	rule := &api.Rule{
		EndpointSelector: endpointSelector,
		Ingress:          ingressRules,
		Egress:           egressRules,
	}

	// Create the CiliumNetworkPolicy with the rule
	ciliumNetworkPolicy := &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      podDetail.Name,
			Namespace: podDetail.Namespace,
			Labels: map[string]string{
				"kguardian.dev/managed-by": "kguardian",
				"kguardian.dev/version":    Version,
			},
		},
		Spec: rule,
	}

	return ciliumNetworkPolicy, nil
}

// processCiliumIngressRules processes pod traffic data into Cilium ingress rules
func processCiliumIngressRules(podTraffic []apiapi.PodTraffic, config *Config) ([]api.IngressRule, error) {
	if config == nil {
		return nil, fmt.Errorf("kubernetes configuration is nil")
	}

	if len(podTraffic) == 0 {
		log.Debug().Msg("No traffic data provided for ingress rules")
		return []api.IngressRule{}, nil
	}

	var ingressRules []api.IngressRule

	for _, traffic := range podTraffic {
		if strings.ToUpper(traffic.TrafficType) != "INGRESS" {
			continue
		}

		// Create Cilium endpoint selector
		endpointSelectors, err := determineCiliumEndpointForTraffic(traffic, config)
		if err != nil {
			log.Error().Err(err).Msgf("Error determining endpoint selectors for traffic: %v", traffic)
			continue // Skip this rule but continue processing others
		}

		// Create port rules
		port, err := strconv.Atoi(traffic.SrcPodPort)
		if err != nil {
			log.Error().Err(err).Msgf("Error converting port %s to integer", traffic.SrcPodPort)
			continue
		}

		// Create the port protocol
		l4Proto := api.L4Proto(strings.ToUpper(string(traffic.Protocol)))

		ports := []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     strconv.Itoa(port),
						Protocol: l4Proto,
					},
				},
			},
		}

		ingressRule := api.IngressRule{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: endpointSelectors,
			},
			ToPorts: ports,
		}

		ingressRules = append(ingressRules, ingressRule)
	}

	// Deduplicate rules
	return deduplicateCiliumIngressRules(ingressRules), nil
}

// processCiliumEgressRules processes pod traffic data into Cilium egress rules
func processCiliumEgressRules(podTraffic []apiapi.PodTraffic, config *Config) ([]api.EgressRule, error) {
	if config == nil {
		return nil, fmt.Errorf("kubernetes configuration is nil")
	}

	if len(podTraffic) == 0 {
		log.Debug().Msg("No traffic data provided for egress rules")
		return []api.EgressRule{}, nil
	}

	var egressRules []api.EgressRule

	for _, traffic := range podTraffic {
		if strings.ToUpper(traffic.TrafficType) != "EGRESS" {
			continue
		}

		// Create Cilium endpoint selector
		endpointSelectors, err := determineCiliumEndpointForTraffic(traffic, config)
		if err != nil {
			log.Error().Err(err).Msgf("Error determining endpoint selectors for traffic: %v", traffic)
			continue // Skip this rule but continue processing others
		}

		// Create port rules
		port, err := strconv.Atoi(traffic.DstPort)
		if err != nil {
			log.Error().Err(err).Msgf("Error converting port %s to integer", traffic.DstPort)
			continue
		}

		// Create the port protocol
		l4Proto := api.L4Proto(strings.ToUpper(string(traffic.Protocol)))

		ports := []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     strconv.Itoa(port),
						Protocol: l4Proto,
					},
				},
			},
		}

		egressRule := api.EgressRule{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: endpointSelectors,
			},
			ToPorts: ports,
		}

		// Handle CIDR-based rules for external traffic
		if len(endpointSelectors) == 0 {
			// This is an external destination, use ToCIDR instead
			egressRule.ToCIDR = []api.CIDR{api.CIDR(traffic.DstIP + "/32")}
		}

		egressRules = append(egressRules, egressRule)
	}

	// Deduplicate rules
	return deduplicateCiliumEgressRules(egressRules), nil
}

// determineCiliumEndpointForTraffic determines the appropriate endpoint selector for traffic
func determineCiliumEndpointForTraffic(traffic apiapi.PodTraffic, config *Config) ([]api.EndpointSelector, error) {
	if config == nil {
		return nil, fmt.Errorf("kubernetes configuration is nil")
	}

	if config.Clientset == nil {
		return nil, fmt.Errorf("kubernetes clientset is nil")
	}

	// Default empty selector for cases where no valid endpoints are found
	emptySelectors := []api.EndpointSelector{}

	// Check if traffic destination IP is valid
	if traffic.DstIP == "" {
		log.Debug().Msg("Empty destination IP in traffic data")
		return emptySelectors, nil
	}

	var origin interface{} = nil

	podOrigin, err := apiapi.GetPodSpec(traffic.DstIP)
	if err != nil {
		log.Debug().Err(err).Msgf("Error getting pod spec for IP %s, will try service lookup", traffic.DstIP)
		// Just continue to try service lookup, don't return error
	}

	// Handle pods with hostNetwork: true where the IP will be Node IP
	if podOrigin != nil && podOrigin.Pod.Spec.HostNetwork {
		log.Debug().Msgf("Pod traffic detected is using HostNetwork %s", podOrigin.PodIP)
		return emptySelectors, nil
	}

	if podOrigin != nil {
		origin = podOrigin
	}

	if origin == nil {
		svcOrigin, err := apiapi.GetSvcSpec(traffic.DstIP)
		if err != nil {
			log.Debug().Err(err).Msgf("Error getting service spec for IP %s", traffic.DstIP)
			// Just continue, may be external traffic
		}
		if svcOrigin != nil {
			origin = svcOrigin
		}
	}

	if origin == nil {
		log.Debug().Msgf("Could not find details for origin assuming IP is external %s", traffic.DstIP)
		return emptySelectors, nil
	}

	peerSelectorLabels, err := detectSelectorLabels(config.Clientset, origin)
	if err != nil {
		log.Debug().Err(err).Msg("Error detecting selector labels, using empty selectors")
		return emptySelectors, nil
	}

	if peerSelectorLabels == nil || len(peerSelectorLabels) == 0 {
		log.Debug().Msg("No peer selector labels found, using empty selectors")
		return emptySelectors, nil
	}

	var metadata metav1.ObjectMeta
	switch o := origin.(type) {
	case *apiapi.PodDetail:
		metadata = o.Pod.ObjectMeta
	case *apiapi.SvcDetail:
		metadata = o.Service.ObjectMeta
	default:
		log.Debug().Msgf("Unknown origin type: %T", origin)
		return emptySelectors, nil
	}

	// Create Cilium endpoint selector with pod and namespace labels
	endpointSelector := api.EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels: peerSelectorLabels,
		},
	}

	// Add namespace selector if namespace is available
	if metadata.Namespace != "" {
		namespaceSelector := api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"io.kubernetes.pod.namespace": metadata.Namespace},
			},
		}
		return []api.EndpointSelector{endpointSelector, namespaceSelector}, nil
	}

	return []api.EndpointSelector{endpointSelector}, nil
}

// deduplicateCiliumIngressRules removes duplicate ingress rules
func deduplicateCiliumIngressRules(rules []api.IngressRule) []api.IngressRule {
	seen := make(map[string]bool)
	var deduplicated []api.IngressRule

	for _, rule := range rules {
		ruleStr, _ := json.Marshal(rule)
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}

// deduplicateCiliumEgressRules removes duplicate egress rules
func deduplicateCiliumEgressRules(rules []api.EgressRule) []api.EgressRule {
	seen := make(map[string]bool)
	var deduplicated []api.EgressRule

	for _, rule := range rules {
		ruleStr, _ := json.Marshal(rule)
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}
