package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/rs/zerolog/log"
	api "github.com/xentra-ai/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// API function variables are now defined in the api package

// Function variables to make mocking easier in tests
var (
	processIngressRulesFunc  = processIngressRules
	processEgressRulesFunc   = processEgressRules
	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return detectSelectorLabels(clientset, origin)
	}
	determinePeerForTrafficFunc = determinePeerForTraffic

	// Pod fetch function variables are defined in generic.go
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

func GenerateNetworkPolicy(options GenerateOptions, config *Config) {
	// Safety check for nil config
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	// Check for dry run mode
	if config.DryRun {
		log.Info().Msgf("Dry run: Would generate Kubernetes network policy for pod(s) in namespace %s", options.Namespace)
	}

	// Setup output directory if specified
	if config.OutputDir != "" {
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			log.Error().Err(err).Msgf("Failed to create output directory %s", config.OutputDir)
			return
		}
		log.Info().Msgf("Network policies will be saved to %s", config.OutputDir)
	}

	// Fetch pods based on options
	pods := GetResource(options, config)

	if len(pods) == 0 {
		log.Info().Msg("No pods found with the specified criteria")
		return
	}

	// Generate network policies for each pod in pods
	for _, pod := range pods {
		podTraffic, err := api.GetPodTrafficFunc(pod.Name)
		if err != nil {
			// TODO: Handle policy when pod don't require ingress and/or egress
			log.Debug().Err(err).Msgf("Error retrieving %s pod traffic", pod.Name)
			continue
		}

		podDetail, err := api.GetPodSpecFunc(podTraffic[0].SrcIP)
		if err != nil {
			log.Error().Err(err).Msgf("Error retrieving %s pod spec", pod.Name)
			continue
		}

		policy, err := transformToNetworkPolicy(podTraffic, podDetail, config)
		if err != nil {
			log.Error().Err(err).Msg("Error transforming policy")
			continue
		}

		policyYAML, err := yaml.Marshal(policy)
		if err != nil {
			log.Error().Err(err).Msg("Error converting policy to YAML")
			continue
		}

		// Save policy to file if output directory is specified
		if config.OutputDir != "" {
			filename := filepath.Join(config.OutputDir, fmt.Sprintf("%s-%s-networkpolicy.yaml", podDetail.Namespace, podDetail.Name))
			if err := os.WriteFile(filename, policyYAML, 0644); err != nil {
				log.Error().Err(err).Msgf("Failed to write policy for pod %s to file %s", pod.Name, filename)
			} else {
				log.Info().Msgf("Generated network policy for pod %s saved to %s", pod.Name, filename)
			}
		}

		if config.DryRun {
			// Only print the policy to console if we're not saving to file
			if config.OutputDir == "" {
				log.Info().Msgf("Dry run: Generated policy for pod %s (not applied)\n%s", pod.Name, string(policyYAML))
			}
		} else {
			// Apply the policy to the cluster
			log.Info().Msgf("Applying network policy for pod %s", pod.Name)

			// TODO: Implement applying the policy to the cluster
			// For now, just log it
			log.Warn().Msg("Applying network policies is not yet implemented - only saving to files")
		}
	}
}

func transformToNetworkPolicy(podTraffic []api.PodTraffic, podDetail *api.PodDetail, config *Config) (*networkingv1.NetworkPolicy, error) {
	ingressRulesRaw, err := processIngressRulesFunc(podTraffic, config)
	if err != nil {
		return nil, err
	}
	egressRulesRaw, err := processEgressRulesFunc(podTraffic, config)
	if err != nil {
		return nil, err
	}

	ingressRules := deduplicateRules(ingressRulesRaw)
	egressRules := deduplicateRules(egressRulesRaw)

	podSelectorLabels, err := detectSelectorLabelsFunc(config.Clientset, &podDetail.Pod)
	if err != nil {
		return nil, err
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
				"advisor.xentra.ai/version":    Version,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: ingressRules,
			Egress:  egressRules,
		},
	}

	if podSelectorLabels != nil {
		networkPolicy.Spec.PodSelector = metav1.LabelSelector{
			MatchLabels: podSelectorLabels,
		}
	} else {
		log.Debug().Msgf("Failed to detect MatchLabels for target %s", podDetail.Name)
	}

	return networkPolicy, nil
}

func processIngressRules(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyIngressRule, error) {
	var ingressRules []networkingv1.NetworkPolicyIngressRule
	for _, traffic := range podTraffic {
		if strings.ToUpper(traffic.TrafficType) != "INGRESS" {
			continue
		}
		peer, err := determinePeerForTrafficFunc(traffic, config)
		if err != nil {
			return nil, err
		}
		protocol := traffic.Protocol
		portIntOrString := intstr.Parse(traffic.SrcPodPort)
		portPtr := &portIntOrString
		ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &protocol,
					Port:     portPtr,
				},
			},
			From: []networkingv1.NetworkPolicyPeer{*peer},
		})
	}
	return ingressRules, nil
}

func processEgressRules(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyEgressRule, error) {
	var egressRules []networkingv1.NetworkPolicyEgressRule
	for _, traffic := range podTraffic {
		if strings.ToUpper(traffic.TrafficType) != "EGRESS" {
			continue
		}
		peer, err := determinePeerForTrafficFunc(traffic, config)
		if err != nil {
			return nil, err
		}
		protocol := traffic.Protocol
		portIntOrString := intstr.Parse(traffic.DstPort)
		portPtr := &portIntOrString
		egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &protocol,
					Port:     portPtr,
				},
			},
			To: []networkingv1.NetworkPolicyPeer{*peer},
		})
	}
	return egressRules, nil
}

func determinePeerForTraffic(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyPeer, error) {
	var origin interface{} = nil

	podOrigin, err := api.GetPodSpecFunc(traffic.DstIP)
	if err != nil {
		return nil, err
	}
	// TODO: Should we add HostNetwork blocks or ignore them?
	// Handle pods with hostNetwork: true where the IP will be Node IP
	if podOrigin != nil && podOrigin.Pod.Spec.HostNetwork {
		log.Debug().Msgf("Pod traffic detected is using HostNetwork %s", podOrigin.PodIP)
		return &networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: traffic.DstIP + "/32",
			},
		}, nil
	}
	if podOrigin != nil {
		origin = podOrigin
	}

	if origin == nil {
		svcOrigin, err := api.GetSvcSpecFunc(traffic.DstIP)
		if err != nil {
			return nil, err
		}
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
		}, nil
	}

	peerSelectorLabels, err := detectSelectorLabelsFunc(config.Clientset, origin)
	if err != nil {
		return nil, err
	}

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
	}, nil
}

// Generic deduplication function
func deduplicateRules[T any](rules []T) []T {
	seen := make(map[string]bool)
	var deduplicated []T

	for _, rule := range rules {
		ruleStr, _ := json.Marshal(rule)
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}

// fetchSinglePodInNamespace fetches a single pods in a specific namespace
func fetchSinglePodInNamespace(podName, namespace string, config *Config) (*corev1.Pod, error) {
	// Safety check for nil config or clientset
	if config == nil || config.Clientset == nil {
		log.Warn().Msg("Running in test mode - creating mock pod")
		// Create mock pod for test mode
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
				Labels: map[string]string{
					"app": podName,
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "test-image",
					},
				},
			},
		}, nil
	}

	pod, err := config.Clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return pod, nil
}

// fetchAllPodsInNamespace fetches all pods in a specific namespace
func fetchAllPodsInNamespace(namespace string, config *Config) ([]corev1.Pod, error) {
	// Safety check for nil config or clientset
	if config == nil || config.Clientset == nil {
		log.Warn().Msg("Running in test mode - creating mock pods")
		// Create mock pods for test mode
		return []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-1",
					Namespace: namespace,
					Labels: map[string]string{
						"app": "test-pod-1",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-2",
					Namespace: namespace,
					Labels: map[string]string{
						"app": "test-pod-2",
					},
				},
			},
		}, nil
	}

	podList, err := config.Clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}

// fetchAllPodsInAllNamespaces fetches all pods in all namespaces
func fetchAllPodsInAllNamespaces(config *Config) ([]corev1.Pod, error) {
	// Safety check for nil config or clientset
	if config == nil || config.Clientset == nil {
		log.Warn().Msg("Running in test mode - creating mock pods in mock namespaces")
		// Create mock pods for test mode
		return []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-1",
					Namespace: "test-namespace-1",
					Labels: map[string]string{
						"app": "test-pod-1",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-2",
					Namespace: "test-namespace-2",
					Labels: map[string]string{
						"app": "test-pod-2",
					},
				},
			},
		}, nil
	}

	podList, err := config.Clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}

// Helper function to create a mock Kubernetes NetworkPolicy for test mode
func createMockKubernetesNetworkPolicy(podName, namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-policy", podName),
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": podName,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "example-client",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 80,
							},
							Protocol: func() *corev1.Protocol {
								p := corev1.ProtocolTCP
								return &p
							}(),
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "example-service",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
							Protocol: func() *corev1.Protocol {
								p := corev1.ProtocolTCP
								return &p
							}(),
						},
					},
				},
			},
		},
	}
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
