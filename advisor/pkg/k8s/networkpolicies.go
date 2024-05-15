package k8s

import (
	"context"
	"encoding/json"
	"strings"

	log "github.com/rs/zerolog/log"
	api "github.com/xentra-ai/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

// Version is set at build time using -ldflags
var Version = "development" // default value

// ModeType defines the mode of operation for generating network policies
type ModeType int

const (
	SinglePod ModeType = iota
	AllPodsInNamespace
	AllPodsInAllNamespaces
)

// GenerateOptions holds options for the GenerateNetworkPolicy function
type GenerateOptions struct {
	Mode      ModeType
	PodName   string // Used if Mode is SinglePod
	Namespace string // Used if Mode is AllPodsInNamespace or SinglePod
}

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
	var pods []corev1.Pod

	switch options.Mode {
	case SinglePod:
		// Fetch all pods in the given namespace
		fetchedPod, err := fetchSinglePodInNamespace(options.PodName, options.Namespace, config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch pods in namespace %s", options.Namespace)
		}
		pods = append(pods, *fetchedPod)

	case AllPodsInNamespace:
		// Fetch all pods in the given namespace
		fetchedPods, err := fetchAllPodsInNamespace(options.Namespace, config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch pods in namespace %s", options.Namespace)
		}
		pods = append(pods, fetchedPods...)

	case AllPodsInAllNamespaces:
		// Fetch all pods in all namespaces
		fetchedPods, err := fetchAllPodsInAllNamespaces(config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch all pods in all namespaces")
		}
		pods = append(pods, fetchedPods...)
	}

	// Generate network policies for each pod in pods
	for _, pod := range pods {
		podTraffic, err := api.GetPodTraffic(pod.Name)
		if err != nil {
			// TODO: Handle policy when pod don't require ingress and/or egress
			log.Debug().Err(err).Msgf("Error retrieving %s pod traffic", pod.Name)
			continue
		}

		podDetail, err := api.GetPodSpec(podTraffic[0].SrcIP)
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
		log.Info().Msgf("Generated policy for pod %s\n%s", pod.Name, string(policyYAML))
	}
}

func transformToNetworkPolicy(podTraffic []api.PodTraffic, podDetail *api.PodDetail, config *Config) (*networkingv1.NetworkPolicy, error) {
	ingressRulesRaw, err := processIngressRules(podTraffic, config)
	if err != nil {
		return nil, err
	}
	egressRulesRaw, err := processEgressRules(podTraffic, config)
	if err != nil {
		return nil, err
	}

	ingressRules := deduplicateIngressRules(ingressRulesRaw)
	egressRules := deduplicateEgressRules(egressRulesRaw)

	podSelectorLabels, err := detectSelectorLabels(config.Clientset, &podDetail.Pod)
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
		peer, err := determinePeerForTraffic(traffic, config)
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
		peer, err := determinePeerForTraffic(traffic, config)
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

	podOrigin, err := api.GetPodSpec(traffic.DstIP)
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
		svcOrigin, err := api.GetSvcSpec(traffic.DstIP)
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

	peerSelectorLabels, err := detectSelectorLabels(config.Clientset, origin)
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

func deduplicateIngressRules(rules []networkingv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyIngressRule {
	seen := make(map[string]bool)
	var deduplicated []networkingv1.NetworkPolicyIngressRule

	for _, rule := range rules {
		ruleStr, _ := json.Marshal(rule)
		if !seen[string(ruleStr)] {
			seen[string(ruleStr)] = true
			deduplicated = append(deduplicated, rule)
		}
	}
	return deduplicated
}

func deduplicateEgressRules(rules []networkingv1.NetworkPolicyEgressRule) []networkingv1.NetworkPolicyEgressRule {
	seen := make(map[string]bool)
	var deduplicated []networkingv1.NetworkPolicyEgressRule

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
	pod, err := config.Clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return pod, nil
}

// fetchAllPodsInNamespace fetches all pods in a specific namespace
func fetchAllPodsInNamespace(namespace string, config *Config) ([]corev1.Pod, error) {
	podList, err := config.Clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}

// fetchAllPodsInAllNamespaces fetches all pods in all namespaces
func fetchAllPodsInAllNamespaces(config *Config) ([]corev1.Pod, error) {
	podList, err := config.Clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}
