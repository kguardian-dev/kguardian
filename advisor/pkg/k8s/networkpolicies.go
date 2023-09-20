package k8s

import (
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
		return
	}

	if podTraffic == nil {
		log.Fatal().Msgf("No pod traffic found for pod %s\n", podName)
		return
	}

	podDetail, err := api.GetPodSpec(podTraffic[0].SrcIP)
	if err != nil {
		log.Fatal().Err(err).Msg("Error retrieving pod spec")
		return
	}

	if podDetail == nil {
		log.Fatal().Msgf("No pod spec found for pod %s\n", podTraffic[0].SrcIP)
		return
	}

	policy := TransformToNetworkPolicy(&podTraffic, podDetail, config)
	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		log.Error().Err(err).Msg("Error converting policy to YAML")
		return
	}
	log.Info().Msgf("Generated policy for pod %s:\n%s", podName, string(policyYAML))
}

func TransformToNetworkPolicy(podTraffic *[]api.PodTraffic, podDetail *api.PodDetail, config *Config) *networkingv1.NetworkPolicy {
	var ingressRules []networkingv1.NetworkPolicyIngressRule
	var egressRules []networkingv1.NetworkPolicyEgressRule

	podSelectorLabels, err := DetectSelectorLabels(config.Clientset, &podDetail.Pod)
	if err != nil {
		// This would mean a controller was detected but may no longer exist due to the pod being deleted but still present in the database
		// TODO: Handle this case
		log.Error().Err(err).Msg("Detect Pod Labels")
		return nil
	}

	for _, traffic := range *podTraffic {
		var origin interface{}

		// Get pod spec for the pod that is sending traffic
		podOrigin, err := api.GetPodSpec(traffic.DstIP)
		if err != nil {
			log.Error().Err(err).Msg("Get Pod Spec of origin")
		}
		if podOrigin != nil {
			origin = podOrigin
		}

		// If we couldn't get the Pod details, try getting the Service details
		if origin == nil {
			svcOrigin, err := api.GetSvcSpec(traffic.DstIP)
			if err != nil {
				log.Error().Err(err).Msg("Get Svc Spec of origin")
				continue
			} else if svcOrigin != nil {
				origin = svcOrigin
			}
		}

		if origin == nil {
			log.Info().Msgf("Could not find details for origin assuming IP is external %s", traffic.DstIP)
		}

		var metadata metav1.ObjectMeta
		var peerSelectorLabels map[string]string
		peer := networkingv1.NetworkPolicyPeer{}
		// If the traffic originated from in-cluster as either a pod or service
		if origin != nil {
			peerSelectorLabels, err = DetectSelectorLabels(config.Clientset, origin)
			if err != nil {
				log.Error().Err(err).Msg("Detect Peer Labels")
				continue
			}
			switch o := origin.(type) {
			case *api.PodDetail:
				metadata = o.Pod.ObjectMeta
			case *api.SvcDetail:
				metadata = o.Service.ObjectMeta
			default:
				log.Error().Msg("Unknown type for origin")
				continue
			}
			peer = networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: peerSelectorLabels,
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": metadata.Namespace},
				},
			}
		} else {
			peer = networkingv1.NetworkPolicyPeer{
				IPBlock: &networkingv1.IPBlock{
					CIDR: traffic.DstIP + "/32",
				},
			}
		}

		protocol := traffic.Protocol
		if traffic.TrafficType == "INGRESS" {
			port := intstr.Parse(traffic.SrcPodPort)
			ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
						Port:     &port,
					},
				},
				From: []networkingv1.NetworkPolicyPeer{peer},
			})
		} else if traffic.TrafficType == "EGRESS" {
			port := intstr.Parse(traffic.DstPort)

			egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
						Port:     &port,
					},
				},
				To: []networkingv1.NetworkPolicyPeer{peer},
			})
		}
	}

	networkPolicy := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      podDetail.Name,
			Namespace: podDetail.Namespace,
			// TODO: What labels should we use?
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

	return networkPolicy
}
