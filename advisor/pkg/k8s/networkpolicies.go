package k8s

import (
	"fmt"
	"log"

	api "github.com/arx-inc/advisor/pkg/api"
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
		log.Fatalf("Error retrieving pod traffic: %v\n", err)
		return
	}

	if podTraffic == nil {
		log.Fatalf("No pod traffic found for pod %s\n", podName)
		return
	}

	podDetail, err := api.GetPodSpec(podTraffic[0].SrcIP)
	if err != nil {
		log.Fatalf("Error retrieving pod spec: %v\n", err)
		return
	}

	if podDetail == nil {
		log.Fatalf("No pod spec found for pod %s\n", podDetail.Name)
		return
	}

	policy := TransformToNetworkPolicy(&podTraffic, podDetail, config)
	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		fmt.Printf("Error converting policy to YAML: %v", err)
		return
	}

	fmt.Println(string(policyYAML))
}

func TransformToNetworkPolicy(podTraffic *[]api.PodTraffic, podDetail *api.PodDetail, config *Config) *networkingv1.NetworkPolicy {
	var ingressRules []networkingv1.NetworkPolicyIngressRule
	var egressRules []networkingv1.NetworkPolicyEgressRule

	// TODO: How to perform this action offline
	podSelectorLabels, err := DetectSelectorLabels(config.Clientset, &podDetail.Pod)
	if err != nil {
		fmt.Println(err)
		// TODO: Handle errors, this would mean a controller was detected but may no longer exist due to the pod being deleted but still present in the database
		fmt.Println("Detect Labels of pod", err)
		return nil
	}

	for _, traffic := range *podTraffic {

		// TODO: Check PODCIDR and SVCCIDR to determine if IP originated from inside or outside the cluster

		// Get pod spec for the pod that is sending traffic
		origin, err := api.GetPodSpec(traffic.DstIP)
		if err != nil {
			// TODO: Handle errors, for now just continue as this is not a fatal error and it assumes the traffic originated from outside the cluster
			fmt.Println("Get Pod Spec of origin", traffic.DstIP, err)
			continue
		}

		peerSelectorLabels, err := DetectSelectorLabels(config.Clientset, &origin.Pod)
		if err != nil {
			// TODO: Handle errors, this would mean a controller was detected but may no longer exist due to the pod being deleted but still present in the database
			fmt.Println("Detect Labels", origin.Name, err)
			continue
		}

		peer := networkingv1.NetworkPolicyPeer{}
		// If the traffic originated from in-cluster as either a pod or service
		if origin != nil {
			peer = networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: peerSelectorLabels,
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": origin.Pod.ObjectMeta.Namespace},
				},
			}
		}

		if traffic.TrafficType == "INGRESS" {
			port := intstr.Parse(traffic.SrcPodPort)
			ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &traffic.Protocol,
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
						Protocol: &traffic.Protocol,
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
				"advisor.arx.io/managed-by": "arx",
				"advisor.arx.io/version":    "0.0.1",
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
