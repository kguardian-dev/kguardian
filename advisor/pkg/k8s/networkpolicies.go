package k8s

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkPolicySpec struct {
	PodSelector metav1.LabelSelector
	PolicyTypes []networkingv1.PolicyType
	Ingress     []networkingv1.NetworkPolicyIngressRule
	Egress      []networkingv1.NetworkPolicyEgressRule
}

func CreateNetworkPolicy(name, namespace string, spec NetworkPolicySpec) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: spec.PodSelector,
			PolicyTypes: spec.PolicyTypes,
			Ingress:     spec.Ingress,
			Egress:      spec.Egress,
		},
	}
}
