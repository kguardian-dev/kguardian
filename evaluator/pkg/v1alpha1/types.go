// Package v1alpha1 defines the AuditNetworkPolicy CRD types for kguardian.
//
// AuditNetworkPolicy mirrors networking.k8s.io/v1.NetworkPolicy 1:1 in spec
// shape. The semantic difference is purely in *what kguardian does with it*:
// we evaluate observed flows against the policy and report what would be
// denied, but never actually drop traffic. Promotion to enforced policy is
// done by re-applying the same spec under kind: NetworkPolicy.
package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "kguardian.dev"
	Version   = "v1alpha1"
)

// SchemeGroupVersion is group + version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

// Resource takes an unqualified resource and returns a Group-qualified one.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// AuditNetworkPolicy is the Schema for namespaced audit-mode network policies.
type AuditNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec mirrors networking.k8s.io/v1.NetworkPolicySpec 1:1. Reusing the
	// upstream type means existing tooling (kubectl explain, jsonpath
	// queries, conversion to enforced policy) Just Works.
	Spec networkingv1.NetworkPolicySpec `json:"spec"`

	// Status is populated by the kguardian-evaluator with rolling counts
	// and example flows that would have been denied.
	Status AuditNetworkPolicyStatus `json:"status,omitempty"`
}

// AuditNetworkPolicyStatus reports evaluation state.
type AuditNetworkPolicyStatus struct {
	// ObservedGeneration is the .metadata.generation that the evaluator
	// last reconciled against.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Evaluation summarises what would have been denied.
	Evaluation EvaluationStatus `json:"evaluation,omitempty"`
}

// EvaluationStatus is a rolling-window summary of audit verdicts.
type EvaluationStatus struct {
	// LastEvaluated is the timestamp of the most recent flow evaluated
	// against this policy.
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`

	// FlowsEvaluated is the total number of flows checked against this
	// policy in the rolling window.
	FlowsEvaluated int64 `json:"flowsEvaluated,omitempty"`

	// FlowsWouldDeny is the count within the rolling window that would
	// have been denied if this policy were enforced.
	FlowsWouldDeny int64 `json:"flowsWouldDeny,omitempty"`

	// TopOffenders lists the most frequent (src, dst, port, protocol)
	// tuples that would have been denied. Bounded length.
	TopOffenders []OffenderSummary `json:"topOffenders,omitempty"`
}

// OffenderSummary describes a flow shape that would have been denied
// repeatedly.
type OffenderSummary struct {
	// SrcPod is namespace/name of the source pod.
	SrcPod string `json:"srcPod,omitempty"`
	// DstPod is namespace/name of the destination pod.
	DstPod string `json:"dstPod,omitempty"`
	// DstPort is the destination port that would have been denied.
	DstPort int32 `json:"dstPort,omitempty"`
	// Protocol is TCP, UDP, or SCTP.
	Protocol string `json:"protocol,omitempty"`
	// Direction is "Ingress" or "Egress" relative to the selected pod.
	Direction string `json:"direction,omitempty"`
	// Count is the number of times this exact tuple was seen in the
	// rolling window.
	Count int64 `json:"count,omitempty"`
}

// AuditNetworkPolicyList contains a list of AuditNetworkPolicy.
type AuditNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditNetworkPolicy `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *AuditNetworkPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AuditNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out.
func (in *AuditNetworkPolicy) DeepCopyInto(out *AuditNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto for AuditNetworkPolicyStatus.
func (in *AuditNetworkPolicyStatus) DeepCopyInto(out *AuditNetworkPolicyStatus) {
	*out = *in
	in.Evaluation.DeepCopyInto(&out.Evaluation)
}

// DeepCopyInto for EvaluationStatus.
func (in *EvaluationStatus) DeepCopyInto(out *EvaluationStatus) {
	*out = *in
	if in.LastEvaluated != nil {
		out.LastEvaluated = in.LastEvaluated.DeepCopy()
	}
	if in.TopOffenders != nil {
		out.TopOffenders = make([]OffenderSummary, len(in.TopOffenders))
		copy(out.TopOffenders, in.TopOffenders)
	}
}

// DeepCopyObject implements runtime.Object for the list.
func (in *AuditNetworkPolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AuditNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto for the list type.
func (in *AuditNetworkPolicyList) DeepCopyInto(out *AuditNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AuditNetworkPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
