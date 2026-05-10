package v1alpha1

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Scheme registration tests. A regression that registers a new type
// without adding it here (or removes one accidentally) breaks the
// dynamic informer's encoder/decoder for that kind, which produces
// mysterious "no kind registered" errors at runtime.

func TestAddToScheme_RegistersAllFourTypes(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	for _, kind := range []string{
		"AuditNetworkPolicy",
		"AuditNetworkPolicyList",
		"AuditClusterNetworkPolicy",
		"AuditClusterNetworkPolicyList",
	} {
		gvk := SchemeGroupVersion.WithKind(kind)
		if _, err := scheme.New(gvk); err != nil {
			t.Errorf("scheme missing %s: %v", kind, err)
		}
	}
}

func TestSchemeGroupVersion_GroupAndVersion(t *testing.T) {
	if SchemeGroupVersion.Group != GroupName {
		t.Errorf("group: want %q, got %q", GroupName, SchemeGroupVersion.Group)
	}
	if SchemeGroupVersion.Version != Version {
		t.Errorf("version: want %q, got %q", Version, SchemeGroupVersion.Version)
	}
}

func TestResource_QualifiesGroup(t *testing.T) {
	gr := Resource("auditnetworkpolicies")
	if gr.Group != GroupName {
		t.Errorf("group: want %q, got %q", GroupName, gr.Group)
	}
	if gr.Resource != "auditnetworkpolicies" {
		t.Errorf("resource: want auditnetworkpolicies, got %s", gr.Resource)
	}
}

// DeepCopy correctness — must produce a fully independent object.
// A shallow copy regression would let mutations on the copy bleed
// back into the source, corrupting cached store entries between the
// informer and the matcher.

func TestAuditNetworkPolicy_DeepCopyIndependent(t *testing.T) {
	src := &AuditNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "prod",
			Name:       "web-deny",
			Generation: 7,
			Labels:     map[string]string{"team": "platform"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
		Status: AuditNetworkPolicyStatus{
			ObservedGeneration: 5,
			Evaluation: EvaluationStatus{
				FlowsEvaluated: 100,
				FlowsWouldDeny: 25,
				TopOffenders: []OffenderSummary{
					{SrcPod: "client-1", DstPod: "web-1", DstPort: 8080, Protocol: "TCP", Direction: "Ingress", Count: 5},
				},
			},
		},
	}

	out := &AuditNetworkPolicy{}
	src.DeepCopyInto(out)

	// Mutate the copy; source must not see it.
	out.ObjectMeta.Labels["team"] = "infra"
	out.Spec.PodSelector.MatchLabels["app"] = "api"
	out.Status.Evaluation.TopOffenders[0].DstPod = "tampered"

	if got := src.ObjectMeta.Labels["team"]; got != "platform" {
		t.Errorf("ObjectMeta.Labels leaked through: got %q", got)
	}
	if got := src.Spec.PodSelector.MatchLabels["app"]; got != "web" {
		t.Errorf("Spec.PodSelector.MatchLabels leaked through: got %q", got)
	}
	if got := src.Status.Evaluation.TopOffenders[0].DstPod; got != "web-1" {
		t.Errorf("Status.TopOffenders leaked through: got %q", got)
	}

	// Identity values still propagate.
	if out.ObjectMeta.Generation != 7 {
		t.Errorf("scalar field not copied: %d", out.ObjectMeta.Generation)
	}
	if out.Status.ObservedGeneration != 5 {
		t.Errorf("status.observedGeneration not copied: %d", out.Status.ObservedGeneration)
	}
}

func TestAuditClusterNetworkPolicy_DeepCopyIndependent(t *testing.T) {
	src := &AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline-audit"},
		Spec: ClusterNetworkPolicySpec{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"team": "platform"},
			},
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}

	out := &AuditClusterNetworkPolicy{}
	src.DeepCopyInto(out)

	out.Spec.NamespaceSelector.MatchLabels["team"] = "tampered"

	if got := src.Spec.NamespaceSelector.MatchLabels["team"]; got != "platform" {
		t.Errorf("NamespaceSelector leaked: got %q", got)
	}
}

func TestAuditNetworkPolicy_DeepCopyObjectImplementsRuntimeObject(t *testing.T) {
	// runtime.Object requires DeepCopyObject() runtime.Object.
	// Catch a regression that returns a different shape.
	var _ runtime.Object = (&AuditNetworkPolicy{}).DeepCopyObject()
	var _ runtime.Object = (&AuditNetworkPolicyList{}).DeepCopyObject()
	var _ runtime.Object = (&AuditClusterNetworkPolicy{}).DeepCopyObject()
	var _ runtime.Object = (&AuditClusterNetworkPolicyList{}).DeepCopyObject()
}

func TestAuditNetworkPolicy_DeepCopyObjectOnNil(t *testing.T) {
	var p *AuditNetworkPolicy
	if got := p.DeepCopyObject(); got != nil {
		t.Errorf("nil receiver should return nil, got %#v", got)
	}
	var pl *AuditNetworkPolicyList
	if got := pl.DeepCopyObject(); got != nil {
		t.Errorf("nil receiver list should return nil, got %#v", got)
	}
	var cp *AuditClusterNetworkPolicy
	if got := cp.DeepCopyObject(); got != nil {
		t.Errorf("nil receiver cluster should return nil, got %#v", got)
	}
}
