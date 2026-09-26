package policycoverage

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pod(ns, name string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
	}
}

func policy(ns, name string, sel metav1.LabelSelector, types []networkingv1.PolicyType, egress bool) *networkingv1.NetworkPolicy {
	p := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: sel, PolicyTypes: types},
	}
	if egress {
		p.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
	}
	return p
}

func matchApp(v string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{"app": v}}
}

// The reclassification this exists for: with no policies, a reported
// drop cannot have been caused by one, so the operator should be sent
// looking somewhere else entirely.
func TestNoPoliciesNeverGoverns(t *testing.T) {
	p := pod("prod", "web", map[string]string{"app": "web"})
	if Governs(nil, p, Egress) {
		t.Error("no policies must not govern")
	}
	if Governs([]*networkingv1.NetworkPolicy{}, p, Egress) {
		t.Error("empty policy set must not govern")
	}
	if got := Classify(true, false); got != CauseNoPolicy {
		t.Errorf("want %q, got %q", CauseNoPolicy, got)
	}
}

func TestSelectorMatchingDecidesCoverage(t *testing.T) {
	p := pod("prod", "web", map[string]string{"app": "web"})
	governing := policy("prod", "np", matchApp("web"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, true)
	other := policy("prod", "np2", matchApp("db"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, true)

	if !Governs([]*networkingv1.NetworkPolicy{governing}, p, Egress) {
		t.Error("a matching selector must govern")
	}
	if Governs([]*networkingv1.NetworkPolicy{other}, p, Egress) {
		t.Error("a non-matching selector must not govern")
	}
}

func TestEmptySelectorSelectsEveryPodInTheNamespace(t *testing.T) {
	// {} is the default-deny idiom, and it is the single most likely
	// policy to exist in a cluster that has any.
	p := pod("prod", "web", map[string]string{"app": "web"})
	all := policy("prod", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	if !Governs([]*networkingv1.NetworkPolicy{all}, p, Egress) {
		t.Error("an empty podSelector must select every pod in the namespace")
	}
}

func TestAPolicyNeverReachesAnotherNamespace(t *testing.T) {
	// A NetworkPolicy only selects pods in its own namespace, however
	// broad its peer rules are. Getting this wrong would mark pods
	// cluster-wide as governed the moment one namespace had a policy.
	p := pod("prod", "web", map[string]string{"app": "web"})
	elsewhere := policy("staging", "np", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	if Governs([]*networkingv1.NetworkPolicy{elsewhere}, p, Egress) {
		t.Error("a policy in another namespace must not govern")
	}
}

// The upstream defaulting rule, which is the subtle part: absent
// policyTypes implies Ingress always, and Egress only when egress rules
// exist. Treating an empty list as "governs everything" would make
// every namespace with any policy look like it governed egress, and the
// drop probe only ever reports egress.
func TestPolicyTypesDefaulting(t *testing.T) {
	p := pod("prod", "web", map[string]string{"app": "web"})
	sel := matchApp("web")

	ingressOnly := policy("prod", "in", sel, nil, false)
	if Governs([]*networkingv1.NetworkPolicy{ingressOnly}, p, Egress) {
		t.Error("no policyTypes and no egress rules must NOT govern egress")
	}
	if !Governs([]*networkingv1.NetworkPolicy{ingressOnly}, p, Ingress) {
		t.Error("no policyTypes always implies Ingress")
	}

	withEgressRules := policy("prod", "eg", sel, nil, true)
	if !Governs([]*networkingv1.NetworkPolicy{withEgressRules}, p, Egress) {
		t.Error("no policyTypes but egress rules present must govern egress")
	}
}

func TestExplicitPolicyTypesAreHonouredExactly(t *testing.T) {
	p := pod("prod", "web", map[string]string{"app": "web"})
	sel := matchApp("web")

	// Egress rules present but policyTypes says Ingress only: the
	// explicit list wins and the egress rules are inert.
	ingressDeclared := policy("prod", "np", sel, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, true)
	if Governs([]*networkingv1.NetworkPolicy{ingressDeclared}, p, Egress) {
		t.Error("an explicit Ingress-only policyTypes must not govern egress")
	}

	both := policy("prod", "np", sel, []networkingv1.PolicyType{
		networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress,
	}, false)
	if !Governs([]*networkingv1.NetworkPolicy{both}, p, Egress) {
		t.Error("both types declared must govern egress")
	}
}

func TestMatchExpressionsAreEvaluated(t *testing.T) {
	// The reason this delegates to apimachinery rather than comparing
	// maps by hand: matchExpressions is where a hand-rolled selector
	// silently diverges from what the API server actually selects.
	p := pod("prod", "web", map[string]string{"tier": "frontend"})
	sel := metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "tier",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"frontend", "edge"},
		}},
	}
	in := policy("prod", "np", sel, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	if !Governs([]*networkingv1.NetworkPolicy{in}, p, Egress) {
		t.Error("matchExpressions In must select a matching pod")
	}

	notIn := policy("prod", "np", metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "tier",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"frontend"},
		}},
	}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	if Governs([]*networkingv1.NetworkPolicy{notIn}, p, Egress) {
		t.Error("matchExpressions NotIn must exclude a matching pod")
	}
}

func TestAnyGoverningPolicyIsEnough(t *testing.T) {
	p := pod("prod", "web", map[string]string{"app": "web"})
	nonMatching := policy("prod", "a", matchApp("db"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	matching := policy("prod", "b", matchApp("web"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, false)
	if !Governs([]*networkingv1.NetworkPolicy{nonMatching, matching}, p, Egress) {
		t.Error("one governing policy among several must be enough")
	}
}

func TestClassifyKeepsIgnoranceDistinct(t *testing.T) {
	// "read the policies and found none" and "could not read the
	// policies" are different answers. Collapsing the second into the
	// first would tell an operator their policies are definitively
	// uninvolved on the strength of a failed API call.
	if got := Classify(false, false); got != CauseUnknown {
		t.Errorf("unknown coverage must stay unknown, got %q", got)
	}
	if got := Classify(false, true); got != CauseUnknown {
		t.Errorf("unknown coverage must stay unknown, got %q", got)
	}
	if got := Classify(true, true); got != CausePolicyGoverns {
		t.Errorf("want %q, got %q", CausePolicyGoverns, got)
	}
}

func TestNilsAreSurvivable(t *testing.T) {
	if Governs(nil, nil, Egress) {
		t.Error("nil pod must not govern")
	}
	p := pod("prod", "web", nil)
	if Governs([]*networkingv1.NetworkPolicy{nil}, p, Egress) {
		t.Error("a nil policy entry must be skipped, not panic")
	}
}
