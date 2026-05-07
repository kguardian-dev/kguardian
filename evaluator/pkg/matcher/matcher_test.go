package matcher

import (
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// fakeLookup is a small in-memory PodLookup + NamespaceLookup for tests.
type fakeLookup struct {
	pods       map[string]*corev1.Pod
	namespaces map[string]map[string]string
}

func newLookup() *fakeLookup {
	return &fakeLookup{
		pods:       map[string]*corev1.Pod{},
		namespaces: map[string]map[string]string{},
	}
}

func (l *fakeLookup) addPod(ns, name string, lbls map[string]string) {
	l.pods[ns+"/"+name] = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
	}
}

func (l *fakeLookup) addNamespace(name string, lbls map[string]string) {
	l.namespaces[name] = lbls
}

func (l *fakeLookup) GetPod(ns, name string) *corev1.Pod {
	return l.pods[ns+"/"+name]
}

func (l *fakeLookup) GetNamespaceLabels(name string) map[string]string {
	return l.namespaces[name]
}

// helpers for building common test fixtures
func tcpPort(p int32) networkingv1.NetworkPolicyPort {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(p)
	return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port}
}

func tcpPortRange(start, end int32) networkingv1.NetworkPolicyPort {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(start)
	return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port, EndPort: &end}
}

func policy(ns, name string, spec networkingv1.NetworkPolicySpec) *v1alpha1.AuditNetworkPolicy {
	return &v1alpha1.AuditNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       spec,
	}
}

func selectMatchLabels(m map[string]string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: m}
}

func TestMatch_DefaultDenyIngress_NoRules(t *testing.T) {
	// A policy that selects pod app=web in ns prod with policyTypes
	// [Ingress] and no rules at all. Any ingress flow to that pod
	// should be WouldDeny.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	p := policy("prod", "web-deny-all-ingress", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP, Timestamp: time.Now(),
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected one WouldDeny verdict, got %#v", got)
	}
	if got[0].Direction != DirectionIngress {
		t.Fatalf("expected Ingress direction, got %s", got[0].Direction)
	}
}

func TestMatch_AllowFromMatchingPodSelector(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "client-1", map[string]string{"app": "client", "tier": "frontend"})

	p := policy("prod", "web-allow-frontend", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: ptrSelector(selectMatchLabels(map[string]string{"tier": "frontend"}))},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(8080)},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictAllow {
		t.Fatalf("expected Allow verdict, got %#v", got)
	}
}

func TestMatch_DenyFromNonMatchingPodSelector(t *testing.T) {
	// Same setup as above, but the source pod's labels don't match
	// the rule's podSelector — should be WouldDeny.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "rogue-1", map[string]string{"app": "rogue"})

	p := policy("prod", "web-allow-frontend", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: ptrSelector(selectMatchLabels(map[string]string{"tier": "frontend"}))},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(8080)},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "rogue-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny verdict, got %#v", got)
	}
}

func TestMatch_DenyOnPortMismatch(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	p := policy("prod", "web-allow-8080", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			// Empty From → all peers; port-only rule.
			{Ports: []networkingv1.NetworkPolicyPort{tcpPort(8080)}},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 9999, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny on port mismatch, got %#v", got)
	}
}

func TestMatch_AllowFromMatchingNamespaceSelector(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("monitoring", "prom-1", map[string]string{"app": "prometheus"})
	lookup.addNamespace("monitoring", map[string]string{"team": "platform"})

	p := policy("prod", "web-allow-platform-ns", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{NamespaceSelector: ptrSelector(selectMatchLabels(map[string]string{"team": "platform"}))},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(9090)},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "monitoring", SrcPodName: "prom-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 9090, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictAllow {
		t.Fatalf("expected Allow via namespaceSelector, got %#v", got)
	}
}

func TestMatch_NamespaceSelectorRequiresLabels(t *testing.T) {
	// If the namespace's labels don't match the namespaceSelector,
	// the rule should not allow the flow.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("strangeland", "x-1", map[string]string{"app": "x"})
	lookup.addNamespace("strangeland", map[string]string{"team": "other"})

	p := policy("prod", "web-allow-platform-ns", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{NamespaceSelector: ptrSelector(selectMatchLabels(map[string]string{"team": "platform"}))},
				},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "strangeland", SrcPodName: "x-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny when namespaceSelector doesn't match, got %#v", got)
	}
}

func TestMatch_NotApplicableWhenSubjectPodInOtherNamespace(t *testing.T) {
	// The policy lives in `prod`; the flow targets a pod in `dev`.
	// Should be NotApplicable.
	lookup := newLookup()
	lookup.addPod("dev", "web-1", map[string]string{"app": "web"})
	lookup.addPod("dev", "client-1", map[string]string{"app": "client"})

	p := policy("prod", "web-deny", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
	})

	flow := Flow{
		SrcPodNamespace: "dev", SrcPodName: "client-1",
		DstPodNamespace: "dev", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if got[0].Verdict != VerdictNotApplicable {
		t.Fatalf("expected NotApplicable across namespaces, got %#v", got)
	}
}

func TestMatch_PortRangeWithEndPort(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	p := policy("prod", "web-allow-range", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{Ports: []networkingv1.NetworkPolicyPort{tcpPortRange(8000, 8100)}},
		},
	})

	for _, tc := range []struct {
		port    int32
		verdict Verdict
	}{
		{port: 7999, verdict: VerdictWouldDeny},
		{port: 8000, verdict: VerdictAllow},
		{port: 8050, verdict: VerdictAllow},
		{port: 8100, verdict: VerdictAllow},
		{port: 8101, verdict: VerdictWouldDeny},
	} {
		flow := Flow{
			SrcPodNamespace: "prod", SrcPodName: "client-1",
			DstPodNamespace: "prod", DstPodName: "web-1",
			DstPort: tc.port, Protocol: ProtocolTCP,
		}
		got := Match(flow, p, lookup)
		if got[0].Verdict != tc.verdict {
			t.Errorf("port %d: expected %s, got %s", tc.port, tc.verdict, got[0].Verdict)
		}
	}
}

func TestMatch_EgressDenyByDefault(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "external-target", map[string]string{"app": "x"})

	p := policy("prod", "web-no-egress", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "web-1",
		DstPodNamespace: "prod", DstPodName: "external-target",
		DstPort: 5432, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny || got[0].Direction != DirectionEgress {
		t.Fatalf("expected WouldDeny on egress, got %#v", got)
	}
}

func TestMatch_PolicyTypesInferredFromRules(t *testing.T) {
	// When PolicyTypes is omitted but Egress rules are present, both
	// Ingress and Egress are evaluated.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "db-1", map[string]string{"app": "db"})

	p := policy("prod", "web-allow-db-egress-only", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{
					{PodSelector: ptrSelector(selectMatchLabels(map[string]string{"app": "db"}))},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(5432)},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "web-1",
		DstPodNamespace: "prod", DstPodName: "db-1",
		DstPort: 5432, Protocol: ProtocolTCP,
	}

	got := Match(flow, p, lookup)
	// Two verdicts: Ingress (NotApplicable — flow targets db-1, not web-1)
	// and Egress (Allow — web-1 is the source).
	if len(got) != 2 {
		t.Fatalf("expected 2 verdicts (inferred PolicyTypes), got %d: %#v", len(got), got)
	}
	var sawAllow, sawNA bool
	for _, r := range got {
		switch r.Verdict {
		case VerdictAllow:
			sawAllow = true
		case VerdictNotApplicable:
			sawNA = true
		}
	}
	if !sawAllow || !sawNA {
		t.Fatalf("expected one Allow and one NotApplicable, got %#v", got)
	}
}

// ptrSelector helps write peer specs cleanly.
func ptrSelector(s metav1.LabelSelector) *metav1.LabelSelector { return &s }
