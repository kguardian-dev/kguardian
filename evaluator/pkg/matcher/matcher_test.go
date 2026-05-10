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

func TestMatch_IPBlockAllow(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})

	p := policy("prod", "web-allow-vpn", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(8080)},
			},
		},
	})

	flow := Flow{
		// External source: no SrcPodNamespace/Name, only SrcIP.
		DstPodNamespace: "prod", DstPodName: "web-1",
		SrcIP: "10.5.6.7", DstIP: "10.0.0.1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got := Match(flow, p, lookup)
	if got[0].Verdict != VerdictAllow {
		t.Fatalf("expected Allow via ipBlock CIDR, got %#v", got)
	}
}

func TestMatch_IPBlockExceptDenies(t *testing.T) {
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})

	p := policy("prod", "web-allow-vpn-not-bastion", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{IPBlock: &networkingv1.IPBlock{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.5.0.0/16"},
					}},
				},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(8080)},
			},
		},
	})

	for _, tc := range []struct {
		ip      string
		verdict Verdict
	}{
		{ip: "10.5.6.7", verdict: VerdictWouldDeny},  // in except → denied
		{ip: "10.6.6.7", verdict: VerdictAllow},      // outside except, in cidr → allowed
		{ip: "192.168.1.1", verdict: VerdictWouldDeny}, // outside cidr → denied
	} {
		flow := Flow{
			DstPodNamespace: "prod", DstPodName: "web-1",
			SrcIP: tc.ip, DstPort: 8080, Protocol: ProtocolTCP,
		}
		got := Match(flow, p, lookup)
		if got[0].Verdict != tc.verdict {
			t.Errorf("ip=%s: expected %s, got %s", tc.ip, tc.verdict, got[0].Verdict)
		}
	}
}

func TestMatch_NamedPortAllow(t *testing.T) {
	lookup := newLookup()
	dst := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web-1", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "web", Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
	}
	lookup.pods["prod/web-1"] = dst
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	tcp := corev1.ProtocolTCP
	namedPort := intstr.FromString("http")
	p := policy("prod", "web-allow-named", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &namedPort},
			}},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got := Match(flow, p, lookup)
	if got[0].Verdict != VerdictAllow {
		t.Fatalf("expected Allow via named port, got %#v", got)
	}
}

func TestMatch_NamedPortEgress(t *testing.T) {
	// Upstream invariant: NetworkPolicyPort describes the *destination*
	// port of the connection, regardless of direction. For an egress
	// rule from `app=web` to `app=db` on named port "postgres", the
	// db pod (the peer / connection destination) is the one whose
	// containers must declare the name. The web pod's container ports
	// are irrelevant.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	db := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "db-1",
			Labels: map[string]string{"app": "db"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "postgres", Ports: []corev1.ContainerPort{
					{Name: "postgres", ContainerPort: 5432, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
	}
	lookup.pods["prod/db-1"] = db

	tcp := corev1.ProtocolTCP
	namedPort := intstr.FromString("postgres")
	p := policy("prod", "web-egress-db", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{
					{PodSelector: ptrSelector(selectMatchLabels(map[string]string{"app": "db"}))},
				},
				Ports: []networkingv1.NetworkPolicyPort{
					{Protocol: &tcp, Port: &namedPort},
				},
			},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "web-1",
		DstPodNamespace: "prod", DstPodName: "db-1",
		DstPort: 5432, Protocol: ProtocolTCP,
	}
	got := Match(flow, p, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictAllow || got[0].Direction != DirectionEgress {
		t.Fatalf("expected Egress Allow via destination-pod named port, got %#v", got)
	}
}

func TestMatchCluster_NamespaceSelectorScopes(t *testing.T) {
	// Cluster-scoped policy with namespaceSelector matching team=platform.
	// Should apply to web pods in `monitoring` (team=platform) but not
	// in `dev` (team=app).
	lookup := newLookup()
	lookup.addPod("monitoring", "web-1", map[string]string{"app": "web"})
	lookup.addPod("dev", "web-1", map[string]string{"app": "web"})
	lookup.addPod("monitoring", "client-1", map[string]string{"app": "client"})
	lookup.addNamespace("monitoring", map[string]string{"team": "platform"})
	lookup.addNamespace("dev", map[string]string{"team": "app"})

	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-web-deny"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: ptrSelector(selectMatchLabels(map[string]string{"team": "platform"})),
			PodSelector:       selectMatchLabels(map[string]string{"app": "web"}),
			PolicyTypes:       []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			// no ingress rules — default-deny in the matched namespaces
		},
	}

	// Flow into monitoring's web pod → cluster policy applies → WouldDeny
	flow1 := Flow{
		SrcPodNamespace: "monitoring", SrcPodName: "client-1",
		DstPodNamespace: "monitoring", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got := MatchCluster(flow1, cp, lookup)
	if got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny in matching ns, got %#v", got)
	}

	// Flow into dev's web pod → namespace doesn't match → NotApplicable
	flow2 := Flow{
		DstPodNamespace: "dev", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got = MatchCluster(flow2, cp, lookup)
	if got[0].Verdict != VerdictNotApplicable {
		t.Fatalf("expected NotApplicable in non-matching ns, got %#v", got)
	}
}

func TestMatchCluster_IngressRuleAllow(t *testing.T) {
	// Cluster policy with an ingress rule that explicitly allows from
	// pods carrying app=client. Flow from such a client pod → Allow.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(8080)
	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web-allow-clients", UID: "uid-cp-allow"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: ptrSelector(selectMatchLabels(map[string]string{"app": "client"})),
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
			}},
		},
	}

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got := MatchCluster(flow, cp, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictAllow {
		t.Fatalf("expected Allow on ingress rule match, got %#v", got)
	}
	if got[0].PolicyUID != "uid-cp-allow" {
		t.Errorf("expected policyUID propagated, got %q", got[0].PolicyUID)
	}
}

func TestMatchCluster_IngressRuleNonMatchYieldsWouldDeny(t *testing.T) {
	// Same shape as above but the source pod's labels don't match the
	// rule's peer selector → no rule allows the flow → WouldDeny with a
	// reason that points at the failed match (not "no rules").
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "stranger", map[string]string{"app": "stranger"})

	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(8080)
	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web-allow-clients-only"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: ptrSelector(selectMatchLabels(map[string]string{"app": "client"})),
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
			}},
		},
	}

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "stranger",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: ProtocolTCP,
	}
	got := MatchCluster(flow, cp, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny on non-matching peer, got %#v", got)
	}
	if got[0].Reason == "" {
		t.Error("expected a non-empty reason for the deny")
	}
	if got[0].Reason == "policy has no ingress rules — default-deny" {
		t.Errorf("expected the rule-mismatch reason, not the no-rules one: got %q", got[0].Reason)
	}
}

func TestMatchCluster_EgressRuleAllow(t *testing.T) {
	// Cluster-scoped egress: subject is the SOURCE pod, peer is the
	// destination. Allow when destination labels match.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})
	lookup.addPod("prod", "db-1", map[string]string{"app": "db"})

	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(5432)
	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web-egress-to-db"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: ptrSelector(selectMatchLabels(map[string]string{"app": "db"})),
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
			}},
		},
	}

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "web-1",
		DstPodNamespace: "prod", DstPodName: "db-1",
		DstPort: 5432, Protocol: ProtocolTCP,
	}
	got := MatchCluster(flow, cp, lookup)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d: %#v", len(got), got)
	}
	if got[0].Direction != DirectionEgress {
		t.Errorf("expected Egress direction, got %s", got[0].Direction)
	}
	if got[0].Verdict != VerdictAllow {
		t.Errorf("expected Allow on egress to allowed peer, got %s reason=%q", got[0].Verdict, got[0].Reason)
	}
}

func TestMatchCluster_EgressNoRulesDefaultDeny(t *testing.T) {
	// Cluster policy listing Egress in policyTypes but with empty
	// egress rules — every egress flow from the subject should be
	// WouldDeny with the "no egress rules" reason.
	lookup := newLookup()
	lookup.addPod("prod", "web-1", map[string]string{"app": "web"})

	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web-egress-deny-all"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "web-1",
		DstPodNamespace: "prod", DstPodName: "anywhere",
		DstPort: 80, Protocol: ProtocolTCP,
	}
	got := MatchCluster(flow, cp, lookup)
	if len(got) != 1 || got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny on egress default-deny, got %#v", got)
	}
	if got[0].Reason != "policy has no egress rules — default-deny" {
		t.Errorf("expected egress-default-deny reason, got %q", got[0].Reason)
	}
}

func TestMatchCluster_NilSelectorMatchesAll(t *testing.T) {
	// nil namespaceSelector → applies to every namespace.
	lookup := newLookup()
	lookup.addPod("ns-a", "web-1", map[string]string{"app": "web"})
	lookup.addPod("ns-b", "web-1", map[string]string{"app": "web"})

	cp := &v1alpha1.AuditClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "all-web-deny"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		},
	}

	for _, ns := range []string{"ns-a", "ns-b"} {
		flow := Flow{
			DstPodNamespace: ns, DstPodName: "web-1",
			DstPort: 8080, Protocol: ProtocolTCP,
		}
		got := MatchCluster(flow, cp, lookup)
		if got[0].Verdict != VerdictWouldDeny {
			t.Errorf("ns=%s: expected WouldDeny, got %s", ns, got[0].Verdict)
		}
	}
}

func TestMatch_NamedPortMismatchOnPort(t *testing.T) {
	// Container declares "http"=8080; flow hits 9090 — should not match.
	lookup := newLookup()
	dst := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web-1", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "web", Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
	}
	lookup.pods["prod/web-1"] = dst
	lookup.addPod("prod", "client-1", map[string]string{"app": "client"})

	tcp := corev1.ProtocolTCP
	namedPort := intstr.FromString("http")
	p := policy("prod", "web-allow-named", networkingv1.NetworkPolicySpec{
		PodSelector: selectMatchLabels(map[string]string{"app": "web"}),
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &namedPort}}},
		},
	})

	flow := Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 9090, Protocol: ProtocolTCP,
	}
	got := Match(flow, p, lookup)
	if got[0].Verdict != VerdictWouldDeny {
		t.Fatalf("expected WouldDeny when named port resolves to a different containerPort, got %#v", got)
	}
}
