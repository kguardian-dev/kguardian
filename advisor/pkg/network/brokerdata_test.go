package network

import (
	"strings"
	"testing"

	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// stubBrokerData is a fully in-memory BrokerData — no package globals, no
// network, no api.*Func overrides. Used to prove the generators and
// PolicyService read from the injected data source.
type stubBrokerData struct {
	traffic []api.PodTraffic
	pods    map[string]*api.PodDetail // keyed by IP
	svcs    map[string]*api.SvcDetail // keyed by IP
}

func (s stubBrokerData) PodTrafficByName(string) ([]api.PodTraffic, error) { return s.traffic, nil }
func (s stubBrokerData) PodByIP(ip string) (*api.PodDetail, error)         { return s.pods[ip], nil }
func (s stubBrokerData) ServiceByIP(ip string) (*api.SvcDetail, error)     { return s.svcs[ip], nil }

func podDetail(name, ip string, labels map[string]string) *api.PodDetail {
	return &api.PodDetail{
		Name: name, Namespace: "prod", PodIP: ip,
		Pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: labels}},
	}
}

// TestPolicyService_UsesInjectedBrokerData proves the entire synthesis path —
// traffic fetch, the pod's own detail lookup, AND peer resolution — reads from
// the injected BrokerData, with no api.*Func globals overridden.
func TestPolicyService_UsesInjectedBrokerData(t *testing.T) {
	stub := stubBrokerData{
		traffic: []api.PodTraffic{{
			SrcPodName: "web-1", SrcIP: "10.0.0.1", SrcNamespace: "prod",
			TrafficType: "EGRESS", DstIP: "10.0.0.2", DstPort: "5432", Protocol: corev1.ProtocolTCP,
		}},
		pods: map[string]*api.PodDetail{
			"10.0.0.1": podDetail("web-1", "10.0.0.1", map[string]string{"app": "web"}), // the pod itself
			"10.0.0.2": podDetail("db-1", "10.0.0.2", map[string]string{"app": "db"}),   // the egress peer
		},
		svcs: map[string]*api.SvcDetail{},
	}

	svc := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	svc.UseBrokerData(stub)
	svc.RegisterGenerator(NewStandardPolicyGenerator())

	out, err := svc.GeneratePolicy("web-1", StandardPolicy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	yaml := string(out.YAML)
	if !strings.Contains(yaml, "kind: NetworkPolicy") {
		t.Errorf("expected a NetworkPolicy; got:\n%s", yaml)
	}
	// pod selector resolved from injected pod detail (10.0.0.1 -> app=web)
	if !strings.Contains(yaml, "app: web") {
		t.Errorf("pod selector not from injected data; got:\n%s", yaml)
	}
	// egress peer resolved from injected pod (10.0.0.2 -> app=db) — this is the
	// peer-resolution path that previously read package globals.
	if !strings.Contains(yaml, "app: db") {
		t.Errorf("egress peer not resolved from injected data; got:\n%s", yaml)
	}
}

// TestRegisterGenerator_PropagatesBrokerData proves the service injects its data
// source into generators registered after UseBrokerData was called.
func TestRegisterGenerator_PropagatesBrokerData(t *testing.T) {
	stub := stubBrokerData{
		traffic: []api.PodTraffic{{
			SrcPodName: "web-1", SrcIP: "10.0.0.1", TrafficType: "EGRESS",
			DstIP: "10.0.0.2", DstPort: "443", Protocol: corev1.ProtocolTCP,
		}},
		pods: map[string]*api.PodDetail{
			"10.0.0.1": podDetail("web-1", "10.0.0.1", map[string]string{"app": "web"}),
			"10.0.0.2": podDetail("api-1", "10.0.0.2", map[string]string{"app": "api"}),
		},
		svcs: map[string]*api.SvcDetail{},
	}
	svc := NewPolicyService(&mockConfigProvider{}, CiliumPolicy)
	svc.UseBrokerData(stub)
	svc.RegisterGenerator(NewCiliumPolicyGenerator()) // registered AFTER UseBrokerData

	out, err := svc.GeneratePolicy("web-1", CiliumPolicy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out.YAML), "kind: CiliumNetworkPolicy") {
		t.Errorf("expected a CiliumNetworkPolicy; got:\n%s", out.YAML)
	}
	if !strings.Contains(string(out.YAML), "app: api") {
		t.Errorf("cilium peer not resolved from injected data; got:\n%s", out.YAML)
	}
}
