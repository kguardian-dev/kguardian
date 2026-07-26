package network

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// G2 generator golden fixtures — network policy, reference side
// (SIMPLIFICATION-GOAL.md §3). advisor is the reference: these committed
// YAML goldens pin its deterministic output for representative scenarios and
// are the target the shared generator package (WS-C, incl. the frontend
// consumer) must reproduce. Regenerate deliberately:
//   UPDATE_GOLDEN=1 go test ./pkg/network -run FixtureGolden
//
// Frontend consumption of these fixtures lands with the shared package
// extraction in WS-C, where the frontend's async-identity input shape and the
// advisor's resolved-input shape converge on one seam.

func fixturePodDetail(name, ns, ip string, labels map[string]string) *api.PodDetail {
	return &api.PodDetail{
		Name:      name,
		Namespace: ns,
		PodIP:     ip,
		Pod: corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		},
	}
}

func checkPolicyGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "generators", "networkpolicy", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (UPDATE_GOLDEN=1 to create): %v", name, err)
	}
	if string(want) != string(got) {
		t.Errorf("G2 network-policy golden drift in %s.\nThis pins the advisor reference output any generator reimplementation must reproduce.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func TestFixtureGolden_StandardWithTraffic(t *testing.T) {
	detail := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		// Ingress: a peer reaches our pod on 8080/TCP.
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.7", Protocol: "TCP"},
		// Egress: our pod reaches a peer on 5432/TCP.
		{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
	}
	policy, err := NewStandardPolicyGenerator().Generate("web", traffic, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "standard_with_traffic.golden.yaml", out)
}

func TestFixtureGolden_StandardNoTrafficDefaultDeny(t *testing.T) {
	detail := fixturePodDetail("idle", "prod", "10.0.0.2", map[string]string{"app": "idle"})
	policy, err := NewStandardPolicyGenerator().Generate("idle", []api.PodTraffic{}, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "standard_default_deny.golden.yaml", out)
}

func TestFixtureGolden_CiliumWithTraffic(t *testing.T) {
	detail := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.7", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
	}
	policy, err := NewCiliumPolicyGenerator().Generate("web", traffic, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "cilium_with_traffic.golden.yaml", out)
}
