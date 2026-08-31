package network

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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

// Additional cilium fixtures covering the paths the CIDR-only golden misses —
// default-deny (no traffic) and endpoint-resolved peers (a peer IP that
// resolves to a service selector becomes a from/toEndpoints selector, not a
// CIDR). These capture the current cilium-library output so the dependency can
// later be replaced by hand-rolled types with a golden guarding every path.

func TestFixtureGolden_CiliumDefaultDeny(t *testing.T) {
	detail := fixturePodDetail("idle", "prod", "10.0.0.2", map[string]string{"app": "idle"})
	policy, err := NewCiliumPolicyGenerator().Generate("idle", []api.PodTraffic{}, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "cilium_default_deny.golden.yaml", out)
}

func TestFixtureGolden_CiliumEndpointResolved(t *testing.T) {
	detail := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		// Egress peer 10.96.0.10 resolves to the db service selector -> ToEndpoints.
		{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
		// Ingress peer 10.0.0.7 resolves to a pod (app=frontend) -> FromEndpoints.
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.7", Protocol: "TCP"},
	}
	stub := stubBrokerData{
		svcs: map[string]*api.SvcDetail{
			"10.96.0.10": {
				SvcName: "db", SvcNamespace: "prod", SvcIp: "10.96.0.10",
				Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "db"}}},
			},
		},
		pods: map[string]*api.PodDetail{
			"10.0.0.7": podDetail("frontend-1", "10.0.0.7", map[string]string{"app": "frontend"}),
		},
	}
	gen := NewCiliumPolicyGenerator()
	gen.setBrokerData(stub)
	policy, err := gen.Generate("web", traffic, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "cilium_endpoint_resolved.golden.yaml", out)
}

// Dual-stack fixtures. A real dual-stack pod does not talk exclusively to
// one address family: it reaches IPv6 peers over its ULA range and still
// reaches IPv4-only Services (kube-dns, anything behind a single-stack
// ClusterIP) over 10.x. The mixed-family egress row below is therefore
// deliberate, and the goldens must show a /128 ipBlock and a /32 ipBlock
// living side by side in the same policy.
//
// Both APIs allow that. Upstream NetworkPolicy validates each
// ipBlock.cidr independently — the family is not pinned per policy, per
// rule, or per peer list (this is exactly how the API supports dual-stack
// clusters), and a rule may carry several peers of different families.
// CiliumNetworkPolicy is the same: toCIDR/fromCIDR are plain lists of CIDR
// strings validated one by one, and Cilium's dual-stack support relies on
// mixing them.
//
// The hardcoded "/32" these fixtures replaced would have emitted
// fd00::7/32 here — a valid CIDR covering roughly 2^96 addresses instead
// of the one peer that was actually observed.

func dualStackFixtureTraffic() []api.PodTraffic {
	return []api.PodTraffic{
		// Ingress: an IPv6 peer reaches our pod on 8080/TCP.
		{TrafficType: "INGRESS", SrcIP: "fd00::1", SrcPodPort: "8080", DstIP: "fd00::7", Protocol: "TCP"},
		// Egress: our pod reaches an IPv6 peer on 5432/TCP.
		{TrafficType: "EGRESS", SrcIP: "fd00::1", DstIP: "fd00:96::a", DstPort: "5432", Protocol: "TCP"},
		// Egress: the same pod also reaches an IPv4-only peer on 5432/TCP.
		{TrafficType: "EGRESS", SrcIP: "fd00::1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
	}
}

func TestFixtureGolden_StandardDualStack(t *testing.T) {
	detail := fixturePodDetail("web6", "prod", "fd00::1", map[string]string{"app": "web"})
	policy, err := NewStandardPolicyGenerator().Generate("web6", dualStackFixtureTraffic(), detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "standard_dualstack.golden.yaml", out)
}

func TestFixtureGolden_CiliumDualStack(t *testing.T) {
	detail := fixturePodDetail("web6", "prod", "fd00::1", map[string]string{"app": "web"})
	policy, err := NewCiliumPolicyGenerator().Generate("web6", dualStackFixtureTraffic(), detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, "cilium_dualstack.golden.yaml", out)
}

// Guards the mixed-family claim the dual-stack goldens rest on, so it is
// checked rather than asserted in a comment: every CIDR the generators
// emit must parse, must be a single-host prefix, and the two families
// must genuinely coexist in one policy.
//
// The one family rule that does exist upstream is *within* a single
// ipBlock — every `except` entry has to sit inside `cidr`, so an ipBlock
// cannot mix families internally. Neither generator emits `except`, and
// nothing constrains sibling peers or sibling rules to share a family;
// that is precisely what makes a dual-stack policy expressible.
func TestFixtureGolden_DualStackGoldensAreValidMixedFamily(t *testing.T) {
	for _, name := range []string{"standard_dualstack.golden.yaml", "cilium_dualstack.golden.yaml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "test", "fixtures", "generators", "networkpolicy", name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v", name, err)
			}

			cidrs := extractCIDRs(string(raw))
			if len(cidrs) == 0 {
				t.Fatalf("%s: expected CIDR peers in a dual-stack golden, found none", name)
			}

			var sawV4, sawV6 bool
			for _, c := range cidrs {
				addr, network, err := net.ParseCIDR(c)
				if err != nil {
					t.Errorf("%s: %q is not a valid CIDR: %v", name, c, err)
					continue
				}
				ones, bits := network.Mask.Size()
				if ones != bits {
					t.Errorf("%s: %q is a /%d of %d bits; a peer observed as one address must stay one host",
						name, c, ones, bits)
				}
				if addr.To4() != nil {
					sawV4 = true
				} else {
					sawV6 = true
				}
			}
			if !sawV4 || !sawV6 {
				t.Errorf("%s: want both families in one policy, got v4=%v v6=%v (cidrs %v)",
					name, sawV4, sawV6, cidrs)
			}
		})
	}
}

// extractCIDRs pulls every CIDR-looking scalar out of a marshalled
// policy. Deliberately format-agnostic (it reads both the standard
// generator's `cidr:` fields and Cilium's to/fromCIDR list items) so this
// check keeps working if either schema is restructured.
func extractCIDRs(yamlDoc string) []string {
	var out []string
	for _, line := range strings.Split(yamlDoc, "\n") {
		field := strings.TrimSpace(line)
		field = strings.TrimPrefix(field, "- ")
		if i := strings.LastIndex(field, ": "); i >= 0 {
			field = field[i+2:]
		}
		field = strings.Trim(field, `"`)
		if !strings.Contains(field, "/") {
			continue
		}
		if _, _, err := net.ParseCIDR(field); err != nil {
			continue
		}
		out = append(out, field)
	}
	return out
}
