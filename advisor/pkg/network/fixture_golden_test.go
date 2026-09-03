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
//. advisor is the reference: these committed
// YAML goldens pin its deterministic output for representative scenarios and
// are the target the shared generator package (incl. the frontend
// consumer) must reproduce. Regenerate deliberately:
//   UPDATE_GOLDEN=1 go test ./pkg/network -run FixtureGolden
//
// Frontend consumption of these fixtures lands with the shared package
// extraction into the shared package, where the frontend's async-identity input shape and the
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

// ---- Host-network peers and targets -----------------------------------------
//
// A host-network pod shares its node's IP, so a podSelector/endpointSelector
// built from its labels never matches its traffic. These goldens pin the
// alternative rendering (ipBlock of the node IP / [host, remote-node]
// entities) AND the YAML comments explaining it — so they are produced through
// GenerateWithComments + MarshalPolicyYAML, the path PolicyService uses. The
// reimplementations compare the parsed policy plus the ordered "#" lines.
//
// Peer identities come from the broker's flat host_network / node_name /
// workload_name fields (broker-api-v3). host_network=false is used on the
// ordinary peers deliberately: false and nil must both mean "as before".

func hostFixturePodDetail(name, ns, ip string, labels map[string]string, node, workload string, hostNetwork bool) *api.PodDetail {
	d := fixturePodDetail(name, ns, ip, labels)
	d.NodeName = node
	d.WorkloadName = workload
	d.HostNetwork = &hostNetwork
	return d
}

func checkCommentedPolicyGolden(t *testing.T, name string, gen CommentedPolicyGenerator, podName string, traffic []api.PodTraffic, detail *api.PodDetail) {
	t.Helper()
	policy, comments, err := gen.GenerateWithComments(podName, traffic, detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := MarshalPolicyYAML(policy, comments)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkPolicyGolden(t, name, out)
}

// (a) Egress to host-network peers: Prometheus scrapes node-exporter on two
// nodes (9100/TCP) and also reaches an unresolvable ClusterIP. Sorted peer
// order is bytewise: 10.96.0.10 < 192.168.50.101 < 192.168.50.102.
func hostNetworkEgressFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{
			"192.168.50.101": hostFixturePodDetail("node-exporter-abc12", "monitoring", "192.168.50.101",
				map[string]string{"app": "node-exporter"}, "worker-1", "node-exporter", true),
			"192.168.50.102": hostFixturePodDetail("node-exporter-def34", "monitoring", "192.168.50.102",
				map[string]string{"app": "node-exporter"}, "worker-2", "node-exporter", true),
		},
		svcs: map[string]*api.SvcDetail{},
	}
	detail := hostFixturePodDetail("prometheus", "monitoring", "10.0.0.5", map[string]string{"app": "prometheus"}, "worker-3", "prometheus", false)
	traffic := []api.PodTraffic{
		{TrafficType: "EGRESS", SrcIP: "10.0.0.5", DstIP: "192.168.50.101", DstPort: "9100", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "10.0.0.5", DstIP: "192.168.50.102", DstPort: "9100", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "10.0.0.5", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
	}
	return stub, detail, traffic
}

// (b) Ingress from a host-network peer: a hostNetwork ingress-nginx controller
// and an ordinary frontend pod both reach web:8080.
func hostNetworkIngressFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{
			"192.168.50.101": hostFixturePodDetail("ingress-nginx-controller-abc12", "ingress-nginx", "192.168.50.101",
				map[string]string{"app.kubernetes.io/name": "ingress-nginx"}, "worker-1", "ingress-nginx-controller", true),
			"10.0.0.7": hostFixturePodDetail("frontend-1", "prod", "10.0.0.7",
				map[string]string{"app": "frontend"}, "worker-2", "frontend", false),
		},
		svcs: map[string]*api.SvcDetail{},
	}
	detail := hostFixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"}, "worker-3", "web", false)
	traffic := []api.PodTraffic{
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "192.168.50.101", Protocol: "TCP"},
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.7", Protocol: "TCP"},
	}
	return stub, detail, traffic
}

// (c) The target itself is host-network: node-exporter scraped by Prometheus.
// The policy is emitted as usual (the peer resolves to a normal pod) but is
// headed by the WARNING block.
func hostNetworkTargetFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{
			"10.0.0.5": hostFixturePodDetail("prometheus", "monitoring", "10.0.0.5",
				map[string]string{"app": "prometheus"}, "worker-3", "prometheus", false),
		},
		svcs: map[string]*api.SvcDetail{},
	}
	detail := hostFixturePodDetail("node-exporter-abc12", "monitoring", "192.168.50.101",
		map[string]string{"app": "node-exporter"}, "worker-1", "node-exporter", true)
	traffic := []api.PodTraffic{
		{TrafficType: "INGRESS", SrcIP: "192.168.50.101", SrcPodPort: "9100", DstIP: "10.0.0.5", Protocol: "TCP"},
	}
	return stub, detail, traffic
}

// (d) A Service whose backing pods are host-network: Prometheus scrapes the
// node-exporter ClusterIP (10.96.0.20:9100). The Service's selector matches two
// host-network DaemonSet pods, so the ClusterIP is pinned by IP / entities and
// named "<ns>/svc/<name>", with the backends' nodes listed. The db Service
// (10.96.0.10) is backed by a normal pod and keeps the podSelector rendering.
func hostNetworkServiceFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	svc := func(name, ns, ip string, selector map[string]string) *api.SvcDetail {
		return &api.SvcDetail{SvcName: name, SvcNamespace: ns, SvcIp: ip,
			Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: selector}}}
	}
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{},
		svcs: map[string]*api.SvcDetail{
			"10.96.0.20": svc("node-exporter", "monitoring", "10.96.0.20", map[string]string{"app": "node-exporter"}),
			"10.96.0.10": svc("db", "prod", "10.96.0.10", map[string]string{"app": "db"}),
		},
		allPods: []api.PodDetail{
			*hostFixturePodDetail("node-exporter-def34", "monitoring", "192.168.50.102",
				map[string]string{"app": "node-exporter"}, "worker-2", "node-exporter", true),
			*hostFixturePodDetail("node-exporter-abc12", "monitoring", "192.168.50.101",
				map[string]string{"app": "node-exporter"}, "worker-1", "node-exporter", true),
			*hostFixturePodDetail("db-0", "prod", "10.0.0.9",
				map[string]string{"app": "db"}, "worker-3", "db", false),
		},
	}
	detail := hostFixturePodDetail("prometheus", "monitoring", "10.0.0.5", map[string]string{"app": "prometheus"}, "worker-3", "prometheus", false)
	traffic := []api.PodTraffic{
		{TrafficType: "EGRESS", SrcIP: "10.0.0.5", DstIP: "10.96.0.20", DstPort: "9100", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "10.0.0.5", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
	}
	return stub, detail, traffic
}

func TestFixtureGolden_HostNetwork(t *testing.T) {
	cases := []struct {
		name    string
		fixture func() (stubBrokerData, *api.PodDetail, []api.PodTraffic)
	}{
		{"egress_peer", hostNetworkEgressFixture},
		{"ingress_peer", hostNetworkIngressFixture},
		{"target", hostNetworkTargetFixture},
		{"service_peer", hostNetworkServiceFixture},
	}
	for _, tc := range cases {
		t.Run("standard_"+tc.name, func(t *testing.T) {
			stub, detail, traffic := tc.fixture()
			gen := NewStandardPolicyGenerator()
			gen.setBrokerData(stub)
			checkCommentedPolicyGolden(t, "standard_hostnetwork_"+tc.name+".golden.yaml", gen, detail.Name, traffic, detail)
		})
		t.Run("cilium_"+tc.name, func(t *testing.T) {
			stub, detail, traffic := tc.fixture()
			gen := NewCiliumPolicyGenerator()
			gen.setBrokerData(stub)
			checkCommentedPolicyGolden(t, "cilium_hostnetwork_"+tc.name+".golden.yaml", gen, detail.Name, traffic, detail)
		})
	}
}

// The comment path must be a no-op for every pre-existing scenario: with no
// host-network involvement, MarshalPolicyYAML must equal yaml.Marshal byte for
// byte, so the older goldens above stay valid through the same call path
// PolicyService now uses.
func TestFixtureGolden_NoHostNetworkIsByteIdentical(t *testing.T) {
	detail := fixturePodDetail("web6", "prod", "fd00::1", map[string]string{"app": "web"})
	for _, gen := range []CommentedPolicyGenerator{NewStandardPolicyGenerator(), NewCiliumPolicyGenerator()} {
		policy, comments, err := gen.GenerateWithComments("web6", dualStackFixtureTraffic(), detail)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !comments.IsEmpty() {
			t.Fatalf("%s: expected no comments without host-network peers, got %+v", gen.GetType(), comments)
		}
		plain, _ := yaml.Marshal(policy)
		withComments, _ := MarshalPolicyYAML(policy, comments)
		if string(plain) != string(withComments) {
			t.Errorf("%s: MarshalPolicyYAML must equal yaml.Marshal when there are no comments", gen.GetType())
		}
	}
}

// ---- Cross-namespace peers ----------------------------------------------------
//
// A CiliumNetworkPolicy endpoint selector without a namespace label is scoped
// to the policy's own namespace, so a peer in another namespace rendered from
// its labels alone matched nothing (media/maintainerr → downloads/sonarr was
// denied). The Cilium golden pins `k8s:io.kubernetes.pod.namespace` beside the
// labels for every cross-namespace peer (pod or Service); the standard golden
// pins the namespaceSelector the NetworkPolicy generator already emitted. The
// pre-existing cilium_endpoint_resolved golden is same-namespace (prod →
// prod) and stays unchanged.
func crossNamespaceFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{
			"10.0.0.30": fixturePodDetail("sonarr-0", "downloads", "10.0.0.30", map[string]string{"app": "sonarr"}),
			"10.0.0.40": fixturePodDetail("maintainerr-0", "media", "10.0.0.40", map[string]string{"app": "maintainerr"}),
		},
		svcs: map[string]*api.SvcDetail{
			"10.96.0.50": {SvcName: "prometheus", SvcNamespace: "monitoring", SvcIp: "10.96.0.50",
				Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "prometheus"}}}},
		},
	}
	detail := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		// Egress to a pod in another namespace and to a Service in a third.
		{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.0.0.30", DstPort: "8989", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.96.0.50", DstPort: "9090", Protocol: "TCP"},
		// Ingress from a pod in another namespace.
		{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.40", Protocol: "TCP"},
	}
	return stub, detail, traffic
}

// ---- Peer attribution: stale IPs and stored identity (CONTRACT v4) ---------
//
// Pod IPs are recycled. Resolving a flow's peer IP against today's pod table
// names whoever holds the IP NOW — on cluster-00 that drew autobrr
// (home-system, started 2026-08-04) as the peer of cmangos-database INGRESS
// rows from May and July, because it inherited a CronJob pod's IP. Two
// fixtures pin the fix; see peer.go and test/fixtures/generators/networkpolicy/README.md.

func v4FixturePod(name, ns, ip string, labels map[string]string, node, workload, startedAt string, dead bool) api.PodDetail {
	d := fixturePodDetail(name, ns, ip, labels)
	d.NodeName = node
	d.WorkloadName = workload
	d.StartedAt = startedAt
	d.IsDead = dead
	return *d
}

// (a) stale_ip_peer: legacy rows (no stored peer) from 10.244.12.199, dated
// 2026-05-21 and 2026-07-23; the only pod known to hold that IP is autobrr,
// started 2026-08-04 — later than both flows, so the start-time guard leaves
// the peer UNATTRIBUTED: an ipBlock with a comment quoting the newest row
// time_stamp, never autobrr's selector. The egress peer cmangos-web-0 started
// before its flow and resolves normally, proving the guard is per candidate.
func staleIPPeerFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{},
		svcs: map[string]*api.SvcDetail{},
		allPods: []api.PodDetail{
			v4FixturePod("autobrr-7d9c4b8f6-q2x9k", "home-system", "10.244.12.199",
				map[string]string{"app": "autobrr"}, "worker-2", "autobrr", "2026-08-04T09:12:41", false),
			v4FixturePod("cmangos-web-0", "game-servers", "10.244.5.8",
				map[string]string{"app": "cmangos-web"}, "worker-1", "cmangos-web", "2026-07-01T00:00:00", false),
		},
	}
	detail := fixturePodDetail("cmangos-database", "game-servers", "10.244.3.17", map[string]string{"app": "cmangos-database"})
	traffic := []api.PodTraffic{
		{TrafficType: "INGRESS", SrcIP: "10.244.3.17", SrcPodPort: "3306", DstIP: "10.244.12.199", DstPort: "51234", Protocol: "TCP", TimeStamp: "2026-05-21T08:30:00"},
		{TrafficType: "INGRESS", SrcIP: "10.244.3.17", SrcPodPort: "3306", DstIP: "10.244.12.199", DstPort: "51235", Protocol: "TCP", TimeStamp: "2026-07-23T10:00:00"},
		{TrafficType: "EGRESS", SrcIP: "10.244.3.17", DstIP: "10.244.5.8", DstPort: "8080", Protocol: "TCP", TimeStamp: "2026-07-23T10:00:05"},
	}
	return stub, detail, traffic
}

// (b) stored_peer_identity: rows the broker resolved at ingest. The INGRESS
// row names the CronJob pod that held 10.244.12.199 at flow time; the IP is
// NOW held by autobrr (alive, start unknown — a by-IP lookup would pick it).
// The stored identity wins. The egress rows carry a stored Service and a
// stored host-network ("node") peer, so all three peer_kind values are pinned.
func storedPeerIdentityFixture() (stubBrokerData, *api.PodDetail, []api.PodTraffic) {
	backup := v4FixturePod("cmangos-backup-29271840-x7k2p", "game-servers", "10.244.12.199",
		map[string]string{"app": "cmangos-backup"}, "worker-1", "cmangos-backup", "2026-09-03T04:59:30", true)
	backup.Pod.UID = "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6"
	nodeExporter := v4FixturePod("node-exporter-abc12", "monitoring", "192.168.50.101",
		map[string]string{"app": "node-exporter"}, "worker-1", "node-exporter", "2026-08-01T00:00:00", false)
	hostNetwork := true
	nodeExporter.HostNetwork = &hostNetwork
	nodeExporter.Pod.UID = "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3"
	stub := stubBrokerData{
		pods: map[string]*api.PodDetail{},
		svcs: map[string]*api.SvcDetail{
			"10.96.0.10": {SvcName: "db", SvcNamespace: "game-servers", SvcIp: "10.96.0.10",
				Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "db"}}}},
		},
		allPods: []api.PodDetail{
			v4FixturePod("autobrr-7d9c4b8f6-q2x9k", "home-system", "10.244.12.199",
				map[string]string{"app": "autobrr"}, "worker-2", "autobrr", "", false),
			backup,
			nodeExporter,
		},
	}
	detail := fixturePodDetail("cmangos-database", "game-servers", "10.244.3.17", map[string]string{"app": "cmangos-database"})
	traffic := []api.PodTraffic{
		{TrafficType: "INGRESS", SrcIP: "10.244.3.17", SrcPodPort: "3306", DstIP: "10.244.12.199", DstPort: "51234", Protocol: "TCP",
			TimeStamp: "2026-09-03T05:00:00", PeerKind: "pod", PeerNamespace: "game-servers", PeerName: "cmangos-backup-29271840-x7k2p",
			PeerUID: "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6", PeerWorkloadKind: "CronJob", PeerWorkloadName: "cmangos-backup", PeerResolvedAt: "2026-09-03T05:00:00.201118"},
		{TrafficType: "EGRESS", SrcIP: "10.244.3.17", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP",
			TimeStamp: "2026-09-03T05:00:01", PeerKind: "service", PeerNamespace: "game-servers", PeerName: "db", PeerResolvedAt: "2026-09-03T05:00:01.100000"},
		{TrafficType: "EGRESS", SrcIP: "10.244.3.17", DstIP: "192.168.50.101", DstPort: "9100", Protocol: "TCP",
			TimeStamp: "2026-09-03T05:00:02", PeerKind: "node", PeerNamespace: "monitoring", PeerName: "node-exporter-abc12",
			PeerUID: "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3", PeerWorkloadKind: "DaemonSet", PeerWorkloadName: "node-exporter", PeerResolvedAt: "2026-09-03T05:00:02.100000"},
	}
	return stub, detail, traffic
}

func TestFixtureGolden_PeerAttribution(t *testing.T) {
	cases := []struct {
		name    string
		fixture func() (stubBrokerData, *api.PodDetail, []api.PodTraffic)
	}{
		{"stale_ip_peer", staleIPPeerFixture},
		{"stored_peer_identity", storedPeerIdentityFixture},
	}
	for _, tc := range cases {
		t.Run("standard_"+tc.name, func(t *testing.T) {
			stub, detail, traffic := tc.fixture()
			gen := NewStandardPolicyGenerator()
			gen.setBrokerData(stub)
			checkCommentedPolicyGolden(t, "standard_"+tc.name+".golden.yaml", gen, detail.Name, traffic, detail)
		})
		t.Run("cilium_"+tc.name, func(t *testing.T) {
			stub, detail, traffic := tc.fixture()
			gen := NewCiliumPolicyGenerator()
			gen.setBrokerData(stub)
			checkCommentedPolicyGolden(t, "cilium_"+tc.name+".golden.yaml", gen, detail.Name, traffic, detail)
		})
	}
}

func TestFixtureGolden_CrossNamespacePeer(t *testing.T) {
	t.Run("standard", func(t *testing.T) {
		stub, detail, traffic := crossNamespaceFixture()
		gen := NewStandardPolicyGenerator()
		gen.setBrokerData(stub)
		checkCommentedPolicyGolden(t, "standard_cross_namespace_peer.golden.yaml", gen, detail.Name, traffic, detail)
	})
	t.Run("cilium", func(t *testing.T) {
		stub, detail, traffic := crossNamespaceFixture()
		gen := NewCiliumPolicyGenerator()
		gen.setBrokerData(stub)
		checkCommentedPolicyGolden(t, "cilium_cross_namespace_peer.golden.yaml", gen, detail.Name, traffic, detail)
	})
}
