package network

import (
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

func boolPtr(b bool) *bool { return &b }

func metav1ObjectMeta(labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Labels: labels}
}

func mustPorts(ports ...int) []networkingv1.NetworkPolicyPort {
	out := make([]networkingv1.NetworkPolicyPort, 0, len(ports))
	for _, p := range ports {
		port := intstr.FromInt(p)
		out = append(out, networkingv1.NetworkPolicyPort{Port: &port, Protocol: protocolPtr("TCP")})
	}
	return out
}

func TestIsHostNetwork_NilAndFalseMeanNormalPod(t *testing.T) {
	assert.False(t, isHostNetwork(nil))
	assert.False(t, isHostNetwork(&api.PodDetail{}), "nil host_network (old broker) is not host-network")
	assert.False(t, isHostNetwork(&api.PodDetail{HostNetwork: boolPtr(false)}))
	assert.True(t, isHostNetwork(&api.PodDetail{HostNetwork: boolPtr(true)}))
}

func TestHostNetworkComment_NameAndNodeFallbacks(t *testing.T) {
	d := &api.PodDetail{Name: "node-exporter-abc12", Namespace: "monitoring"}
	// No workload, no node anywhere: pod name and the observed IP.
	assert.Equal(t,
		"host-network peer monitoring/node-exporter-abc12 on node 192.168.50.101 — podSelector cannot match host traffic",
		hostNetworkPeerComment(d, "192.168.50.101", "podSelector"))

	// Manifest nodeName is used before falling back to the IP.
	d.Pod.Spec.NodeName = "worker-9"
	assert.Contains(t, hostNetworkPeerComment(d, "192.168.50.101", "podSelector"), "on node worker-9 ")

	// Flat broker columns win over both.
	d.NodeName, d.WorkloadName = "worker-1", "node-exporter"
	assert.Equal(t,
		"host-network peer monitoring/node-exporter on node worker-1 — endpointSelector cannot match host traffic",
		hostNetworkPeerComment(d, "192.168.50.101", "endpointSelector"))
}

func TestInsertComments_EmptyIsIdentity(t *testing.T) {
	doc := []byte("apiVersion: v1\nkind: X\nspec:\n  egress:\n  - a: 1\n")
	assert.Equal(t, doc, insertComments(doc, nil))
	assert.Equal(t, doc, insertComments(doc, &PolicyComments{}))
}

func TestInsertComments_PlacesHeaderAndRuleLines(t *testing.T) {
	// Real generator output shape: sigs.k8s.io/yaml, sequences at the parent
	// key's column. Includes a label literally named "ingress" under
	// metadata to prove only spec.ingress/egress are treated as rule lists.
	doc := strings.Join([]string{
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  labels:",
		"    ingress: nope",
		"  name: p",
		"spec:",
		"  egress:",
		"  - ports:",
		"    - port: 9100",
		"    to:",
		"    - ipBlock:",
		"        cidr: 192.168.50.101/32",
		"  - ports:",
		"    - port: 5432",
		"  ingress:",
		"  - from:",
		"    - ipBlock:",
		"        cidr: 10.0.0.7/32",
		"  podSelector:",
		"    matchLabels:",
		"      app: web",
		"",
	}, "\n")
	c := &PolicyComments{}
	c.addHeader("WARNING: one", "two")
	c.addEgress(0, "egress zero")
	c.addEgress(1, "egress one a")
	c.addEgress(1, "egress one b")
	c.addIngress(0, "ingress zero")
	c.addIngress(7, "no such rule") // must be ignored, never rendered

	got := string(insertComments([]byte(doc), c))
	want := strings.Join([]string{
		"# WARNING: one",
		"# two",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  labels:",
		"    ingress: nope",
		"  name: p",
		"spec:",
		"  egress:",
		"  # egress zero",
		"  - ports:",
		"    - port: 9100",
		"    to:",
		"    - ipBlock:",
		"        cidr: 192.168.50.101/32",
		"  # egress one a",
		"  # egress one b",
		"  - ports:",
		"    - port: 5432",
		"  ingress:",
		"  # ingress zero",
		"  - from:",
		"    - ipBlock:",
		"        cidr: 10.0.0.7/32",
		"  podSelector:",
		"    matchLabels:",
		"      app: web",
		"",
	}, "\n")
	assert.Equal(t, want, got)
	assert.NotContains(t, got, "no such rule")

	// The comments must not disturb the document: parsing the commented
	// output yields the same object as the plain one.
	var plain, commented map[string]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(doc), &plain))
	require.NoError(t, yaml.Unmarshal([]byte(got), &commented))
	assert.Equal(t, plain, commented)
}

func TestStandardPeer_HostNetworkWinsOverLabels(t *testing.T) {
	// Even with perfectly good labels, a host-network pod must be pinned by
	// IP: a podSelector on those labels matches nothing the CNI sees.
	gen := NewStandardPolicyGenerator()
	gen.setBrokerData(stubBrokerData{pods: map[string]*api.PodDetail{
		"192.168.50.101": {
			Name: "node-exporter-abc12", Namespace: "monitoring", PodIP: "192.168.50.101",
			NodeName: "worker-1", WorkloadName: "node-exporter", HostNetwork: boolPtr(true),
			Pod: corev1.Pod{ObjectMeta: metav1ObjectMeta(map[string]string{"app": "node-exporter"})},
		},
		// Same labels, host_network unset: the pre-existing podSelector path.
		"10.0.0.9": {
			Name: "other", Namespace: "monitoring", PodIP: "10.0.0.9",
			Pod: corev1.Pod{ObjectMeta: metav1ObjectMeta(map[string]string{"app": "node-exporter"})},
		},
	}})

	peers, comment := gen.createNetworkPolicyPeers("192.168.50.101")
	require.Len(t, peers, 1)
	peer := peers[0]
	assert.Nil(t, peer.PodSelector)
	assert.Nil(t, peer.NamespaceSelector)
	require.NotNil(t, peer.IPBlock)
	assert.Equal(t, "192.168.50.101/32", peer.IPBlock.CIDR)
	assert.Equal(t, "host-network peer monitoring/node-exporter on node worker-1 — podSelector cannot match host traffic", comment)

	peers, comment = gen.createNetworkPolicyPeers("10.0.0.9")
	require.Len(t, peers, 1)
	peer = peers[0]
	assert.Nil(t, peer.IPBlock)
	require.NotNil(t, peer.PodSelector)
	assert.Equal(t, "", comment)
}

func TestCiliumHostNetwork_DedupIsPerPortList(t *testing.T) {
	// Two host-network peers on the same ports collapse into one entities
	// rule carrying both comments; a third on different ports stays separate.
	gen := NewCiliumPolicyGenerator()
	mk := func(name, node, ip string) *api.PodDetail {
		return &api.PodDetail{Name: name, Namespace: "monitoring", PodIP: ip, NodeName: node, WorkloadName: "node-exporter", HostNetwork: boolPtr(true)}
	}
	gen.setBrokerData(stubBrokerData{pods: map[string]*api.PodDetail{
		"192.168.50.101": mk("ne-a", "worker-1", "192.168.50.101"),
		"192.168.50.102": mk("ne-b", "worker-2", "192.168.50.102"),
		"192.168.50.103": mk("ne-c", "worker-3", "192.168.50.103"),
	}})
	rules := []NetworkPolicyRule{
		{PeerIP: "192.168.50.101", Ports: mustPorts(9100)},
		{PeerIP: "192.168.50.102", Ports: mustPorts(9100)},
		{PeerIP: "192.168.50.103", Ports: mustPorts(10250)},
	}
	comments := &PolicyComments{}
	egress := gen.transformToCiliumEgressRules(rules, comments)
	require.Len(t, egress, 2)
	assert.Equal(t, []string{"host", "remote-node"}, egress[0].ToEntities)
	assert.Equal(t, "9100", egress[0].ToPorts[0].Ports[0].Port)
	assert.Equal(t, []string{"host", "remote-node"}, egress[1].ToEntities)
	assert.Equal(t, "10250", egress[1].ToPorts[0].Ports[0].Port)
	assert.Len(t, comments.Egress[0], 2, "both 9100 peers explain the merged rule")
	assert.Contains(t, comments.Egress[0][0], "on node worker-1")
	assert.Contains(t, comments.Egress[0][1], "on node worker-2")
	assert.Len(t, comments.Egress[1], 1)
	assert.Contains(t, comments.Egress[1][0], "on node worker-3")
}

func TestPolicyService_RendersCommentsInYAML(t *testing.T) {
	// End to end through PolicyService: the YAML handed to the CLI carries
	// the comment, and the pre-existing peer rendering is untouched.
	stub := stubBrokerData{
		traffic: []api.PodTraffic{{
			SrcPodName: "prometheus", SrcIP: "10.0.0.5", SrcNamespace: "monitoring",
			TrafficType: "EGRESS", DstIP: "192.168.50.101", DstPort: "9100", Protocol: corev1.ProtocolTCP,
		}},
		pods: map[string]*api.PodDetail{
			"10.0.0.5": podDetail("prometheus", "10.0.0.5", map[string]string{"app": "prometheus"}),
			"192.168.50.101": {
				Name: "node-exporter-abc12", Namespace: "monitoring", PodIP: "192.168.50.101",
				NodeName: "worker-1", WorkloadName: "node-exporter", HostNetwork: boolPtr(true),
			},
		},
		svcs: map[string]*api.SvcDetail{},
	}
	svc := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	svc.UseBrokerData(stub)
	svc.RegisterGenerator(NewStandardPolicyGenerator())

	out, err := svc.GeneratePolicy("prometheus", StandardPolicy)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Contains(t, string(out.YAML), "\n  # host-network peer monitoring/node-exporter on node worker-1 — podSelector cannot match host traffic\n  - ports:")
	assert.Contains(t, string(out.YAML), "cidr: 192.168.50.101/32")
	assert.NotContains(t, string(out.YAML), "namespaceSelector")
	require.NotNil(t, out.Comments)
	assert.Len(t, out.Comments.Egress[0], 1)
}

func TestHostNetworkServiceBackends_FilterAndComment(t *testing.T) {
	svc := &api.SvcDetail{SvcName: "node-exporter", SvcNamespace: "monitoring",
		Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "node-exporter"}}}}
	mk := func(name, ns, node string, labels map[string]string, host, dead bool) api.PodDetail {
		return api.PodDetail{Name: name, Namespace: ns, NodeName: node, HostNetwork: boolPtr(host), IsDead: dead,
			Pod: corev1.Pod{ObjectMeta: metav1ObjectMeta(labels)}}
	}
	ne := map[string]string{"app": "node-exporter", "extra": "label"}
	data := stubBrokerData{allPods: []api.PodDetail{
		mk("ne-b", "monitoring", "worker-2", ne, true, false),
		mk("ne-a", "monitoring", "worker-1", ne, true, false),
		mk("ne-a-same-node", "monitoring", "worker-1", ne, true, false), // duplicate node
		mk("ne-dead", "monitoring", "worker-9", ne, true, true),         // dead: ignored
		mk("ne-other-ns", "prod", "worker-8", ne, true, false),          // wrong namespace
		mk("ne-plain", "monitoring", "worker-7", ne, false, false),      // pod-network backend
		mk("unrelated", "monitoring", "worker-6", map[string]string{"app": "x"}, true, false),
	}}

	backends := hostNetworkServiceBackends(data, svc)
	names := []string{}
	for _, b := range backends {
		names = append(names, b.Name)
	}
	assert.Equal(t, []string{"ne-a", "ne-a-same-node", "ne-b"}, names, "alive, same-namespace, selector-matching, host-network only; sorted by name")
	assert.Equal(t,
		"host-network peer monitoring/svc/node-exporter on node worker-1,worker-2 — podSelector cannot match host traffic",
		hostNetworkServiceComment(svc, backends, "10.96.0.20", "podSelector"))

	// No host-network backend ⇒ nil ⇒ the pre-existing podSelector path.
	assert.Nil(t, hostNetworkServiceBackends(stubBrokerData{allPods: []api.PodDetail{mk("ne-plain", "monitoring", "w", ne, false, false)}}, svc))
	// Selector-less Service (headless/manual endpoints) never consults the pod list.
	assert.Nil(t, hostNetworkServiceBackends(data, &api.SvcDetail{SvcName: "manual", SvcNamespace: "monitoring"}))
	// Unknown nodes fall back to the observed IP.
	noNode := []api.PodDetail{mk("ne", "monitoring", "", ne, true, false)}
	assert.Contains(t, hostNetworkServiceComment(svc, noNode, "10.96.0.20", "podSelector"), "on node 10.96.0.20 ")
}

func TestStandardPeer_HostNetworkService_IPBlockPerBackendNode(t *testing.T) {
	// NetworkPolicy is evaluated post-DNAT: the peer set for a Service backed
	// by host-network pods is one ipBlock per distinct backend (node) IP,
	// sorted — never the ClusterIP.
	svc := &api.SvcDetail{SvcName: "node-exporter", SvcNamespace: "monitoring", SvcIp: "10.96.0.20",
		Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "node-exporter"}}}}
	mk := func(name, node, ip string) api.PodDetail {
		return api.PodDetail{Name: name, Namespace: "monitoring", PodIP: ip, NodeName: node, HostNetwork: boolPtr(true),
			Pod: corev1.Pod{ObjectMeta: metav1ObjectMeta(map[string]string{"app": "node-exporter"})}}
	}
	gen := NewStandardPolicyGenerator()
	gen.setBrokerData(stubBrokerData{
		svcs: map[string]*api.SvcDetail{"10.96.0.20": svc},
		allPods: []api.PodDetail{
			mk("ne-b", "worker-2", "192.168.50.102"),
			mk("ne-a", "worker-1", "192.168.50.101"),
			mk("ne-a-dup", "worker-1", "192.168.50.101"), // same node IP: one ipBlock
			mk("ne-bad", "worker-4", "not-an-ip"),        // skipped
		},
	})
	peers, comment := gen.createNetworkPolicyPeers("10.96.0.20")
	require.Len(t, peers, 2)
	assert.Equal(t, "192.168.50.101/32", peers[0].IPBlock.CIDR)
	assert.Equal(t, "192.168.50.102/32", peers[1].IPBlock.CIDR)
	for _, p := range peers {
		assert.Nil(t, p.PodSelector)
		assert.Nil(t, p.NamespaceSelector)
		assert.NotEqual(t, "10.96.0.20/32", p.IPBlock.CIDR, "ClusterIP must never be the peer")
	}
	assert.Equal(t, "host-network peer monitoring/svc/node-exporter on node worker-1,worker-2,worker-4 — podSelector cannot match host traffic", comment)

	// Every backend unparseable ⇒ drop the rule rather than fall back to the ClusterIP.
	gen.setBrokerData(stubBrokerData{svcs: map[string]*api.SvcDetail{"10.96.0.20": svc}, allPods: []api.PodDetail{mk("ne-bad", "w", "junk")}})
	peers, _ = gen.createNetworkPolicyPeers("10.96.0.20")
	assert.Empty(t, peers)
}
