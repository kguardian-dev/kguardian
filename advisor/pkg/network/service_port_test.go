package network

import (
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func svcPeer(ports ...corev1.ServicePort) resolvedPeer {
	return resolvedPeer{IP: "10.96.0.10", Svc: &api.SvcDetail{SvcName: "api", SvcNamespace: "prod",
		Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}, Ports: ports}}}}
}

func TestServicePortFor(t *testing.T) {
	cases := []struct {
		name   string
		peer   resolvedPeer
		port   int
		proto  string
		want   intstr.IntOrString
		mapped bool
	}{
		{"not a service", resolvedPeer{IP: "10.0.0.9"}, 80, "TCP", intstr.FromInt(80), true},
		{"numeric targetPort", svcPeer(corev1.ServicePort{Port: 80, Protocol: "TCP", TargetPort: intstr.FromInt(8080)}), 80, "TCP", intstr.FromInt(8080), true},
		{"named targetPort", svcPeer(corev1.ServicePort{Port: 80, Protocol: "TCP", TargetPort: intstr.FromString("http")}), 80, "TCP", intstr.FromString("http"), true},
		{"targetPort omitted", svcPeer(corev1.ServicePort{Port: 80, Protocol: "TCP"}), 80, "TCP", intstr.FromInt(80), true},
		{"protocol omitted is TCP", svcPeer(corev1.ServicePort{Port: 80, TargetPort: intstr.FromInt(8080)}), 80, "TCP", intstr.FromInt(8080), true},
		{"protocol must match", svcPeer(corev1.ServicePort{Port: 53, Protocol: "TCP", TargetPort: intstr.FromInt(5353)}), 53, "UDP", intstr.FromInt(53), false},
		{"no spec.ports", svcPeer(), 80, "TCP", intstr.FromInt(80), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, mapped := servicePortFor(c.peer, c.port, c.proto)
			assert.Equal(t, []intstr.IntOrString{c.want}, got)
			assert.Equal(t, c.mapped, mapped)
		})
	}
}

// Two Service ports that target the same container port collapse into one
// policy port, and ingress ports (the target pod's own) are never mapped.
func TestServiceTargetPort_DedupAndIngressUntouched(t *testing.T) {
	svc := &api.SvcDetail{SvcName: "api", SvcNamespace: "prod", SvcIp: "10.96.0.10",
		Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}, Ports: []corev1.ServicePort{
			{Port: 80, Protocol: "TCP", TargetPort: intstr.FromInt(8080)},
			{Port: 8080, Protocol: "TCP", TargetPort: intstr.FromInt(8080)},
		}}}}
	gen := NewStandardPolicyGenerator()
	gen.setBrokerData(stubBrokerData{pods: map[string]*api.PodDetail{}, svcs: map[string]*api.SvcDetail{"10.96.0.10": svc}})
	detail := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		{TrafficType: "EGRESS", DstIP: "10.96.0.10", DstPort: "80", Protocol: "TCP"},
		{TrafficType: "EGRESS", DstIP: "10.96.0.10", DstPort: "8080", Protocol: "TCP"},
		{TrafficType: "INGRESS", DstIP: "10.96.0.10", SrcPodPort: "80", Protocol: "TCP"},
	}
	out, comments, err := gen.GenerateWithComments("web", traffic, detail)
	require.NoError(t, err)
	np := out.(*networkingv1.NetworkPolicy)
	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].Ports, 1)
	assert.Equal(t, intstr.FromInt(8080), *np.Spec.Egress[0].Ports[0].Port)
	require.Len(t, np.Spec.Ingress, 1)
	assert.Equal(t, intstr.FromInt(80), *np.Spec.Ingress[0].Ports[0].Port)
	assert.True(t, comments.IsEmpty())
}
