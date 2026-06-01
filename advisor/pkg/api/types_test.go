package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

// Wire-format contract tests for the broker → advisor boundary. These
// structs deserialise broker JSON; a rename or case change on either
// side breaks policy generation silently. Lock the JSON tag names so a
// regression fails the tests, not production.

func TestPodTraffic_JSONRoundtrip(t *testing.T) {
	body := []byte(`{
		"uuid": "abc-123",
		"pod_name": "web-1",
		"pod_ip": "10.0.0.1",
		"pod_namespace": "prod",
		"pod_port": "8080",
		"traffic_type": "INGRESS",
		"traffic_in_out_ip": "10.1.0.1",
		"traffic_in_out_port": "9090",
		"ip_protocol": "TCP"
	}`)

	var got PodTraffic
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	assert.Equal(t, "abc-123", got.UUID)
	assert.Equal(t, "web-1", got.SrcPodName)
	assert.Equal(t, "10.0.0.1", got.SrcIP)
	assert.Equal(t, "prod", got.SrcNamespace)
	assert.Equal(t, "8080", got.SrcPodPort)
	assert.Equal(t, "INGRESS", got.TrafficType)
	assert.Equal(t, "10.1.0.1", got.DstIP)
	assert.Equal(t, "9090", got.DstPort)
	assert.Equal(t, v1.Protocol("TCP"), got.Protocol)
}

func TestPodTraffic_RoundtripsThroughMarshal(t *testing.T) {
	// Marshal a populated struct, parse the JSON, then re-marshal and
	// compare. Catches regressions where the JSON tags drift between
	// what we accept (Unmarshal) and what we emit (Marshal).
	want := PodTraffic{
		UUID:         "id",
		SrcPodName:   "web-1",
		SrcIP:        "10.0.0.1",
		SrcNamespace: "prod",
		SrcPodPort:   "8080",
		TrafficType:  "EGRESS",
		DstIP:        "10.1.0.1",
		DstPort:      "443",
		Protocol:     v1.ProtocolTCP,
	}
	bytes1, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	var got PodTraffic
	if err := json.Unmarshal(bytes1, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bytes2, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}
	assert.JSONEq(t, string(bytes1), string(bytes2))
}

func TestPodDetail_JSONShape(t *testing.T) {
	body := []byte(`{
		"uuid": "u-1",
		"pod_ip": "10.0.0.1",
		"pod_name": "web-1",
		"pod_namespace": "prod",
		"pod_obj": {
			"metadata": {"name": "web-1", "namespace": "prod"}
		}
	}`)
	var got PodDetail
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assert.Equal(t, "10.0.0.1", got.PodIP)
	assert.Equal(t, "web-1", got.Name)
	assert.Equal(t, "prod", got.Namespace)
	assert.Equal(t, "web-1", got.Pod.Name)
}

func TestSvcDetail_JSONShape(t *testing.T) {
	body := []byte(`{
		"svc_ip": "10.96.0.1",
		"svc_name": "kubernetes",
		"svc_namespace": "default",
		"service_spec": {
			"metadata": {"name": "kubernetes", "namespace": "default"}
		}
	}`)
	var got SvcDetail
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assert.Equal(t, "10.96.0.1", got.SvcIp)
	assert.Equal(t, "kubernetes", got.SvcName)
	assert.Equal(t, "default", got.SvcNamespace)
	assert.Equal(t, "kubernetes", got.Service.Name)
}

// Function-variable injection contract: GetPodTrafficFunc /
// GetPodSpecFunc / GetSvcSpecFunc are the test seam. A regression
// that bypassed the variable would silently re-introduce real HTTP
// calls in tests.

func TestGetPodTraffic_UsesInjectedFunc(t *testing.T) {
	prev := GetPodTrafficFunc
	defer func() { GetPodTrafficFunc = prev }()

	called := false
	GetPodTrafficFunc = func(podName string) ([]PodTraffic, error) {
		called = true
		assert.Equal(t, "web-1", podName)
		return []PodTraffic{{UUID: "from-mock"}}, nil
	}

	got, err := GetPodTraffic("web-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.True(t, called, "injected func not invoked")
	if assert.Len(t, got, 1) {
		assert.Equal(t, "from-mock", got[0].UUID)
	}
}

func TestGetPodSpec_UsesInjectedFunc(t *testing.T) {
	prev := GetPodSpecFunc
	defer func() { GetPodSpecFunc = prev }()

	GetPodSpecFunc = func(podIP string) (*PodDetail, error) {
		return &PodDetail{PodIP: podIP, Name: "from-mock"}, nil
	}

	got, err := GetPodSpec("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	assert.Equal(t, "10.0.0.1", got.PodIP)
	assert.Equal(t, "from-mock", got.Name)
}

func TestGetSvcSpec_UsesInjectedFunc(t *testing.T) {
	prev := GetSvcSpecFunc
	defer func() { GetSvcSpecFunc = prev }()

	GetSvcSpecFunc = func(svcIP string) (*SvcDetail, error) {
		return &SvcDetail{SvcIp: svcIP, SvcName: "from-mock"}, nil
	}

	got, err := GetSvcSpec("10.96.0.1")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	assert.Equal(t, "10.96.0.1", got.SvcIp)
	assert.Equal(t, "from-mock", got.SvcName)
}
