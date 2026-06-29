package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/network"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newServePolicyService() *network.PolicyService {
	svc := network.NewPolicyService(serveConfig{}, network.StandardPolicy)
	svc.RegisterGenerator(network.NewStandardPolicyGenerator())
	svc.RegisterGenerator(network.NewCiliumPolicyGenerator())
	return svc
}

// withStubbedAPI overrides advisor's package-global broker accessors with
// canned data for one pod (10.0.0.1, labelled app=web) talking out to an
// external peer (8.8.8.8:443), and restores them on cleanup.
func withStubbedAPI(t *testing.T) {
	t.Helper()
	origTraffic := api.GetPodTrafficFunc
	origPod := api.GetPodSpecFunc
	origSvc := api.GetSvcSpecFunc
	t.Cleanup(func() {
		api.GetPodTrafficFunc = origTraffic
		api.GetPodSpecFunc = origPod
		api.GetSvcSpecFunc = origSvc
	})

	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{{
			SrcPodName:   podName,
			SrcIP:        "10.0.0.1",
			SrcNamespace: "prod",
			TrafficType:  "EGRESS",
			DstIP:        "8.8.8.8",
			DstPort:      "443",
			Protocol:     corev1.ProtocolTCP,
		}}, nil
	}
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		if ip == "10.0.0.1" {
			return &api.PodDetail{
				Name:      "web-1",
				Namespace: "prod",
				PodIP:     "10.0.0.1",
				Pod: corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			}, nil
		}
		return nil, nil // peer 8.8.8.8 -> CIDR fallback
	}
	api.GetSvcSpecFunc = func(string) (*api.SvcDetail, error) { return nil, nil }
}

func TestNetworkPolicyHandler_GeneratesStandardYAML(t *testing.T) {
	withStubbedAPI(t)
	h := networkPolicyHandler(newServePolicyService())

	req := httptest.NewRequest(http.MethodGet, "/generate/networkpolicy?pod=web-1", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("content-type: want application/yaml, got %s", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "kind: NetworkPolicy") {
		t.Errorf("expected a NetworkPolicy YAML; got:\n%s", body)
	}
	if !strings.Contains(body, "app: web") {
		t.Errorf("expected pod selector label app=web; got:\n%s", body)
	}
}

func TestNetworkPolicyHandler_CiliumType(t *testing.T) {
	withStubbedAPI(t)
	h := networkPolicyHandler(newServePolicyService())

	req := httptest.NewRequest(http.MethodGet, "/generate/networkpolicy?pod=web-1&type=cilium", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "kind: CiliumNetworkPolicy") {
		t.Errorf("expected a CiliumNetworkPolicy; got:\n%s", rr.Body.String())
	}
}

func TestNetworkPolicyHandler_MissingPodIs400(t *testing.T) {
	h := networkPolicyHandler(newServePolicyService())
	req := httptest.NewRequest(http.MethodGet, "/generate/networkpolicy", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", rr.Code)
	}
}

func TestNetworkPolicyHandler_InvalidTypeIs400(t *testing.T) {
	h := networkPolicyHandler(newServePolicyService())
	req := httptest.NewRequest(http.MethodGet, "/generate/networkpolicy?pod=web-1&type=bogus", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", rr.Code)
	}
}

func TestSeccompHandler_GeneratesProfile(t *testing.T) {
	// handleSeccompGenerate uses api.GetPodSysCall, which hits BrokerBaseURL
	// directly (not a func var), so point it at a mock broker.
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/pod/syscalls/") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"pod_name":"web-1","pod_namespace":"prod","syscalls":"read,write,openat","arch":"x86_64"}]`))
	}))
	defer broker.Close()

	orig := api.BrokerBaseURL
	api.BrokerBaseURL = broker.URL
	t.Cleanup(func() { api.BrokerBaseURL = orig })

	req := httptest.NewRequest(http.MethodGet, "/generate/seccomp?pod=web-1", nil)
	rr := httptest.NewRecorder()
	handleSeccompGenerate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &profile); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if profile["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction: want SCMP_ACT_ERRNO, got %v", profile["defaultAction"])
	}
	if !strings.Contains(rr.Body.String(), "openat") {
		t.Errorf("expected observed syscalls in profile; got:\n%s", rr.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	handleHealthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rr.Code)
	}
}
