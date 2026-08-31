package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/matcher"
	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// fakeLookup implements PolicyLookup with in-memory state.
type fakeLookup struct {
	pods        map[string]*corev1.Pod
	nsLabels    map[string]map[string]string
	policies    map[string][]*v1alpha1.AuditNetworkPolicy
	clusterPols []*v1alpha1.AuditClusterNetworkPolicy
}

func (f *fakeLookup) GetPod(ns, name string) *corev1.Pod {
	return f.pods[ns+"/"+name]
}
func (f *fakeLookup) GetNamespaceLabels(name string) map[string]string {
	return f.nsLabels[name]
}
func (f *fakeLookup) PoliciesInNamespace(ns string) []*v1alpha1.AuditNetworkPolicy {
	return f.policies[ns]
}
func (f *fakeLookup) ClusterPolicies() []*v1alpha1.AuditClusterNetworkPolicy {
	return f.clusterPols
}

func setup(t *testing.T) (*Server, *fakeLookup) {
	t.Helper()
	f := &fakeLookup{
		pods:     map[string]*corev1.Pod{},
		nsLabels: map[string]map[string]string{},
		policies: map[string][]*v1alpha1.AuditNetworkPolicy{},
	}
	log := logrus.New()
	log.SetOutput(io.Discard) // keep test output clean
	s := New(":0", f, nil, log)
	s.SetReady()
	return s, f
}

func decode(t *testing.T, body io.Reader) EvaluateResponse {
	t.Helper()
	var resp EvaluateResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func TestHandleHealth(t *testing.T) {
	s, _ := setup(t)
	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d", rec.Code)
	}
}

func TestHandleReady_NotReadyUntilSetReady(t *testing.T) {
	f := &fakeLookup{
		pods:     map[string]*corev1.Pod{},
		nsLabels: map[string]map[string]string{},
		policies: map[string][]*v1alpha1.AuditNetworkPolicy{},
	}
	log := logrus.New()
	log.SetOutput(io.Discard)
	s := New(":0", f, nil, log) // SetReady() not called

	rec := httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("pre-ready: want 503, got %d", rec.Code)
	}

	s.SetReady()
	rec = httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("post-ready: want 200, got %d", rec.Code)
	}
}

func TestHandleEvaluate_RejectsNonPost(t *testing.T) {
	s, _ := setup(t)
	rec := httptest.NewRecorder()
	s.handleEvaluate(rec, httptest.NewRequest(http.MethodGet, "/evaluate", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /evaluate: want 405, got %d", rec.Code)
	}
}

func TestHandleEvaluate_BadJSON(t *testing.T) {
	s, _ := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/evaluate", strings.NewReader("not-json"))
	s.handleEvaluate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", rec.Code)
	}
}

func TestHandleEvaluate_BodyTooLarge(t *testing.T) {
	s, _ := setup(t)
	rec := httptest.NewRecorder()
	// 128KB of zeros — exceeds the 64KB cap and should not blow up the
	// process. The decoder will fail with "http: request body too large".
	big := bytes.Repeat([]byte("a"), 128*1024)
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(big))
	s.handleEvaluate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: want 400, got %d", rec.Code)
	}
}

func TestHandleEvaluate_MatchesNamespacedPolicy(t *testing.T) {
	s, f := setup(t)
	// Subject pod selected by the policy; no rules → would-deny ingress.
	f.pods["prod/web-1"] = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "web-1",
			Labels: map[string]string{"app": "web"},
		},
	}
	f.pods["prod/client-1"] = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "client-1",
			Labels: map[string]string{"app": "client"},
		},
	}
	f.policies["prod"] = []*v1alpha1.AuditNetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "web-deny", UID: "uid-1",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}}

	body, _ := json.Marshal(matcher.Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: matcher.ProtocolTCP,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	s.handleEvaluate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decode(t, rec.Body)
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d: %#v", len(resp.Results), resp.Results)
	}
	if resp.Results[0].Verdict != matcher.VerdictWouldDeny {
		t.Errorf("verdict: want WouldDeny, got %s", resp.Results[0].Verdict)
	}
	if resp.Results[0].PolicyUID != "uid-1" {
		t.Errorf("policyUID: want uid-1, got %q", resp.Results[0].PolicyUID)
	}
	if s.denied.Load() != 1 {
		t.Errorf("denied counter: want 1, got %d", s.denied.Load())
	}
}

// Regression test for kguardian-dev/kguardian#880.
//
// When a flow matches no policies, the response was `{"results":null}`
// (Go's nil-slice JSON gotcha), which the broker's
// Vec<VerdictResult> deserialiser rejects. The fix initialises results
// as a non-nil empty slice so the wire becomes `{"results":[]}`. Guard
// that contract here so the regression can't re-land silently.
func TestHandleEvaluate_EmptyResultsEncodesAsJSONArray(t *testing.T) {
	s, _ := setup(t) // empty store: no namespaced policies, no cluster policies

	body, _ := json.Marshal(matcher.Flow{
		SrcPodNamespace: "prod", SrcPodName: "client-1",
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: matcher.ProtocolTCP,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	s.handleEvaluate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}

	// Inspect the raw bytes — `null` and `[]` decode identically into
	// Go's []T but the broker (serde Rust) treats them differently.
	raw := rec.Body.String()
	if strings.Contains(raw, `"results":null`) {
		t.Fatalf("results encoded as JSON null; broker would fail to decode. body=%s", raw)
	}
	if !strings.Contains(raw, `"results":[]`) {
		t.Fatalf("expected `\"results\":[]` in body, got %s", raw)
	}

	// Also assert the field is a JSON array on the wire — defensive
	// against future field-rename or shape regressions.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	resultsRaw, ok := parsed["results"]
	if !ok {
		t.Fatalf("response missing `results` field: %s", raw)
	}
	if string(resultsRaw) != "[]" {
		t.Fatalf("results field: want `[]`, got %s", resultsRaw)
	}
}

func TestHandleEvaluate_ClusterPolicyNamespaceGate(t *testing.T) {
	s, f := setup(t)
	f.pods["prod/web-1"] = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "web-1",
			Labels: map[string]string{"app": "web"},
		},
	}
	f.nsLabels["prod"] = map[string]string{"team": "platform"}

	// Cluster-scoped policy gated to team=platform — should match
	// (return WouldDeny when no ingress rules + Ingress in policyTypes).
	f.clusterPols = []*v1alpha1.AuditClusterNetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-deny", UID: "uid-c1"},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "platform"}},
			PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes:       []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}}

	body, _ := json.Marshal(matcher.Flow{
		DstPodNamespace: "prod", DstPodName: "web-1",
		DstPort: 8080, Protocol: matcher.ProtocolTCP,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	s.handleEvaluate(rec, req)
	resp := decode(t, rec.Body)

	var sawClusterDeny bool
	for _, r := range resp.Results {
		if r.PolicyUID == "uid-c1" && r.Verdict == matcher.VerdictWouldDeny {
			sawClusterDeny = true
		}
	}
	if !sawClusterDeny {
		t.Errorf("expected cluster-scoped WouldDeny verdict in results: %#v", resp.Results)
	}
}

// End of the line for a v6 flow: the /evaluate handler itself. The
// matcher tests cover the decision logic; this covers the two things only
// the handler can break — JSON decoding an IPv6 address into Flow.SrcIP /
// Flow.DstIP (a v6 literal is just a string with colons in it, but a
// future change to the wire format or a "parse the IP here" step would
// land right here), and the namespace routing that picks which policies a
// v6 flow is even evaluated against.
func TestHandleEvaluate_IPv6FlowEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		srcIP  string
		port   int32
		want   matcher.Verdict
		denied int64
	}{
		{name: "peer inside cidr is allowed", srcIP: "fd00::7", port: 8080, want: matcher.VerdictAllow},
		{name: "peer inside except subnet would deny", srcIP: "fd00::bad:1", port: 8080, want: matcher.VerdictWouldDeny, denied: 1},
		{name: "peer outside cidr would deny", srcIP: "fd01::7", port: 8080, want: matcher.VerdictWouldDeny, denied: 1},
		// A dual-stack pod also receives IPv4 traffic; a v6-only rule
		// must not be read as covering it.
		{name: "ipv4 peer against v6 block would deny", srcIP: "10.0.0.7", port: 8080, want: matcher.VerdictWouldDeny, denied: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := setup(t)
			f.pods["prod/web6-1"] = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "prod", Name: "web6-1",
					Labels: map[string]string{"app": "web"},
				},
			}
			f.policies["prod"] = []*v1alpha1.AuditNetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "prod", Name: "web6-allow-ula", UID: "uid-v6",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{
							{IPBlock: &networkingv1.IPBlock{
								CIDR:   "fd00::/64",
								Except: []string{"fd00::bad:0/112"},
							}},
						},
						Ports: []networkingv1.NetworkPolicyPort{tcpPort(tc.port)},
					}},
				},
			}}

			// Marshal/unmarshal is the point: the v6 literals have to
			// survive the wire, not just the matcher.
			body, err := json.Marshal(matcher.Flow{
				DstPodNamespace: "prod", DstPodName: "web6-1",
				SrcIP: tc.srcIP, DstIP: "fd00::1",
				DstPort: tc.port, Protocol: matcher.ProtocolTCP,
			})
			if err != nil {
				t.Fatalf("marshal flow: %v", err)
			}
			rec := httptest.NewRecorder()
			s.handleEvaluate(rec, httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status: want 200, got %d body=%s", rec.Code, rec.Body.String())
			}
			resp := decode(t, rec.Body)
			if len(resp.Results) != 1 {
				t.Fatalf("expected 1 result, got %d: %#v", len(resp.Results), resp.Results)
			}
			got := resp.Results[0]
			if got.Verdict != tc.want {
				t.Errorf("verdict: want %s, got %s (reason %q)", tc.want, got.Verdict, got.Reason)
			}
			if got.Direction != matcher.DirectionIngress {
				t.Errorf("direction: want Ingress, got %s", got.Direction)
			}
			if got.PolicyUID != "uid-v6" {
				t.Errorf("policyUID: want uid-v6, got %q", got.PolicyUID)
			}
			if s.denied.Load() != tc.denied {
				t.Errorf("denied counter: want %d, got %d", tc.denied, s.denied.Load())
			}
		})
	}
}

func tcpPort(p int32) networkingv1.NetworkPolicyPort {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(p)
	return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port}
}
