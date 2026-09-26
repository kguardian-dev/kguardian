package imagetrust

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestStatusAgainstARealAPIServer runs the runner against a real
// kube-apiserver with the chart's CRDs (envtest; CI's test-evaluator job
// installs the binaries with setup-envtest). It proves what the fake
// client cannot: server-side apply removes status fields that no longer
// hold, the CRD schema keeps every field the runner writes, and the
// printer columns `kubectl get` shows are blank, never 0, whenever there
// is no current evaluation.
func TestStatusAgainstARealAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS (setup-envtest) to run against a real API server")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "charts", "kguardian", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx := context.Background()
	dc := dynamic.NewForConfigOrDie(cfg)
	ns := dc.Resource(PolicyGVR).Namespace("default")
	create := func(p *v1alpha1.ImageTrustPolicy) {
		t.Helper()
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: m}
		u.SetAPIVersion(v1alpha1.SchemeGroupVersion.String())
		u.SetKind("ImageTrustPolicy")
		delete(u.Object, "status")
		if _, err := ns.Create(ctx, u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	status := func(name string) v1alpha1.ImageTrustPolicyStatus {
		t.Helper()
		u, err := ns.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var p v1alpha1.ImageTrustPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
			t.Fatal(err)
		}
		return p.Status
	}
	// cells returns the printer-column cells of one policy, as kubectl get
	// renders them (a Table from the API server).
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cells := func(name string) map[string]any {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(cfg.Host, "/")+"/apis/kguardian.dev/v1alpha1/namespaces/default/imagetrustpolicies/"+name, nil)
		req.Header.Set("Accept", "application/json;as=Table;g=meta.k8s.io;v=v1")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var tbl metav1.Table
		if err := json.Unmarshal(body, &tbl); err != nil || len(tbl.Rows) != 1 {
			t.Fatalf("table: %v %s", err, body)
		}
		out := map[string]any{}
		for i, c := range tbl.ColumnDefinitions {
			out[c.Name] = tbl.Rows[0].Cells[i]
		}
		return out
	}
	blankCounts := func(when string) {
		t.Helper()
		c := cells("p")
		for _, col := range []string{"Containers", "Would-Deny", "Unknown"} {
			if v := c[col]; v != nil && v != "" {
				t.Fatalf("%s: %s cell = %v, want blank", when, col, v)
			}
		}
	}
	shownCounts := func(when string, wouldDeny float64) {
		t.Helper()
		c := cells("p")
		if c["Containers"] != float64(1) || c["Would-Deny"] != wouldDeny || c["Unknown"] != float64(0) {
			t.Fatalf("%s: cells = %v", when, c)
		}
	}

	create(&v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}, Spec: both()})
	create(&v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "broken", Namespace: "default"},
		Spec: v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{Issuer: "i", SubjectRegExp: "("}}}}})

	// A previous pass of this evaluator left every optional field set:
	// counts, findings, truncated, an error and a message.
	nine := int64(9)
	seed := v1alpha1.ImageTrustPolicyStatus{ObservedGeneration: 1, Error: "old error", Message: "old message",
		Evaluation: v1alpha1.ImageTrustEvaluation{State: v1alpha1.StateEvaluated, Containers: &nine, Trusted: &nine, WouldDeny: &nine, Unknown: &nine,
			Truncated: true, Findings: []v1alpha1.ImageTrustFinding{{Namespace: "default", Workload: "Deployment/old", Container: "c", Digest: "sha256:old", Verdict: "WouldDeny", Reason: "unsigned"}}}}
	u, err := statusApplyObject(policyRef{gvr: PolicyGVR, namespace: "default", name: "p"}, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ns.ApplyStatus(ctx, "p", u, metav1.ApplyOptions{FieldManager: FieldManager, Force: true}); err != nil {
		t.Fatal(err)
	}
	if s := status("p"); !s.Evaluation.Truncated || s.Error == "" || len(s.Evaluation.Findings) != 1 {
		t.Fatalf("seed not stored: %+v", s)
	}

	ck := &clock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	feed := &switchFeed{err: &FeedError{StatusCode: 503, Message: "starting"}}
	r := &Runner{Dynamic: dc, Feed: feed, Log: logrus.New(), Interval: 5 * time.Minute, now: ck.now,
		Namespaces: func(string) map[string]string { return map[string]string{} }}

	// Never read: said so, and every stale field from the seed is gone;
	// the count cells are blank.
	_ = r.Pass(ctx)
	st := status("p")
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead)
	if st.Evaluation.State != v1alpha1.StateNeverRead || c == nil || c.Reason != v1alpha1.ReasonNeverRead || st.Message == "" ||
		st.Error != "" || st.Evaluation.Truncated || len(st.Evaluation.Findings) != 0 || noCounts(st) != "" {
		t.Fatalf("never-read status = %+v", st)
	}
	blankCounts("never-read")

	// First read: an unsigned image is a finding; the broken spec errors;
	// the counts appear.
	feed.err = nil
	feed.cs = []Container{in("default", named(unsigned, "app"))}
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	st = status("p")
	if st.Evaluation.State != v1alpha1.StateEvaluated || Count(st.Evaluation.WouldDeny) != 1 || len(st.Evaluation.Findings) != 1 ||
		st.Message != "" || st.Evaluation.LastEvaluated == nil || !st.Evaluation.LastEvaluated.Time.Equal(ck.t) {
		t.Fatalf("first read status = %+v", st)
	}
	shownCounts("first read", 1)
	if b := status("broken"); !strings.Contains(b.Error, "subjectRegExp") {
		t.Fatalf("broken status = %+v", b)
	}

	// The image gets signed and the spec is fixed: no findings and no
	// error left behind.
	feed.cs = []Container{in("default", named(keyless, "app"))}
	bu, err := ns.Get(ctx, "broken", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixed := both()
	sm, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&fixed)
	bu.Object["spec"] = sm
	if _, err := ns.Update(ctx, bu, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	st = status("p")
	if Count(st.Evaluation.Trusted) != 1 || Count(st.Evaluation.WouldDeny) != 0 || len(st.Evaluation.Findings) != 0 || st.Evaluation.Truncated {
		t.Fatalf("after signing, stale findings kept: %+v", st)
	}
	shownCounts("after signing", 0)
	b := status("broken")
	if b.Error != "" || b.ObservedGeneration != 2 || Count(b.Evaluation.Trusted) != 1 {
		t.Fatalf("after fixing, stale error kept: %+v", b)
	}

	// Broker unavailable: inside the window the last counts stand;
	// past it (15m) they are blank.
	feed.err = &FeedError{StatusCode: 503, Message: "down"}
	ck.t = ck.t.Add(10 * time.Minute)
	_ = r.Pass(ctx)
	shownCounts("inside the window", 0)
	ck.t = ck.t.Add(10 * time.Minute)
	_ = r.Pass(ctx)
	if s := status("p"); s.Evaluation.State != v1alpha1.StateBrokerUnavailable {
		t.Fatalf("past window state = %q", s.Evaluation.State)
	}
	blankCounts("past the window")

	// Recovery brings them back; a rejected token blanks them at once.
	feed.err = nil
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	shownCounts("recovered", 0)
	feed.err = &FeedError{StatusCode: http.StatusForbidden, Message: "no"}
	ck.t = ck.t.Add(time.Minute)
	_ = r.Pass(ctx)
	if s := status("p"); s.Evaluation.State != v1alpha1.StateBrokerUnauthorized {
		t.Fatalf("unauthorized state = %q", s.Evaluation.State)
	}
	blankCounts("unauthorized")
}
