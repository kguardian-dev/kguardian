package imagetrust

import (
	"context"
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
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestStatusAgainstARealAPIServer runs the runner against a real
// kube-apiserver with the chart's CRDs (envtest; CI's test-evaluator job
// installs the binaries with setup-envtest). It proves what the fake
// client cannot: server-side apply removes status fields that no longer
// hold, the CRD schema keeps every field the runner writes (nothing is
// pruned), and a never-read broker is visible as such.
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
	create(&v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}, Spec: both()})
	create(&v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "broken", Namespace: "default"},
		Spec: v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{Issuer: "i", SubjectRegExp: "("}}}}})

	ck := &clock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	feed := &switchFeed{err: &FeedError{StatusCode: 503, Message: "starting"}}
	r := &Runner{Dynamic: dc, Feed: feed, Log: logrus.New(), Interval: 5 * time.Minute, now: ck.now,
		Namespaces: func(string) map[string]string { return map[string]string{} }}

	// Never read: the stored status says so.
	_ = r.Pass(ctx)
	st := status("p")
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead)
	if st.Evaluation.State != v1alpha1.StateNeverRead || c == nil || c.Reason != v1alpha1.ReasonNeverRead || st.Message == "" {
		t.Fatalf("never-read status = %+v", st)
	}

	// First read: an unsigned image is a finding; the broken spec errors.
	feed.err = nil
	feed.cs = []Container{in("default", named(unsigned, "app"))}
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	st = status("p")
	if st.Evaluation.State != v1alpha1.StateEvaluated || st.Evaluation.WouldDeny != 1 || len(st.Evaluation.Findings) != 1 ||
		st.Message != "" || st.Evaluation.LastEvaluated == nil || !st.Evaluation.LastEvaluated.Time.Equal(ck.t) {
		t.Fatalf("first read status = %+v", st)
	}
	if b := status("broken"); !strings.Contains(b.Error, "subjectRegExp") {
		t.Fatalf("broken status = %+v", b)
	}

	// The image gets signed and the spec is fixed: the stored status has
	// no findings and no error left behind.
	feed.cs = []Container{in("default", named(keyless, "app"))}
	u, err := ns.Get(ctx, "broken", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixed := both()
	sm, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&fixed)
	u.Object["spec"] = sm
	if _, err := ns.Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	st = status("p")
	if st.Evaluation.Trusted != 1 || st.Evaluation.WouldDeny != 0 || len(st.Evaluation.Findings) != 0 || st.Evaluation.Truncated {
		t.Fatalf("after signing, stale findings kept: %+v", st)
	}
	b := status("broken")
	if b.Error != "" || b.ObservedGeneration != 2 || b.Evaluation.Trusted != 1 {
		t.Fatalf("after fixing, stale error kept: %+v", b)
	}
}
