package imagetrust

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

type staticFeed []Container

func (f staticFeed) Running(context.Context) ([]Container, error) { return f, nil }

func toUnstructured(t *testing.T, obj runtime.Object, kind string) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(v1alpha1.GroupName + "/" + v1alpha1.Version)
	u.SetKind(kind)
	return u
}

func newFake(t *testing.T, objs ...runtime.Object) *dynfake.FakeDynamicClient {
	t.Helper()
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		PolicyGVR:  "ImageTrustPolicyList",
		ClusterGVR: "ClusterImageTrustPolicyList",
	}, objs...)
}

func in(ns string, c Container) Container {
	c.Namespace = ns
	return c
}

func named(c Container, name string) Container {
	c.WorkloadName = name
	return c
}

func getStatus(t *testing.T, dc *dynfake.FakeDynamicClient, gvr schema.GroupVersionResource, ns, name string) v1alpha1.ImageTrustPolicyStatus {
	t.Helper()
	var ri = dc.Resource(gvr)
	var u *unstructured.Unstructured
	var err error
	if ns != "" {
		u, err = ri.Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	} else {
		u, err = ri.Get(context.Background(), name, metav1.GetOptions{})
	}
	if err != nil {
		t.Fatal(err)
	}
	var p v1alpha1.ImageTrustPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
		t.Fatal(err)
	}
	return p.Status
}

func patches(dc *dynfake.FakeDynamicClient) int {
	n := 0
	for _, a := range dc.Actions() {
		if a.GetVerb() == "patch" {
			n++
		}
	}
	return n
}

func TestRunnerWritesStatusOnlyOnChange(t *testing.T) {
	nsPol := &v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "signed", Namespace: "shop", Generation: 3}, Spec: both()}
	clSpec := both()
	clSpec.Images = []string{"registry.k8s.io/**"}
	clPol := &v1alpha1.ClusterImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "prod", Generation: 1},
		Spec: v1alpha1.ClusterImageTrustPolicySpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}, ImageTrustPolicySpec: clSpec}}
	bad := &v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "broken", Namespace: "shop", Generation: 1},
		Spec: v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{Issuer: "i", SubjectRegExp: "("}}}}}
	dc := newFake(t,
		toUnstructured(t, nsPol, "ImageTrustPolicy"),
		toUnstructured(t, clPol, "ClusterImageTrustPolicy"),
		toUnstructured(t, bad, "ImageTrustPolicy"))

	feed := staticFeed{
		in("shop", named(keyless, "a")),
		in("shop", named(keyed, "b")),
		in("shop", named(unsigned, "c")),
		in("shop", named(tampered, "d")),
		in("shop", named(container(nil), "e")),
		in("tools", named(unsigned, "f")), // other namespace: only the cluster policy, if it selects tools
	}
	r := &Runner{Dynamic: dc, Feed: feed, Log: logrus.New(),
		Namespaces: func(ns string) map[string]string {
			return map[string]map[string]string{"shop": {"env": "prod"}, "tools": {"env": "dev"}}[ns]
		},
		now: func() time.Time { return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC) },
	}
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := getStatus(t, dc, PolicyGVR, "shop", "signed")
	ev := st.Evaluation
	if st.ObservedGeneration != 3 || ev.Containers != 5 || ev.Trusted != 2 || ev.WouldDeny != 2 || ev.Unknown != 1 || ev.LastChanged == nil {
		t.Fatalf("status = %+v", st)
	}
	if len(ev.Findings) != 3 || ev.Findings[0].Reason != ReasonUnsigned || ev.Findings[1].Reason != ReasonInvalid ||
		ev.Findings[2].Verdict != v1alpha1.ImageUnknown || ev.Findings[0].Workload != "Deployment/c" {
		t.Fatalf("findings = %+v", ev.Findings)
	}
	cl := getStatus(t, dc, ClusterGVR, "", "prod")
	if cl.Evaluation.Containers != 5 { // shop is env=prod, tools is not
		t.Fatalf("cluster status = %+v", cl)
	}
	if b := getStatus(t, dc, PolicyGVR, "shop", "broken"); !strings.Contains(b.Error, "subjectRegExp") {
		t.Fatalf("broken status = %+v", b)
	}
	res, _ := r.Results()
	if len(res) != 10 {
		t.Fatalf("results = %d", len(res))
	}

	// Same inputs: nothing written.
	before := patches(dc)
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if patches(dc) != before {
		t.Fatalf("unchanged pass wrote %d patches", patches(dc)-before)
	}
	// A change is written.
	r.Feed = append(feed[:0:0], feed...)
	r.Feed.(staticFeed)[2] = in("shop", named(keyless, "c"))
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getStatus(t, dc, PolicyGVR, "shop", "signed").Evaluation; got.Trusted != 3 || got.WouldDeny != 1 {
		t.Fatalf("after change = %+v", got)
	}
}

// Helm installs crds/ only on first install: an upgraded cluster may not
// have the CRDs. That is "no policies", not an error.
func TestRunnerToleratesMissingCRDs(t *testing.T) {
	dc := newFake(t)
	dc.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: v1alpha1.GroupName, Resource: "imagetrustpolicies"}, "")
	})
	called := false
	r := &Runner{Dynamic: dc, Feed: feedFunc(func() { called = true }), Log: logrus.New(), Namespaces: func(string) map[string]string { return nil }}
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("feed read with no policies")
	}
}

type feedFunc func()

func (f feedFunc) Running(context.Context) ([]Container, error) { f(); return nil, nil }

func TestBrokerFeedPagesAndAuth(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Path != "/attestations/running" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("after") {
		case "":
			_, _ = io.WriteString(w, `{"items":[{"namespace":"shop","workloadKind":"Deployment","workloadName":"api","container":"app","digest":"sha256:1","imageRef":"x","repository":"r","verdict":"verified","signers":[{"signerKind":"key","keyFingerprint":"ab","verified":true}],"attestations":[]}],"nextAfter":"c1"}`)
		case "c1":
			_, _ = io.WriteString(w, `{"items":[{"namespace":"shop","workloadKind":"Deployment","workloadName":"api","container":"side","digest":"sha256:2","imageRef":"y","repository":null,"verdict":null,"signers":[],"attestations":[]}],"nextAfter":null}`)
		}
	}))
	defer srv.Close()
	got, err := (&BrokerFeed{BaseURL: srv.URL + "/", Token: "tok"}).Running(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Signers[0].KeyFingerprint != "ab" || got[1].Verdict != nil || got[1].Repository != nil {
		b, _ := json.Marshal(got)
		t.Fatalf("got %s", b)
	}
	if auth[0] != "Bearer tok" {
		t.Fatalf("auth = %v", auth)
	}
	if _, err := (&BrokerFeed{BaseURL: srv.URL + "/nope"}).Running(context.Background()); err == nil {
		t.Fatal("404 accepted")
	}
}
