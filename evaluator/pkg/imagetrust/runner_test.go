package imagetrust

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

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

// applied records the statuses the runner server-side-applied (the fake
// dynamic client does not implement apply, as in appprofile's tests).
type applied struct {
	byKey map[string]v1alpha1.ImageTrustPolicyStatus
	count int
}

func newFake(t *testing.T, objs ...runtime.Object) (*dynfake.FakeDynamicClient, *applied) {
	t.Helper()
	dc := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		PolicyGVR:  "ImageTrustPolicyList",
		ClusterGVR: "ClusterImageTrustPolicyList",
	}, objs...)
	ap := &applied{byKey: map[string]v1alpha1.ImageTrustPolicyStatus{}}
	dc.PrependReactor("patch", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pa := a.(k8stesting.PatchAction)
		if pa.GetPatchType() != types.ApplyPatchType || pa.GetSubresource() != "status" {
			t.Errorf("want server-side apply on status, got %s on %q", pa.GetPatchType(), pa.GetSubresource())
		}
		var u map[string]any
		if err := json.Unmarshal(pa.GetPatch(), &u); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(u["status"])
		var st v1alpha1.ImageTrustPolicyStatus
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		key := pa.GetNamespace() + "/" + pa.GetName()
		ap.byKey[key] = st
		ap.count++
		// Reflect it into the tracker so the next List sees it, as the
		// API server would (the whole status is replaced).
		obj, err := dc.Tracker().Get(a.GetResource(), pa.GetNamespace(), pa.GetName())
		if err != nil {
			return true, nil, err
		}
		uo := obj.(*unstructured.Unstructured).DeepCopy()
		var sm map[string]any
		_ = json.Unmarshal(raw, &sm)
		uo.Object["status"] = sm
		return true, uo, dc.Tracker().Update(a.GetResource(), uo, pa.GetNamespace())
	})
	return dc, ap
}

func in(ns string, c Container) Container {
	c.Namespace = ns
	return c
}

func named(c Container, name string) Container {
	c.WorkloadName = name
	return c
}

type switchFeed struct {
	cs  []Container
	err error
}

func (f *switchFeed) Running(context.Context) ([]Container, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.cs, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T, feed Feed, objs ...runtime.Object) (*Runner, *applied, *clock) {
	t.Helper()
	dc, ap := newFake(t, objs...)
	ck := &clock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	r := &Runner{Dynamic: dc, Feed: feed, Log: logrus.New(), Interval: 5 * time.Minute, now: ck.now,
		Namespaces: func(ns string) map[string]string {
			return map[string]map[string]string{"shop": {"env": "prod"}, "tools": {"env": "dev"}}[ns]
		},
	}
	return r, ap, ck
}

func baseFeed() []Container {
	return []Container{
		in("shop", named(keyless, "a")),
		in("shop", named(keyed, "b")),
		in("shop", named(unsigned, "c")),
		in("shop", named(tampered, "d")),
		in("shop", named(container(nil), "e")),
		in("tools", named(unsigned, "f")),
	}
}

func nsPolicy() *v1alpha1.ImageTrustPolicy {
	return &v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "signed", Namespace: "shop", Generation: 3}, Spec: both()}
}

func TestRunnerStatus(t *testing.T) {
	clSpec := both()
	clSpec.Images = []string{"registry.k8s.io/**"}
	clPol := &v1alpha1.ClusterImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "prod", Generation: 1},
		Spec: v1alpha1.ClusterImageTrustPolicySpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}, ImageTrustPolicySpec: clSpec}}
	bad := &v1alpha1.ImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "broken", Namespace: "shop", Generation: 1},
		Spec: v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{Issuer: "i", SubjectRegExp: "("}}}}}
	feed := &switchFeed{cs: baseFeed()}
	r, ap, ck := setup(t, feed,
		toUnstructured(t, nsPolicy(), "ImageTrustPolicy"),
		toUnstructured(t, clPol, "ClusterImageTrustPolicy"),
		toUnstructured(t, bad, "ImageTrustPolicy"))
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := ap.byKey["shop/signed"]
	ev := st.Evaluation
	if c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead); ev.State != v1alpha1.StateEvaluated ||
		c == nil || c.Status != metav1.ConditionTrue || c.Reason != v1alpha1.ReasonRead {
		t.Fatalf("state %q, condition %+v", ev.State, c)
	}
	if st.ObservedGeneration != 3 || ev.Containers != 5 || ev.Trusted != 2 || ev.WouldDeny != 2 || ev.Unknown != 1 ||
		ev.LastChanged == nil || ev.LastEvaluated == nil || !ev.LastEvaluated.Time.Equal(ck.t) || st.Message != "" {
		t.Fatalf("status = %+v", st)
	}
	if len(ev.Findings) != 3 || ev.Findings[0].Reason != ReasonUnsigned || ev.Findings[1].Reason != ReasonInvalid ||
		ev.Findings[2].Verdict != v1alpha1.ImageUnknown || ev.Findings[0].Workload != "Deployment/c" {
		t.Fatalf("findings = %+v", ev.Findings)
	}
	if cl := ap.byKey["/prod"]; cl.Evaluation.Containers != 5 { // shop is env=prod, tools is not
		t.Fatalf("cluster status = %+v", cl)
	}
	if b := ap.byKey["shop/broken"]; !strings.Contains(b.Error, "subjectRegExp") {
		t.Fatalf("broken status = %+v", b)
	}
	if res, _ := r.Results(); len(res) != 10 {
		t.Fatalf("results = %d", len(res))
	}

	// Same inputs, same clock: nothing written.
	before := ap.count
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ap.count != before {
		t.Fatalf("unchanged pass wrote %d applies", ap.count-before)
	}

	// B1: the unsigned and tampered images get signed. The applied status
	// carries no trace of the old findings (server-side apply removes what
	// is not sent), and lastChanged moves.
	ck.t = ck.t.Add(5 * time.Minute)
	feed.cs = baseFeed()
	feed.cs[2] = in("shop", named(keyless, "c"))
	feed.cs[3] = in("shop", named(keyless, "d"))
	feed.cs[4] = in("shop", named(keyless, "e"))
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := ap.byKey["shop/signed"]
	if got.Evaluation.Trusted != 5 || got.Evaluation.WouldDeny != 0 || len(got.Evaluation.Findings) != 0 || got.Evaluation.Truncated {
		t.Fatalf("after signing = %+v", got)
	}
	if !got.Evaluation.LastChanged.Time.Equal(ck.t) {
		t.Fatalf("lastChanged = %v", got.Evaluation.LastChanged)
	}
	// Only time moves: lastEvaluated is rewritten, lastChanged kept.
	ck.t = ck.t.Add(5 * time.Minute)
	_ = r.Pass(context.Background())
	again := ap.byKey["shop/signed"]
	if !again.Evaluation.LastEvaluated.Time.Equal(ck.t) || !again.Evaluation.LastChanged.Time.Equal(got.Evaluation.LastChanged.Time) {
		t.Fatalf("time-only pass: %+v", again.Evaluation)
	}
}

// B2: a broker outage keeps the last verdicts for 3x the interval, then
// reports every known container Unknown with the error and the last good
// read; a rejected token is Unknown at once; recovery restores verdicts.
func TestRunnerBrokerOutage(t *testing.T) {
	feed := &switchFeed{cs: baseFeed()}
	r, ap, ck := setup(t, feed, toUnstructured(t, nsPolicy(), "ImageTrustPolicy"))
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	good := ck.t
	feed.err = errors.New("dial tcp: connection refused")

	// In the window: an error, and nothing rewritten.
	before := ap.count
	for i := 0; i < 3; i++ {
		ck.t = ck.t.Add(5 * time.Minute)
		if err := r.Pass(context.Background()); err == nil {
			t.Fatal("outage not reported")
		}
	}
	if ap.count != before || ap.byKey["shop/signed"].Evaluation.Trusted != 2 {
		t.Fatalf("in-window pass changed status: %+v", ap.byKey["shop/signed"])
	}

	// Past the window (15m): all five Unknown, broker-unavailable.
	ck.t = ck.t.Add(5 * time.Minute)
	_ = r.Pass(context.Background())
	st := ap.byKey["shop/signed"]
	if c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead); st.Evaluation.State != v1alpha1.StateBrokerUnavailable ||
		c == nil || c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonBrokerUnavailable {
		t.Fatalf("state %q, condition %+v", st.Evaluation.State, c)
	}
	if st.Evaluation.Unknown != 5 || st.Evaluation.Trusted != 0 || st.Evaluation.WouldDeny != 0 ||
		!strings.Contains(st.Message, "connection refused") || !strings.Contains(st.Message, good.Format(time.RFC3339)) ||
		!st.Evaluation.LastEvaluated.Time.Equal(good) || st.Evaluation.Findings[0].Reason != ReasonBrokerUnavailable {
		t.Fatalf("past window = %+v", st)
	}

	// Recovery.
	feed.err = nil
	ck.t = ck.t.Add(5 * time.Minute)
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := ap.byKey["shop/signed"]; st.Evaluation.Trusted != 2 || st.Message != "" || st.Evaluation.State != v1alpha1.StateEvaluated ||
		meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead).Status != metav1.ConditionTrue {
		t.Fatalf("recovered = %+v", st)
	}

	// 401/403: Unknown immediately, even right after a good read.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		feed.err = &FeedError{StatusCode: code, Message: "no"}
		ck.t = ck.t.Add(time.Minute)
		_ = r.Pass(context.Background())
		st := ap.byKey["shop/signed"]
		if c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead); st.Evaluation.State != v1alpha1.StateBrokerUnauthorized ||
			c == nil || c.Reason != v1alpha1.ReasonBrokerUnauthorized {
			t.Fatalf("%d: state %q, condition %+v", code, st.Evaluation.State, c)
		}
		if st.Evaluation.Unknown != 5 || st.Evaluation.Findings[0].Reason != ReasonBrokerUnauthorized || !strings.Contains(st.Message, "READ-scope token") {
			t.Fatalf("%d = %+v", code, st)
		}
		feed.err = nil
		_ = r.Pass(context.Background())
	}
}

// Never read successfully and the broker is down: no containers to judge,
// but the status says why.
func TestRunnerNeverRead(t *testing.T) {
	feed := &switchFeed{err: errors.New("no route to host")}
	r, ap, _ := setup(t, feed, toUnstructured(t, nsPolicy(), "ImageTrustPolicy"))
	_ = r.Pass(context.Background())
	st := ap.byKey["shop/signed"]
	if st.Evaluation.Containers != 0 || st.Evaluation.LastEvaluated != nil || !strings.Contains(st.Message, "last successful read: never") {
		t.Fatalf("status = %+v", st)
	}
	// The zero counts must not read as "nothing to deny": the state and
	// the condition say the broker was never read.
	if st.Evaluation.State != v1alpha1.StateNeverRead {
		t.Fatalf("state = %q", st.Evaluation.State)
	}
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionBrokerRead)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonNeverRead || !strings.Contains(c.Message, "never") {
		t.Fatalf("condition = %+v", c)
	}
}

// L7: a cluster policy with a namespace selector counts containers of a
// namespace the cache does not know as Unknown, never skips them.
func TestRunnerUnknownNamespace(t *testing.T) {
	cl := &v1alpha1.ClusterImageTrustPolicy{ObjectMeta: metav1.ObjectMeta{Name: "prod"},
		Spec: v1alpha1.ClusterImageTrustPolicySpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}, ImageTrustPolicySpec: both()}}
	feed := &switchFeed{cs: []Container{in("shop", named(keyless, "a")), in("ghost", named(keyless, "b")), in("tools", named(keyless, "c"))}}
	r, ap, _ := setup(t, feed, toUnstructured(t, cl, "ClusterImageTrustPolicy"))
	if err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := ap.byKey["/prod"]
	if st.Evaluation.Containers != 2 || st.Evaluation.Trusted != 1 || st.Evaluation.Unknown != 1 ||
		st.Evaluation.Findings[0].Namespace != "ghost" || st.Evaluation.Findings[0].Reason != ReasonNamespaceUnknown {
		t.Fatalf("status = %+v", st)
	}
}

// Helm installs crds/ only on first install: an upgraded cluster may not
// have the CRDs. That is "no policies", not an error.
func TestRunnerToleratesMissingCRDs(t *testing.T) {
	dc, _ := newFake(t)
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
	// A page over the limit is refused, never decoded truncated.
	if _, err := (&BrokerFeed{BaseURL: srv.URL, MaxPageBytes: 100}).Running(context.Background()); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("oversized page: %v", err)
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "token rejected", http.StatusForbidden)
	}))
	defer deny.Close()
	_, err = (&BrokerFeed{BaseURL: deny.URL}).Running(context.Background())
	if !IsAuthError(err) {
		t.Fatalf("403 not an auth error: %v", err)
	}
}
