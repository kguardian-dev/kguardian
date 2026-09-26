package imagetrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/appprofile"
	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// GVRs of the two CRDs.
var (
	PolicyGVR  = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "imagetrustpolicies"}
	ClusterGVR = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "clusterimagetrustpolicies"}
)

// MaxFindings bounds status.evaluation.findings.
const MaxFindings = 20

// Feed lists every running container with its image's signature result.
type Feed interface {
	Running(ctx context.Context) ([]Container, error)
}

// NamespaceLabels returns a namespace's labels; nil = unknown namespace.
type NamespaceLabels func(name string) map[string]string

// Runner evaluates every policy each Interval.
type Runner struct {
	Dynamic    dynamic.Interface
	Feed       Feed
	Namespaces NamespaceLabels
	Log        *logrus.Logger
	Interval   time.Duration
	now        func() time.Time

	mu       sync.Mutex
	absent   map[schema.GroupVersionResource]bool // CRD not installed (logged once)
	last     []Result
	lastPass time.Time
	// The last successful broker read, reused (all Unknown) once the
	// broker has been unreadable for longer than the staleness window.
	lastGood   []Container
	lastGoodAt time.Time
}

// FieldManager owns .status of the image trust policies (server-side
// apply: fields this manager no longer sends are removed).
const FieldManager = "kguardian-evaluator-imagetrust"

func (r *Runner) interval() time.Duration {
	if r.Interval <= 0 {
		return 5 * time.Minute
	}
	return r.Interval
}

// Result is one (policy, container) evaluation, for GET /image-trust.
type Result struct {
	Policy    string `json:"policy"` // "namespace/name" or "cluster/name"
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
	Digest    string `json:"digest"`
	Image     string `json:"image"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason,omitempty"`
}

// Results returns the last pass's results and when it ran.
func (r *Runner) Results() ([]Result, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Result(nil), r.last...), r.lastPass
}

// Run passes until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	iv := r.interval()
	for {
		if err := r.Pass(ctx); err != nil && ctx.Err() == nil {
			r.Log.WithError(err).Warn("image trust: pass failed; retrying next interval")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}

type policyRef struct {
	gvr       schema.GroupVersionResource
	namespace string // "" for cluster policies
	name      string
	gen       int64
	status    v1alpha1.ImageTrustPolicyStatus // as stored
	spec      v1alpha1.ImageTrustPolicySpec
	decodeErr string
	nsSel     *metav1.LabelSelector
}

func (p policyRef) key() string {
	if p.namespace == "" {
		return "cluster/" + p.name
	}
	return p.namespace + "/" + p.name
}

// feedState is what a pass evaluates against.
type feedState struct {
	containers []Container
	at         time.Time // last successful read; zero = never
	// unknownReason/message are set when the broker could not be read:
	// every selected container is Unknown for that reason.
	unknownReason, message string
}

// Pass evaluates every policy once.
//
// A failed broker read keeps the last statuses for up to the staleness
// window (3x the interval, as for ApplicationSecurityProfile); past it,
// or at once when the broker rejects the token, every container known
// from the last good read is reported Unknown with the error and the time
// of that read, never as its last verdict.
func (r *Runner) Pass(ctx context.Context) error {
	pols, err := r.policies(ctx)
	if err != nil {
		return err
	}
	if len(pols) == 0 {
		r.store(nil)
		return nil
	}
	now := r.clock()
	fs := feedState{}
	containers, ferr := r.Feed.Running(ctx)
	r.mu.Lock()
	if ferr == nil {
		r.lastGood, r.lastGoodAt = containers, now
	}
	fs.containers, fs.at = r.lastGood, r.lastGoodAt
	r.mu.Unlock()
	if ferr != nil {
		auth := IsAuthError(ferr)
		window := appprofile.StaleAfter(0, r.interval())
		if !auth && !fs.at.IsZero() && now.Sub(fs.at) <= window {
			return fmt.Errorf("reading running images from the broker (keeping the last results for up to %s): %w", window, ferr)
		}
		when := "never"
		if !fs.at.IsZero() {
			when = fs.at.UTC().Format(time.RFC3339)
		}
		fs.unknownReason = ReasonBrokerUnavailable
		fs.message = fmt.Sprintf("cannot read running images from the broker (%v); last successful read: %s; unknown because nothing was read within %s", ferr, when, window)
		if auth {
			fs.unknownReason = ReasonBrokerUnauthorized
			fs.message = fmt.Sprintf("the broker rejected the evaluator's token (%v); it needs the READ-scope token; last successful read: %s", ferr, when)
		}
		r.Log.WithError(ferr).Warn("image trust: broker unreadable; reporting containers as unknown")
	}
	var all []Result
	for _, p := range pols {
		st, res := r.evaluate(p, fs)
		all = append(all, res...)
		if err := r.writeStatus(ctx, p, st); err != nil {
			r.Log.WithError(err).WithField("policy", p.key()).Warn("image trust: status update failed")
		}
	}
	r.store(all)
	if ferr != nil {
		return fmt.Errorf("reading running images from the broker: %w", ferr)
	}
	return nil
}

func (r *Runner) store(res []Result) {
	r.mu.Lock()
	r.last, r.lastPass = res, r.clock()
	r.mu.Unlock()
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// policies lists both kinds. A CRD that is not installed (Helm installs
// crds/ only on first install) is "no policies", logged once.
func (r *Runner) policies(ctx context.Context) ([]policyRef, error) {
	var out []policyRef
	for _, gvr := range []schema.GroupVersionResource{PolicyGVR, ClusterGVR} {
		list, err := r.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
		if apierrors.IsNotFound(err) {
			r.mu.Lock()
			if r.absent == nil {
				r.absent = map[schema.GroupVersionResource]bool{}
			}
			if !r.absent[gvr] {
				r.Log.WithField("resource", gvr.Resource).Info("image trust: CRD not installed; apply charts/kguardian/crds to use it")
			}
			r.absent[gvr] = true
			r.mu.Unlock()
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", gvr.Resource, err)
		}
		r.mu.Lock()
		delete(r.absent, gvr)
		r.mu.Unlock()
		for i := range list.Items {
			u := &list.Items[i]
			ref := policyRef{gvr: gvr, namespace: u.GetNamespace(), name: u.GetName(), gen: u.GetGeneration()}
			if gvr == PolicyGVR {
				var p v1alpha1.ImageTrustPolicy
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
					ref.decodeErr = "spec does not decode: " + err.Error()
				}
				ref.spec, ref.status = p.Spec, p.Status
			} else {
				var p v1alpha1.ClusterImageTrustPolicy
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
					ref.decodeErr = "spec does not decode: " + err.Error()
				}
				ref.spec, ref.nsSel, ref.status = p.Spec.ImageTrustPolicySpec, p.Spec.NamespaceSelector, p.Status
				ref.namespace = ""
			}
			out = append(out, ref)
		}
	}
	return out, nil
}

// selectsNamespace reports whether p applies to namespace ns, and whether
// that cannot be told (a cluster policy with a selector, and a namespace
// the cache does not know): such containers count as Unknown, never
// silently skipped.
func (r *Runner) selectsNamespace(p policyRef, ns string) (selected, unknown bool) {
	if p.gvr == PolicyGVR {
		return p.namespace == ns, false
	}
	if p.nsSel == nil {
		return true, false
	}
	sel, err := metav1.LabelSelectorAsSelector(p.nsSel)
	if err != nil {
		return false, false
	}
	if sel.Empty() {
		return true, false
	}
	lbls := r.Namespaces(ns)
	if lbls == nil {
		return true, true
	}
	return sel.Matches(labels.Set(lbls)), false
}

// evaluate returns the new status for p and its per-container results.
func (r *Runner) evaluate(p policyRef, fs feedState) (v1alpha1.ImageTrustPolicyStatus, []Result) {
	cs := fs.containers
	st := v1alpha1.ImageTrustPolicyStatus{ObservedGeneration: p.gen, Message: fs.message}
	st.Conditions = append([]metav1.Condition(nil), p.status.Conditions...)
	cond := metav1.Condition{Type: v1alpha1.ConditionBrokerRead, ObservedGeneration: p.gen,
		Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonRead, Message: "running containers read from the broker"}
	st.Evaluation.State = v1alpha1.StateEvaluated
	switch {
	case fs.unknownReason != "" && fs.at.IsZero():
		st.Evaluation.State = v1alpha1.StateNeverRead
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, v1alpha1.ReasonNeverRead, fs.message
	case fs.unknownReason == ReasonBrokerUnauthorized:
		st.Evaluation.State = v1alpha1.StateBrokerUnauthorized
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, v1alpha1.ReasonBrokerUnauthorized, fs.message
	case fs.unknownReason != "":
		st.Evaluation.State = v1alpha1.StateBrokerUnavailable
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, v1alpha1.ReasonBrokerUnavailable, fs.message
	}
	cond.LastTransitionTime = metav1.NewTime(r.clock().UTC().Truncate(time.Second))
	meta.SetStatusCondition(&st.Conditions, cond)
	if !fs.at.IsZero() {
		t := metav1.NewTime(fs.at.UTC().Truncate(time.Second))
		st.Evaluation.LastEvaluated = &t
	}
	if p.decodeErr != "" {
		st.Error = p.decodeErr
		return st, nil
	}
	if p.nsSel != nil {
		if _, err := metav1.LabelSelectorAsSelector(p.nsSel); err != nil {
			st.Error = "namespaceSelector: " + err.Error()
			return st, nil
		}
	}
	pol, err := Compile(p.spec)
	if err != nil {
		st.Error = err.Error()
		return st, nil
	}
	var res []Result
	ev := &st.Evaluation
	for _, c := range cs {
		selected, nsUnknown := r.selectsNamespace(p, c.Namespace)
		if !selected || !pol.Selects(c) {
			continue
		}
		verdict, reason := pol.Evaluate(c)
		switch {
		case fs.unknownReason != "":
			verdict, reason = v1alpha1.ImageUnknown, fs.unknownReason
		case nsUnknown:
			verdict, reason = v1alpha1.ImageUnknown, ReasonNamespaceUnknown
		}
		ev.Containers++
		switch verdict {
		case v1alpha1.ImageTrusted:
			ev.Trusted++
		case v1alpha1.ImageWouldDeny:
			ev.WouldDeny++
		default:
			ev.Unknown++
		}
		workload := c.WorkloadKind + "/" + c.WorkloadName
		res = append(res, Result{Policy: p.key(), Namespace: c.Namespace, Workload: workload, Container: c.Container,
			Digest: c.Digest, Image: c.repository(), Verdict: verdict, Reason: reason})
		if verdict != v1alpha1.ImageTrusted {
			ev.Findings = append(ev.Findings, v1alpha1.ImageTrustFinding{Namespace: c.Namespace, Workload: workload,
				Container: c.Container, Repository: c.repository(), Digest: c.Digest, Verdict: verdict, Reason: reason})
		}
	}
	// Would-deny before unknown, then stable by location, so the bounded
	// list is deterministic across passes and replicas.
	sort.SliceStable(ev.Findings, func(i, j int) bool {
		a, b := ev.Findings[i], ev.Findings[j]
		if a.Verdict != b.Verdict {
			return a.Verdict == v1alpha1.ImageWouldDeny
		}
		return strings.Join([]string{a.Namespace, a.Workload, a.Container, a.Digest}, "\x00") <
			strings.Join([]string{b.Namespace, b.Workload, b.Container, b.Digest}, "\x00")
	})
	if len(ev.Findings) > MaxFindings {
		ev.Findings, ev.Truncated = ev.Findings[:MaxFindings], true
	}
	return st, res
}

// writeStatus applies the status when anything in it changed. The
// verdicts rarely change, but lastEvaluated moves on every successful
// read, so a healthy policy is written once per interval (lastChanged
// keeps the time the verdicts last changed).
func (r *Runner) writeStatus(ctx context.Context, p policyRef, st v1alpha1.ImageTrustPolicyStatus) error {
	// lastChanged moves only when the verdicts change.
	old := p.status
	oldEval, newEval := old.Evaluation, st.Evaluation
	oldEval.LastChanged, newEval.LastChanged = nil, nil
	oldEval.LastEvaluated, newEval.LastEvaluated = nil, nil
	same := old.ObservedGeneration == st.ObservedGeneration && old.Error == st.Error &&
		old.Message == st.Message && reflect.DeepEqual(oldEval, newEval) &&
		sameConditions(old.Conditions, st.Conditions)
	if same && sameTime(old.Evaluation.LastEvaluated, st.Evaluation.LastEvaluated) {
		return nil
	}
	if same && old.Evaluation.LastChanged != nil {
		st.Evaluation.LastChanged = old.Evaluation.LastChanged
	} else {
		t := metav1.NewTime(r.clock().UTC().Truncate(time.Second))
		st.Evaluation.LastChanged = &t
	}
	u, err := statusApplyObject(p, st)
	if err != nil {
		return err
	}
	res := r.Dynamic.Resource(p.gvr)
	var ri dynamic.ResourceInterface = res
	if p.namespace != "" {
		ri = res.Namespace(p.namespace)
	}
	// Server-side apply of the whole status: a field this manager no
	// longer sends (an old error, findings that went away) is removed,
	// which a merge patch of omitempty fields would leave behind.
	_, err = ri.ApplyStatus(ctx, p.name, u, metav1.ApplyOptions{FieldManager: FieldManager, Force: true})
	if apierrors.IsNotFound(err) {
		return nil // deleted meanwhile
	}
	if err == nil && st.Evaluation.WouldDeny > 0 && !same {
		r.Log.WithFields(logrus.Fields{"policy": p.key(), "wouldDeny": st.Evaluation.WouldDeny, "unknown": st.Evaluation.Unknown}).
			Info("image trust: containers would be denied")
	}
	return err
}

// sameConditions ignores transition times (kept by SetStatusCondition).
func sameConditions(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}

// sameTime compares instants: a stored metav1.Time decodes in local time.
func sameTime(a, b *metav1.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Time.Equal(b.Time)
}

func statusApplyObject(p policyRef, st v1alpha1.ImageTrustPolicyStatus) (*unstructured.Unstructured, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	kind := "ImageTrustPolicy"
	meta := map[string]any{"name": p.name}
	if p.gvr == ClusterGVR {
		kind = "ClusterImageTrustPolicy"
	} else {
		meta["namespace"] = p.namespace
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.SchemeGroupVersion.String(),
		"kind":       kind,
		"metadata":   meta,
		"status":     m,
	}}, nil
}

// --- Broker feed ---

// BrokerFeed pages GET /attestations/running with a read token.
type BrokerFeed struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// MaxPages bounds one pass (default 500 pages of 200: 100 000
	// containers). Pages are small because the broker charges each row
	// at its worst case against its read budget.
	MaxPages int
	// MaxPageBytes bounds one page (default maxFeedPageBytes).
	MaxPageBytes int
}

// maxFeedPageBytes bounds one page: 200 rows at the broker's worst-case
// row (one stored result, 512 KiB) is 100 MiB; more is refused, never
// decoded truncated.
const maxFeedPageBytes = 200 * 512 << 10

// FeedError is a non-200 broker answer.
type FeedError struct {
	StatusCode int
	Message    string
}

func (e *FeedError) Error() string {
	return fmt.Sprintf("GET /attestations/running: %d %s", e.StatusCode, e.Message)
}

// IsAuthError: the broker rejected the token (401/403). Not transient.
func IsAuthError(err error) bool {
	var fe *FeedError
	return errors.As(err, &fe) && (fe.StatusCode == http.StatusUnauthorized || fe.StatusCode == http.StatusForbidden)
}

// ErrTruncated: more running containers than MaxPages covers.
var ErrTruncated = errors.New("running container list truncated")

type runningPage struct {
	Items     []Container `json:"items"`
	NextAfter *string     `json:"nextAfter"`
}

// Running implements Feed.
func (b *BrokerFeed) Running(ctx context.Context) ([]Container, error) {
	max := b.MaxPages
	if max <= 0 {
		max = 500
	}
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	var out []Container
	after := ""
	for page := 0; page < max; page++ {
		q := url.Values{"limit": {"200"}}
		if after != "" {
			q.Set("after", after)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(b.BaseURL, "/")+"/attestations/running?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if b.Token != "" {
			req.Header.Set("Authorization", "Bearer "+b.Token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		limit := b.MaxPageBytes
		if limit <= 0 {
			limit = maxFeedPageBytes
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			msg := string(body)
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return nil, &FeedError{StatusCode: resp.StatusCode, Message: msg}
		}
		if len(body) > limit {
			return nil, fmt.Errorf("GET /attestations/running: page larger than %d bytes; refusing a truncated read", limit)
		}
		var p runningPage
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("GET /attestations/running: %w", err)
		}
		out = append(out, p.Items...)
		if p.NextAfter == nil || *p.NextAfter == "" {
			return out, nil
		}
		after = *p.NextAfter
	}
	return nil, ErrTruncated
}
