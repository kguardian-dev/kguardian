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

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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
	iv := r.Interval
	if iv <= 0 {
		iv = 5 * time.Minute
	}
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

// Pass evaluates every policy once.
func (r *Runner) Pass(ctx context.Context) error {
	pols, err := r.policies(ctx)
	if err != nil {
		return err
	}
	if len(pols) == 0 {
		r.store(nil)
		return nil
	}
	containers, err := r.Feed.Running(ctx)
	if err != nil {
		return fmt.Errorf("reading running images from the broker: %w", err)
	}
	var all []Result
	for _, p := range pols {
		st, res := r.evaluate(p, containers)
		all = append(all, res...)
		if err := r.writeStatus(ctx, p, st); err != nil {
			r.Log.WithError(err).WithField("policy", p.key()).Warn("image trust: status update failed")
		}
	}
	r.store(all)
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

func (r *Runner) selectsNamespace(p policyRef, ns string) bool {
	if p.gvr == PolicyGVR {
		return p.namespace == ns
	}
	if p.nsSel == nil {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(p.nsSel)
	if err != nil {
		return false
	}
	if sel.Empty() {
		return true
	}
	lbls := r.Namespaces(ns)
	if lbls == nil {
		return false // namespace not known to the cache: cannot judge
	}
	return sel.Matches(labels.Set(lbls))
}

// evaluate returns the new status for p and its per-container results.
func (r *Runner) evaluate(p policyRef, cs []Container) (v1alpha1.ImageTrustPolicyStatus, []Result) {
	st := v1alpha1.ImageTrustPolicyStatus{ObservedGeneration: p.gen}
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
		if !r.selectsNamespace(p, c.Namespace) || !pol.Selects(c) {
			continue
		}
		verdict, reason := pol.Evaluate(c)
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

// writeStatus patches status only when it changed (lastChanged aside), so
// replicas and quiet passes write nothing.
func (r *Runner) writeStatus(ctx context.Context, p policyRef, st v1alpha1.ImageTrustPolicyStatus) error {
	old := p.status
	oldEval, newEval := old.Evaluation, st.Evaluation
	oldEval.LastChanged, newEval.LastChanged = nil, nil
	if old.ObservedGeneration == st.ObservedGeneration && old.Error == st.Error && reflect.DeepEqual(oldEval, newEval) {
		return nil
	}
	t := metav1.NewTime(r.clock().UTC().Truncate(time.Second))
	st.Evaluation.LastChanged = &t
	body, err := json.Marshal(map[string]any{"status": st})
	if err != nil {
		return err
	}
	res := r.Dynamic.Resource(p.gvr)
	var ri dynamic.ResourceInterface = res
	if p.namespace != "" {
		ri = res.Namespace(p.namespace)
	}
	_, err = ri.Patch(ctx, p.name, types.MergePatchType, body, metav1.PatchOptions{}, "status")
	if apierrors.IsNotFound(err) {
		return nil // deleted meanwhile
	}
	if err == nil && st.Evaluation.WouldDeny > 0 {
		r.Log.WithFields(logrus.Fields{"policy": p.key(), "wouldDeny": st.Evaluation.WouldDeny, "unknown": st.Evaluation.Unknown}).
			Info("image trust: containers would be denied")
	}
	return err
}

// --- Broker feed ---

// BrokerFeed pages GET /attestations/running with a read token.
type BrokerFeed struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// MaxPages bounds one pass (default 100 pages of 1000).
	MaxPages int
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
		max = 100
	}
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	var out []Container
	after := ""
	for page := 0; page < max; page++ {
		q := url.Values{"limit": {"1000"}}
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
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			msg := string(body)
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return nil, fmt.Errorf("GET /attestations/running: %d %s", resp.StatusCode, msg)
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
