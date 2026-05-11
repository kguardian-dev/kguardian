// Package status owns the rolling aggregation of audit verdicts and
// the periodic write-back to AuditNetworkPolicy.status.evaluation.
//
// Aggregation is in-memory: every Server.handleEvaluate WouldDeny
// verdict calls Aggregator.Record, which bumps a counter keyed by
// (policyKey, srcPod, dstPod, port, protocol, direction). A background
// goroutine wakes every interval and patches each touched policy's
// .status.evaluation with totals + the top-N offenders.
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// Aggregator collects verdicts in memory and periodically reconciles
// them onto AuditNetworkPolicy.status.evaluation (and the cluster-scoped
// equivalent).
type Aggregator struct {
	log        *logrus.Logger
	dyn        dynamic.Interface
	gvr        schema.GroupVersionResource // namespaced
	clusterGVR schema.GroupVersionResource // cluster-scoped
	topN       int
	period     time.Duration

	mu     sync.Mutex
	counts map[policyKey]*policyAgg
}

type policyKey struct {
	namespace string
	name      string
}

type tupleKey struct {
	srcPod, dstPod, protocol, direction string
	dstPort                              int32
}

type policyAgg struct {
	flowsEvaluated int64
	flowsWouldDeny int64
	lastEvaluated  time.Time
	// observedGeneration is the .metadata.generation of the policy the
	// most recent verdict was evaluated against. Reported on the
	// status subresource so operators can compare against the live
	// .metadata.generation to know whether the evaluator has seen
	// their latest spec edit (standard k8s controller convention).
	observedGeneration int64
	tuples             map[tupleKey]int64
}

// New returns an Aggregator wired to a dynamic client.
func New(dyn dynamic.Interface, log *logrus.Logger) *Aggregator {
	return &Aggregator{
		log:        log,
		dyn:        dyn,
		gvr:        schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies"},
		clusterGVR: schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies"},
		topN:       25,
		period:     30 * time.Second,
		counts:     map[policyKey]*policyAgg{},
	}
}

// SetPeriod overrides the default 30s reconcile interval.
func (a *Aggregator) SetPeriod(d time.Duration) { a.period = d }

// SetTopN overrides the default top-25 offender list size.
func (a *Aggregator) SetTopN(n int) { a.topN = n }

// Record updates the in-memory counters for one verdict.
//
// `wouldDeny` distinguishes the two paths the server takes: any
// verdict (Allow / WouldDeny / NotApplicable) bumps `flowsEvaluated`,
// but only WouldDeny adds to the offender table.
//
// `generation` is the policy's .metadata.generation at the time of
// evaluation. The aggregator keeps the highest value seen so the
// status's observedGeneration monotonically tracks operator edits.
func (a *Aggregator) Record(policyNamespace, policyName, srcPod, dstPod, protocol, direction string, dstPort int32, wouldDeny bool, generation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := policyKey{namespace: policyNamespace, name: policyName}
	agg, ok := a.counts[key]
	if !ok {
		agg = &policyAgg{tuples: map[tupleKey]int64{}}
		a.counts[key] = agg
	}
	agg.flowsEvaluated++
	agg.lastEvaluated = time.Now().UTC()
	// Monotonic: only update if we've seen a newer generation. Two
	// flows for the same policy could arrive concurrently with
	// different stale views; the larger wins so status doesn't
	// appear to regress.
	if generation > agg.observedGeneration {
		agg.observedGeneration = generation
	}
	if !wouldDeny {
		return
	}
	agg.flowsWouldDeny++
	tk := tupleKey{
		srcPod:    srcPod,
		dstPod:    dstPod,
		protocol:  protocol,
		direction: direction,
		dstPort:   dstPort,
	}
	agg.tuples[tk]++
}

// Run starts the background reconcile loop until ctx is cancelled.
func (a *Aggregator) Run(ctx context.Context) {
	t := time.NewTicker(a.period)
	defer t.Stop()
	a.log.WithField("interval", a.period).Info("status aggregator started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.flush(ctx)
		}
	}
}

// flush walks the in-memory counters and patches each policy's status.
// Counters are *not* zeroed after a flush — totals are cumulative for
// the lifetime of the evaluator pod (which restarts reset them). A
// later iteration could move to a sliding-window store.
func (a *Aggregator) flush(ctx context.Context) {
	a.mu.Lock()
	snapshot := make(map[policyKey]*policyAgg, len(a.counts))
	for k, v := range a.counts {
		// Take a shallow copy of the agg + a fresh tuples map snapshot
		// so we can release the lock before doing API calls.
		copyAgg := &policyAgg{
			flowsEvaluated:     v.flowsEvaluated,
			flowsWouldDeny:     v.flowsWouldDeny,
			lastEvaluated:      v.lastEvaluated,
			observedGeneration: v.observedGeneration,
			tuples:             make(map[tupleKey]int64, len(v.tuples)),
		}
		for tk, n := range v.tuples {
			copyAgg.tuples[tk] = n
		}
		snapshot[k] = copyAgg
	}
	a.mu.Unlock()

	for key, agg := range snapshot {
		if err := a.patchStatus(ctx, key, agg); err != nil {
			if apierrors.IsNotFound(err) {
				// The policy was deleted while we held a verdict for it.
				// Evict the in-memory entry so (a) we don't leak memory
				// for every deleted policy and (b) a recreate of the
				// same name doesn't inherit a stale observedGeneration
				// counter (the new policy starts at gen=1 but we'd be
				// reporting whatever was last seen — confusing operators
				// and breaking the standard k8s monotonic invariant).
				a.mu.Lock()
				delete(a.counts, key)
				a.mu.Unlock()
				a.log.WithField("policy", key.namespace+"/"+key.name).
					Info("evicted aggregator entry: policy no longer exists")
				continue
			}
			a.log.WithError(err).
				WithField("policy", key.namespace+"/"+key.name).
				Warn("could not patch AuditNetworkPolicy status")
		}
	}
}

// patchStatus writes one policy's aggregated counts back to the API
// server using a JSON merge patch on the status subresource. The
// namespace == "" case is treated as a cluster-scoped policy and
// patches via the cluster GVR; otherwise the namespaced GVR is used.
func (a *Aggregator) patchStatus(ctx context.Context, key policyKey, agg *policyAgg) error {
	last := metav1.NewTime(agg.lastEvaluated)
	statusPatch := v1alpha1.AuditNetworkPolicyStatus{
		ObservedGeneration: agg.observedGeneration,
		Evaluation: v1alpha1.EvaluationStatus{
			LastEvaluated:  &last,
			FlowsEvaluated: agg.flowsEvaluated,
			FlowsWouldDeny: agg.flowsWouldDeny,
			TopOffenders:   topOffenders(agg.tuples, a.topN),
		},
	}

	patch := map[string]any{"status": statusPatch}
	body, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal status patch: %w", err)
	}

	if key.namespace == "" {
		_, err = a.dyn.Resource(a.clusterGVR).
			Patch(ctx, key.name, types.MergePatchType, body, metav1.PatchOptions{}, "status")
	} else {
		_, err = a.dyn.Resource(a.gvr).
			Namespace(key.namespace).
			Patch(ctx, key.name, types.MergePatchType, body, metav1.PatchOptions{}, "status")
	}
	return err
}

// topOffenders sorts the tuple counters by count desc and returns the
// top-N as OffenderSummary structs ready for status.
//
// Sort order is (count DESC, srcPod ASC, dstPod ASC, dstPort ASC,
// protocol ASC, direction ASC) — count first (the actual ranking), and
// the lexicographic tail breaks ties deterministically. Without the
// tail, equal-count tuples land in map-iteration order, which Go
// randomises per process. The status subresource would then "flicker"
// between flushes whenever ties exist at the top-N boundary (which is
// the common case — many short bursts share counts on the same minute
// boundary), making the topOffenders list look unstable to operators
// staring at `kubectl get auditnetworkpolicy -o yaml`.
func topOffenders(m map[tupleKey]int64, n int) []v1alpha1.OffenderSummary {
	if n <= 0 || len(m) == 0 {
		return nil
	}
	type sorted struct {
		k tupleKey
		c int64
	}
	all := make([]sorted, 0, len(m))
	for k, c := range m {
		all = append(all, sorted{k, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].c != all[j].c {
			return all[i].c > all[j].c
		}
		if all[i].k.srcPod != all[j].k.srcPod {
			return all[i].k.srcPod < all[j].k.srcPod
		}
		if all[i].k.dstPod != all[j].k.dstPod {
			return all[i].k.dstPod < all[j].k.dstPod
		}
		if all[i].k.dstPort != all[j].k.dstPort {
			return all[i].k.dstPort < all[j].k.dstPort
		}
		if all[i].k.protocol != all[j].k.protocol {
			return all[i].k.protocol < all[j].k.protocol
		}
		return all[i].k.direction < all[j].k.direction
	})
	if len(all) > n {
		all = all[:n]
	}
	out := make([]v1alpha1.OffenderSummary, 0, len(all))
	for _, s := range all {
		out = append(out, v1alpha1.OffenderSummary{
			SrcPod:    s.k.srcPod,
			DstPod:    s.k.dstPod,
			DstPort:   s.k.dstPort,
			Protocol:  s.k.protocol,
			Direction: s.k.direction,
			Count:     s.c,
		})
	}
	return out
}
