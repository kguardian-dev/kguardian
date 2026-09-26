package appprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// GVR of the ApplicationSecurityProfile CRD.
var GVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "applicationsecurityprofiles",
}

// FieldManager is the server-side apply manager that owns .status.
const FieldManager = "kguardian-evaluator"

// Controller watches ApplicationSecurityProfiles and applies their status.
// One worker: profile reads are computed live by the broker, so they are
// serialised rather than fanned out, and a resync spreads over time.
type Controller struct {
	log    *logrus.Logger
	dyn    dynamic.Interface
	broker Broker
	// staleAfter bounds how long last-known data is shown when the broker
	// cannot be read (see computeStatus).
	staleAfter time.Duration
	informer   cache.SharedIndexInformer
	queue      workqueue.TypedRateLimitingInterface[string]
	now        func() time.Time
}

// New builds a controller. resync is how often every profile is re-read
// even when nothing about the resource changed (the workload's profile
// changes on the broker side, which raises no Kubernetes event).
// staleAfter is how long the last successfully read profile may still be
// shown while the broker cannot be read; see StaleAfter for the default
// and floor.
func New(dyn dynamic.Interface, broker Broker, resync, staleAfter time.Duration, log *logrus.Logger) *Controller {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dyn, resync)
	c := &Controller{
		log:        log,
		dyn:        dyn,
		broker:     broker,
		staleAfter: StaleAfter(staleAfter, resync),
		informer:   factory.ForResource(GVR).Informer(),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](5*time.Second, 5*time.Minute),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "applicationsecurityprofiles"},
		),
		now: time.Now,
	}
	_, _ = c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueue,
		UpdateFunc: func(oldObj, newObj any) {
			if shouldEnqueueUpdate(asUnstructured(oldObj), asUnstructured(newObj)) {
				c.enqueue(newObj)
			}
		},
		DeleteFunc: func(obj any) {
			// A deleted resource may have been the one a duplicate lost
			// to; re-evaluate its namespace siblings.
			if u := asUnstructured(obj); u != nil {
				c.enqueueNamespace(u.GetNamespace())
			}
		},
	})
	return c
}

// StaleAfter resolves the staleness window: 3x resync when unset (0), and
// never shorter than one resync interval, since a single failed read right
// after a resync would otherwise flip a healthy profile to unknown.
func StaleAfter(configured, resync time.Duration) time.Duration {
	if configured <= 0 {
		return 3 * resync
	}
	if configured < resync {
		return resync
	}
	return configured
}

// shouldEnqueueUpdate: a spec edit (generation change) or a periodic
// resync (the informer redelivers the same resourceVersion). Our own
// status writes bump resourceVersion but not generation; reacting to them
// would loop.
func shouldEnqueueUpdate(o, n *unstructured.Unstructured) bool {
	if o == nil || n == nil {
		return false
	}
	return o.GetGeneration() != n.GetGeneration() || o.GetResourceVersion() == n.GetResourceVersion()
}

// Run starts the informer and the worker; it returns when ctx is done.
// It never blocks evaluator startup: when the CRD is missing the informer
// just keeps retrying and logs.
func (c *Controller) Run(ctx context.Context) {
	defer c.queue.ShutDown()
	go c.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return
	}
	c.log.Info("applicationsecurityprofile controller started")
	go func() {
		for c.processNext(ctx) {
		}
	}()
	<-ctx.Done()
}

func (c *Controller) processNext(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.reconcile(ctx, key)
	var te errTransient
	switch {
	case err == nil:
		c.queue.Forget(key)
	case errors.As(err, &te):
		c.log.WithError(err).WithField("profile", key).Warn("broker read failed; retrying with backoff")
		c.queue.AddRateLimited(key)
	default:
		c.log.WithError(err).WithField("profile", key).Warn("could not reconcile ApplicationSecurityProfile")
		c.queue.AddRateLimited(key)
	}
	return true
}

func (c *Controller) enqueue(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err == nil {
		c.queue.Add(key)
	}
}

func (c *Controller) enqueueNamespace(ns string) {
	for _, o := range c.informer.GetStore().List() {
		if u := asUnstructured(o); u != nil && u.GetNamespace() == ns {
			c.enqueue(u)
		}
	}
}

// reconcile computes and applies one resource's status.
func (c *Controller) reconcile(ctx context.Context, key string) error {
	obj, exists, err := c.informer.GetStore().GetByKey(key)
	if err != nil || !exists {
		return err
	}
	u := asUnstructured(obj)
	if u == nil {
		return nil
	}
	asp, err := fromUnstructured(u)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", key, err)
	}

	var status v1alpha1.ApplicationSecurityProfileStatus
	var brokerErr error
	if winner := c.ownerOf(asp); winner != "" {
		status = duplicateStatus(asp, winner)
	} else {
		status, brokerErr = computeStatus(ctx, c.broker, asp, c.now(), c.staleAfter)
	}
	if err := c.apply(ctx, asp, status); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return brokerErr
}

// ownerOf returns the name of the resource that owns asp's workload when
// asp is a duplicate, else "". The oldest resource (then name order) wins,
// so the choice is stable and does not flip between resyncs.
func (c *Controller) ownerOf(asp *v1alpha1.ApplicationSecurityProfile) string {
	best := asp
	for _, o := range c.informer.GetStore().List() {
		u := asUnstructured(o)
		if u == nil || u.GetNamespace() != asp.Namespace || u.GetName() == asp.Name || u.GetDeletionTimestamp() != nil {
			continue
		}
		other, err := fromUnstructured(u)
		if err != nil || other.Spec.WorkloadRef != asp.Spec.WorkloadRef {
			continue
		}
		if older(other, best) {
			best = other
		}
	}
	if best.Name == asp.Name {
		return ""
	}
	return best.Name
}

func older(a, b *v1alpha1.ApplicationSecurityProfile) bool {
	ta, tb := a.CreationTimestamp.Time, b.CreationTimestamp.Time
	if !ta.Equal(tb) {
		return ta.Before(tb)
	}
	return a.Name < b.Name
}

func duplicateStatus(asp *v1alpha1.ApplicationSecurityProfile, winner string) v1alpha1.ApplicationSecurityProfileStatus {
	out := v1alpha1.ApplicationSecurityProfileStatus{
		ObservedGeneration: asp.Generation,
		Conditions:         copyConditions(asp.Status.Conditions),
	}
	msg := fmt.Sprintf("ApplicationSecurityProfile %q already covers %s %s; only one profile per workload is reported. Delete this one.",
		winner, asp.Spec.WorkloadRef.Kind, asp.Spec.WorkloadRef.Name)
	setCond(&out, asp.Generation, v1alpha1.ConditionProfileAvailable, metav1.ConditionFalse, v1alpha1.ReasonDuplicateWorkloadRef, msg)
	setCond(&out, asp.Generation, v1alpha1.ConditionDeviated, metav1.ConditionUnknown, v1alpha1.ReasonProfileUnavailable, "Not evaluated: duplicate of "+winner)
	return out
}

// apply writes status with server-side apply on the status subresource.
// The applied object carries only identity and status, so the evaluator
// never owns (or can clobber) any spec or metadata field. Force takes
// ownership back if someone else wrote status fields by hand.
func (c *Controller) apply(ctx context.Context, asp *v1alpha1.ApplicationSecurityProfile, status v1alpha1.ApplicationSecurityProfileStatus) error {
	u, err := statusApplyObject(asp, status)
	if err != nil {
		return err
	}
	_, err = c.dyn.Resource(GVR).Namespace(asp.Namespace).ApplyStatus(ctx, asp.Name, u,
		metav1.ApplyOptions{FieldManager: FieldManager, Force: true})
	return err
}

func statusApplyObject(asp *v1alpha1.ApplicationSecurityProfile, status v1alpha1.ApplicationSecurityProfileStatus) (*unstructured.Unstructured, error) {
	raw, err := json.Marshal(status)
	if err != nil {
		return nil, err
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.SchemeGroupVersion.String(),
		"kind":       "ApplicationSecurityProfile",
		"metadata": map[string]any{
			"name":      asp.Name,
			"namespace": asp.Namespace,
		},
		"status": st,
	}}
	return u, nil
}

func asUnstructured(obj any) *unstructured.Unstructured {
	switch t := obj.(type) {
	case *unstructured.Unstructured:
		return t
	case cache.DeletedFinalStateUnknown:
		if u, ok := t.Obj.(*unstructured.Unstructured); ok {
			return u
		}
	}
	return nil
}

func fromUnstructured(u *unstructured.Unstructured) (*v1alpha1.ApplicationSecurityProfile, error) {
	out := &v1alpha1.ApplicationSecurityProfile{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out); err != nil {
		return nil, err
	}
	return out, nil
}
