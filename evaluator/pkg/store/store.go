// Package store provides an in-memory cache of pods, namespaces, and
// AuditNetworkPolicies, backed by client-go informers. It implements
// matcher.Lookup so the matcher can be unit-tested with a fake store.
//
// AuditNetworkPolicies are watched via the dynamic client to avoid
// generating typed client code for our CRD — Unstructured -> typed
// conversion happens lazily on read.
package store

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Store is the running cache.
type Store struct {
	log *logrus.Logger

	podInformer  cache.SharedIndexInformer
	nsInformer   cache.SharedIndexInformer
	anpInformer  cache.SharedIndexInformer
	acnpInformer cache.SharedIndexInformer
	stopCh       chan struct{}

	policyMu sync.RWMutex
	// policiesByNamespace caches the typed projection of the dynamic
	// AuditNetworkPolicy informer for fast namespace-scoped lookup.
	policiesByNamespace map[string][]*v1alpha1.AuditNetworkPolicy
	// clusterPolicies caches typed AuditClusterNetworkPolicy items —
	// always evaluated against every flow regardless of namespace.
	clusterPolicies []*v1alpha1.AuditClusterNetworkPolicy
}

// AuditNetworkPolicyGVR is the GroupVersionResource the dynamic informer
// watches.
var AuditNetworkPolicyGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "auditnetworkpolicies",
}

// AuditClusterNetworkPolicyGVR — cluster-scoped sibling.
var AuditClusterNetworkPolicyGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "auditclusternetworkpolicies",
}

// New constructs a Store ready to start.
func New(cfg *rest.Config, log *logrus.Logger) (*Store, error) {
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	factory := informers.NewSharedInformerFactory(kc, 30*time.Minute)
	dynFactory := dynamicinformer.NewDynamicSharedInformerFactory(dc, 30*time.Minute)

	s := &Store{
		log:                 log,
		podInformer:         factory.Core().V1().Pods().Informer(),
		nsInformer:          factory.Core().V1().Namespaces().Informer(),
		anpInformer:         dynFactory.ForResource(AuditNetworkPolicyGVR).Informer(),
		acnpInformer:        dynFactory.ForResource(AuditClusterNetworkPolicyGVR).Informer(),
		stopCh:              make(chan struct{}),
		policiesByNamespace: map[string][]*v1alpha1.AuditNetworkPolicy{},
	}

	// Wire AuditNetworkPolicy lifecycle handlers — convert Unstructured
	// to typed once on insert/update, store under the namespace key.
	_, _ = s.anpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    s.onPolicyAddOrUpdate,
		UpdateFunc: func(_, obj interface{}) { s.onPolicyAddOrUpdate(obj) },
		DeleteFunc: s.onPolicyDelete,
	})
	// Cluster-scoped sibling — same lifecycle, different storage.
	_, _ = s.acnpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    s.onClusterPolicyAddOrUpdate,
		UpdateFunc: func(_, obj interface{}) { s.onClusterPolicyAddOrUpdate(obj) },
		DeleteFunc: s.onClusterPolicyDelete,
	})

	return s, nil
}

// Start launches the informers and blocks on cache sync.
func (s *Store) Start(ctx context.Context) error {
	go s.podInformer.Run(s.stopCh)
	go s.nsInformer.Run(s.stopCh)
	go s.anpInformer.Run(s.stopCh)
	go s.acnpInformer.Run(s.stopCh)

	if !cache.WaitForCacheSync(ctx.Done(),
		s.podInformer.HasSynced,
		s.nsInformer.HasSynced,
		s.anpInformer.HasSynced,
		s.acnpInformer.HasSynced,
	) {
		return context.Canceled
	}
	s.log.Info("informer caches synced (pods, namespaces, auditnetworkpolicies, auditclusternetworkpolicies)")

	go func() {
		<-ctx.Done()
		close(s.stopCh)
	}()
	return nil
}

func (s *Store) onPolicyAddOrUpdate(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	policy, err := unstructuredToPolicy(u)
	if err != nil {
		s.log.WithError(err).Warn("could not convert AuditNetworkPolicy from Unstructured")
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	// Replace the namespace's slice with a fresh one to handle updates
	// without dup tracking.
	list := s.policiesByNamespace[policy.Namespace]
	updated := list[:0:0]
	for _, p := range list {
		if p.Name == policy.Name {
			continue // dropped — replaced below
		}
		updated = append(updated, p)
	}
	updated = append(updated, policy)
	s.policiesByNamespace[policy.Namespace] = updated
}

func (s *Store) onPolicyDelete(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		// Could be a tombstone — best-effort.
		return
	}
	ns := u.GetNamespace()
	name := u.GetName()
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	list := s.policiesByNamespace[ns]
	out := list[:0]
	for _, p := range list {
		if p.Name != name {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		delete(s.policiesByNamespace, ns)
	} else {
		s.policiesByNamespace[ns] = out
	}
}

// unstructuredToPolicy converts an Unstructured to a typed
// AuditNetworkPolicy via JSON round-trip. Cheap relative to per-flow
// evaluation; runs once per add/update.
func unstructuredToPolicy(u *unstructured.Unstructured) (*v1alpha1.AuditNetworkPolicy, error) {
	raw, err := u.MarshalJSON()
	if err != nil {
		return nil, err
	}
	out := &v1alpha1.AuditNetworkPolicy{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PoliciesInNamespace returns a snapshot of policies in the given
// namespace. Safe for concurrent callers.
func (s *Store) PoliciesInNamespace(ns string) []*v1alpha1.AuditNetworkPolicy {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	src := s.policiesByNamespace[ns]
	if len(src) == 0 {
		return nil
	}
	out := make([]*v1alpha1.AuditNetworkPolicy, len(src))
	copy(out, src)
	return out
}

// ClusterPolicies returns a snapshot of every AuditClusterNetworkPolicy.
// Safe for concurrent callers.
func (s *Store) ClusterPolicies() []*v1alpha1.AuditClusterNetworkPolicy {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	if len(s.clusterPolicies) == 0 {
		return nil
	}
	out := make([]*v1alpha1.AuditClusterNetworkPolicy, len(s.clusterPolicies))
	copy(out, s.clusterPolicies)
	return out
}

func (s *Store) onClusterPolicyAddOrUpdate(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	policy, err := unstructuredToClusterPolicy(u)
	if err != nil {
		s.log.WithError(err).Warn("could not convert AuditClusterNetworkPolicy from Unstructured")
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	updated := s.clusterPolicies[:0:0]
	for _, p := range s.clusterPolicies {
		if p.Name != policy.Name {
			updated = append(updated, p)
		}
	}
	s.clusterPolicies = append(updated, policy)
}

func (s *Store) onClusterPolicyDelete(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	name := u.GetName()
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	out := s.clusterPolicies[:0]
	for _, p := range s.clusterPolicies {
		if p.Name != name {
			out = append(out, p)
		}
	}
	s.clusterPolicies = out
}

func unstructuredToClusterPolicy(u *unstructured.Unstructured) (*v1alpha1.AuditClusterNetworkPolicy, error) {
	raw, err := u.MarshalJSON()
	if err != nil {
		return nil, err
	}
	out := &v1alpha1.AuditClusterNetworkPolicy{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPod implements matcher.PodLookup.
func (s *Store) GetPod(namespace, name string) *corev1.Pod {
	if namespace == "" || name == "" {
		return nil
	}
	key := namespace + "/" + name
	obj, exists, err := s.podInformer.GetStore().GetByKey(key)
	if err != nil || !exists {
		return nil
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	return pod
}

// GetNamespaceLabels implements matcher.NamespaceLookup.
func (s *Store) GetNamespaceLabels(name string) map[string]string {
	if name == "" {
		return nil
	}
	obj, exists, err := s.nsInformer.GetStore().GetByKey(name)
	if err != nil || !exists {
		return nil
	}
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return nil
	}
	return ns.Labels
}
