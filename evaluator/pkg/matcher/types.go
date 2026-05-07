// Package matcher decides whether an observed flow would be denied by a
// given AuditNetworkPolicy.
//
// Semantics follow networking.k8s.io/v1 NetworkPolicy:
//
//   - A policy "selects" a pod when the pod's namespace equals the policy's
//     namespace AND the pod's labels match policy.spec.podSelector.
//   - For each selected pod and direction listed in policyTypes, the
//     default action is DENY unless at least one rule explicitly permits
//     the flow.
//   - A rule permits a flow when (peer matches) AND (port+protocol matches).
//   - An empty `from:` / `to:` block matches *any* peer; an empty `ports:`
//     block matches *any* port. An empty rule list (`ingress: []`) means
//     no flow is permitted in that direction.
//
// MVP scope: podSelector + namespaceSelector + numeric ports (with
// endPort ranges). ipBlock and named-port resolution are stubbed and
// noted as follow-ups in the matcher's Match() result.
package matcher

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Direction is the side the AuditNetworkPolicy is evaluating.
type Direction string

const (
	DirectionIngress Direction = "Ingress"
	DirectionEgress  Direction = "Egress"
)

// Protocol is a normalised L4 protocol name.
type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolSCTP Protocol = "SCTP"
)

// Flow is the minimal description of an observed connection that the
// matcher needs. The broker assembles these from eBPF events.
type Flow struct {
	// SrcPodNamespace, SrcPodName identify the originating pod (may be
	// empty when the source is outside the cluster — those flows are
	// matched against ipBlock peers using SrcIP).
	SrcPodNamespace string `json:"srcPodNamespace,omitempty"`
	SrcPodName      string `json:"srcPodName,omitempty"`
	// DstPodNamespace, DstPodName identify the destination pod.
	DstPodNamespace string `json:"dstPodNamespace,omitempty"`
	DstPodName      string `json:"dstPodName,omitempty"`
	// SrcIP / DstIP carry the L3 addresses observed by the eBPF
	// controller. Used to match `ipBlock` peers (cidr + except).
	// Empty string means "unknown" — the matcher then falls back to
	// pod-selector evaluation only.
	SrcIP string `json:"srcIP,omitempty"`
	DstIP string `json:"dstIP,omitempty"`
	// DstPort is the destination port number observed on the wire.
	DstPort int32 `json:"dstPort"`
	// Protocol is TCP / UDP / SCTP.
	Protocol Protocol `json:"protocol"`
	// Timestamp is when the flow was observed.
	Timestamp time.Time `json:"timestamp"`
}

// Verdict is the outcome of evaluating one Flow against one
// AuditNetworkPolicy in one direction.
type Verdict string

const (
	// VerdictNotApplicable means the policy does not select either side
	// of this flow in this direction; no audit signal is emitted.
	VerdictNotApplicable Verdict = "NotApplicable"
	// VerdictAllow means at least one rule in the policy permits this
	// flow.
	VerdictAllow Verdict = "Allow"
	// VerdictWouldDeny means the policy selects the relevant pod but no
	// rule permits the flow. If this policy were enforced, the CNI would
	// drop the connection.
	VerdictWouldDeny Verdict = "WouldDeny"
)

// Result is what /evaluate returns for one (Flow, Policy, Direction)
// triple.
type Result struct {
	PolicyNamespace string    `json:"policyNamespace"`
	PolicyName      string    `json:"policyName"`
	// PolicyUID is the .metadata.uid of the matched
	// AuditNetworkPolicy / AuditClusterNetworkPolicy. Stable across
	// renames of the same generation; empty when the matcher couldn't
	// resolve a UID (e.g. a synthetic test policy).
	PolicyUID string    `json:"policyUID,omitempty"`
	Direction Direction `json:"direction"`
	Verdict   Verdict   `json:"verdict"`
	// Reason is a human-readable explanation populated for
	// WouldDeny verdicts.
	Reason string `json:"reason,omitempty"`
}

// PodLookup returns the in-cluster Pod matching (namespace, name), or nil
// when the pod is unknown to the cache. Implemented in production by a
// client-go Lister; mocked in tests.
type PodLookup interface {
	GetPod(namespace, name string) *corev1.Pod
}

// NamespaceLookup returns the labels of an in-cluster Namespace, or nil
// when unknown.
type NamespaceLookup interface {
	GetNamespaceLabels(name string) map[string]string
}

// Lookup bundles the two reads the matcher needs.
type Lookup interface {
	PodLookup
	NamespaceLookup
}
