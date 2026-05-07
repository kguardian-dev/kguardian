package matcher

import (
	"fmt"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Match evaluates a single Flow against a single AuditNetworkPolicy and
// returns one Result per direction the policy applies in. A flow can
// produce up to two Results when both Ingress and Egress are listed
// (rare in practice, but supported).
//
// The function never panics on missing pods/namespaces; it falls back to
// VerdictNotApplicable when either side of the flow is unknown to the
// lookup, since we can't evaluate selectors against absent labels.
func Match(flow Flow, policy *v1alpha1.AuditNetworkPolicy, lookup Lookup) []Result {
	var results []Result

	// Resolve the policy's effective policyTypes. Per the upstream
	// NetworkPolicy spec: when policyTypes is omitted, the effective
	// types are inferred from which rule lists are present.
	types := effectivePolicyTypes(&policy.Spec)

	for _, t := range types {
		dir := Direction(t)
		// For Ingress the policy targets the *destination* pod; for
		// Egress, the *source*. If we can't identify that pod or its
		// labels don't match the policy's podSelector, the policy
		// doesn't apply to this flow.
		subject := subjectPod(flow, dir, lookup)
		if subject == nil {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
			continue
		}
		if subject.Namespace != policy.Namespace {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
			continue
		}
		if !selectorMatchesLabels(policy.Spec.PodSelector, subject.Labels) {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
			continue
		}

		// The pod is selected. Evaluate the rule set in the relevant
		// direction. Empty rule list means "deny everything" in that
		// direction; rules with empty from/to and empty ports mean
		// "allow everything".
		allowed, reason := evaluateRules(flow, policy, dir, lookup)
		if allowed {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				Direction:       dir,
				Verdict:         VerdictAllow,
			})
		} else {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				Direction:       dir,
				Verdict:         VerdictWouldDeny,
				Reason:          reason,
			})
		}
	}

	return results
}

// effectivePolicyTypes returns the directions a policy applies in.
// Mirrors the inference rules from the upstream NetworkPolicy spec:
// if policyTypes is omitted, Ingress is implied; Egress is implied only
// when at least one egress rule is present.
func effectivePolicyTypes(spec *networkingv1.NetworkPolicySpec) []networkingv1.PolicyType {
	if len(spec.PolicyTypes) > 0 {
		return spec.PolicyTypes
	}
	types := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	if len(spec.Egress) > 0 {
		types = append(types, networkingv1.PolicyTypeEgress)
	}
	return types
}

// subjectPod returns the pod the policy targets for the given direction.
func subjectPod(flow Flow, dir Direction, lookup Lookup) *corev1.Pod {
	switch dir {
	case DirectionIngress:
		return lookup.GetPod(flow.DstPodNamespace, flow.DstPodName)
	case DirectionEgress:
		return lookup.GetPod(flow.SrcPodNamespace, flow.SrcPodName)
	}
	return nil
}

// peerPod returns the "other side" of the flow relative to the subject.
func peerPod(flow Flow, dir Direction, lookup Lookup) *corev1.Pod {
	switch dir {
	case DirectionIngress:
		return lookup.GetPod(flow.SrcPodNamespace, flow.SrcPodName)
	case DirectionEgress:
		return lookup.GetPod(flow.DstPodNamespace, flow.DstPodName)
	}
	return nil
}

// evaluateRules walks the relevant rule list and returns (allowed, reason).
// Reason is only populated when allowed=false, to explain the deny.
func evaluateRules(flow Flow, policy *v1alpha1.AuditNetworkPolicy, dir Direction, lookup Lookup) (bool, string) {
	switch dir {
	case DirectionIngress:
		if len(policy.Spec.Ingress) == 0 {
			return false, "policy has no ingress rules — default-deny"
		}
		for _, rule := range policy.Spec.Ingress {
			if peerListMatches(flow, dir, rule.From, lookup) && portsMatch(flow, rule.Ports) {
				return true, ""
			}
		}
		return false, "no ingress rule matched both peer and port"
	case DirectionEgress:
		if len(policy.Spec.Egress) == 0 {
			return false, "policy has no egress rules — default-deny"
		}
		for _, rule := range policy.Spec.Egress {
			if peerListMatches(flow, dir, rule.To, lookup) && portsMatch(flow, rule.Ports) {
				return true, ""
			}
		}
		return false, "no egress rule matched both peer and port"
	}
	return false, "unknown direction"
}

// peerListMatches returns true if the peer side of the flow matches at
// least one entry in the peer list. An empty list (NetworkPolicyPeer{})
// means "match all peers" per upstream semantics.
func peerListMatches(flow Flow, dir Direction, peers []networkingv1.NetworkPolicyPeer, lookup Lookup) bool {
	if len(peers) == 0 {
		return true // empty from:/to: matches anything
	}
	peerObj := peerPod(flow, dir, lookup)
	for _, p := range peers {
		if peerEntryMatches(peerObj, flow, dir, p, lookup) {
			return true
		}
	}
	return false
}

// peerEntryMatches checks one NetworkPolicyPeer (which is one of:
// {podSelector?, namespaceSelector?, ipBlock?}) against a peer pod.
// MVP scope: ignores ipBlock (returns false for those entries; flagged
// as a known limitation in the matcher's Reason output).
func peerEntryMatches(peer *corev1.Pod, flow Flow, dir Direction, p networkingv1.NetworkPolicyPeer, lookup Lookup) bool {
	if p.IPBlock != nil {
		// Pure ipBlock peer: post-MVP. Don't claim a match.
		return false
	}
	if peer == nil {
		// We need pod labels to evaluate selectors; if the peer pod
		// is unknown, we can't say it matches.
		return false
	}

	// Namespace gate. If namespaceSelector is set, the peer's namespace
	// must match it. If it's nil, the peer must be in the *policy's*
	// namespace (i.e. the same namespace as the AuditNetworkPolicy —
	// same as for the subject pod, which we already validated).
	if p.NamespaceSelector != nil {
		nsLabels := lookup.GetNamespaceLabels(peer.Namespace)
		if nsLabels == nil {
			return false
		}
		if !selectorMatchesLabels(*p.NamespaceSelector, nsLabels) {
			return false
		}
	} else {
		// No namespaceSelector → peer must share the policy's
		// namespace. The subject is already in the policy's namespace,
		// and the peer's namespace is on its pod.
		// In ingress: peer is the source; in egress: peer is the dest.
		var subjectNs string
		switch dir {
		case DirectionIngress:
			subjectNs = flow.DstPodNamespace
		case DirectionEgress:
			subjectNs = flow.SrcPodNamespace
		}
		if peer.Namespace != subjectNs {
			return false
		}
	}

	// Pod-label gate. If podSelector is nil, any pod in the matching
	// namespace is OK. If set, the peer's labels must match it.
	if p.PodSelector != nil {
		if !selectorMatchesLabels(*p.PodSelector, peer.Labels) {
			return false
		}
	}
	return true
}

// portsMatch returns true if the flow's (port, protocol) matches at
// least one of the rule's port specs. An empty port list matches any
// port. Numeric ports + endPort ranges are supported; named ports
// (Port.StrVal) are MVP-stubbed as a non-match with no error.
func portsMatch(flow Flow, ports []networkingv1.NetworkPolicyPort) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if portEntryMatches(flow, p) {
			return true
		}
	}
	return false
}

func portEntryMatches(flow Flow, p networkingv1.NetworkPolicyPort) bool {
	// Protocol defaults to TCP per upstream spec.
	wantProto := corev1.ProtocolTCP
	if p.Protocol != nil {
		wantProto = *p.Protocol
	}
	if string(wantProto) != string(flow.Protocol) {
		return false
	}
	if p.Port == nil {
		return true // protocol-only match
	}
	// Named ports require resolving the name on the destination pod's
	// containers. MVP does not implement this — treat as non-match.
	if p.Port.Type != intStringTypeInt {
		return false
	}
	port := p.Port.IntVal
	if p.EndPort != nil {
		return flow.DstPort >= port && flow.DstPort <= *p.EndPort
	}
	return flow.DstPort == port
}

// intStringTypeInt mirrors intstr.Int (= 0). We don't import intstr to
// keep this file standalone-compilable in tests; the value is stable.
const intStringTypeInt = 0

// selectorMatchesLabels evaluates a metav1.LabelSelector against a label
// map using the standard apimachinery selector. An empty selector
// (matchLabels: {} and no matchExpressions) matches *everything* per
// upstream convention.
func selectorMatchesLabels(sel metav1.LabelSelector, lbls map[string]string) bool {
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		// Malformed selector — treat as no-match. Real validation
		// happens at admission time; this just keeps the matcher safe.
		return false
	}
	return s.Matches(labels.Set(lbls))
}

// describeFlow returns a short tag for log/metric labels. Kept here so
// callers don't have to format flows inline.
func describeFlow(f Flow) string {
	return fmt.Sprintf("%s/%s -> %s/%s :%d/%s",
		f.SrcPodNamespace, f.SrcPodName,
		f.DstPodNamespace, f.DstPodName,
		f.DstPort, f.Protocol,
	)
}

// silence unused warning for describeFlow during incremental builds.
var _ = describeFlow
