package matcher

import (
	"net"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// MatchCluster evaluates a Flow against a cluster-scoped
// AuditClusterNetworkPolicy. The semantic difference vs. Match: the
// policy can target pods in any namespace whose labels match
// spec.namespaceSelector (nil/empty matches all). Within a matching
// namespace the rule evaluation is identical.
func MatchCluster(flow Flow, policy *v1alpha1.AuditClusterNetworkPolicy, lookup Lookup) []Result {
	var results []Result

	types := effectivePolicyTypesCluster(&policy.Spec)
	for _, t := range types {
		dir := Direction(t)
		subject := subjectPod(flow, dir, lookup)
		notApplicable := func() {
			results = append(results, Result{
				PolicyNamespace: "", // cluster-scoped: no namespace
				PolicyName:      policy.Name,
				PolicyUID:       string(policy.UID),
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
		}
		if subject == nil {
			notApplicable()
			continue
		}
		// Namespace gate from the cluster-scope spec.
		if policy.Spec.NamespaceSelector != nil {
			nsLabels := lookup.GetNamespaceLabels(subject.Namespace)
			if nsLabels == nil || !selectorMatchesLabels(*policy.Spec.NamespaceSelector, nsLabels) {
				notApplicable()
				continue
			}
		}
		if !selectorMatchesLabels(policy.Spec.PodSelector, subject.Labels) {
			notApplicable()
			continue
		}

		allowed, reason := evaluateRulesCluster(flow, policy, dir, lookup)
		if allowed {
			results = append(results, Result{
				PolicyName: policy.Name,
				PolicyUID:  string(policy.UID),
				Direction:  dir,
				Verdict:    VerdictAllow,
			})
		} else {
			results = append(results, Result{
				PolicyName: policy.Name,
				PolicyUID:  string(policy.UID),
				Direction:  dir,
				Verdict:    VerdictWouldDeny,
				Reason:     reason,
			})
		}
	}
	return results
}

func effectivePolicyTypesCluster(spec *v1alpha1.ClusterNetworkPolicySpec) []networkingv1.PolicyType {
	if len(spec.PolicyTypes) > 0 {
		return spec.PolicyTypes
	}
	types := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	if len(spec.Egress) > 0 {
		types = append(types, networkingv1.PolicyTypeEgress)
	}
	return types
}

// evaluateRulesCluster mirrors evaluateRules but reads from a
// ClusterNetworkPolicySpec and threads the subject's namespace into
// peer matching (so peers without a namespaceSelector default to the
// subject pod's namespace, same as upstream).
func evaluateRulesCluster(flow Flow, policy *v1alpha1.AuditClusterNetworkPolicy, dir Direction, lookup Lookup) (bool, string) {
	portPod := portTargetPod(flow, dir, lookup)
	switch dir {
	case DirectionIngress:
		if len(policy.Spec.Ingress) == 0 {
			return false, "policy has no ingress rules — default-deny"
		}
		for _, rule := range policy.Spec.Ingress {
			if peerListMatches(flow, dir, rule.From, lookup) && portsMatch(flow, rule.Ports, portPod) {
				return true, ""
			}
		}
		return false, "no ingress rule matched both peer and port"
	case DirectionEgress:
		if len(policy.Spec.Egress) == 0 {
			return false, "policy has no egress rules — default-deny"
		}
		for _, rule := range policy.Spec.Egress {
			if peerListMatches(flow, dir, rule.To, lookup) && portsMatch(flow, rule.Ports, portPod) {
				return true, ""
			}
		}
		return false, "no egress rule matched both peer and port"
	}
	return false, "unknown direction"
}

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
				PolicyUID:       string(policy.UID),
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
			continue
		}
		if subject.Namespace != policy.Namespace {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				PolicyUID:       string(policy.UID),
				Direction:       dir,
				Verdict:         VerdictNotApplicable,
			})
			continue
		}
		if !selectorMatchesLabels(policy.Spec.PodSelector, subject.Labels) {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				PolicyUID:       string(policy.UID),
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
				PolicyUID:       string(policy.UID),
				Direction:       dir,
				Verdict:         VerdictAllow,
			})
		} else {
			results = append(results, Result{
				PolicyNamespace: policy.Namespace,
				PolicyName:      policy.Name,
				PolicyUID:       string(policy.UID),
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
//
// Named-port resolution reads the pod whose containers expose the port:
// for Ingress that's the *destination* pod (the one being connected to);
// for Egress that's also the destination — i.e. the egress *peer*. The
// upstream NetworkPolicy spec is explicit on this: NetworkPolicyPort
// always describes the listener side of the connection.
func evaluateRules(flow Flow, policy *v1alpha1.AuditNetworkPolicy, dir Direction, lookup Lookup) (bool, string) {
	portPod := portTargetPod(flow, dir, lookup)
	switch dir {
	case DirectionIngress:
		if len(policy.Spec.Ingress) == 0 {
			return false, "policy has no ingress rules — default-deny"
		}
		for _, rule := range policy.Spec.Ingress {
			if peerListMatches(flow, dir, rule.From, lookup) && portsMatch(flow, rule.Ports, portPod) {
				return true, ""
			}
		}
		return false, "no ingress rule matched both peer and port"
	case DirectionEgress:
		if len(policy.Spec.Egress) == 0 {
			return false, "policy has no egress rules — default-deny"
		}
		for _, rule := range policy.Spec.Egress {
			if peerListMatches(flow, dir, rule.To, lookup) && portsMatch(flow, rule.Ports, portPod) {
				return true, ""
			}
		}
		return false, "no egress rule matched both peer and port"
	}
	return false, "unknown direction"
}

// portTargetPod returns the pod whose container port declarations are
// canonical for this rule's named-port resolution.
//
// The upstream NetworkPolicy spec defines NetworkPolicyPort as the
// *destination* port of the connection, regardless of whether the rule
// is Ingress or Egress. So named-port resolution reads the destination
// pod's containers in both directions — Ingress: the policy's subject
// pod; Egress: the peer pod that the subject is connecting to. In both
// cases that's `flow.Dst*`. Centralising this here documents the
// invariant.
func portTargetPod(flow Flow, dir Direction, lookup Lookup) *corev1.Pod {
	return lookup.GetPod(flow.DstPodNamespace, flow.DstPodName)
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
// {podSelector?, namespaceSelector?, ipBlock?}) against the peer side
// of the flow.
func peerEntryMatches(peer *corev1.Pod, flow Flow, dir Direction, p networkingv1.NetworkPolicyPeer, lookup Lookup) bool {
	// ipBlock is exclusive of the pod/namespace selectors per upstream
	// schema validation — when set, evaluate it against the peer IP.
	if p.IPBlock != nil {
		return ipBlockMatches(peerIP(flow, dir), p.IPBlock)
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
// port. Both numeric ports (with optional endPort range) and named
// ports are supported — named ports are resolved against the
// destination pod's container declarations.
func portsMatch(flow Flow, ports []networkingv1.NetworkPolicyPort, dstPod *corev1.Pod) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if portEntryMatches(flow, p, dstPod) {
			return true
		}
	}
	return false
}

func portEntryMatches(flow Flow, p networkingv1.NetworkPolicyPort, dstPod *corev1.Pod) bool {
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
	if p.Port.Type == intStringTypeInt {
		port := p.Port.IntVal
		if p.EndPort != nil {
			return flow.DstPort >= port && flow.DstPort <= *p.EndPort
		}
		return flow.DstPort == port
	}
	// Named port — resolve against the destination pod's container
	// port declarations. The upstream semantics: a named port matches
	// if any container on the target pod declares that name with the
	// same protocol AND containerPort equal to the observed dst port.
	return namedPortMatches(p.Port.StrVal, wantProto, flow.DstPort, dstPod)
}

// intStringTypeInt mirrors intstr.Int (= 0). We don't import intstr to
// keep this file standalone-compilable in tests; the value is stable.
const intStringTypeInt = 0

// namedPortMatches returns true when `name` is declared as a container
// port on `pod` with matching protocol and containerPort == observed.
func namedPortMatches(name string, proto corev1.Protocol, observed int32, pod *corev1.Pod) bool {
	if pod == nil || name == "" {
		return false
	}
	for _, c := range pod.Spec.Containers {
		for _, cp := range c.Ports {
			if cp.Name != name {
				continue
			}
			cpProto := cp.Protocol
			if cpProto == "" {
				cpProto = corev1.ProtocolTCP
			}
			if cpProto != proto {
				continue
			}
			if cp.ContainerPort == observed {
				return true
			}
		}
	}
	return false
}

// peerIP returns the L3 address of the *peer* side of the flow,
// relative to the policy's subject. For ingress the peer is the source;
// for egress it's the destination.
func peerIP(flow Flow, dir Direction) string {
	switch dir {
	case DirectionIngress:
		return flow.SrcIP
	case DirectionEgress:
		return flow.DstIP
	}
	return ""
}

// ipBlockMatches returns true when `ip` is contained in `block.CIDR`
// AND not contained in any `block.Except` CIDR. Per upstream semantics,
// `Except` entries must be subsets of `CIDR`; we don't validate that
// here (admission does). Unknown / unparseable inputs are non-matches.
func ipBlockMatches(ip string, block *networkingv1.IPBlock) bool {
	if block == nil || ip == "" {
		return false
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	_, allow, err := net.ParseCIDR(block.CIDR)
	if err != nil || !allow.Contains(addr) {
		return false
	}
	for _, exStr := range block.Except {
		_, ex, err := net.ParseCIDR(exStr)
		if err == nil && ex.Contains(addr) {
			return false
		}
	}
	return true
}

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

