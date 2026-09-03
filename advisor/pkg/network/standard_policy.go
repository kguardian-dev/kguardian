package network

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/common"
	log "github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// StandardPolicyGenerator generates standard Kubernetes NetworkPolicy resources
type StandardPolicyGenerator struct {
	data BrokerData
}

// NewStandardPolicyGenerator creates a new generator for standard NetworkPolicy
// resources, resolving peers via the default (api-backed) broker data source.
func NewStandardPolicyGenerator() *StandardPolicyGenerator {
	return &StandardPolicyGenerator{data: DefaultBrokerData()}
}

func (g *StandardPolicyGenerator) setBrokerData(d BrokerData) {
	if d != nil {
		g.data = d
	}
}

// broker returns the injected BrokerData, falling back to the default so a
// zero-value generator never nil-panics.
func (g *StandardPolicyGenerator) broker() BrokerData {
	if g.data == nil {
		return DefaultBrokerData()
	}
	return g.data
}

// GetType returns the policy type
func (g *StandardPolicyGenerator) GetType() PolicyType {
	return StandardPolicy
}

// Generate creates a NetworkPolicy for the specified pod. It is
// GenerateWithComments minus the comments — kept for the PolicyGenerator
// interface and existing callers.
func (g *StandardPolicyGenerator) Generate(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, error) {
	policy, _, err := g.GenerateWithComments(podName, podTraffic, podDetail)
	return policy, err
}

// GenerateWithComments creates a NetworkPolicy for the specified pod together
// with the YAML comments that explain host-network peers and targets (see
// hostnetwork.go). The returned comments are empty for a policy with no
// host-network involvement, so MarshalPolicyYAML emits exactly yaml.Marshal.
func (g *StandardPolicyGenerator) GenerateWithComments(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, *PolicyComments, error) {
	log.Info().Msgf("Generating standard network policy for pod %s", podName)

	if podDetail == nil {
		return nil, nil, fmt.Errorf("pod detail is nil for pod %s", podName)
	}

	comments := &PolicyComments{}
	if isHostNetwork(podDetail) {
		log.Warn().Msgf("Pod %s/%s runs with hostNetwork: true; a NetworkPolicy podSelector cannot select it", podDetail.Namespace, podDetail.Name)
		comments.addHeader(hostNetworkTargetWarning(podDetail, "NetworkPolicy", "podSelector")...)
	}

	if len(podTraffic) == 0 {
		// If there's no traffic, generate a default-deny policy
		log.Warn().Msgf("No traffic data available for pod %s. Generating a default-deny policy.", podName)
		return g.generateDefaultDenyPolicy(podDetail), comments, nil
	}

	// Group traffic by ingress/egress
	ingressRules, egressRules := g.processTrafficRules(podTraffic, podDetail)

	// Create the NetworkPolicy object
	policy := &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy"), // Use standard-policy for clarity
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels, // Use actual pod labels
			},
			PolicyTypes: []networkingv1.PolicyType{},
		},
	}

	// Add ingress rules if any
	if len(ingressRules) > 0 {
		policy.Spec.PolicyTypes = append(policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
		policy.Spec.Ingress = g.transformToNetworkPolicyIngressRules(ingressRules, comments)
	}

	// Add egress rules if any
	if len(egressRules) > 0 {
		policy.Spec.PolicyTypes = append(policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
		policy.Spec.Egress = g.transformToNetworkPolicyEgressRules(egressRules, comments)
	}

	// If no rules were added (e.g., only traffic to self or unidentifiable IPs), make it default deny
	if len(policy.Spec.PolicyTypes) == 0 {
		log.Warn().Msgf("No valid ingress or egress rules generated for pod %s. Applying default-deny.", podName)
		return g.generateDefaultDenyPolicy(podDetail), comments, nil
	}

	return policy, comments, nil
}

// generateDefaultDenyPolicy creates a policy that denies all ingress and egress traffic
func (g *StandardPolicyGenerator) generateDefaultDenyPolicy(podDetail *api.PodDetail) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy-deny-all"),
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy-deny-all"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels,
			},
			// An empty PolicyTypes slice makes it default-deny for both ingress and egress
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			// Explicitly empty Ingress and Egress rules further clarify the deny-all stance
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	}
}

// processTrafficRules groups traffic rules by direction
//
// IMPORTANT: Traffic Data Structure Understanding
// The PodTraffic struct has a confusing naming convention. Here's the correct interpretation:
//
// Fields prefixed with "Src" represent the TARGET POD (the pod we're generating policy for):
// - SrcPodName, SrcIP, SrcPodPort: These refer to the pod we're protecting
//
// Fields prefixed with "Dst" represent the PEER/REMOTE ENTITY:
// - DstIP, DstPort: These refer to the external entity communicating with our pod
//
// For NetworkPolicy generation:
//
// INGRESS Rules (external -> our pod):
// - Peer: DstIP (the external source sending traffic to us)
// - Port: SrcPodPort (the port on our pod receiving the traffic)
// - Example: Allow frontend-pod (DstIP) to reach our pod on port 8080 (SrcPodPort)
//
// EGRESS Rules (our pod -> external):
// - Peer: DstIP (the external destination we're sending to)
// - Port: DstPort (the port on the external service/pod)
// - Example: Allow our pod to reach database-svc (DstIP) on port 5432 (DstPort)
func (g *StandardPolicyGenerator) processTrafficRules(podTraffic []api.PodTraffic, podDetail *api.PodDetail) ([]NetworkPolicyRule, []NetworkPolicyRule) {
	var ingressRules, egressRules []NetworkPolicyRule

	for _, traffic := range podTraffic {
		var portInt int
		var err error
		var peer string
		var port intstr.IntOrString
		var protocolStr string

		if IsIngressTraffic(traffic, podDetail) {
			// For INGRESS traffic: External peer -> Our Pod
			// - Peer is the source sending to us (traffic.DstIP - the external entity)
			// - Port is the port on our pod receiving the traffic (traffic.SrcPodPort)
			peer = traffic.DstIP

			// Skip if peer is empty or same as pod's own IP (self-traffic)
			if peer == "" {
				log.Debug().Msgf("Skipping ingress traffic with empty peer IP")
				continue
			}
			if peer == podDetail.PodIP {
				log.Debug().Msgf("Skipping ingress self-traffic (peer %s == pod IP %s)", peer, podDetail.PodIP)
				continue
			}

			portInt, err = parsePort(traffic.SrcPodPort)
			if err != nil {
				log.Warn().Err(err).Msgf("Skipping ingress traffic record due to invalid pod port: %s", traffic.SrcPodPort)
				continue
			}
			port = intstr.FromInt(portInt)
			protocolStr = string(traffic.Protocol)

			log.Debug().Msgf("Processing INGRESS: allowing peer %s to reach our pod port %d (%s)", peer, portInt, protocolStr)
			ingressRules = g.addOrUpdateRule(ingressRules, peer, port, protocolStr)

		} else if IsEgressTraffic(traffic, podDetail) {
			// For EGRESS traffic: Our Pod -> External destination
			// - Peer is the destination (traffic.DstIP - where our pod is connecting to)
			// - Port is the destination port (traffic.DstPort - the port on the target service/pod)
			peer = traffic.DstIP

			// Skip if peer is empty or same as pod's own IP (self-traffic)
			if peer == "" {
				log.Debug().Msgf("Skipping egress traffic with empty peer IP")
				continue
			}
			if peer == podDetail.PodIP {
				log.Debug().Msgf("Skipping egress self-traffic (peer %s == pod IP %s)", peer, podDetail.PodIP)
				continue
			}

			portInt, err = parsePort(traffic.DstPort)
			if err != nil {
				log.Warn().Err(err).Msgf("Skipping egress traffic record due to invalid destination port: %s", traffic.DstPort)
				continue
			}
			port = intstr.FromInt(portInt)
			protocolStr = string(traffic.Protocol)

			log.Debug().Msgf("Processing EGRESS: allowing our pod to reach peer %s on port %d (%s)", peer, portInt, protocolStr)
			egressRules = g.addOrUpdateRule(egressRules, peer, port, protocolStr)
		} else {
			log.Debug().Msgf("Skipping traffic record with unknown type: %s", traffic.TrafficType)
		}
	}

	log.Info().Msgf("Generated %d ingress rules and %d egress rules for pod %s",
		len(ingressRules), len(egressRules), podDetail.Name)

	return ingressRules, egressRules
}

// addOrUpdateRule delegates to the shared mergeOrAppendRule helper.
// Kept as a method for backwards compatibility with existing tests +
// call sites; the underlying logic lives in types.go so both generators
// stay in lockstep.
func (g *StandardPolicyGenerator) addOrUpdateRule(rules []NetworkPolicyRule, peer string, port intstr.IntOrString, protocolStr string) []NetworkPolicyRule {
	return mergeOrAppendRule(rules, peer, port, protocolStr)
}

// transformToNetworkPolicyIngressRules converts our internal rules to K8s
// NetworkPolicyIngressRule. comments (nil-safe) receives one line per
// host-network peer, keyed by the emitted rule's index.
func (g *StandardPolicyGenerator) transformToNetworkPolicyIngressRules(rules []NetworkPolicyRule, comments *PolicyComments) []networkingv1.NetworkPolicyIngressRule {
	var ingressRules []networkingv1.NetworkPolicyIngressRule

	// Group rules by peer IP
	peerRules := make(map[string][]networkingv1.NetworkPolicyPort)
	for _, rule := range rules {
		peerRules[rule.PeerIP] = append(peerRules[rule.PeerIP], rule.Ports...)
	}

	// Iterate in sorted peer-IP order so the generated YAML is
	// deterministic across runs of identical input. Without this,
	// `kguardian generate networkpolicy` produced different rule
	// orderings each call (Go map iteration randomises per process),
	// surfacing as spurious `kubectl diff` output and noise in
	// git-tracked policy review.
	for _, peerIP := range sortedKeys(peerRules) {
		ports := peerRules[peerIP]
		peers, comment := g.createNetworkPolicyPeers(peerIP)
		if len(peers) == 0 { // Skip if peer could not be determined (e.g., internal error)
			continue
		}
		comments.addIngress(len(ingressRules), comment)
		ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
			From:  peers,
			Ports: deduplicatePorts(ports),
		})
	}

	return ingressRules
}

// transformToNetworkPolicyEgressRules converts our internal rules to K8s
// NetworkPolicyEgressRule. See the ingress sibling for comments.
func (g *StandardPolicyGenerator) transformToNetworkPolicyEgressRules(rules []NetworkPolicyRule, comments *PolicyComments) []networkingv1.NetworkPolicyEgressRule {
	var egressRules []networkingv1.NetworkPolicyEgressRule

	// Group rules by peer IP
	peerRules := make(map[string][]networkingv1.NetworkPolicyPort)
	for _, rule := range rules {
		peerRules[rule.PeerIP] = append(peerRules[rule.PeerIP], rule.Ports...)
	}

	// Sorted iteration — see the ingress sibling for rationale.
	for _, peerIP := range sortedKeys(peerRules) {
		ports := peerRules[peerIP]
		peers, comment := g.createNetworkPolicyPeers(peerIP)
		if len(peers) == 0 { // Skip if peer could not be determined
			continue
		}
		comments.addEgress(len(egressRules), comment)

		egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
			To:    peers,
			Ports: deduplicatePorts(ports),
		})
	}

	return egressRules
}

// sortedKeys returns the keys of a string-keyed map in ascending
// order. Used by the policy transforms to produce deterministic
// rule ordering — Go's map iteration is randomised per process, so
// without sorting, regenerating a policy from identical input
// produces different YAML each run (spurious diffs).
func sortedKeys(m map[string][]networkingv1.NetworkPolicyPort) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// createNetworkPolicyPeers determines the NetworkPolicyPeer set for one observed
// peer IP. It prioritizes Service selectors, then Pod selectors, then falls
// back to IPBlock. Every path yields exactly one peer except a Service backed
// by host-network pods, which yields one ipBlock per backend node IP (the
// post-DNAT destinations). An empty result means the rule must be dropped.
//
// The second return value is a YAML comment to render above the rule, or ""
// — it is set only for host-network peers, which are rendered as ipBlocks of
// node IPs because no podSelector can match them.
func (g *StandardPolicyGenerator) createNetworkPolicyPeers(peerIP string) ([]networkingv1.NetworkPolicyPeer, string) {
	log.Debug().Msgf("Creating network policy peer for IP: %s", peerIP)
	one := func(p *networkingv1.NetworkPolicyPeer, comment string) ([]networkingv1.NetworkPolicyPeer, string) {
		if p == nil {
			return nil, ""
		}
		return []networkingv1.NetworkPolicyPeer{*p}, comment
	}

	// Try to get Service info first
	svcSpec, err := g.broker().ServiceByIP(peerIP)
	if err == nil && svcSpec != nil {
		// Validate service has selectors before using it
		if len(svcSpec.Service.Spec.Selector) > 0 {
			log.Debug().Msgf("Found service %s/%s with selector %v for IP %s",
				svcSpec.SvcNamespace, svcSpec.SvcName, svcSpec.Service.Spec.Selector, peerIP)

			// A Service fronting host-network pods fronts node IPs: its
			// selector would match nothing the CNI sees, and NetworkPolicy is
			// evaluated post-DNAT, so pin the backend node IPs — one ipBlock
			// each — not the ClusterIP.
			if backends := hostNetworkServiceBackends(g.broker(), svcSpec); len(backends) > 0 {
				cidrs := hostNetworkServiceCIDRs(backends)
				if len(cidrs) == 0 {
					log.Warn().Msgf("Skipping host-network service peer %s/%s: no backend IP could be expressed as a host CIDR", svcSpec.SvcNamespace, svcSpec.SvcName)
					return nil, ""
				}
				log.Debug().Msgf("Service %s/%s is backed by host-network pods; using IPBlocks %v", svcSpec.SvcNamespace, svcSpec.SvcName, cidrs)
				peers := make([]networkingv1.NetworkPolicyPeer, 0, len(cidrs))
				for _, cidr := range cidrs {
					peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
				}
				return peers, hostNetworkServiceComment(svcSpec, backends, peerIP, "podSelector")
			}

			return one(&networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: svcSpec.Service.Spec.Selector,
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": svcSpec.SvcNamespace,
					},
				},
			}, "")
		} else {
			log.Debug().Msgf("Service %s/%s found for IP %s but has no selector, trying pod lookup",
				svcSpec.SvcNamespace, svcSpec.SvcName, peerIP)
		}
	} else if err != nil {
		log.Debug().Err(err).Msgf("Error fetching service spec for IP %s, trying pod spec", peerIP)
	} else {
		log.Debug().Msgf("No service found for IP %s, trying pod spec", peerIP)
	}

	// Try to get Pod info
	podSpec, err := g.broker().PodByIP(peerIP)
	if err == nil && podSpec != nil {
		// A host-network pod shares the node IP; its labels select nothing
		// the CNI can see. Pin the observed node address instead and say so.
		if isHostNetwork(podSpec) {
			cidr, err := common.HostCIDR(peerIP)
			if err != nil {
				log.Warn().Err(err).Msgf("Skipping host-network peer %s: cannot express it as a host CIDR", peerIP)
				return nil, ""
			}
			log.Debug().Msgf("Peer %s is host-network pod %s/%s; using IPBlock %s", peerIP, podSpec.Namespace, podSpec.Name, cidr)
			return one(&networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}},
				hostNetworkPeerComment(podSpec, peerIP, "podSelector"))
		}
		// Validate pod has labels before using it
		if len(podSpec.Pod.Labels) > 0 {
			log.Debug().Msgf("Found pod %s/%s with labels %v for IP %s",
				podSpec.Namespace, podSpec.Name, podSpec.Pod.Labels, peerIP)

			return one(&networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: podSpec.Pod.Labels,
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": podSpec.Namespace,
					},
				},
			}, "")
		} else {
			log.Debug().Msgf("Pod %s/%s found for IP %s but has no labels, falling back to IPBlock",
				podSpec.Namespace, podSpec.Name, peerIP)
		}
	} else if err != nil {
		log.Debug().Err(err).Msgf("Error fetching pod spec for IP %s, falling back to IPBlock", peerIP)
	} else {
		log.Debug().Msgf("No pod found for IP %s, falling back to IPBlock", peerIP)
	}

	// Fall back to IPBlock for external IPs or unresolvable cluster IPs.
	//
	// common.HostCIDR picks the prefix length from the address family
	// (/32 for IPv4, /128 for IPv6) — this used to be a hardcoded "/32",
	// which on a dual-stack cluster turned a single peer into the whole
	// fd00::/32 block. It rejects anything it cannot parse; returning nil
	// here is the established "peer could not be determined" signal that
	// both transform loops already skip on, so an unusable address costs
	// us that one rule instead of poisoning the entire policy with a
	// malformed ipBlock.
	cidr, err := common.HostCIDR(peerIP)
	if err != nil {
		log.Warn().Err(err).Msgf("Skipping peer %s: cannot express it as a host CIDR", peerIP)
		return nil, ""
	}
	log.Debug().Msgf("Using IPBlock %s for peer %s", cidr, peerIP)
	return one(&networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{
			CIDR: cidr,
		},
	}, "")
}

// Helper functions

// parsePort converts a string port to an integer.
//
// Uses strconv.Atoi instead of fmt.Sscanf("%d") because Sscanf silently
// accepts trailing junk: Sscanf("80junk", "%d") returns 80 with no
// error, Sscanf("8.5", "%d") returns 8 (truncated), Sscanf(" 80", "%d")
// strips whitespace and returns 80. Atoi rejects all of those cleanly.
// We can't trust the input to be well-formed — port strings come from
// observed eBPF traffic data and persist through the broker; silently
// truncating "8.5" to 8 in a generated NetworkPolicy is a real bug.
func parsePort(portStr string) (int, error) {
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port format '%s': %w", portStr, err)
	}
	if portInt <= 0 || portInt > 65535 {
		return 0, fmt.Errorf("port number '%d' out of range", portInt)
	}
	return portInt, nil
}

// protocolPtr returns a pointer to the protocol type.
func protocolPtr(protocol string) *corev1.Protocol {
	var p corev1.Protocol
	switch protocol {
	case "TCP":
		p = corev1.ProtocolTCP
	case "UDP":
		p = corev1.ProtocolUDP
	case "SCTP":
		p = corev1.ProtocolSCTP
	default:
		log.Warn().Msgf("Unknown protocol '%s', defaulting to TCP.", protocol)
		p = corev1.ProtocolTCP // Default to TCP for unknown protocols
	}
	return &p
}

// deduplicatePorts removes duplicate ports from a slice AND returns
// them in a deterministic order (numeric port ASC, then protocol ASC).
//
// The sort matters because the input order depends on whatever order
// PodTraffic rows arrived from the broker — and the broker's
// /pod/traffic/{name} has no ORDER BY, so two queries can return the
// same rows in different orders. Without the sort, a single peer's
// port list flips between e.g. [80,443] and [443,80] between
// regenerations of the same policy, surfacing as spurious YAML
// diff churn in operator workflows. The peer-IP sort in
// transformToNetworkPolicy{Ingress,Egress}Rules covers the outer
// dimension; this covers the inner.
func deduplicatePorts(ports []networkingv1.NetworkPolicyPort) []networkingv1.NetworkPolicyPort {
	uniquePorts := make(map[string]networkingv1.NetworkPolicyPort)
	var result []networkingv1.NetworkPolicyPort

	for _, port := range ports {
		if port.Port == nil || port.Protocol == nil {
			log.Warn().Msg("Skipping port with nil port or protocol during deduplication.")
			continue // Skip ports with nil values
		}
		key := fmt.Sprintf("%s-%s", port.Port.String(), string(*port.Protocol))
		if _, exists := uniquePorts[key]; !exists {
			uniquePorts[key] = port
			result = append(result, port)
		}
	}

	// Stable ordering: numeric port ASC, then protocol ASC (so a
	// peer that exposes 80/TCP, 80/UDP, 443/TCP comes out in that
	// canonical order regardless of which traffic event arrived
	// first). intstr.IntOrString can be String-typed for named
	// ports — fall back to .String() compare for those.
	sort.Slice(result, func(i, j int) bool {
		pi, pj := result[i].Port, result[j].Port
		// Numeric ports first, named ports after. Within each
		// kind, ascending.
		iNum := pi.Type == intstr.Int
		jNum := pj.Type == intstr.Int
		if iNum != jNum {
			return iNum // numeric < named
		}
		if iNum {
			if pi.IntVal != pj.IntVal {
				return pi.IntVal < pj.IntVal
			}
		} else if pi.StrVal != pj.StrVal {
			return pi.StrVal < pj.StrVal
		}
		// Same port — break by protocol string. Pointer non-nil
		// guaranteed by the skip above.
		return string(*result[i].Protocol) < string(*result[j].Protocol)
	})

	return result
}
