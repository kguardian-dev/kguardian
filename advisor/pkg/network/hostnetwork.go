package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/common"
	log "github.com/rs/zerolog/log"
	"sigs.k8s.io/yaml"
)

// Host-network peers and targets.
//
// A pod running with spec.hostNetwork: true has no pod IP of its own — it
// shares the node's IP and, to the CNI, carries the node's identity. A
// NetworkPolicy podSelector (or Cilium endpointSelector) built from that pod's
// labels therefore never matches its traffic; the rule is silently
// ineffective. The generators handle two cases:
//
//   - a PEER resolves to a host-network pod: emit the observed node IP as an
//     ipBlock (NetworkPolicy) or the host + remote-node entities (Cilium)
//     instead of a label selector, and leave a YAML comment above the rule
//     saying why.
//   - the TARGET pod is itself host-network: the policy is emitted unchanged
//     but headed by a WARNING comment block — no selector can select it, and
//     the right tool is a CiliumClusterwideNetworkPolicy with a nodeSelector.
//
// The Kubernetes API types cannot carry comments, so the generators return
// them beside the policy in a PolicyComments and MarshalPolicyYAML splices
// them into the marshalled text. With no comments the output is byte-identical
// to yaml.Marshal, which is what keeps every pre-existing golden unchanged.

// PolicyComments is the set of YAML comments a generator wants rendered with a
// policy. Header lines precede the document; Ingress/Egress map a rule index
// (position in spec.ingress / spec.egress) to the comment lines rendered
// directly above that rule. Lines are stored without the leading "# ".
type PolicyComments struct {
	Header  []string
	Ingress map[int][]string
	Egress  map[int][]string
}

// CommentedPolicyGenerator is implemented by generators that can explain
// their output. PolicyService prefers it when available; plain
// PolicyGenerator implementations keep working unchanged.
type CommentedPolicyGenerator interface {
	PolicyGenerator
	// GenerateWithComments is Generate plus the comments to render with the
	// policy. The returned *PolicyComments may be nil.
	GenerateWithComments(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, *PolicyComments, error)
}

// IsEmpty reports whether there is nothing to render.
func (c *PolicyComments) IsEmpty() bool {
	return c == nil || (len(c.Header) == 0 && len(c.Ingress) == 0 && len(c.Egress) == 0)
}

func (c *PolicyComments) addHeader(lines ...string) {
	if c == nil {
		return
	}
	c.Header = append(c.Header, lines...)
}

func (c *PolicyComments) addIngress(idx int, line string) {
	if c == nil || line == "" {
		return
	}
	if c.Ingress == nil {
		c.Ingress = map[int][]string{}
	}
	c.Ingress[idx] = append(c.Ingress[idx], line)
}

func (c *PolicyComments) addEgress(idx int, line string) {
	if c == nil || line == "" {
		return
	}
	if c.Egress == nil {
		c.Egress = map[int][]string{}
	}
	c.Egress[idx] = append(c.Egress[idx], line)
}

func (c *PolicyComments) ruleLines(section string, idx int) []string {
	if c == nil {
		return nil
	}
	switch section {
	case "ingress":
		return c.Ingress[idx]
	case "egress":
		return c.Egress[idx]
	}
	return nil
}

// MarshalPolicyYAML marshals a generated policy exactly as yaml.Marshal does
// and then splices the comments in. A nil or empty PolicyComments yields the
// yaml.Marshal bytes untouched.
func MarshalPolicyYAML(policy interface{}, comments *PolicyComments) ([]byte, error) {
	out, err := yaml.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return insertComments(out, comments), nil
}

// insertComments places Header lines before the document and each rule
// comment directly above its rule, at the rule's indentation.
//
// It works on the text sigs.k8s.io/yaml emits — two-space indentation, block
// sequences at the same column as their parent key — so a rule under
// `spec:`/`  egress:` starts with "  - ". Rules are counted in order within
// the section; the section ends at the next line at indent <= 2 that is not a
// rule start. Only the top-level `spec` key is inspected, so an `ingress` key
// anywhere else (a label, say) is never mistaken for the rule list.
func insertComments(doc []byte, c *PolicyComments) []byte {
	if c.IsEmpty() {
		return doc
	}
	text := strings.TrimRight(string(doc), "\n")
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+len(c.Header)+len(c.Ingress)+len(c.Egress))

	for _, h := range c.Header {
		out = append(out, "# "+h)
	}

	top, section := "", ""
	idx := -1
	for _, line := range lines {
		switch {
		case line != "" && line[0] != ' ':
			top = strings.TrimSuffix(line, ":")
			section = ""
		case top == "spec" && (line == "  ingress:" || line == "  egress:"):
			section = strings.TrimSpace(strings.TrimSuffix(line, ":"))
			idx = -1
		case section != "":
			if strings.HasPrefix(line, "  - ") {
				idx++
				for _, cm := range c.ruleLines(section, idx) {
					out = append(out, "  # "+cm)
				}
			} else if !strings.HasPrefix(line, "    ") {
				section = ""
			}
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// isHostNetwork is true only when the broker positively reports
// host_network: true. nil (old broker / unknown) and false both mean "treat
// as a normal pod" — the pre-existing behaviour.
func isHostNetwork(d *api.PodDetail) bool {
	return d != nil && d.HostNetwork != nil && *d.HostNetwork
}

// hostWorkloadName names a host-network pod in comments: the owning workload
// when the broker knows it (stable across restarts), else the pod name.
func hostWorkloadName(d *api.PodDetail) string {
	if d.WorkloadName != "" {
		return d.WorkloadName
	}
	return d.Name
}

// hostNodeName names the node a host-network peer runs on: the broker's flat
// node_name, then the manifest's spec.nodeName, then the observed IP itself
// (which for a host-network pod IS the node address).
func hostNodeName(d *api.PodDetail, peerIP string) string {
	if d.NodeName != "" {
		return d.NodeName
	}
	if d.Pod.Spec.NodeName != "" {
		return d.Pod.Spec.NodeName
	}
	return peerIP
}

// hostNetworkPeerComment is the line rendered above a rule whose peer is a
// host-network pod. selector is the field the reader would otherwise expect
// ("podSelector" for NetworkPolicy, "endpointSelector" for Cilium).
func hostNetworkPeerComment(d *api.PodDetail, peerIP, selector string) string {
	return fmt.Sprintf("host-network peer %s/%s on node %s — %s cannot match host traffic",
		d.Namespace, hostWorkloadName(d), hostNodeName(d, peerIP), selector)
}

// hostNetworkTargetWarning is the header block for a policy whose target pod
// is itself host-network. kind/selector name the emitted resource and its
// selector field ("NetworkPolicy"/"podSelector", "CiliumNetworkPolicy"/
// "endpointSelector").
func hostNetworkTargetWarning(d *api.PodDetail, kind, selector string) []string {
	return []string{
		fmt.Sprintf("WARNING: %s/%s runs with hostNetwork: true. A %s %s cannot select",
			d.Namespace, hostWorkloadName(d), kind, selector),
		"host-network pods; this policy will have no effect. Use a CiliumClusterwideNetworkPolicy",
		"with a nodeSelector (host firewall) instead.",
	}
}

// hostNetworkServiceBackends returns the host-network pods backing svc: alive
// pods in the Service's namespace whose labels contain the whole selector,
// sorted by name. Empty when the Service has no selector, no backing pods, or
// none of them is host-network. A failed pod listing is logged and treated as
// "unknown" — the pre-existing podSelector rendering.
func hostNetworkServiceBackends(data BrokerData, svc *api.SvcDetail) []api.PodDetail {
	if svc == nil || len(svc.Service.Spec.Selector) == 0 || data == nil {
		return nil
	}
	pods, err := data.Pods()
	if err != nil {
		log.Warn().Err(err).Msgf("Cannot list pods to inspect backends of service %s/%s; assuming pod-network", svc.SvcNamespace, svc.SvcName)
		return nil
	}
	var out []api.PodDetail
	for _, p := range pods {
		if p.IsDead || p.Namespace != svc.SvcNamespace || !isHostNetwork(&p) {
			continue
		}
		if !labelsContain(p.Pod.Labels, svc.Service.Spec.Selector) {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func labelsContain(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// hostNetworkServiceComment is the rule comment for a Service whose backing
// pods are host-network. The Service is named "<ns>/svc/<name>"; the node is
// the sorted, deduplicated node list of the host-network backends (a
// ClusterIP has no single node), falling back to the observed IP.
func hostNetworkServiceComment(svc *api.SvcDetail, backends []api.PodDetail, peerIP, selector string) string {
	seen := map[string]bool{}
	var nodes []string
	for i := range backends {
		n := hostNodeName(&backends[i], "")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	node := strings.Join(nodes, ",")
	if node == "" {
		node = peerIP
	}
	return fmt.Sprintf("host-network peer %s/svc/%s on node %s — %s cannot match host traffic",
		svc.SvcNamespace, svc.SvcName, node, selector)
}

// hostNetworkServiceCIDRs is the NetworkPolicy peer set for a Service backed
// by host-network pods: one host CIDR per distinct backend pod IP (which IS a
// node IP), sorted bytewise on the raw IP like every other peer. NetworkPolicy
// is evaluated against the post-DNAT destination, so the ClusterIP itself is
// never the right peer. Unparseable IPs are skipped; an empty result means
// the caller drops the rule.
func hostNetworkServiceCIDRs(backends []api.PodDetail) []string {
	seen := map[string]bool{}
	var ips []string
	for _, b := range backends {
		if b.PodIP == "" || seen[b.PodIP] {
			continue
		}
		seen[b.PodIP] = true
		ips = append(ips, b.PodIP)
	}
	sort.Strings(ips)
	var cidrs []string
	for _, ip := range ips {
		cidr, err := common.HostCIDR(ip)
		if err != nil {
			log.Warn().Err(err).Msgf("Skipping host-network backend %s: cannot express it as a host CIDR", ip)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

// hostEntities is the Cilium entity list for a host-network peer. Both are
// needed: `host` is the local node, `remote-node` every other node, and the
// peer may sit on either.
var hostEntities = []string{"host", "remote-node"}
