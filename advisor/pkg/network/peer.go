package network

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	log "github.com/rs/zerolog/log"
	networkingv1 "k8s.io/api/networking/v1"
)

// Peer attribution.
//
// pod_traffic rows store the peer IP, and pod IPs are recycled constantly
// (hourly Jobs, migrations: one IP had 50+ dead owners). Resolving the IP
// against today's pod table therefore names whoever holds the IP NOW, not
// whoever held it when the flow happened — autobrr was drawn talking to
// cmangos-database because it inherited a CronJob pod's IP months later.
//
// The fix (CONTRACT v4, mirroring how Cilium Hubble stamps endpoint identity
// at capture time) has two halves, both implemented here:
//
//  1. Rows the broker resolved at ingest carry peer_kind/peer_namespace/
//     peer_name (…); that identity is used verbatim and the IP is never
//     looked up again.
//  2. Rows with no stored peer (legacy, or the peer spec never arrived) are
//     resolved by IP under the START-TIME GUARD: a pod whose started_at is
//     later than the row's time_stamp cannot have been the peer. Candidates
//     are every known pod record holding the IP; alive ones are preferred,
//     then the newest start. If pods held the IP but none survives the guard
//     the peer is UNATTRIBUTED and rendered as an ipBlock/toCIDR with an
//     explanatory comment — never as a selector for the wrong pod.
//
// Rules are grouped by (peer IP, identity), not by IP alone, so one IP that
// was held by two different peers over the retention window yields two rules.
// The frontend and llm-bridge generators implement the same algorithm; the
// goldens in test/fixtures/generators/networkpolicy pin it.

// storedPeer is the identity the broker stamped on a traffic row at ingest.
type storedPeer struct {
	Kind         string // pod | node | service
	Namespace    string
	Name         string
	UID          string
	WorkloadKind string
	WorkloadName string
}

// storedPeerOf extracts the ingest-time identity from a row, or nil when the
// broker left it unresolved.
func storedPeerOf(t api.PodTraffic) *storedPeer {
	if t.PeerKind == "" {
		return nil
	}
	return &storedPeer{
		Kind: t.PeerKind, Namespace: t.PeerNamespace, Name: t.PeerName, UID: t.PeerUID,
		WorkloadKind: t.PeerWorkloadKind, WorkloadName: t.PeerWorkloadName,
	}
}

func (s *storedPeer) key() string {
	if s == nil {
		return ""
	}
	return s.Kind + ":" + s.Namespace + "/" + s.Name + "/" + s.UID
}

// resolvedPeer is the attributed identity of one observed peer. Exactly one
// of Pod / Svc is set for an attributed peer; both nil means "render the
// observed IP as a CIDR" — with a comment when Unattributed.
type resolvedPeer struct {
	IP string
	// Pod is the peer pod (plain or host-network). For Kind "node" it is the
	// host-network pod that holds the node IP.
	Pod *api.PodDetail
	// Svc is the peer Service; Backends its host-network backing pods (empty
	// for a Service backed by ordinary pods).
	Svc      *api.SvcDetail
	Backends []api.PodDetail
	// Unattributed: pods held this IP but none could have been the peer at
	// flow time (all started later), or the stored identity no longer
	// exists. The rule is pinned to the IP and commented.
	Unattributed bool
}

// identityKey groups rows for the same IP that resolved to the same
// rendering, and sorts sibling groups deterministically. It is derived from
// what is RENDERED (namespace + labels, or the host-network comment
// identity), so every implementation computes the same key from the same
// broker data:
//
//	"cidr"                              unresolved / external
//	"unattributed"                      guarded out
//	"host:<ns>/<workload-or-pod>"       host-network pod
//	"host:<ns>/svc/<name>"              Service backed by host-network pods
//	"sel:<ns>:k1=v1,k2=v2"              selector peer (labels sorted bytewise)
func (p resolvedPeer) identityKey() string {
	switch {
	case p.Unattributed:
		return "unattributed"
	case p.Svc != nil && len(p.Backends) > 0:
		return "host:" + p.Svc.SvcNamespace + "/svc/" + p.Svc.SvcName
	case p.Svc != nil:
		return "sel:" + p.Svc.SvcNamespace + ":" + canonicalLabels(p.Svc.Service.Spec.Selector)
	case p.Pod != nil && isHostNetwork(p.Pod):
		return "host:" + p.Pod.Namespace + "/" + hostWorkloadName(p.Pod)
	case p.Pod != nil && len(p.Pod.Pod.Labels) > 0:
		return "sel:" + p.Pod.Namespace + ":" + canonicalLabels(p.Pod.Pod.Labels)
	}
	return "cidr"
}

func canonicalLabels(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// unattributedPeerComment is the line rendered above an unattributed rule.
// at is the row time_stamp verbatim (the newest in the group); empty when
// no row carried one.
func unattributedPeerComment(ip, at string) string {
	if at == "" {
		return fmt.Sprintf("unattributed peer %s", ip)
	}
	return fmt.Sprintf("unattributed peer %s at %s", ip, at)
}

// brokerTimeLayouts are the forms a broker timestamp may take: the naive UTC
// chrono default ("2026-07-23T10:00:00.123456", no zone) and RFC 3339 (the
// API server's status.startTime, should a client pass it through).
var brokerTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
}

// parseBrokerTime parses a broker timestamp; a zone-less value is UTC. ok is
// false for an empty or unparseable string, which callers treat as
// "unknown" — never as a reason to exclude or prefer a candidate.
func parseBrokerTime(s string) (t time.Time, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range brokerTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// laterThan reports whether a (a pod's started_at) is strictly later than b
// (a row's time_stamp) — the start-time guard. Either side unknown ⇒ false:
// nothing to compare, so the candidate stays.
func laterThan(a, b string) bool {
	ta, okA := parseBrokerTime(a)
	tb, okB := parseBrokerTime(b)
	return okA && okB && ta.After(tb)
}

// newestTimeStamp picks the newest of the given broker timestamps and
// returns it VERBATIM (no reformatting, so every implementation prints the
// same text). Unparseable values are ignored; ties keep the first seen.
func newestTimeStamp(stamps []string) string {
	best, bestSet := "", false
	var bestT time.Time
	for _, s := range stamps {
		t, ok := parseBrokerTime(s)
		if !ok {
			continue
		}
		if !bestSet || t.After(bestT) {
			best, bestT, bestSet = s, t, true
		}
	}
	return best
}

func podHoldsIP(p *api.PodDetail, ip string) bool {
	if p.PodIP == ip {
		return true
	}
	for _, other := range p.PodIPs {
		if other == ip {
			return true
		}
	}
	return false
}

// peerResolver resolves rows to identities for one generation. It memoises
// per (ip, stored identity, time_stamp) so a pod with thousands of flows to
// the same peer costs one resolution, and fetches the pod listing at most
// once.
type peerResolver struct {
	data    BrokerData
	cache   map[string]resolvedPeer
	pods    []api.PodDetail
	podsSet bool
	// The broker reads depend on the IP alone; only the candidate choice is
	// time-dependent. Memoised per IP so N rows to one peer cost one fetch.
	svcByIP  map[string]svcLookup
	podByIPs map[string]podLookup
}

type svcLookup struct {
	svc *api.SvcDetail
	err error
}

type podLookup struct {
	pod *api.PodDetail
	err error
}

func newPeerResolver(data BrokerData) *peerResolver {
	if data == nil {
		data = DefaultBrokerData()
	}
	return &peerResolver{
		data: data, cache: map[string]resolvedPeer{},
		svcByIP: map[string]svcLookup{}, podByIPs: map[string]podLookup{},
	}
}

func (r *peerResolver) serviceByIP(ip string) (*api.SvcDetail, error) {
	if l, ok := r.svcByIP[ip]; ok {
		return l.svc, l.err
	}
	svc, err := r.data.ServiceByIP(ip)
	r.svcByIP[ip] = svcLookup{svc, err}
	return svc, err
}

func (r *peerResolver) podByIP(ip string) (*api.PodDetail, error) {
	if l, ok := r.podByIPs[ip]; ok {
		return l.pod, l.err
	}
	pod, err := r.data.PodByIP(ip)
	r.podByIPs[ip] = podLookup{pod, err}
	return pod, err
}

// listing returns the broker's pod listing, fetched once. A failed listing
// is logged and treated as empty: stored identities then cannot be
// materialised (unattributed) and by-IP resolution sees only the
// PodByIP record.
func (r *peerResolver) listing() []api.PodDetail {
	if !r.podsSet {
		r.podsSet = true
		pods, err := r.data.Pods()
		if err != nil {
			log.Warn().Err(err).Msg("Cannot list pods; peer attribution falls back to the by-IP record only")
		}
		r.pods = pods
	}
	return r.pods
}

// resolveRow resolves the peer of one traffic row.
func (r *peerResolver) resolveRow(peerIP string, t api.PodTraffic) resolvedPeer {
	return r.resolve(peerIP, storedPeerOf(t), t.TimeStamp)
}

// resolveIP resolves a bare IP with no row context — no stored identity and
// no time, so the guard cannot exclude anything. This is the pre-v4
// behaviour, kept for callers that only have an IP.
func (r *peerResolver) resolveIP(peerIP string) resolvedPeer {
	return r.resolve(peerIP, nil, "")
}

func (r *peerResolver) resolve(peerIP string, stored *storedPeer, at string) resolvedPeer {
	key := peerIP + "\x00" + stored.key() + "\x00" + at
	if p, ok := r.cache[key]; ok {
		return p
	}
	var p resolvedPeer
	if stored != nil {
		p = r.resolveStored(peerIP, stored)
	} else {
		p = r.resolveByIP(peerIP, at)
	}
	r.cache[key] = p
	return p
}

// resolveStored materialises an ingest-time identity: the pod (or
// host-network pod) by namespace + name (+ uid when both sides know it)
// from the listing, or the Service by ClusterIP when it is still the same
// Service. An identity that no longer exists is unattributed — the IP is
// NOT re-resolved, that would recreate the bug the stored identity exists
// to prevent.
func (r *peerResolver) resolveStored(peerIP string, s *storedPeer) resolvedPeer {
	switch s.Kind {
	case "pod", "node":
		if s.Name == "" {
			// A bare node IP with no host-network pod: nothing to select.
			return resolvedPeer{IP: peerIP}
		}
		pods := r.listing()
		for i := range pods {
			p := &pods[i]
			if p.Name != s.Name || p.Namespace != s.Namespace {
				continue
			}
			if uid := string(p.Pod.UID); uid != "" && s.UID != "" && uid != s.UID {
				continue
			}
			return resolvedPeer{IP: peerIP, Pod: p}
		}
		log.Warn().Msgf("Stored peer %s/%s (%s) for IP %s is no longer known; pinning the IP", s.Namespace, s.Name, s.Kind, peerIP)
		return resolvedPeer{IP: peerIP, Unattributed: true}
	case "service":
		svc, err := r.serviceByIP(peerIP)
		if err == nil && svc != nil && svc.SvcName == s.Name && svc.SvcNamespace == s.Namespace &&
			len(svc.Service.Spec.Selector) > 0 {
			return resolvedPeer{IP: peerIP, Svc: svc, Backends: hostNetworkServiceBackends(r.data, svc)}
		}
		if err != nil {
			log.Debug().Err(err).Msgf("Error fetching service spec for IP %s", peerIP)
		}
		log.Warn().Msgf("Stored peer service %s/%s for IP %s no longer matches; pinning the IP", s.Namespace, s.Name, peerIP)
		return resolvedPeer{IP: peerIP, Unattributed: true}
	}
	log.Warn().Msgf("Unknown stored peer kind %q for IP %s; resolving by IP", s.Kind, peerIP)
	return r.resolveByIP(peerIP, "")
}

// resolveByIP is the guarded fallback for rows with no stored identity:
// Service by ClusterIP first (a ClusterIP is not recycled the way pod IPs
// are), then the pod candidates holding the IP under the start-time guard.
func (r *peerResolver) resolveByIP(peerIP, at string) resolvedPeer {
	svc, err := r.serviceByIP(peerIP)
	if err == nil && svc != nil && len(svc.Service.Spec.Selector) > 0 {
		log.Debug().Msgf("Found service %s/%s with selector %v for IP %s", svc.SvcNamespace, svc.SvcName, svc.Service.Spec.Selector, peerIP)
		return resolvedPeer{IP: peerIP, Svc: svc, Backends: hostNetworkServiceBackends(r.data, svc)}
	}
	if err != nil {
		log.Debug().Err(err).Msgf("Error fetching service spec for IP %s, trying pod", peerIP)
	} else if svc != nil {
		log.Debug().Msgf("Service %s/%s found for IP %s but has no selector, trying pod", svc.SvcNamespace, svc.SvcName, peerIP)
	}

	candidates := r.candidatesByIP(peerIP)
	if len(candidates) == 0 {
		log.Debug().Msgf("No pod found for IP %s, falling back to CIDR", peerIP)
		return resolvedPeer{IP: peerIP}
	}
	chosen := choosePeerCandidate(candidates, at)
	if chosen == nil {
		log.Warn().Msgf("Every pod that held IP %s started after the flow at %s; leaving the peer unattributed", peerIP, at)
		return resolvedPeer{IP: peerIP, Unattributed: true}
	}
	return resolvedPeer{IP: peerIP, Pod: chosen}
}

// candidatesByIP is every pod record known to hold the IP: the listing plus
// the broker's own by-IP record (the same table, but a stub or an older
// broker may only serve one of them). Deduplicated by namespace/name.
func (r *peerResolver) candidatesByIP(peerIP string) []*api.PodDetail {
	var out []*api.PodDetail
	seen := map[string]bool{}
	add := func(p *api.PodDetail) {
		if p == nil {
			return
		}
		k := p.Namespace + "/" + p.Name
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, p)
	}
	pods := r.listing()
	for i := range pods {
		if podHoldsIP(&pods[i], peerIP) {
			add(&pods[i])
		}
	}
	byIP, err := r.podByIP(peerIP)
	if err != nil {
		log.Debug().Err(err).Msgf("Error fetching pod spec for IP %s", peerIP)
	}
	add(byIP)
	return out
}

// choosePeerCandidate applies the start-time guard and the broker's
// precedence: drop candidates started after the flow; prefer alive; then the
// newest started_at (unknown last); then the newest record; then name, so
// the choice is stable. nil when the guard removed every candidate.
func choosePeerCandidate(candidates []*api.PodDetail, at string) *api.PodDetail {
	var kept []*api.PodDetail
	for _, c := range candidates {
		if laterThan(c.StartedAt, at) {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return nil
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.IsDead != b.IsDead {
			return !a.IsDead
		}
		if c := compareBrokerTimesDesc(a.StartedAt, b.StartedAt); c != 0 {
			return c < 0
		}
		if c := compareBrokerTimesDesc(a.TimeStamp, b.TimeStamp); c != 0 {
			return c < 0
		}
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	return kept[0]
}

// peerGroup is one emitted rule's worth of input: a resolved peer and every
// port it was observed on.
type peerGroup struct {
	peer   resolvedPeer
	ports  []networkingv1.NetworkPolicyPort
	stamps []string
}

// groupPeerRules folds rules into one group per (peer IP, identity), ordered
// by the raw peer IP bytewise (as before — never canonicalised first) and
// then by identity key, so output is deterministic and every pre-existing
// scenario (one identity per IP) keeps its order. Rules with no resolved
// peer are resolved here from the IP alone.
func groupPeerRules(rules []NetworkPolicyRule, resolver *peerResolver) []peerGroup {
	groups := map[string]*peerGroup{}
	var keys []string
	for _, rule := range rules {
		peer := resolvedPeer{IP: rule.PeerIP}
		if rule.Peer != nil {
			peer = *rule.Peer
		} else if resolver != nil {
			peer = resolver.resolveIP(rule.PeerIP)
		}
		key := rule.PeerIP + "\x00" + peer.identityKey()
		g, ok := groups[key]
		if !ok {
			g = &peerGroup{peer: peer}
			groups[key] = g
			keys = append(keys, key)
		}
		g.ports = append(g.ports, rule.Ports...)
		g.stamps = append(g.stamps, rule.Stamps...)
	}
	sort.Strings(keys)
	out := make([]peerGroup, 0, len(keys))
	for _, k := range keys {
		out = append(out, *groups[k])
	}
	return out
}

// compareBrokerTimesDesc orders known timestamps newest-first and unknown
// ones last; 0 when equal or both unknown.
func compareBrokerTimesDesc(a, b string) int {
	ta, okA := parseBrokerTime(a)
	tb, okB := parseBrokerTime(b)
	switch {
	case okA && okB:
		if ta.After(tb) {
			return -1
		}
		if tb.After(ta) {
			return 1
		}
		return 0
	case okA:
		return -1
	case okB:
		return 1
	}
	return 0
}
