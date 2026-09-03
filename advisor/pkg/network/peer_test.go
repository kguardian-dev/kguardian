package network

import (
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Peer attribution (CONTRACT v4): stored identity first, else by IP under the
// start-time guard. The goldens pin the rendered output; these tests pin the
// decision rules the goldens cannot show one by one.

func v4Pod(name, ns, ip, startedAt string, dead bool, labels map[string]string) api.PodDetail {
	return api.PodDetail{
		Name: name, Namespace: ns, PodIP: ip, StartedAt: startedAt, IsDead: dead,
		Pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}},
	}
}

func rowAt(ip, ts string) api.PodTraffic {
	return api.PodTraffic{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "80", DstIP: ip, Protocol: "TCP", TimeStamp: ts}
}

func TestParseBrokerTime(t *testing.T) {
	naive, ok := parseBrokerTime("2026-07-23T10:00:00")
	require.True(t, ok)
	fraction, ok := parseBrokerTime("2026-07-23T10:00:00.123456")
	require.True(t, ok)
	rfc, ok := parseBrokerTime("2026-07-23T12:00:00+02:00")
	require.True(t, ok)
	assert.True(t, fraction.After(naive))
	assert.True(t, rfc.Equal(naive), "an offset is converted to UTC")
	for _, bad := range []string{"", "  ", "yesterday", "2026-07-23"} {
		_, ok := parseBrokerTime(bad)
		assert.False(t, ok, "%q must be unknown", bad)
	}
}

func TestStartTimeGuard_ExcludedByGuard(t *testing.T) {
	assert.True(t, excludedByGuard("2026-08-04T09:12:41", "2026-07-23T10:00:00"), "started after the flow ⇒ excluded")
	assert.False(t, excludedByGuard("2026-07-23T10:00:00", "2026-07-23T10:00:00"), "equal is not after")
	assert.False(t, excludedByGuard("2026-07-01T00:00:00", "2026-07-23T10:00:00"))
	assert.True(t, excludedByGuard("", "2026-07-23T10:00:00"), "unknown start is a ghost/Pending row ⇒ excluded")
	assert.False(t, excludedByGuard("2026-08-04T09:12:41", ""), "no flow time ⇒ nothing to compare")
	assert.False(t, excludedByGuard("", ""), "no flow time ⇒ nothing to compare")
}

func TestChoosePeerCandidate_Precedence(t *testing.T) {
	deadOld := v4Pod("job-old", "ns", "10.0.0.9", "2026-07-01T00:00:00", true, nil)
	deadNew := v4Pod("job-new", "ns", "10.0.0.9", "2026-07-20T00:00:00", true, nil)
	deadUnknown := v4Pod("job-unknown", "ns", "10.0.0.9", "", true, nil)
	aliveUnknown := v4Pod("ghost", "ns", "10.0.0.9", "", false, nil)
	alive := v4Pod("deploy", "ns", "10.0.0.9", "2026-07-10T00:00:00", false, nil)
	all := []*api.PodDetail{&deadOld, &deadNew, &deadUnknown, &aliveUnknown, &alive}

	assert.Equal(t, "deploy", choosePeerCandidate(all, "2026-07-23T10:00:00").Name, "alive with a known start wins")
	assert.Equal(t, "job-new", choosePeerCandidate([]*api.PodDetail{&deadOld, &deadUnknown, &deadNew}, "2026-07-23T10:00:00").Name, "newest known start among the dead")
	assert.Equal(t, "job-old", choosePeerCandidate(all, "2026-07-05T00:00:00").Name, "guard drops everything started after the flow and every unknown start")
	assert.Nil(t, choosePeerCandidate([]*api.PodDetail{&deadUnknown, &aliveUnknown}, "2026-07-05T00:00:00"), "unknown start is never a candidate, alive or not")
	assert.Nil(t, choosePeerCandidate([]*api.PodDetail{&deadNew, &alive}, "2026-06-01T00:00:00"), "every candidate started later ⇒ unattributed")
	assert.Equal(t, "deploy", choosePeerCandidate(all, "").Name, "no flow time ⇒ no guard, pre-v4 precedence (unknown start ranks last)")
	assert.Equal(t, "ghost", choosePeerCandidate([]*api.PodDetail{&deadOld, &aliveUnknown}, "").Name, "no flow time ⇒ alive still preferred")
}

func TestResolveByIP_GhostRowWithUnknownStartIsUnattributed(t *testing.T) {
	// Live finding: ghost pod_details rows (NULL started_at) absorbed old
	// flows. With a row time_stamp, such a row is not a candidate.
	ghost := v4Pod("ghost", "ns", "10.0.0.9", "", false, map[string]string{"app": "ghost"})
	r := newPeerResolver(stubBrokerData{allPods: []api.PodDetail{ghost}})
	got := r.resolveRow("10.0.0.9", rowAt("10.0.0.9", "2026-07-23T10:00:00"))
	assert.True(t, got.Unattributed)
	assert.Nil(t, got.Pod)
}

func TestResolveByIP_GuardedOutIsUnattributed_ExternalIsNot(t *testing.T) {
	autobrr := v4Pod("autobrr", "home-system", "10.244.12.199", "2026-08-04T09:12:41", false, map[string]string{"app": "autobrr"})
	r := newPeerResolver(stubBrokerData{allPods: []api.PodDetail{autobrr}})

	stale := r.resolveRow("10.244.12.199", rowAt("10.244.12.199", "2026-07-23T10:00:00"))
	assert.True(t, stale.Unattributed)
	assert.Nil(t, stale.Pod)
	assert.Equal(t, "unattributed", stale.identityKey())

	fresh := r.resolveRow("10.244.12.199", rowAt("10.244.12.199", "2026-08-05T00:00:00"))
	require.NotNil(t, fresh.Pod)
	assert.Equal(t, "autobrr", fresh.Pod.Name)
	assert.Equal(t, "sel:home-system:app=autobrr", fresh.identityKey())

	external := r.resolveRow("8.8.8.8", rowAt("8.8.8.8", "2026-07-23T10:00:00"))
	assert.False(t, external.Unattributed, "no candidate at all is a plain CIDR, not unattributed")
	assert.Equal(t, "cidr", external.identityKey())
}

func TestResolveByIP_UnionsListingAndByIPRecord(t *testing.T) {
	// The listing and the /pod/ip record are the same table; a stub may
	// serve either. Both feed the candidate set, deduplicated by ns/name.
	viaIP := podDetail("frontend-1", "10.0.0.7", map[string]string{"app": "frontend"})
	viaIP.StartedAt = "2026-08-04T00:00:00"
	older := v4Pod("job-1", "prod", "10.0.0.7", "2026-07-01T00:00:00", true, map[string]string{"app": "job"})
	r := newPeerResolver(stubBrokerData{
		pods:    map[string]*api.PodDetail{"10.0.0.7": viaIP},
		allPods: []api.PodDetail{older, *viaIP},
	})
	got := r.resolveRow("10.0.0.7", rowAt("10.0.0.7", "2026-07-15T00:00:00"))
	require.NotNil(t, got.Pod)
	assert.Equal(t, "job-1", got.Pod.Name, "the alive pod started after the flow; the dead one held the IP then")
	got = r.resolveIP("10.0.0.7")
	require.NotNil(t, got.Pod)
	assert.Equal(t, "frontend-1", got.Pod.Name, "no row context ⇒ alive wins")
}

func TestResolveStored_UsedVerbatim_NeverByIP(t *testing.T) {
	now := v4Pod("autobrr", "home-system", "10.244.12.199", "", false, map[string]string{"app": "autobrr"})
	then := v4Pod("cmangos-backup-1", "game-servers", "10.244.12.199", "2026-09-03T04:59:30", true, map[string]string{"app": "cmangos-backup"})
	then.Pod.UID = "uid-then"
	r := newPeerResolver(stubBrokerData{allPods: []api.PodDetail{now, then}})

	row := rowAt("10.244.12.199", "2026-09-03T05:00:00")
	row.PeerKind, row.PeerNamespace, row.PeerName, row.PeerUID = "pod", "game-servers", "cmangos-backup-1", "uid-then"
	got := r.resolveRow("10.244.12.199", row)
	require.NotNil(t, got.Pod)
	assert.Equal(t, "cmangos-backup-1", got.Pod.Name)

	// A uid mismatch is a different pod of the same name: not materialised.
	row.PeerUID = "uid-other"
	assert.True(t, r.resolveRow("10.244.12.199", row).Unattributed)

	// A stored pod that is gone is unattributed — the IP is NOT re-resolved
	// to autobrr.
	row.PeerName, row.PeerUID = "cmangos-backup-gone", ""
	gone := r.resolveRow("10.244.12.199", row)
	assert.True(t, gone.Unattributed)
	assert.Nil(t, gone.Pod)
}

func TestResolveStored_ServiceMustStillMatch(t *testing.T) {
	svc := &api.SvcDetail{SvcName: "db", SvcNamespace: "prod", SvcIp: "10.96.0.10",
		Service: corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "db"}}}}
	r := newPeerResolver(stubBrokerData{svcs: map[string]*api.SvcDetail{"10.96.0.10": svc}})
	row := rowAt("10.96.0.10", "2026-09-03T05:00:00")
	row.PeerKind, row.PeerNamespace, row.PeerName = "service", "prod", "db"
	assert.Equal(t, svc, r.resolveRow("10.96.0.10", row).Svc)
	row.PeerName = "db-old"
	assert.True(t, r.resolveRow("10.96.0.10", row).Unattributed, "the ClusterIP now belongs to another Service")
}

func TestGroupPeerRules_OrdersByIPThenIdentity(t *testing.T) {
	// One IP held by two Jobs over the window: two stored identities ⇒ two
	// rules, never merged. Order: raw IP bytewise, then identity key.
	jobA := v4Pod("job-a", "batch", "10.0.0.5", "2026-07-01T00:00:00", true, map[string]string{"app": "a"})
	jobB := v4Pod("job-b", "batch", "10.0.0.5", "2026-07-02T00:00:00", true, map[string]string{"app": "b"})
	r := newPeerResolver(stubBrokerData{allPods: []api.PodDetail{jobA, jobB}})
	stored := func(ip, ts, name string) api.PodTraffic {
		row := rowAt(ip, ts)
		row.PeerKind, row.PeerNamespace, row.PeerName = "pod", "batch", name
		return row
	}
	var rules []NetworkPolicyRule
	for _, row := range []api.PodTraffic{
		stored("10.0.0.5", "2026-07-02T01:00:00", "job-b"),
		stored("10.0.0.5", "2026-07-01T01:00:00", "job-a"),
		rowAt("10.0.0.10", "2026-07-01T01:00:00"), // external, no candidates
		stored("10.0.0.5", "2026-07-02T02:00:00", "job-b"),
	} {
		rules = mergeOrAppendResolvedRule(rules, r.resolveRow(row.DstIP, row), intstr.FromInt(80), "TCP", row.TimeStamp)
	}
	require.Len(t, rules, 3, "job-b's two rows merge; job-a stays separate")

	groups := groupPeerRules(rules, r)
	require.Len(t, groups, 3)
	assert.Equal(t, "10.0.0.10", groups[0].peer.IP, "10.0.0.10 sorts before 10.0.0.5 bytewise")
	assert.Equal(t, "10.0.0.5", groups[1].peer.IP)
	assert.Equal(t, "sel:batch:app=a", groups[1].peer.identityKey())
	assert.Equal(t, "10.0.0.5", groups[2].peer.IP)
	assert.Equal(t, "sel:batch:app=b", groups[2].peer.identityKey())
	assert.Equal(t, []string{"2026-07-02T01:00:00", "2026-07-02T02:00:00"}, groups[2].stamps)
}

func TestUnattributedComment_QuotesNewestStampVerbatim(t *testing.T) {
	assert.Equal(t, "2026-07-23T10:00:00", newestTimeStamp([]string{"2026-05-21T08:30:00", "2026-07-23T10:00:00", "junk"}))
	assert.Equal(t, "", newestTimeStamp([]string{"junk", ""}))
	assert.Equal(t, "unattributed peer 10.244.12.199 at 2026-07-23T10:00:00", unattributedPeerComment("10.244.12.199", "2026-07-23T10:00:00"))
	assert.Equal(t, "unattributed peer 10.244.12.199", unattributedPeerComment("10.244.12.199", ""))
}

func TestGenerators_NeverSelectGuardedOutPeer(t *testing.T) {
	// End to end through both generators: the only pod holding the IP
	// started after the flow, so the rule must be an IP pin with the
	// unattributed comment — no podSelector, no fromEndpoints.
	autobrr := v4Pod("autobrr", "home-system", "10.244.12.199", "2026-08-04T09:12:41", false, map[string]string{"app": "autobrr"})
	stub := stubBrokerData{allPods: []api.PodDetail{autobrr}}
	target := fixturePodDetail("cmangos-database", "game-servers", "10.244.3.17", map[string]string{"app": "cmangos-database"})
	traffic := []api.PodTraffic{{TrafficType: "INGRESS", SrcIP: "10.244.3.17", SrcPodPort: "3306", DstIP: "10.244.12.199", Protocol: "TCP", TimeStamp: "2026-07-23T10:00:00"}}

	std := NewStandardPolicyGenerator()
	std.setBrokerData(stub)
	policy, comments, err := std.GenerateWithComments("cmangos-database", traffic, target)
	require.NoError(t, err)
	out, err := MarshalPolicyYAML(policy, comments)
	require.NoError(t, err)
	assert.Contains(t, string(out), "# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00")
	assert.Contains(t, string(out), "cidr: 10.244.12.199/32")
	assert.NotContains(t, string(out), "app: autobrr")

	cil := NewCiliumPolicyGenerator()
	cil.setBrokerData(stub)
	policy, comments, err = cil.GenerateWithComments("cmangos-database", traffic, target)
	require.NoError(t, err)
	out, err = MarshalPolicyYAML(policy, comments)
	require.NoError(t, err)
	assert.Contains(t, string(out), "# unattributed peer 10.244.12.199 at 2026-07-23T10:00:00")
	assert.Contains(t, string(out), "fromCIDR:\n    - 10.244.12.199/32")
	assert.NotContains(t, string(out), "k8s:app: autobrr")
}
