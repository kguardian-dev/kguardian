package appprofile

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeBroker serves canned profiles and versions keyed by revision.
type fakeBroker struct {
	profile    *Profile
	profileErr error
	versions   map[int64]*Version
	versionErr error
	calls      []string
}

func (f *fakeBroker) Profile(_ context.Context, ns, kind, name string) (*Profile, error) {
	f.calls = append(f.calls, "profile "+ns+"/"+kind+"/"+name)
	return f.profile, f.profileErr
}

func (f *fakeBroker) Version(_ context.Context, ns, kind, name string, rev int64) (*Version, error) {
	f.calls = append(f.calls, "version "+ns+"/"+kind+"/"+name+" "+itoa(rev))
	if f.versionErr != nil {
		return nil, f.versionErr
	}
	v, ok := f.versions[rev]
	if !ok {
		return nil, &BrokerError{StatusCode: 404, Code: "revision_not_found", Message: "no such revision"}
	}
	return v, nil
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func ptr[T any](v T) *T { return &v }

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// testStaleAfter is the staleness window used by computeStatus tests.
const testStaleAfter = 15 * time.Minute

// profileFixture follows the contract's refunds example (v1.3): warn with
// three unknown core dimensions, so posture must not read ok.
func profileFixture() *Profile {
	cov := 0.25
	p := &Profile{
		ContentHash:     "fnv1a64:live",
		Version:         &VersionRef{Revision: 3, ContentHash: "fnv1a64:rev3", CreatedAt: "2026-09-26T02:22:26.368580Z"},
		SnapshotPending: false,
		Posture: ProfilePosture{
			Status:            "warn",
			Coverage:          &cov,
			UnknownDimensions: []string{"network", "syscalls", "images"},
		},
		Dimensions: map[string]Dim{},
		Findings: []Finding{
			{Severity: "medium"}, {Severity: "medium"}, {Severity: "low"}, {Severity: "high"},
		},
	}
	p.Posture.Reasons = []PostureReason{{Dimension: "network", Status: "unknown", Message: "No flows observed for this workload's pods"}}
	dim := func(status, code, msg string) Dim {
		return Dim{Status: status, Reasons: []Reason{{Code: code, Message: msg}}}
	}
	p.Dimensions["network"] = dim("unknown", "no_flows", "No flows observed")
	p.Dimensions["syscalls"] = dim("unknown", "no_observations", "No syscalls captured")
	p.Dimensions["podSecurity"] = dim("warn", "pss_fails_restricted", "At most baseline")
	p.Dimensions["images"] = dim("unknown", "vulnerabilities_not_configured", "1 running digest(s) across 1 container(s); vulnerability data not configured")
	// compute deliberately absent.
	return p
}

func aspFixture(accepted *int64) *v1alpha1.ApplicationSecurityProfile {
	return &v1alpha1.ApplicationSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "refunds", Namespace: "payments", Generation: 2},
		Spec: v1alpha1.ApplicationSecurityProfileSpec{
			WorkloadRef:      v1alpha1.WorkloadRef{Kind: "Deployment", Name: "refunds"},
			AcceptedRevision: accepted,
		},
	}
}

func cond(t *testing.T, s v1alpha1.ApplicationSecurityProfileStatus, typ string) metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(s.Conditions, typ)
	if c == nil {
		t.Fatalf("condition %s missing; have %+v", typ, s.Conditions)
	}
	return *c
}

func TestComputeStatus_CopiesPostureWithoutUpgradingUnknown(t *testing.T) {
	b := &fakeBroker{profile: profileFixture()}
	st, err := computeStatus(context.Background(), b, aspFixture(nil), now, testStaleAfter)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st.ObservedGeneration != 2 {
		t.Errorf("observedGeneration = %d, want 2", st.ObservedGeneration)
	}
	if st.Posture.Status != "warn" || st.Posture.Coverage != "0.25" {
		t.Errorf("posture = %+v", st.Posture)
	}
	if !reflect.DeepEqual(st.Posture.UnknownDimensions, []string{"network", "syscalls", "images"}) {
		t.Errorf("unknownDimensions = %v", st.Posture.UnknownDimensions)
	}
	if len(st.Posture.Reasons) != 1 || st.Posture.Reasons[0].Dimension != "network" {
		t.Errorf("reasons = %+v", st.Posture.Reasons)
	}
	d := st.Dimensions
	if d.Network.Status != "unknown" || d.Network.Reason != "no_flows" {
		t.Errorf("network = %+v", d.Network)
	}
	if d.Images.Status != "unknown" || d.Images.Reason != "vulnerabilities_not_configured" {
		t.Errorf("images = %+v", d.Images)
	}
	if d.PodSecurity.Status != "warn" {
		t.Errorf("podSecurity = %+v", d.PodSecurity)
	}
	// A dimension the broker did not report is unknown, never ok.
	if d.Compute.Status != "unknown" || d.Compute.Reason != "not_reported" {
		t.Errorf("absent compute must be unknown, got %+v", d.Compute)
	}
	if *st.FindingCounts != (v1alpha1.FindingCounts{High: 1, Medium: 2, Low: 1}) {
		t.Errorf("findingCounts = %+v", st.FindingCounts)
	}
	if st.Current.LiveContentHash != "fnv1a64:live" || *st.Current.Revision != 3 || st.Current.CreatedAt == nil {
		t.Errorf("current = %+v", st.Current)
	}
	if !st.LastSyncedAt.Time.Equal(now) {
		t.Errorf("lastSyncedAt = %v", st.LastSyncedAt)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionTrue || c.ObservedGeneration != 2 {
		t.Errorf("ProfileAvailable = %+v", c)
	}
	// No accepted revision: deviation is Unknown, not None.
	if st.Deviation.State != v1alpha1.DeviationUnknown || st.Accepted != nil {
		t.Errorf("deviation = %+v accepted = %+v", st.Deviation, st.Accepted)
	}
	if c := cond(t, st, v1alpha1.ConditionDeviated); c.Status != metav1.ConditionUnknown || c.Reason != v1alpha1.ReasonNoAcceptedRevision {
		t.Errorf("Deviated = %+v", c)
	}
	if len(b.calls) != 1 {
		t.Errorf("no accepted revision should need only the profile call, got %v", b.calls)
	}
}

func TestComputeStatus_MissingPostureStatusIsUnknown(t *testing.T) {
	p := profileFixture()
	p.Posture.Status = ""
	p.Posture.Coverage = nil
	p.Posture.UnknownDimensions = nil
	st, _ := computeStatus(context.Background(), &fakeBroker{profile: p}, aspFixture(nil), now, testStaleAfter)
	if st.Posture.Status != "unknown" || st.Posture.Coverage != "unknown" {
		t.Errorf("posture = %+v", st.Posture)
	}
	if st.Posture.UnknownDimensions == nil {
		t.Error("unknownDimensions must serialise as [] not null")
	}
}

func TestComputeStatus_UnrecognisedStatusIsUnknown(t *testing.T) {
	// A status value outside the CRD enum would make the API server reject
	// the whole status apply; it must degrade to unknown, never ok.
	p := profileFixture()
	p.Posture.Status = "excellent"
	p.Dimensions["network"] = Dim{Status: "partial"}
	st, _ := computeStatus(context.Background(), &fakeBroker{profile: p}, aspFixture(nil), now, testStaleAfter)
	if st.Posture.Status != "unknown" {
		t.Errorf("posture.status = %q, want unknown", st.Posture.Status)
	}
	if st.Dimensions.Network.Status != "unknown" {
		t.Errorf("dimensions.network.status = %q, want unknown", st.Dimensions.Network.Status)
	}
}

func TestComputeStatus_MatchesAccepted(t *testing.T) {
	p := profileFixture()
	p.ContentHash = "fnv1a64:rev3"
	b := &fakeBroker{profile: p, versions: map[int64]*Version{
		3: {Revision: 3, ContentHash: "fnv1a64:rev3", CreatedAt: "2026-09-26T02:22:26Z"},
	}}
	b.versions[3].Posture.Status = "warn"
	st, err := computeStatus(context.Background(), b, aspFixture(ptr[int64](3)), now, testStaleAfter)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deviation.State != v1alpha1.DeviationNone || st.Deviation.ChangedDimensions != nil {
		t.Errorf("deviation = %+v", st.Deviation)
	}
	if st.Accepted.Revision != 3 || st.Accepted.PostureStatus != "warn" {
		t.Errorf("accepted = %+v", st.Accepted)
	}
	if c := cond(t, st, v1alpha1.ConditionDeviated); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonMatchesAccepted {
		t.Errorf("Deviated = %+v", c)
	}
}

func TestComputeStatus_ChangedWithDimensionBreakdown(t *testing.T) {
	p := profileFixture()
	p.ContentHash = "fnv1a64:rev3" // live == latest stored (rev 3)
	b := &fakeBroker{profile: p, versions: map[int64]*Version{
		1: {Revision: 1, ContentHash: "fnv1a64:rev1", DimensionHashes: map[string]string{
			"network": "n1", "syscalls": "s1", "podSecurity": "p1", "images": "i1"}},
		3: {Revision: 3, ContentHash: "fnv1a64:rev3", DimensionHashes: map[string]string{
			"network": "n2", "syscalls": "s1", "podSecurity": "p2", "images": "i1"}},
	}}
	b.versions[1].Posture.Status = "unknown"
	st, err := computeStatus(context.Background(), b, aspFixture(ptr[int64](1)), now, testStaleAfter)
	if err != nil {
		t.Fatal(err)
	}
	dev := st.Deviation
	if dev.State != v1alpha1.DeviationChanged {
		t.Fatalf("state = %s", dev.State)
	}
	if !reflect.DeepEqual(dev.ChangedDimensions, []string{"network", "podSecurity"}) {
		t.Errorf("changedDimensions = %v", dev.ChangedDimensions)
	}
	if dev.PostureFrom != "unknown" || dev.PostureTo != "warn" {
		t.Errorf("posture change = %s -> %s", dev.PostureFrom, dev.PostureTo)
	}
	if !strings.Contains(dev.Message, "network, podSecurity") {
		t.Errorf("message = %q", dev.Message)
	}
	if c := cond(t, st, v1alpha1.ConditionDeviated); c.Status != metav1.ConditionTrue || c.Reason != v1alpha1.ReasonProfileChanged {
		t.Errorf("Deviated = %+v", c)
	}
}

func TestComputeStatus_ChangedButSnapshotPendingHasNoBreakdown(t *testing.T) {
	p := profileFixture()
	p.SnapshotPending = true
	b := &fakeBroker{profile: p, versions: map[int64]*Version{
		3: {Revision: 3, ContentHash: "fnv1a64:rev3"},
	}}
	st, _ := computeStatus(context.Background(), b, aspFixture(ptr[int64](3)), now, testStaleAfter)
	if st.Deviation.State != v1alpha1.DeviationChanged {
		t.Fatalf("state = %s", st.Deviation.State)
	}
	if st.Deviation.ChangedDimensions != nil {
		t.Errorf("breakdown must be absent (unknown) while the snapshot is pending, got %v", st.Deviation.ChangedDimensions)
	}
	if !strings.Contains(st.Deviation.Message, "once the broker stores") {
		t.Errorf("message = %q", st.Deviation.Message)
	}
}

func TestComputeStatus_AcceptedRevisionPruned(t *testing.T) {
	b := &fakeBroker{profile: profileFixture(), versions: map[int64]*Version{}}
	st, err := computeStatus(context.Background(), b, aspFixture(ptr[int64](7)), now, testStaleAfter)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deviation.State != v1alpha1.DeviationUnknown || st.Accepted != nil {
		t.Errorf("deviation = %+v", st.Deviation)
	}
	if c := cond(t, st, v1alpha1.ConditionDeviated); c.Reason != v1alpha1.ReasonAcceptedRevisionNotFound {
		t.Errorf("Deviated = %+v", c)
	}
	// The profile itself is still available.
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionTrue {
		t.Errorf("ProfileAvailable = %+v", c)
	}
}

func TestComputeStatus_WorkloadNotFoundClearsData(t *testing.T) {
	asp := aspFixture(ptr[int64](1))
	asp.Status.Posture = &v1alpha1.ProfilePosture{Status: "warn"}
	b := &fakeBroker{profileErr: &BrokerError{StatusCode: 404, Code: "workload_not_found"}}
	st, err := computeStatus(context.Background(), b, asp, now, testStaleAfter)
	if err != nil {
		t.Fatalf("not-found is not transient: %v", err)
	}
	if st.Posture != nil || st.Deviation != nil {
		t.Errorf("stale data kept for an unknown workload: %+v", st)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonWorkloadNotFound {
		t.Errorf("ProfileAvailable = %+v", c)
	}
	if c := cond(t, st, v1alpha1.ConditionDeviated); c.Status != metav1.ConditionUnknown {
		t.Errorf("Deviated = %+v", c)
	}
}

func TestComputeStatus_BrokerDownKeepsLastDataAndRetries(t *testing.T) {
	asp := aspFixture(nil)
	last := metav1.NewTime(now.Add(-10 * time.Minute))
	asp.Status.LastSyncedAt = &last
	asp.Status.Posture = &v1alpha1.ProfilePosture{Status: "risk", Coverage: "0.50", UnknownDimensions: []string{}}
	b := &fakeBroker{profileErr: errors.New("dial tcp: connection refused")}
	st, err := computeStatus(context.Background(), b, asp, now, testStaleAfter)
	var te errTransient
	if !errors.As(err, &te) {
		t.Fatalf("network failure must be retried, got %v", err)
	}
	if st.Posture == nil || st.Posture.Status != "risk" || !st.LastSyncedAt.Equal(&last) {
		t.Errorf("last-known data not carried over: %+v", st)
	}
	c := cond(t, st, v1alpha1.ConditionProfileAvailable)
	if c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonBrokerUnavailable {
		t.Errorf("ProfileAvailable = %+v", c)
	}
	if !strings.Contains(c.Message, "status shows data from") {
		t.Errorf("message must say the data is old: %q", c.Message)
	}
}

func TestComputeStatus_UnauthorizedNotRetriedEarly(t *testing.T) {
	b := &fakeBroker{profileErr: &BrokerError{StatusCode: 401, Message: "unauthorized"}}
	st, err := computeStatus(context.Background(), b, aspFixture(nil), now, testStaleAfter)
	if err != nil {
		t.Fatalf("auth failures wait for resync, got %v", err)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Reason != v1alpha1.ReasonBrokerUnauthorized {
		t.Errorf("ProfileAvailable = %+v", c)
	}
}

func TestComputeStatus_OldBrokerWithoutRoutes(t *testing.T) {
	b := &fakeBroker{profileErr: &BrokerError{StatusCode: 404}}
	st, _ := computeStatus(context.Background(), b, aspFixture(nil), now, testStaleAfter)
	c := cond(t, st, v1alpha1.ConditionProfileAvailable)
	if c.Reason != v1alpha1.ReasonBrokerError || !strings.Contains(c.Message, "upgrade the broker") {
		t.Errorf("ProfileAvailable = %+v", c)
	}
}

func TestComputeStatus_KeepsTransitionTimeWhenUnchanged(t *testing.T) {
	asp := aspFixture(nil)
	old := metav1.NewTime(now.Add(-time.Hour))
	asp.Status.Conditions = []metav1.Condition{{
		Type: v1alpha1.ConditionProfileAvailable, Status: metav1.ConditionTrue,
		Reason: v1alpha1.ReasonProfileRetrieved, LastTransitionTime: old,
	}}
	st, _ := computeStatus(context.Background(), &fakeBroker{profile: profileFixture()}, asp, now, testStaleAfter)
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); !c.LastTransitionTime.Equal(&old) {
		t.Errorf("lastTransitionTime moved: %v", c.LastTransitionTime)
	}
}

func TestChangedDimensions_OrderAndOneSided(t *testing.T) {
	a := map[string]string{"network": "a", "images": "x", "zeta": "1"}
	b := map[string]string{"network": "b", "images": "x", "alpha": "2"}
	got := changedDimensions(a, b)
	// syscalls and podSecurity are missing on both sides: equal (""), not changed.
	want := []string{"network", "alpha", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// staleFixture is a resource last read successfully `age` before now,
// with an ok posture on it.
func staleFixture(age time.Duration) *v1alpha1.ApplicationSecurityProfile {
	asp := aspFixture(nil)
	last := metav1.NewTime(now.Add(-age))
	asp.Status.LastSyncedAt = &last
	asp.Status.Posture = &v1alpha1.ProfilePosture{Status: "ok", Coverage: "1.00", UnknownDimensions: []string{}}
	asp.Status.Dimensions = &v1alpha1.ProfileDimensions{
		Network: v1alpha1.DimensionStatus{Status: "ok"}, Syscalls: v1alpha1.DimensionStatus{Status: "ok"},
		PodSecurity: v1alpha1.DimensionStatus{Status: "ok"}, Images: v1alpha1.DimensionStatus{Status: "ok"},
		Compute: v1alpha1.DimensionStatus{Status: "ok"},
	}
	return asp
}

func assertAllUnknown(t *testing.T, st v1alpha1.ApplicationSecurityProfileStatus) {
	t.Helper()
	if st.Posture == nil || st.Posture.Status != "unknown" || st.Posture.Coverage != "unknown" {
		t.Fatalf("posture = %+v, want unknown", st.Posture)
	}
	if len(st.Posture.UnknownDimensions) != 4 {
		t.Errorf("unknownDimensions = %v, want all four core dimensions", st.Posture.UnknownDimensions)
	}
	d := st.Dimensions
	for name, s := range map[string]string{"network": d.Network.Status, "syscalls": d.Syscalls.Status,
		"podSecurity": d.PodSecurity.Status, "images": d.Images.Status, "compute": d.Compute.Status} {
		if s != "unknown" {
			t.Errorf("dimensions.%s.status = %q, want unknown", name, s)
		}
	}
	if st.Deviation == nil || st.Deviation.State != v1alpha1.DeviationUnknown {
		t.Errorf("deviation = %+v, want Unknown", st.Deviation)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionFalse {
		t.Errorf("ProfileAvailable = %+v, want False", c)
	}
}

// (1) A transient failure inside the window keeps the last posture.
func TestStaleness_TransientInsideWindowKeepsPosture(t *testing.T) {
	asp := staleFixture(testStaleAfter - time.Second)
	b := &fakeBroker{profileErr: errors.New("dial tcp: connection refused")}
	st, err := computeStatus(context.Background(), b, asp, now, testStaleAfter)
	var te errTransient
	if !errors.As(err, &te) {
		t.Fatalf("want transient retry, got %v", err)
	}
	if st.Posture == nil || st.Posture.Status != "ok" || st.Dimensions.Network.Status != "ok" {
		t.Errorf("last posture not kept inside the window: %+v", st.Posture)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonBrokerUnavailable {
		t.Errorf("ProfileAvailable = %+v", c)
	}
}

// (2) Past the window it is unknown, and the reason names the error and
// the last successful refresh.
func TestStaleness_PastWindowGoesUnknown(t *testing.T) {
	asp := staleFixture(testStaleAfter + time.Second)
	b := &fakeBroker{profileErr: errors.New("dial tcp: connection refused")}
	st, err := computeStatus(context.Background(), b, asp, now, testStaleAfter)
	var te errTransient
	if !errors.As(err, &te) {
		t.Fatalf("still worth retrying, got %v", err)
	}
	assertAllUnknown(t, st)
	lastStr := asp.Status.LastSyncedAt.UTC().Format(time.RFC3339)
	c := cond(t, st, v1alpha1.ConditionProfileAvailable)
	for _, want := range []string{"connection refused", lastStr} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("condition message %q lacks %q", c.Message, want)
		}
		if !strings.Contains(st.Dimensions.Network.Message, want) || !strings.Contains(st.Posture.Reasons[0].Message, want) {
			t.Errorf("dimension/posture reason lacks %q", want)
		}
	}
	if st.LastSyncedAt == nil || !st.LastSyncedAt.Equal(asp.Status.LastSyncedAt) {
		t.Errorf("lastSyncedAt must stay the last successful read, got %v", st.LastSyncedAt)
	}
	if st.FindingCounts != nil || st.Current != nil || st.Accepted != nil {
		t.Errorf("stale counts/revisions kept: %+v", st)
	}
}

// Never read successfully: unknown straight away, reason says "never".
func TestStaleness_NeverSyncedIsUnknown(t *testing.T) {
	b := &fakeBroker{profileErr: errors.New("dial tcp: connection refused")}
	st, _ := computeStatus(context.Background(), b, aspFixture(nil), now, testStaleAfter)
	assertAllUnknown(t, st)
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); !strings.Contains(c.Message, "last successful refresh: never") {
		t.Errorf("message = %q", c.Message)
	}
}

// (3) An auth rejection is unknown at once, even with fresh data.
func TestStaleness_AuthRejectedGoesUnknownImmediately(t *testing.T) {
	for _, code := range []int{401, 403} {
		asp := staleFixture(time.Second)
		b := &fakeBroker{profileErr: &BrokerError{StatusCode: code, Message: "denied"}}
		st, err := computeStatus(context.Background(), b, asp, now, testStaleAfter)
		if err != nil {
			t.Fatalf("%d: auth failures are not retried early, got %v", code, err)
		}
		assertAllUnknown(t, st)
		c := cond(t, st, v1alpha1.ConditionProfileAvailable)
		if c.Reason != v1alpha1.ReasonBrokerUnauthorized || !strings.Contains(c.Message, strconv.Itoa(code)) ||
			!strings.Contains(c.Message, asp.Status.LastSyncedAt.UTC().Format(time.RFC3339)) {
			t.Errorf("%d: ProfileAvailable = %+v", code, c)
		}
	}
}

// (4) Recovery restores the posture and ProfileAvailable=True.
func TestStaleness_RecoveryRestoresPosture(t *testing.T) {
	asp := staleFixture(testStaleAfter + time.Minute)
	down := &fakeBroker{profileErr: errors.New("dial tcp: connection refused")}
	st, _ := computeStatus(context.Background(), down, asp, now, testStaleAfter)
	assertAllUnknown(t, st)

	asp.Status = st
	later := now.Add(time.Minute)
	st, err := computeStatus(context.Background(), &fakeBroker{profile: profileFixture()}, asp, later, testStaleAfter)
	if err != nil {
		t.Fatal(err)
	}
	if st.Posture.Status != "warn" || st.Dimensions.PodSecurity.Status != "warn" {
		t.Errorf("posture not restored: %+v / %+v", st.Posture, st.Dimensions)
	}
	if !st.LastSyncedAt.Time.Equal(later) {
		t.Errorf("lastSyncedAt = %v, want %v", st.LastSyncedAt, later)
	}
	if c := cond(t, st, v1alpha1.ConditionProfileAvailable); c.Status != metav1.ConditionTrue || c.Reason != v1alpha1.ReasonProfileRetrieved {
		t.Errorf("ProfileAvailable = %+v", c)
	}
}

func TestStaleAfter_DefaultAndFloor(t *testing.T) {
	for _, tc := range []struct{ configured, resync, want time.Duration }{
		{0, 5 * time.Minute, 15 * time.Minute},
		{time.Minute, 5 * time.Minute, 5 * time.Minute},
		{time.Hour, 5 * time.Minute, time.Hour},
	} {
		if got := StaleAfter(tc.configured, tc.resync); got != tc.want {
			t.Errorf("StaleAfter(%v, %v) = %v, want %v", tc.configured, tc.resync, got, tc.want)
		}
	}
}
