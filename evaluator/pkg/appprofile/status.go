package appprofile

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// coreDimensions in contract order (section 2.2).
var coreDimensions = []string{"network", "syscalls", "podSecurity", "images"}

// errTransient marks a result worth retrying with backoff (network error,
// 5xx, 503 shedding). Everything else waits for the next resync.
type errTransient struct{ err error }

func (e errTransient) Error() string { return e.err.Error() }
func (e errTransient) Unwrap() error { return e.err }

// computeStatus reads the broker and returns the complete status to apply.
// prev is the status currently on the object: its conditions keep their
// lastTransitionTime when unchanged, and its data is carried over when
// the broker cannot be read (the ProfileAvailable condition and
// lastSyncedAt then say how old it is). The returned error is non-nil
// only for failures worth an early retry; the status is valid either way.
func computeStatus(ctx context.Context, b Broker, asp *v1alpha1.ApplicationSecurityProfile, now time.Time) (v1alpha1.ApplicationSecurityProfileStatus, error) {
	prev := asp.Status
	gen := asp.Generation
	ref := asp.Spec.WorkloadRef
	out := v1alpha1.ApplicationSecurityProfileStatus{
		ObservedGeneration: gen,
		Conditions:         copyConditions(prev.Conditions),
	}

	p, err := b.Profile(ctx, asp.Namespace, ref.Kind, ref.Name)
	if err != nil {
		reason, msg, keep, retry := classifyProfileError(err, asp.Namespace, ref)
		if keep {
			out.LastSyncedAt = prev.LastSyncedAt
			out.Posture = prev.Posture
			out.Dimensions = prev.Dimensions
			out.FindingCounts = prev.FindingCounts
			out.Current = prev.Current
			out.Accepted = prev.Accepted
			out.Deviation = prev.Deviation
			if prev.LastSyncedAt != nil {
				msg += "; status shows data from " + prev.LastSyncedAt.UTC().Format(time.RFC3339)
			}
		}
		setCond(&out, gen, v1alpha1.ConditionProfileAvailable, metav1.ConditionFalse, reason, msg)
		if !keep {
			setCond(&out, gen, v1alpha1.ConditionDeviated, metav1.ConditionUnknown,
				v1alpha1.ReasonProfileUnavailable, "The workload profile could not be read")
		}
		if retry {
			return out, errTransient{err}
		}
		return out, nil
	}

	synced := metav1.NewTime(now.UTC())
	out.LastSyncedAt = &synced
	out.Posture = postureFrom(p)
	out.Dimensions = dimensionsFrom(p)
	out.FindingCounts = countFindings(p)
	out.Current = currentFrom(p)
	setCond(&out, gen, v1alpha1.ConditionProfileAvailable, metav1.ConditionTrue,
		v1alpha1.ReasonProfileRetrieved, "Profile read from the broker")

	retryErr := fillDeviation(ctx, b, asp, p, &out)
	return out, retryErr
}

// classifyProfileError maps a broker error to (condition reason, message,
// keep previous data, retry early).
func classifyProfileError(err error, ns string, ref v1alpha1.WorkloadRef) (string, string, bool, bool) {
	key := ns + "/" + ref.Kind + "/" + ref.Name
	code := statusCode(err)
	switch {
	case errorCode(err) == "workload_not_found":
		// Authoritative: the broker knows nothing about this workload
		// (wrong kind/name, or not observed yet). Old data would mislead.
		return v1alpha1.ReasonWorkloadNotFound,
			"The broker has no profile for " + key + " (check kind and name; kind is case-sensitive, e.g. Deployment)",
			false, false
	case code == http.StatusNotFound:
		return v1alpha1.ReasonBrokerError,
			"The broker does not serve the workload profile API (it is older than the profile routes); upgrade the broker",
			true, false
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return v1alpha1.ReasonBrokerUnauthorized,
			fmt.Sprintf("The broker rejected the evaluator's token (%d); the evaluator needs the READ-scope token", code),
			true, false
	case code == http.StatusBadRequest:
		return v1alpha1.ReasonBrokerError, "The broker rejected the workload reference: " + err.Error(), false, false
	case code != 0 && code < 500 && code != http.StatusTooManyRequests:
		return v1alpha1.ReasonBrokerError, err.Error(), true, false
	default:
		// Network error, 5xx, 503 read-budget shedding.
		return v1alpha1.ReasonBrokerUnavailable, "Could not read the profile from the broker: " + err.Error(), true, true
	}
}

func fillDeviation(ctx context.Context, b Broker, asp *v1alpha1.ApplicationSecurityProfile, p *Profile, out *v1alpha1.ApplicationSecurityProfileStatus) error {
	gen := asp.Generation
	ref := asp.Spec.WorkloadRef
	unknown := func(reason, msg string) {
		out.Deviation = &v1alpha1.ProfileDeviation{State: v1alpha1.DeviationUnknown, Message: msg}
		setCond(out, gen, v1alpha1.ConditionDeviated, metav1.ConditionUnknown, reason, msg)
	}

	if asp.Spec.AcceptedRevision == nil {
		unknown(v1alpha1.ReasonNoAcceptedRevision,
			"No accepted revision; review the profile and set spec.acceptedRevision (for example to status.current.revision)")
		return nil
	}
	rev := *asp.Spec.AcceptedRevision

	acc, err := b.Version(ctx, asp.Namespace, ref.Kind, ref.Name, rev)
	if err != nil {
		if c := errorCode(err); c == "revision_not_found" || c == "workload_not_found" {
			unknown(v1alpha1.ReasonAcceptedRevisionNotFound,
				fmt.Sprintf("Accepted revision %d does not exist on the broker (never stored, or pruned by version retention); accept a current revision", rev))
			return nil
		}
		unknown(v1alpha1.ReasonProfileUnavailable, fmt.Sprintf("Could not read accepted revision %d: %v", rev, err))
		if _, _, _, retry := classifyProfileError(err, asp.Namespace, ref); retry {
			return errTransient{err}
		}
		return nil
	}
	out.Accepted = &v1alpha1.AcceptedProfile{
		Revision:      acc.Revision,
		ContentHash:   acc.ContentHash,
		CreatedAt:     parseTime(acc.CreatedAt),
		PostureStatus: acc.Posture.Status,
	}

	dev := &v1alpha1.ProfileDeviation{}
	out.Deviation = dev
	if acc.Posture.Status != "" && p.Posture.Status != "" && acc.Posture.Status != p.Posture.Status {
		dev.PostureFrom, dev.PostureTo = acc.Posture.Status, p.Posture.Status
	}

	if p.ContentHash == acc.ContentHash {
		dev.State = v1alpha1.DeviationNone
		dev.Message = fmt.Sprintf("The live profile matches accepted revision %d", rev)
		if dev.PostureFrom != "" {
			// Same content, different rollup: the broker's status rules
			// changed (e.g. a contract bump), not the workload.
			dev.Message += fmt.Sprintf("; posture is now %s (was %s) because the broker's status rules changed, not the workload", dev.PostureTo, dev.PostureFrom)
		}
		setCond(out, gen, v1alpha1.ConditionDeviated, metav1.ConditionFalse, v1alpha1.ReasonMatchesAccepted, dev.Message)
		return nil
	}

	dev.State = v1alpha1.DeviationChanged
	var retryErr error
	switch {
	case p.SnapshotPending || p.Version == nil:
		dev.Message = fmt.Sprintf("The live profile differs from accepted revision %d; the per-dimension breakdown is available once the broker stores the change as a new version", rev)
	default:
		latest, err := b.Version(ctx, asp.Namespace, ref.Kind, ref.Name, p.Version.Revision)
		if err != nil {
			dev.Message = fmt.Sprintf("The live profile differs from accepted revision %d; could not read revision %d for the per-dimension breakdown: %v", rev, p.Version.Revision, err)
			if _, _, _, retry := classifyProfileError(err, asp.Namespace, ref); retry {
				retryErr = errTransient{err}
			}
			break
		}
		dev.ChangedDimensions = changedDimensions(acc.DimensionHashes, latest.DimensionHashes)
		dev.Message = fmt.Sprintf("Revision %d differs from accepted revision %d", latest.Revision, rev)
		if len(dev.ChangedDimensions) > 0 {
			dev.Message += " in " + strings.Join(dev.ChangedDimensions, ", ")
		}
	}
	if dev.PostureFrom != "" {
		dev.Message += fmt.Sprintf("; posture %s -> %s", dev.PostureFrom, dev.PostureTo)
	}
	setCond(out, gen, v1alpha1.ConditionDeviated, metav1.ConditionTrue, v1alpha1.ReasonProfileChanged, dev.Message)
	return retryErr
}

// changedDimensions returns the dimensions whose hash differs (or exists
// on one side only), core dimensions first in contract order.
func changedDimensions(a, b map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range coreDimensions {
		seen[d] = true
		if a[d] != b[d] {
			out = append(out, d)
		}
	}
	var extra []string
	for _, m := range []map[string]string{a, b} {
		for d := range m {
			if !seen[d] {
				seen[d] = true
				if a[d] != b[d] {
					extra = append(extra, d)
				}
			}
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func postureFrom(p *Profile) *v1alpha1.ProfilePosture {
	out := &v1alpha1.ProfilePosture{
		Status:            orUnknown(p.Posture.Status),
		UnknownDimensions: append([]string{}, p.Posture.UnknownDimensions...),
	}
	if p.Posture.Coverage != nil {
		out.Coverage = strconv.FormatFloat(*p.Posture.Coverage, 'f', 2, 64)
	} else {
		out.Coverage = "unknown"
	}
	for _, r := range p.Posture.Reasons {
		out.Reasons = append(out.Reasons, v1alpha1.PostureReason{Dimension: r.Dimension, Status: r.Status, Message: r.Message})
	}
	return out
}

func dimensionsFrom(p *Profile) *v1alpha1.ProfileDimensions {
	one := func(name string) v1alpha1.DimensionStatus {
		d, ok := p.Dimensions[name]
		if !ok {
			// Absent from the response: say so rather than guess.
			return v1alpha1.DimensionStatus{Status: "unknown", Reason: "not_reported", Message: "The broker did not report this dimension"}
		}
		out := v1alpha1.DimensionStatus{Status: orUnknown(d.Status)}
		if len(d.Reasons) > 0 {
			out.Reason, out.Message = d.Reasons[0].Code, d.Reasons[0].Message
		}
		return out
	}
	return &v1alpha1.ProfileDimensions{
		Network:     one("network"),
		Syscalls:    one("syscalls"),
		PodSecurity: one("podSecurity"),
		Images:      one("images"),
		Compute:     one("compute"),
	}
}

func countFindings(p *Profile) *v1alpha1.FindingCounts {
	c := &v1alpha1.FindingCounts{}
	for _, f := range p.Findings {
		switch f.Severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		case "info":
			c.Info++
		}
	}
	return c
}

func currentFrom(p *Profile) *v1alpha1.CurrentProfile {
	out := &v1alpha1.CurrentProfile{LiveContentHash: p.ContentHash, SnapshotPending: p.SnapshotPending}
	if p.Version != nil {
		r := p.Version.Revision
		out.Revision = &r
		out.ContentHash = p.Version.ContentHash
		out.CreatedAt = parseTime(p.Version.CreatedAt)
	}
	return out
}

// orUnknown: a missing or unrecognised status is unknown, never ok. The
// CRD enumerates ok|warn|risk|unknown, so passing through a value a newer
// broker adds would make the API server reject the whole status apply.
func orUnknown(s string) string {
	switch s {
	case "ok", "warn", "risk", "unknown":
		return s
	}
	return "unknown"
}

func parseTime(s string) *metav1.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	mt := metav1.NewTime(t.UTC().Truncate(time.Second))
	return &mt
}

func copyConditions(in []metav1.Condition) []metav1.Condition {
	if in == nil {
		return nil
	}
	out := make([]metav1.Condition, len(in))
	copy(out, in)
	return out
}

func setCond(s *v1alpha1.ApplicationSecurityProfileStatus, gen int64, typ string, st metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&s.Conditions, metav1.Condition{
		Type:               typ,
		Status:             st,
		ObservedGeneration: gen,
		Reason:             reason,
		Message:            msg,
	})
}
