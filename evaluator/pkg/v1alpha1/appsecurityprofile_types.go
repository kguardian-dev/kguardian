package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ApplicationSecurityProfile surfaces the broker's workload security
// profile (docs/design/workload-security-profile-api.md) for one workload
// as a Kubernetes resource. It is report-only: the evaluator writes status
// and nothing else, and nothing in kguardian acts on the spec beyond
// reading which profile revision the user has accepted as the baseline.
//
// Users create one per workload. The workload lives in the resource's own
// namespace; spec.workloadRef names it with the same (kind, name) key the
// broker uses (ReplicaSet->Deployment, Job->CronJob, bare pod -> Pod).
type ApplicationSecurityProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationSecurityProfileSpec   `json:"spec"`
	Status ApplicationSecurityProfileStatus `json:"status,omitempty"`
}

// ApplicationSecurityProfileSpec is user-owned.
type ApplicationSecurityProfileSpec struct {
	// WorkloadRef names the workload in this namespace. Immutable.
	WorkloadRef WorkloadRef `json:"workloadRef"`

	// AcceptedRevision is the broker profile revision the user reviewed
	// and accepted as the baseline. Status.deviation compares the live
	// profile against it. Unset = no baseline yet, deviation is Unknown.
	AcceptedRevision *int64 `json:"acceptedRevision,omitempty"`
}

// WorkloadRef is the (kind, name) half of the broker's workload key.
// kind is case-sensitive, exactly as the broker reports it.
type WorkloadRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ApplicationSecurityProfileStatus is written by the evaluator with
// server-side apply (field manager "kguardian-evaluator").
//
// Unknown is never rendered as safe: a dimension the broker cannot assess
// keeps status "unknown", and posture is "ok" only when every core
// dimension is known and ok (contract v1.3, section 2.2).
type ApplicationSecurityProfileStatus struct {
	// ObservedGeneration is the .metadata.generation this status was
	// computed for.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions: ProfileAvailable, Deviated.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncedAt is when the evaluator last read the profile from the
	// broker successfully. Posture and dimensions are as of this time
	// while they are shown; once a failed refresh is older than the
	// staleness window (ASP_STALE_AFTER), or at once when the broker
	// rejects the token, they are reported as unknown instead.
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`

	// Posture is the broker's rollup, copied verbatim. No scores.
	Posture *ProfilePosture `json:"posture,omitempty"`

	// Dimensions holds the per-dimension status. compute is informational
	// and not part of the posture rollup.
	Dimensions *ProfileDimensions `json:"dimensions,omitempty"`

	// FindingCounts counts the profile's findings by severity.
	FindingCounts *FindingCounts `json:"findingCounts,omitempty"`

	// Current describes the live profile and the latest stored version.
	Current *CurrentProfile `json:"current,omitempty"`

	// Accepted describes the version named by spec.acceptedRevision, when
	// the broker still has it.
	Accepted *AcceptedProfile `json:"accepted,omitempty"`

	// Deviation compares the live profile with the accepted version.
	Deviation *ProfileDeviation `json:"deviation,omitempty"`
}

// ProfilePosture mirrors the contract's posture object.
type ProfilePosture struct {
	// Status: ok | warn | risk | unknown.
	Status string `json:"status"`
	// Coverage is known core dimensions / 4, as a decimal string ("0.25")
	// so it round-trips exactly through apply and printer columns.
	Coverage string `json:"coverage"`
	// UnknownDimensions lists core dimensions with status unknown. Always
	// present; empty only when all four are known.
	UnknownDimensions []string `json:"unknownDimensions"`
	// Reasons: one per core dimension that is not ok.
	Reasons []PostureReason `json:"reasons,omitempty"`
}

// PostureReason is one posture.reasons[] entry.
type PostureReason struct {
	Dimension string `json:"dimension"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// ProfileDimensions carries one entry per contract dimension.
type ProfileDimensions struct {
	Network     DimensionStatus `json:"network"`
	Syscalls    DimensionStatus `json:"syscalls"`
	PodSecurity DimensionStatus `json:"podSecurity"`
	Images      DimensionStatus `json:"images"`
	Compute     DimensionStatus `json:"compute"`
}

// DimensionStatus is the status tier plus the dimension's first reason.
type DimensionStatus struct {
	// Status: ok | warn | risk | unknown.
	Status string `json:"status"`
	// Reason is the dimension's first stable reason code, if any.
	Reason string `json:"reason,omitempty"`
	// Message is that reason's human sentence.
	Message string `json:"message,omitempty"`
}

// FindingCounts by severity.
type FindingCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
}

// CurrentProfile describes the live profile and the latest stored version.
type CurrentProfile struct {
	// LiveContentHash hashes the profile computed at LastSyncedAt.
	LiveContentHash string `json:"liveContentHash"`
	// SnapshotPending is true when the live profile differs from the
	// latest stored version (always true before the first snapshot).
	SnapshotPending bool `json:"snapshotPending"`
	// Revision / ContentHash / CreatedAt: the latest stored version.
	// Absent until the broker's snapshotter has stored one.
	Revision    *int64       `json:"revision,omitempty"`
	ContentHash string       `json:"contentHash,omitempty"`
	CreatedAt   *metav1.Time `json:"createdAt,omitempty"`
}

// AcceptedProfile is the stored version the user accepted.
type AcceptedProfile struct {
	Revision    int64        `json:"revision"`
	ContentHash string       `json:"contentHash"`
	CreatedAt   *metav1.Time `json:"createdAt,omitempty"`
	// PostureStatus is the posture status recorded with that version.
	PostureStatus string `json:"postureStatus,omitempty"`
}

// Deviation states.
const (
	DeviationNone    = "None"
	DeviationChanged = "Changed"
	DeviationUnknown = "Unknown"
)

// ProfileDeviation compares the live profile against the accepted version.
type ProfileDeviation struct {
	// State: None | Changed | Unknown.
	State string `json:"state"`
	// ChangedDimensions lists the dimensions whose content hash differs
	// from the accepted version. Present only when State is Changed and
	// the per-dimension breakdown is known (it is not while the live
	// profile has not been stored as a version yet).
	ChangedDimensions []string `json:"changedDimensions,omitempty"`
	// PostureFrom / PostureTo: posture status at the accepted version and
	// now, when both are known and differ.
	PostureFrom string `json:"postureFrom,omitempty"`
	PostureTo   string `json:"postureTo,omitempty"`
	// Message explains the state in one sentence.
	Message string `json:"message,omitempty"`
}

// Condition types and reasons.
const (
	ConditionProfileAvailable = "ProfileAvailable"
	ConditionDeviated         = "Deviated"

	ReasonProfileRetrieved         = "ProfileRetrieved"
	ReasonWorkloadNotFound         = "WorkloadNotFound"
	ReasonBrokerUnavailable        = "BrokerUnavailable"
	ReasonBrokerUnauthorized       = "BrokerUnauthorized"
	ReasonBrokerError              = "BrokerError"
	ReasonDuplicateWorkloadRef     = "DuplicateWorkloadRef"
	ReasonMatchesAccepted          = "MatchesAccepted"
	ReasonProfileChanged           = "ProfileChanged"
	ReasonNoAcceptedRevision       = "NoAcceptedRevision"
	ReasonAcceptedRevisionNotFound = "AcceptedRevisionNotFound"
	ReasonProfileUnavailable       = "ProfileUnavailable"
)

// ApplicationSecurityProfileList is a list of ApplicationSecurityProfile.
type ApplicationSecurityProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationSecurityProfile `json:"items"`
}

// DeepCopyObject implements runtime.Object. The type is only ever handled
// as Unstructured by the dynamic client, so a JSON round-trip copy is
// sufficient and cannot drift from the struct as fields are added.
func (in *ApplicationSecurityProfile) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := &ApplicationSecurityProfile{}
	jsonCopy(in, out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ApplicationSecurityProfileList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := &ApplicationSecurityProfileList{}
	jsonCopy(in, out)
	return out
}

func jsonCopy(in, out any) {
	raw, err := json.Marshal(in)
	if err != nil {
		panic("v1alpha1: deep copy marshal: " + err.Error())
	}
	if err := json.Unmarshal(raw, out); err != nil {
		panic("v1alpha1: deep copy unmarshal: " + err.Error())
	}
}
