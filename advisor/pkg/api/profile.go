package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Workload security profile reads (broker profile API v1). Every documented
// field is always present on the wire and null means unknown, so every
// optional value here is a pointer: nil must render as "unknown", never as
// 0, "none" or a pass.

// PostureReason says why one core dimension is not ok.
type PostureReason struct {
	Dimension string `json:"dimension"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// Posture is the rollup (contract v1.2): Status is the worst known core
// dimension status, derived from findings (there is no numeric score);
// Coverage is the share of the four core dimensions that are known;
// UnknownDimensions lists the core dimensions with status unknown.
type Posture struct {
	Status            string          `json:"status"`
	Coverage          *float64        `json:"coverage"`
	UnknownDimensions []string        `json:"unknownDimensions"`
	Reasons           []PostureReason `json:"reasons"`
}

// ProfileSummary is one row of GET /workloads.
type ProfileSummary struct {
	Namespace     string         `json:"namespace"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Revision      *int           `json:"revision"`
	ComputedAt    string         `json:"computedAt"`
	Posture       Posture        `json:"posture"`
	FindingCounts map[string]int `json:"findingCounts"`
}

// ProfilePage is the GET /workloads envelope.
type ProfilePage struct {
	Items     []ProfileSummary `json:"items"`
	NextAfter *string          `json:"nextAfter"`
}

// ProfileFinding is one entry of attention[] / findings[].
type ProfileFinding struct {
	ID        string  `json:"id"`
	Dimension string  `json:"dimension"`
	Severity  string  `json:"severity"`
	Title     string  `json:"title"`
	Detail    string  `json:"detail"`
	Container *string `json:"container"`
}

// ProfileReadiness is one readiness check; OK nil = cannot tell.
type ProfileReadiness struct {
	ID      string `json:"id"`
	OK      *bool  `json:"ok"`
	Message string `json:"message"`
}

// DimensionCoverage is how complete one dimension's observation is.
type DimensionCoverage struct {
	Level    string   `json:"level"`
	Fraction *float64 `json:"fraction"`
	Note     *string  `json:"note"`
}

// DimensionReason explains a dimension's status.
type DimensionReason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Dimension is the common envelope every dimension carries.
type Dimension struct {
	Status   string             `json:"status"`
	Coverage *DimensionCoverage `json:"coverage"`
	Reasons  []DimensionReason  `json:"reasons"`
}

// PSSRecommendation is the recommended securityContext patch. It is a
// recommendation for a human to review; kguardian never applies it.
type PSSRecommendation struct {
	Recommendation bool     `json:"recommendation"`
	TargetLevel    string   `json:"targetLevel"`
	Format         string   `json:"format"`
	YAML           string   `json:"yaml"`
	Caveats        []string `json:"caveats"`
}

// PodSecurityDimension is the podSecurity dimension's fields the CLI reads.
type PodSecurityDimension struct {
	Dimension
	Level             *string            `json:"level"`
	LevelConfidence   *string            `json:"levelConfidence"`
	UnevaluatedChecks []string           `json:"unevaluatedChecks"`
	StaleContainers   []StaleContainer   `json:"staleContainers"`
	Recommendation    *PSSRecommendation `json:"recommendation"`
}

// StaleContainer is a container no longer in the spec (renamed or
// removed); it is excluded from the level, findings and patch.
type StaleContainer struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Digest   string `json:"digest"`
	LastSeen string `json:"lastSeen"`
}

// ProfileVersion identifies a stored snapshot.
type ProfileVersion struct {
	Revision    int    `json:"revision"`
	ContentHash string `json:"contentHash"`
	CreatedAt   string `json:"createdAt"`
}

// ProfileWorkload identifies the workload a profile is for.
type ProfileWorkload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Transient bool   `json:"transient"`
	Pods      *struct {
		Live int `json:"live"`
	} `json:"pods"`
}

// Profile is GET /workloads/{ns}/{kind}/{name}/profile, the fields the table
// output reads. Dimensions stay raw so any dimension this build does not
// know still decodes; DimensionEnvelope and PodSecurity read them.
type Profile struct {
	Workload        ProfileWorkload            `json:"workload"`
	GeneratedAt     string                     `json:"generatedAt"`
	ContentHash     string                     `json:"contentHash"`
	Version         *ProfileVersion            `json:"version"`
	SnapshotPending bool                       `json:"snapshotPending"`
	Posture         Posture                    `json:"posture"`
	Attention       []ProfileFinding           `json:"attention"`
	Findings        []ProfileFinding           `json:"findings"`
	Readiness       []ProfileReadiness         `json:"readiness"`
	Dimensions      map[string]json.RawMessage `json:"dimensions"`
	// Drift is nil from a broker without the drift block.
	Drift *ProfileDrift `json:"drift"`
}

// ProfileDrift is the profile's drift block (contract section 2.8). A
// check missing from Evaluated, or listed in NotEvaluated, was not
// evaluated: no item for it never means "no drift".
type ProfileDrift struct {
	Evaluated    []string            `json:"evaluated"`
	NotEvaluated []DriftNotEvaluated `json:"notEvaluated"`
	Items        []DriftItem         `json:"items"`
}

// DriftNotEvaluated says why a drift check could not run for a container
// (Container nil = the whole workload).
type DriftNotEvaluated struct {
	Type      string  `json:"type"`
	Container *string `json:"container"`
	Reason    string  `json:"reason"`
}

// DriftItem is one drift item; the detail stays raw.
type DriftItem struct {
	Type      string          `json:"type"`
	FindingID string          `json:"findingId"`
	Severity  string          `json:"severity"`
	Container *string         `json:"container"`
	Detail    json.RawMessage `json:"detail"`
}

// DimensionEnvelope decodes the common envelope of one dimension; ok is
// false when the dimension is absent or malformed.
func (p *Profile) DimensionEnvelope(name string) (Dimension, bool) {
	var d Dimension
	raw, ok := p.Dimensions[name]
	if !ok || json.Unmarshal(raw, &d) != nil {
		return Dimension{}, false
	}
	return d, true
}

// PodSecurity decodes the podSecurity dimension; nil when absent.
func (p *Profile) PodSecurity() *PodSecurityDimension {
	raw, ok := p.Dimensions["podSecurity"]
	if !ok {
		return nil
	}
	var d PodSecurityDimension
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	return &d
}

// ProfileDiff is GET .../profile/diff. Dimensions stay raw for the renderer.
type ProfileDiff struct {
	Namespace   string                     `json:"namespace"`
	Kind        string                     `json:"kind"`
	Name        string                     `json:"name"`
	From        *ProfileVersion            `json:"from"`
	FromTrimmed bool                       `json:"fromTrimmed"`
	To          *ProfileVersion            `json:"to"`
	Changed     bool                       `json:"changed"`
	Dimensions  map[string]json.RawMessage `json:"dimensions"`
}

// ProfileListOptions filters GET /workloads. Zero values are not sent.
type ProfileListOptions struct {
	Namespace string
	Kind      string
	Status    string
	Limit     int
	After     string
}

// Swappable for tests that bypass HTTP.
var (
	GetProfilesFunc    = getRealProfiles
	GetProfileFunc     = getRealProfile
	GetProfileDiffFunc = getRealProfileDiff
)

// GetProfiles fetches one page of workload posture summaries. It returns the
// decoded page and the raw body, so -o json/yaml emit what the broker said.
func GetProfiles(opts ProfileListOptions) (*ProfilePage, []byte, error) {
	return GetProfilesFunc(opts)
}

// GetProfile fetches one workload's live profile.
func GetProfile(namespace, kind, name string) (*Profile, []byte, error) {
	return GetProfileFunc(namespace, kind, name)
}

// GetProfileDiff compares two stored revisions; 0 means "broker default"
// (to = latest, from = to - 1).
func GetProfileDiff(namespace, kind, name string, from, to int) (*ProfileDiff, []byte, error) {
	return GetProfileDiffFunc(namespace, kind, name, from, to)
}

func workloadPath(namespace, kind, name string) string {
	return "/workloads/" + url.PathEscape(namespace) + "/" + url.PathEscape(kind) + "/" + url.PathEscape(name)
}

func getRealProfiles(opts ProfileListOptions) (*ProfilePage, []byte, error) {
	q := url.Values{}
	if opts.Namespace != "" {
		q.Set("namespace", opts.Namespace)
	}
	if opts.Kind != "" {
		q.Set("kind", opts.Kind)
	}
	if opts.Status != "" {
		q.Set("status", opts.Status)
	}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.After != "" {
		q.Set("after", opts.After)
	}
	path := "/workloads"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	body, err := brokerGetBody("GetProfiles", path)
	if err != nil {
		return nil, nil, err
	}
	var out ProfilePage
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("GetProfiles: decoding response: %w", err)
	}
	return &out, body, nil
}

func getRealProfile(namespace, kind, name string) (*Profile, []byte, error) {
	body, err := brokerGetBody("GetProfile", workloadPath(namespace, kind, name)+"/profile")
	if err != nil {
		return nil, nil, err
	}
	var out Profile
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("GetProfile: decoding response: %w", err)
	}
	return &out, body, nil
}

func getRealProfileDiff(namespace, kind, name string, from, to int) (*ProfileDiff, []byte, error) {
	q := url.Values{}
	if from > 0 {
		q.Set("from", strconv.Itoa(from))
	}
	if to > 0 {
		q.Set("to", strconv.Itoa(to))
	}
	path := workloadPath(namespace, kind, name) + "/profile/diff"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	body, err := brokerGetBody("GetProfileDiff", path)
	if err != nil {
		return nil, nil, err
	}
	var out ProfileDiff
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("GetProfileDiff: decoding response: %w", err)
	}
	return &out, body, nil
}
