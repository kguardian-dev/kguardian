package api

import (
	"net/url"
	"strconv"
	"time"
)

// Image signature results (GET /images/{digest}/attestation) and the
// evaluator's ImageTrustPolicy results (GET /image-trust), both broker
// read routes (#1533 P2).

// SignatureResult is the stored signature discovery result for one digest.
type SignatureResult struct {
	Digest       string             `json:"digest"`
	Repository   string             `json:"repository"`
	Verdict      string             `json:"verdict"`
	Reason       *string            `json:"reason"`
	TrustRoot    *string            `json:"trustRoot"`
	SignedVia    *string            `json:"signedVia"`
	SignedDigest *string            `json:"signedDigest"`
	Signatures   []SignatureEntry   `json:"signatures"`
	Attestations []AttestationEntry `json:"attestations"`
	CheckedAt    string             `json:"checkedAt"`
	ReceivedAt   string             `json:"receivedAt"`
}

// SignerIdentity is who produced a verified signature: a keyless identity
// (Issuer, SAN) or a configured key (KeyName, KeyFingerprint). An
// unverified entry has none of these.
type SignerIdentity struct {
	SignerKind     string `json:"signerKind,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	SAN            string `json:"san,omitempty"`
	KeyName        string `json:"keyName,omitempty"`
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
}

// SignatureEntry is one signature found for the digest.
type SignatureEntry struct {
	SignerIdentity
	Format         string     `json:"format"`
	Source         string     `json:"source"`
	Verified       bool       `json:"verified"`
	Error          string     `json:"error,omitempty"`
	Detail         string     `json:"detail,omitempty"`
	KeyHint        string     `json:"keyHint,omitempty"`
	IntegratedTime *time.Time `json:"integratedTime,omitempty"`
}

// AttestationEntry is one Sigstore attestation found for the digest.
type AttestationEntry struct {
	SignerIdentity
	PredicateType string `json:"predicateType"`
	Format        string `json:"format"`
	Source        string `json:"source"`
	Verified      bool   `json:"verified"`
	Error         string `json:"error,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Provenance    *struct {
		BuilderID    string `json:"builderId,omitempty"`
		SourceRepo   string `json:"sourceRepo,omitempty"`
		SourceCommit string `json:"sourceCommit,omitempty"`
		SourceRef    string `json:"sourceRef,omitempty"`
	} `json:"provenance,omitempty"`
}

// ImageTrustOptions filters GET /image-trust.
type ImageTrustOptions struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	Verdict      string // Trusted, WouldDeny or Unknown
	Limit        int
}

// ImageTrustAnswer is the broker's view of the evaluator's last pass.
// Available false (with Reason) means nothing can be reported.
type ImageTrustAnswer struct {
	Available   bool          `json:"available"`
	Reason      string        `json:"reason,omitempty"`
	EvaluatedAt *string       `json:"evaluatedAt"`
	Total       int           `json:"total"`
	WouldDeny   int           `json:"wouldDeny"`
	Unknown     int           `json:"unknown"`
	Trusted     int           `json:"trusted"`
	Policies    []string      `json:"policies"`
	Results     []TrustResult `json:"results"`
	Truncated   bool          `json:"truncated"`
}

// TrustResult is one (policy, container) verdict.
type TrustResult struct {
	Policy    string `json:"policy"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
	Digest    string `json:"digest"`
	Image     string `json:"image"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason,omitempty"`
}

// Swappable for tests that bypass HTTP.
var (
	GetSignatureResultFunc = getRealSignatureResult
	GetImageTrustFunc      = getRealImageTrust
)

// GetSignatureResult returns the stored signature result for a digest
// (ErrNotFound when it has none), plus the raw body.
func GetSignatureResult(digest string) (*SignatureResult, []byte, error) {
	return GetSignatureResultFunc(digest)
}

// GetImageTrust returns the ImageTrustPolicy results, plus the raw body.
func GetImageTrust(opts ImageTrustOptions) (*ImageTrustAnswer, []byte, error) {
	return GetImageTrustFunc(opts)
}

func getRealSignatureResult(digest string) (*SignatureResult, []byte, error) {
	body, err := brokerGetBody("GetSignatureResult", "/images/"+url.PathEscape(digest)+"/attestation")
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[SignatureResult]("GetSignatureResult", body)
}

func getRealImageTrust(o ImageTrustOptions) (*ImageTrustAnswer, []byte, error) {
	q := url.Values{}
	for k, v := range map[string]string{
		"namespace": o.Namespace, "workload_kind": o.WorkloadKind,
		"workload_name": o.WorkloadName, "verdict": o.Verdict,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	body, err := brokerGetBody("GetImageTrust", withQuery("/image-trust", q))
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[ImageTrustAnswer]("GetImageTrust", body)
}
