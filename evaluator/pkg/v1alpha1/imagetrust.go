package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ImageTrustPolicy says who must have signed the images a namespace's
// workloads run (#1533 P2-2). Like AuditNetworkPolicy it is report-only:
// the evaluator compares every running container's image against it, using
// the signatures kguardian's supplychain component verified, and records
// what WOULD be denied in status. Nothing is admitted or blocked; there is
// no webhook. kguardian can generate the enforcing Kyverno or
// policy-controller policy from the same data.
type ImageTrustPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ImageTrustPolicySpec   `json:"spec"`
	Status            ImageTrustPolicyStatus `json:"status,omitempty"`
}

// ImageTrustPolicySpec selects images and lists who may sign them.
type ImageTrustPolicySpec struct {
	// Images are glob patterns over the image repository, e.g.
	// "ghcr.io/example/**" or "docker.io/library/nginx". "*" matches
	// within one path segment, "**" across segments. Empty matches every
	// image.
	Images []string `json:"images,omitempty"`
	// Authorities: an image is trusted when a signature from any one of
	// them verified. At least one.
	Authorities []Authority `json:"authorities"`
	// Attestations that must also be present, verified, and signed by one
	// of Authorities.
	Attestations []AttestationRequirement `json:"attestations,omitempty"`
}

// Authority is one trusted signer: keyless (Fulcio certificate identity)
// or a public key. Exactly one of Keyless and Key.
type Authority struct {
	// Name labels the authority in status.
	Name    string            `json:"name,omitempty"`
	Keyless *KeylessAuthority `json:"keyless,omitempty"`
	Key     *KeyAuthority     `json:"key,omitempty"`
}

// KeylessAuthority matches the OIDC issuer and certificate SAN. Each is
// matched exactly, or by a regular expression that must match the whole
// value. An issuer and a subject are both required.
type KeylessAuthority struct {
	Issuer        string `json:"issuer,omitempty"`
	IssuerRegExp  string `json:"issuerRegExp,omitempty"`
	Subject       string `json:"subject,omitempty"`
	SubjectRegExp string `json:"subjectRegExp,omitempty"`
}

// KeyAuthority is a public key, as PEM or as the sha256 (hex) of its DER
// SubjectPublicKeyInfo. The supplychain component must hold the same key
// (supplychain.signatureDiscovery.publicKeys) to verify such signatures;
// without it they read as key_signed, never trusted.
type KeyAuthority struct {
	PublicKey   string `json:"publicKey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// AttestationRequirement is a predicate that must be attached and signed.
type AttestationRequirement struct {
	// PredicateType, e.g. "https://slsa.dev/provenance/v1".
	PredicateType string `json:"predicateType"`
	// BuilderIDRegExp and SourceRepoRegExp, when set, must match the whole
	// SLSA provenance builder id / source repository.
	BuilderIDRegExp  string `json:"builderIdRegExp,omitempty"`
	SourceRepoRegExp string `json:"sourceRepoRegExp,omitempty"`
}

// ImageTrustPolicyStatus is written by the evaluator.
type ImageTrustPolicyStatus struct {
	ObservedGeneration int64                `json:"observedGeneration,omitempty"`
	Evaluation         ImageTrustEvaluation `json:"evaluation,omitempty"`
	// Error is set when the spec cannot be evaluated (bad regexp or key).
	Error string `json:"error,omitempty"`
}

// ImageTrustEvaluation summarises the running containers the policy
// selects. Written only when it changes.
type ImageTrustEvaluation struct {
	// LastChanged is when these numbers last changed.
	LastChanged *metav1.Time `json:"lastChanged,omitempty"`
	// Containers evaluated, and how many were trusted, would be denied,
	// or could not be judged (signatures not checked or not checkable:
	// never counted as trusted).
	Containers int64 `json:"containers"`
	Trusted    int64 `json:"trusted"`
	WouldDeny  int64 `json:"wouldDeny"`
	Unknown    int64 `json:"unknown"`
	// Findings lists would-deny and unknown containers, bounded.
	Findings []ImageTrustFinding `json:"findings,omitempty"`
	// Truncated is true when there were more findings than listed.
	Truncated bool `json:"truncated,omitempty"`
}

// ImageTrustFinding is one container that is not trusted.
type ImageTrustFinding struct {
	Namespace string `json:"namespace"`
	// Workload is "Kind/name".
	Workload   string `json:"workload"`
	Container  string `json:"container"`
	Repository string `json:"repository,omitempty"`
	Digest     string `json:"digest"`
	// Verdict: WouldDeny or Unknown.
	Verdict string `json:"verdict"`
	// Reason: unsigned, invalid, untrusted-signer, key-not-verified,
	// attestation-missing, not-checked, or the discovery reason for an
	// unknown (registry_auth, rate_limited, ...).
	Reason string `json:"reason"`
}

// ImageTrustPolicyList contains a list of ImageTrustPolicy.
type ImageTrustPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageTrustPolicy `json:"items"`
}

// ClusterImageTrustPolicy is the cluster-scoped sibling: the same spec
// plus a namespaceSelector (nil or {} = every namespace).
type ClusterImageTrustPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClusterImageTrustPolicySpec `json:"spec"`
	Status            ImageTrustPolicyStatus      `json:"status,omitempty"`
}

// ClusterImageTrustPolicySpec is ImageTrustPolicySpec plus a
// namespaceSelector.
type ClusterImageTrustPolicySpec struct {
	NamespaceSelector    *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	ImageTrustPolicySpec `json:",inline"`
}

// ClusterImageTrustPolicyList contains a list of ClusterImageTrustPolicy.
type ClusterImageTrustPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterImageTrustPolicy `json:"items"`
}

// Verdicts in ImageTrustFinding.Verdict.
const (
	ImageTrusted   = "Trusted"
	ImageWouldDeny = "WouldDeny"
	ImageUnknown   = "Unknown"
)

// DeepCopyObject implementations, hand-written like the network policy
// types (no code generation in this module).

func (in *ImageTrustPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	meta := in.ObjectMeta
	meta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec.deepCopy()
	out.Status = in.Status.deepCopy()
	return &out
}

func (in *ImageTrustPolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	out.Items = make([]ImageTrustPolicy, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*ImageTrustPolicy)
	}
	return &out
}

func (in *ClusterImageTrustPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	meta := in.ObjectMeta
	meta.DeepCopyInto(&out.ObjectMeta)
	if in.Spec.NamespaceSelector != nil {
		out.Spec.NamespaceSelector = in.Spec.NamespaceSelector.DeepCopy()
	}
	out.Spec.ImageTrustPolicySpec = in.Spec.deepCopy()
	out.Status = in.Status.deepCopy()
	return &out
}

func (in *ClusterImageTrustPolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	out.Items = make([]ClusterImageTrustPolicy, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*ClusterImageTrustPolicy)
	}
	return &out
}

func (in ImageTrustPolicySpec) deepCopy() ImageTrustPolicySpec {
	out := in
	out.Images = append([]string(nil), in.Images...)
	out.Attestations = append([]AttestationRequirement(nil), in.Attestations...)
	out.Authorities = make([]Authority, len(in.Authorities))
	for i, a := range in.Authorities {
		out.Authorities[i] = a
		if a.Keyless != nil {
			k := *a.Keyless
			out.Authorities[i].Keyless = &k
		}
		if a.Key != nil {
			k := *a.Key
			out.Authorities[i].Key = &k
		}
	}
	return out
}

func (in ImageTrustPolicyStatus) deepCopy() ImageTrustPolicyStatus {
	out := in
	if in.Evaluation.LastChanged != nil {
		t := *in.Evaluation.LastChanged
		out.Evaluation.LastChanged = &t
	}
	out.Evaluation.Findings = append([]ImageTrustFinding(nil), in.Evaluation.Findings...)
	return out
}
