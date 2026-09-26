// Package types holds the normalised, source-independent payloads the
// supplychain component sends to the broker. Every payload is keyed by
// image digest: one image scanned once is one payload, however many
// workloads run it. The workload -> image mapping is owned by the
// broker's own inventory (built from pod status), not by these payloads.
//
// The wire format is documented in supplychain/README.md. Field names are
// snake_case JSON to match the broker's existing ingest bodies.
package types

import "time"

// SchemaVersion is bumped on any breaking change to the wire format so the
// broker can reject or translate payloads from an older/newer component.
const SchemaVersion = 1

// Source identifies where a finding came from. The broker stores it with
// every row so the UI can say "according to Trivy Operator" rather than
// presenting third-party data as kguardian's own verdict.
const (
	SourceTrivyOperator = "trivy-operator"
	// SourceRegistry: an SBOM attached to the image in its registry
	// (OCI referrer, cosign attachment/attestation, BuildKit attestation).
	SourceRegistry = "registry"
	// SourceGrype: vulnerabilities kguardian matched itself with Grype
	// against an SBOM from one of the other sources.
	SourceGrype = "grype"
)

// Scanner describes the tool that produced a report.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}

// OS is the base operating system the scanner detected in the image.
type OS struct {
	Family string `json:"family,omitempty"`
	Name   string `json:"name,omitempty"`
	// EOSL is true when the scanner flagged the distro release as past
	// end of service life (no more security fixes).
	EOSL bool `json:"eosl,omitempty"`
}

// ImageRef is the human-readable identity of the image that was scanned.
type ImageRef struct {
	// Digest is the content digest ("sha256:<64 hex>") that keys the
	// payload. Always set: a report whose digest cannot be resolved is
	// held back, never sent keyed by a mutable tag.
	Digest string `json:"digest"`
	// Ref is "<registry>/<repository>:<tag>" as the report states it.
	Ref        string `json:"ref,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	// DigestKind says what Digest points at: an image index (multi-arch
	// list), a single-platform manifest, or unknown when the registry was
	// not consulted or could not be reached anonymously.
	DigestKind string `json:"digest_kind"`
	// PlatformManifests maps "os/arch[/variant]" to the platform manifest
	// digest, when Digest is an index. Empty otherwise.
	PlatformManifests map[string]string `json:"platform_manifests,omitempty"`
}

// DigestKind values.
const (
	DigestKindIndex    = "index"
	DigestKindManifest = "manifest"
	DigestKindUnknown  = "unknown"
)

// WorkloadRef names a workload container a source report was produced for.
// Informational provenance only: it records which report(s) this payload
// came from at send time. The authoritative workload -> digest mapping is
// the broker's inventory.
type WorkloadRef struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
}

// CVSS is one vendor's CVSS assessment of a vulnerability.
type CVSS struct {
	V2Score   *float64 `json:"v2_score,omitempty"`
	V2Vector  string   `json:"v2_vector,omitempty"`
	V3Score   *float64 `json:"v3_score,omitempty"`
	V3Vector  string   `json:"v3_vector,omitempty"`
	V40Score  *float64 `json:"v40_score,omitempty"`
	V40Vector string   `json:"v40_vector,omitempty"`
}

// Package identifies the installed package a vulnerability is in.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Type is the ecosystem ("debian", "alpine", "gobinary", "npm",
	// "jar", ...), as the scanner names it.
	Type string `json:"type,omitempty"`
	PURL string `json:"purl,omitempty"`
}

// Vulnerability is one finding against one installed package.
type Vulnerability struct {
	ID      string  `json:"id"`
	Package Package `json:"package"`
	// FixedVersion is empty when no fix is published.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Severity is one of CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN.
	Severity string `json:"severity"`
	// Score is the scanner's headline score (its chosen CVSS source).
	Score *float64 `json:"score,omitempty"`
	// CVSS is keyed by vendor ("nvd", "redhat", "ghsa", ...).
	CVSS  map[string]CVSS `json:"cvss,omitempty"`
	Title string          `json:"title,omitempty"`
	// PrimaryURL is the advisory link. The broker must treat it as
	// untrusted text (render as a link, never fetch it).
	PrimaryURL string `json:"primary_url,omitempty"`
	// Target is the scanner's scan target (e.g. "nginx:1.16 (debian 10.3)"
	// or a lockfile path inside the image).
	Target string `json:"target,omitempty"`
	// Class is "os-pkgs" or "lang-pkgs" when the scanner reports it.
	Class string `json:"class,omitempty"`
	// KnownExploited is true when the vulnerability is in CISA's Known
	// Exploited Vulnerabilities catalogue (Grype DB; not set by Trivy).
	KnownExploited bool       `json:"kev,omitempty"`
	KEVDateAdded   *time.Time `json:"kev_date_added,omitempty"`
	// EPSS is the FIRST.org exploit prediction score (0-1) and its
	// percentile, when the source provides them (Grype DB).
	EPSS           *float64   `json:"epss,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	LastModifiedAt *time.Time `json:"last_modified_at,omitempty"`
	// FilePaths are the paths inside the image that belong to the
	// package, when known. These are what the runtime join (files a
	// workload actually executed/loaded) matches against.
	FilePaths []string `json:"file_paths,omitempty"`
}

// ImageVulnerabilities is the full vulnerability set for one image digest
// from one source. It replaces the previous set for (digest, source).
type ImageVulnerabilities struct {
	SchemaVersion int      `json:"schema_version"`
	Image         ImageRef `json:"image"`
	Source        string   `json:"source"`
	Scanner       Scanner  `json:"scanner"`
	// ScannedAt is when the source produced the report.
	ScannedAt time.Time `json:"scanned_at"`
	// DBUpdatedAt is when the vulnerability database used for the scan was
	// built. Nil when the source does not record it (Trivy Operator does
	// not put the trivy-db timestamp in its reports).
	DBUpdatedAt *time.Time `json:"db_updated_at,omitempty"`
	// SBOMSource is, for source=grype, which SBOM was matched
	// (registry or trivy-operator). Empty for scanners that read the image.
	SBOMSource      string          `json:"sbom_source,omitempty"`
	OS              OS              `json:"os"`
	ObservedIn      []WorkloadRef   `json:"observed_in,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Component is one SBOM entry (an installed package or the OS itself).
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	// Type is the package ecosystem (see Package.Type), or
	// "operating-system" for the distro entry (Name is the distro family).
	Type string `json:"type,omitempty"`
	// Class is "os-pkgs" or "lang-pkgs" when known.
	Class       string   `json:"class,omitempty"`
	SrcName     string   `json:"src_name,omitempty"`
	SrcVersion  string   `json:"src_version,omitempty"`
	Licenses    []string `json:"licenses,omitempty"`
	LayerDigest string   `json:"layer_digest,omitempty"`
	FilePaths   []string `json:"file_paths,omitempty"`
}

// ImageSBOM is the normalised software bill of materials for one image
// digest from one source. It replaces the previous SBOM for (digest, source).
type ImageSBOM struct {
	SchemaVersion int       `json:"schema_version"`
	Image         ImageRef  `json:"image"`
	Source        string    `json:"source"`
	Scanner       Scanner   `json:"scanner"`
	ScannedAt     time.Time `json:"scanned_at"`
	// Format/SpecVersion describe the document the components came from,
	// e.g. "CycloneDX" / "1.6".
	Format      string        `json:"format"`
	SpecVersion string        `json:"spec_version,omitempty"`
	ObservedIn  []WorkloadRef `json:"observed_in,omitempty"`
	// Attestation describes where a registry SBOM was found. Nil for
	// other sources.
	Attestation *Attestation `json:"attestation,omitempty"`
	// Page is set when the SBOM is sent in several requests (see Page).
	Page       *Page       `json:"page,omitempty"`
	Components []Component `json:"components"`
}

// Page identifies one request of an SBOM split across several. Every page
// repeats the header fields; the broker assembles pages sharing SetID and
// replaces the stored SBOM for (digest, source) only once all Total pages
// (Index 0..Total-1) of that set have arrived. A newer set supersedes an
// incomplete older one.
type Page struct {
	SetID string `json:"set_id"`
	Index int    `json:"index"`
	Total int    `json:"total"`
}

// Attestation mechanisms for registry SBOMs.
const (
	MechanismOCIReferrer         = "oci-referrer"
	MechanismCosignAttestation   = "cosign-attestation"
	MechanismCosignSBOM          = "cosign-sbom"
	MechanismBuildKitAttestation = "buildkit-attestation"
)

// Attestation records how a registry SBOM was attached to its image.
type Attestation struct {
	Mechanism string `json:"mechanism"`
	// ArtifactDigest is the manifest the SBOM was read from.
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	MediaType      string `json:"media_type,omitempty"`
	PredicateType  string `json:"predicate_type,omitempty"`
	// Verified is always false in this version: the document was found
	// attached to the image, but no signature was checked. Signature and
	// identity verification is a separate step (#1533 P2).
	Verified bool `json:"verified"`
}
