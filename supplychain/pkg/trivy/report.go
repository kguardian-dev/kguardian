// Package trivy reads Trivy Operator's VulnerabilityReport and SbomReport
// custom resources (aquasecurity.github.io/v1alpha1) and normalises them
// into the digest-keyed payloads in pkg/types.
//
// The report structs below are a deliberately minimal, local mirror of
// trivy-operator's pkg/apis/aquasecurity/v1alpha1 types (vulnerability_types.go,
// sbom_types.go, common_types.go at v0.34.0). Importing the upstream module
// would pull the whole Trivy dependency tree into this binary; after the
// March 2026 Trivy supply-chain compromise (GHSA-69fq-xp46-6x23) the
// component should depend on Trivy's *data format* only, never its code.
// Unknown fields are ignored, so newer operator versions that add fields
// keep working.
package trivy

import (
	"bytes"
	"encoding/json"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Group and version served by Trivy Operator's CRDs.
const (
	Group   = "aquasecurity.github.io"
	Version = "v1alpha1"
)

// GVRs the watcher lists and watches. Namespaced; the cluster-scoped
// Cluster* variants (node/control-plane components) are out of scope.
var (
	VulnerabilityReportGVR = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "vulnerabilityreports"}
	SbomReportGVR          = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "sbomreports"}
)

// Labels trivy-operator puts on every per-workload report.
const (
	LabelContainerName     = "trivy-operator.container.name"
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
)

// CycloneDX property names Trivy writes on SBOM components.
const (
	propPkgType     = "aquasecurity:trivy:PkgType"
	propClass       = "aquasecurity:trivy:Class"
	propSrcName     = "aquasecurity:trivy:SrcName"
	propSrcVersion  = "aquasecurity:trivy:SrcVersion"
	propLayerDigest = "aquasecurity:trivy:LayerDigest"
	propFilePath    = "aquasecurity:trivy:FilePath"
	propRepoDigest  = "aquasecurity:trivy:RepoDigest"
	propType        = "aquasecurity:trivy:Type"
)

type reportMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	UID       string            `json:"uid"`
	Labels    map[string]string `json:"labels"`
}

type scanner struct {
	Name    string     `json:"name"`
	Vendor  string     `json:"vendor"`
	Version flexString `json:"version"`
}

type registry struct {
	Server string `json:"server"`
}

type artifact struct {
	Repository string     `json:"repository"`
	Digest     string     `json:"digest"`
	Tag        flexString `json:"tag"`
	MimeType   string     `json:"mimeType"`
}

type osInfo struct {
	EOSL   bool       `json:"eosl"`
	Family string     `json:"family"`
	Name   flexString `json:"name"`
}

type cvss struct {
	V2Vector  string   `json:"V2Vector"`
	V3Vector  string   `json:"V3Vector"`
	V40Vector string   `json:"V40Vector"`
	V2Score   *float64 `json:"V2Score"`
	V3Score   *float64 `json:"V3Score"`
	V40Score  *float64 `json:"V40Score"`
}

type vulnerability struct {
	VulnerabilityID  string          `json:"vulnerabilityID"`
	Resource         string          `json:"resource"`
	InstalledVersion string          `json:"installedVersion"`
	FixedVersion     string          `json:"fixedVersion"`
	PublishedDate    string          `json:"publishedDate"`
	LastModifiedDate string          `json:"lastModifiedDate"`
	Severity         string          `json:"severity"`
	Title            string          `json:"title"`
	PrimaryLink      string          `json:"primaryLink"`
	Score            *float64        `json:"score"`
	Target           string          `json:"target"`
	CVSS             map[string]cvss `json:"cvss"`
	Class            string          `json:"class"`
	PackageType      string          `json:"packageType"`
	PkgPath          string          `json:"packagePath"`
	PkgPURL          string          `json:"packagePURL"`
}

type vulnerabilityReportData struct {
	UpdateTimestamp string          `json:"updateTimestamp"`
	Scanner         scanner         `json:"scanner"`
	Registry        registry        `json:"registry"`
	Artifact        artifact        `json:"artifact"`
	OS              osInfo          `json:"os"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

// VulnerabilityReport mirrors aquasecurity.github.io/v1alpha1 VulnerabilityReport.
type VulnerabilityReport struct {
	Metadata reportMeta              `json:"metadata"`
	Report   vulnerabilityReportData `json:"report"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type license struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type licenseChoice struct {
	License    *license `json:"license"`
	Expression string   `json:"expression"`
}

type component struct {
	BOMRef     string          `json:"bom-ref"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Group      string          `json:"group"`
	Version    flexString      `json:"version"`
	PURL       string          `json:"purl"`
	Licenses   []licenseChoice `json:"licenses"`
	Properties []property      `json:"properties"`
}

type bomMetadata struct {
	Timestamp string     `json:"timestamp"`
	Component *component `json:"component"`
}

type bom struct {
	BOMFormat   string       `json:"bomFormat"`
	SpecVersion flexString   `json:"specVersion"`
	Metadata    *bomMetadata `json:"metadata"`
	Components  []component  `json:"components"`
}

type sbomReportData struct {
	UpdateTimestamp string   `json:"updateTimestamp"`
	Scanner         scanner  `json:"scanner"`
	Registry        registry `json:"registry"`
	Artifact        artifact `json:"artifact"`
	BOM             bom      `json:"components"`
}

// SbomReport mirrors aquasecurity.github.io/v1alpha1 SbomReport.
type SbomReport struct {
	Metadata reportMeta     `json:"metadata"`
	Report   sbomReportData `json:"report"`
}

// flexString decodes a JSON string or a bare number into a string. YAML
// written by hand (the upstream docs samples among it) leaves values like
// "specVersion: 1.4" or "tag: 1.16" unquoted, which arrive as numbers.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	if bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}
