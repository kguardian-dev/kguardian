// Package wire is the localhost contract between the supplychain
// container and this matcher. The JSON field names deliberately equal the
// supplychain payload types (supplychain/pkg/types), so a request body is
// a subset of an ImageSBOM and a response's vulnerabilities decode
// straight into types.Vulnerability. The two modules do not import each
// other: the matcher's dependency tree stays out of supplychain.
package wire

import "time"

// Component is one package of the SBOM to match.
type Component struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	PURL       string   `json:"purl,omitempty"`
	Type       string   `json:"type,omitempty"`
	SrcName    string   `json:"src_name,omitempty"`
	SrcVersion string   `json:"src_version,omitempty"`
	Licenses   []string `json:"licenses,omitempty"`
	FilePaths  []string `json:"file_paths,omitempty"`
}

// MatchRequest is POST /match's body (gzip JSON), an ImageSBOM subset.
type MatchRequest struct {
	Image struct {
		Digest string `json:"digest"`
	} `json:"image"`
	Components []Component `json:"components"`
}

// DB describes the loaded vulnerability database.
type DB struct {
	Built         *time.Time `json:"built,omitempty"`
	SchemaVersion string     `json:"schema_version,omitempty"`
	// Loaded is false until a database is ready to match against.
	Loaded bool `json:"loaded"`
	// LastUpdateCheck/LastUpdateError describe the refresh loop.
	LastUpdateCheck *time.Time `json:"last_update_check,omitempty"`
	LastUpdateError string     `json:"last_update_error,omitempty"`
	// Scanner version string, e.g. "grype v0.119.0".
	Scanner string `json:"scanner"`
}

// CVSS mirrors supplychain types.CVSS.
type CVSS struct {
	V2Score   *float64 `json:"v2_score,omitempty"`
	V2Vector  string   `json:"v2_vector,omitempty"`
	V3Score   *float64 `json:"v3_score,omitempty"`
	V3Vector  string   `json:"v3_vector,omitempty"`
	V40Score  *float64 `json:"v40_score,omitempty"`
	V40Vector string   `json:"v40_vector,omitempty"`
}

// Package mirrors supplychain types.Package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// Vulnerability mirrors supplychain types.Vulnerability.
type Vulnerability struct {
	ID             string          `json:"id"`
	Package        Package         `json:"package"`
	FixedVersion   string          `json:"fixed_version,omitempty"`
	Severity       string          `json:"severity"`
	Score          *float64        `json:"score,omitempty"`
	CVSS           map[string]CVSS `json:"cvss,omitempty"`
	Title          string          `json:"title,omitempty"`
	PrimaryURL     string          `json:"primary_url,omitempty"`
	Target         string          `json:"target,omitempty"`
	Class          string          `json:"class,omitempty"`
	KnownExploited bool            `json:"kev,omitempty"`
	KEVDateAdded   *time.Time      `json:"kev_date_added,omitempty"`
	EPSS           *float64        `json:"epss,omitempty"`
	EPSSPercentile *float64        `json:"epss_percentile,omitempty"`
	FilePaths      []string        `json:"file_paths,omitempty"`
}

// MatchResponse is POST /match's response.
type MatchResponse struct {
	DB              DB              `json:"db"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
