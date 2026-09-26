package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	log "github.com/rs/zerolog/log"
)

// Vulnerability and SBOM reads (broker supply-chain API): findings the
// supplychain component ingested from Trivy Operator reports and, when the
// opt-in matcher is enabled, kguardian's own Grype matches over SBOMs,
// keyed by image digest.
//
// null means unknown throughout: an image with no report has no data (not
// "no vulnerabilities"), kev/epss null means no source said, and inUse is
// null until kguardian can tell which packages a workload loads.

// VulnReport is one source's report on an image.
type VulnReport struct {
	Source         string   `json:"source"`
	ReportDigest   string   `json:"reportDigest"`
	Join           string   `json:"join"`
	DigestKind     string   `json:"digestKind"`
	ScannedAt      string   `json:"scannedAt"`
	DBUpdatedAt    *string  `json:"dbUpdatedAt"`
	ScannerName    *string  `json:"scannerName"`
	ScannerVersion *string  `json:"scannerVersion"`
	OSFamily       *string  `json:"osFamily"`
	OSName         *string  `json:"osName"`
	ItemCount      int      `json:"itemCount"`
	SbomFormat     *string  `json:"sbomFormat"`
	SbomSources    []string `json:"sbomSources"`
	SbomTrust      *string  `json:"sbomTrust"`
	Attestation    *struct {
		Mechanism     *string `json:"mechanism"`
		PredicateType *string `json:"predicate_type"`
		Verified      bool    `json:"verified"`
	} `json:"attestation"`
}

// VulnPackage names the affected package.
type VulnPackage struct {
	Name string  `json:"name"`
	Type *string `json:"type"`
	Purl *string `json:"purl"`
}

// VulnFinding is one finding, deduplicated across sources.
type VulnFinding struct {
	ID               string      `json:"id"`
	Package          VulnPackage `json:"package"`
	InstalledVersion string      `json:"installedVersion"`
	// FixedVersions lists every distinct fixed version the sources give,
	// in source order (not version order: "10.1" sorts before "9.2").
	FixedVersions []string `json:"fixedVersions"`
	Fixable       bool     `json:"fixable"`
	Severity      string   `json:"severity"`
	Score         *float64 `json:"score"`
	Title         *string  `json:"title"`
	Kev           *bool    `json:"kev"`
	Epss          *float64 `json:"epss"`
	Sources       []string `json:"sources"`
	InUse         *bool    `json:"inUse"`
	InUseState    string   `json:"inUseState"`
}

// ImageVulnsPage is GET /images/{digest}/vulnerabilities.
type ImageVulnsPage struct {
	Digest    string        `json:"digest"`
	Reports   []VulnReport  `json:"reports"`
	Items     []VulnFinding `json:"items"`
	NextAfter *string       `json:"nextAfter"`
}

// ImageVulnsOptions filters GET /images/{digest}/vulnerabilities. Zero
// values are not sent; Fixable nil = both.
type ImageVulnsOptions struct {
	Severity string
	Fixable  *bool
	Source   string
	Limit    int
	After    string
}

// CveSummary is one row of GET /vulnerabilities.
type CveSummary struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	MaxScore         *float64 `json:"maxScore"`
	Fixable          bool     `json:"fixable"`
	Kev              *bool    `json:"kev"`
	MaxEpss          *float64 `json:"maxEpss"`
	Packages         []string `json:"packages"`
	Sources          []string `json:"sources"`
	Images           int64    `json:"images"`
	Workloads        int64    `json:"workloads"`
	RunningWorkloads int64    `json:"runningWorkloads"`
	Namespaces       int64    `json:"namespaces"`
	WeakestJoin      string   `json:"weakestJoin"`
	InUse            *bool    `json:"inUse"`
}

// CvePage is GET /vulnerabilities. ComputedAt nil = the summary has not
// been built since the broker started (unknown, not empty).
type CvePage struct {
	Items        []CveSummary `json:"items"`
	NextAfter    *string      `json:"nextAfter"`
	ComputedAt   *string      `json:"computedAt"`
	StaleSeconds *int64       `json:"staleSeconds"`
}

// VulnsListOptions filters GET /vulnerabilities.
type VulnsListOptions struct {
	Namespace string
	Severity  string
	Fixable   *bool
	Running   bool
	Limit     int
	After     string
}

// NetworkExposure is the observed ingress for one workload. Exposed is
// false only when ingress was observed (IngressFlowsObserved > 0) and none
// came from outside; nil = unknown (no ingress observed, even with egress:
// inbound UDP is not captured), never "not exposed".
type NetworkExposure struct {
	WindowHours                  int64    `json:"windowHours"`
	PodsObserved                 int64    `json:"podsObserved"`
	FlowsObserved                int64    `json:"flowsObserved"`
	IngressFlowsObserved         int64    `json:"ingressFlowsObserved"`
	IngressFromOtherNamespaces   int64    `json:"ingressFromOtherNamespaces"`
	IngressFromUnattributedPeers int64    `json:"ingressFromUnattributedPeers"`
	IngressFromPublicIPs         int64    `json:"ingressFromPublicIps"`
	IngressFromNodes             int64    `json:"ingressFromNodes"`
	Exposed                      *bool    `json:"exposed"`
	ExposedVia                   []string `json:"exposedVia"`
}

// ExposedImage is an inventory image a CVE affects.
type ExposedImage struct {
	Digest     string   `json:"digest"`
	Repository *string  `json:"repository"`
	Tags       []string `json:"tags"`
	Sources    []string `json:"sources"`
	Join       string   `json:"join"`
	Severity   string   `json:"severity"`
	Packages   []struct {
		Name             string   `json:"name"`
		InstalledVersion string   `json:"installedVersion"`
		FixedVersions    []string `json:"fixedVersions"`
		Severity         string   `json:"severity"`
	} `json:"packages"`
}

// ExposedWorkload is a workload container running (or having run) an
// affected image.
type ExposedWorkload struct {
	Namespace   string          `json:"namespace"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Container   string          `json:"container"`
	ImageDigest string          `json:"imageDigest"`
	Join        string          `json:"join"`
	Running     bool            `json:"running"`
	LastSeen    string          `json:"lastSeen"`
	Network     NetworkExposure `json:"network"`
	InUse       *bool           `json:"inUse"`
}

// NamespaceExposure summarises one namespace.
type NamespaceExposure struct {
	Namespace                string `json:"namespace"`
	Workloads                int64  `json:"workloads"`
	RunningWorkloads         int64  `json:"runningWorkloads"`
	ExposedWorkloads         int64  `json:"exposedWorkloads"`
	UnknownExposureWorkloads int64  `json:"unknownExposureWorkloads"`
}

// Exposure is GET /vulnerabilities/{id}/exposure.
type Exposure struct {
	ID         string              `json:"id"`
	Severity   string              `json:"severity"`
	Fixable    bool                `json:"fixable"`
	Images     []ExposedImage      `json:"images"`
	Workloads  []ExposedWorkload   `json:"workloads"`
	Namespaces []NamespaceExposure `json:"namespaces"`
	Truncated  bool                `json:"truncated"`
	InUse      *bool               `json:"inUse"`
}

// SbomComponent is one SBOM component.
type SbomComponent struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Version  *string  `json:"version"`
	Purl     *string  `json:"purl"`
	Type     *string  `json:"type"`
	Licenses []string `json:"licenses"`
}

// SbomPage is GET /images/{digest}/sbom. Report nil = no SBOM (unknown).
type SbomPage struct {
	Digest    string          `json:"digest"`
	Reports   []VulnReport    `json:"reports"`
	Report    *VulnReport     `json:"report"`
	Items     []SbomComponent `json:"items"`
	NextAfter *int64          `json:"nextAfter"`
}

// maxCycloneDXBytes bounds the CycloneDX download. The broker caps the
// document at its SBOM component limit; this is a client-side backstop
// well above that, and a document that reaches it is refused rather than
// written out truncated.
const maxCycloneDXBytes = 64 << 20

// Swappable for tests that bypass HTTP.
var (
	GetImageVulnsFunc    = getRealImageVulns
	GetVulnsFunc         = getRealVulns
	GetExposureFunc      = getRealExposure
	GetSbomFunc          = getRealSbom
	GetSbomCycloneDXFunc = getRealSbomCycloneDX
)

// GetImageVulns returns one page of findings for an image, plus the raw body.
func GetImageVulns(digest string, opts ImageVulnsOptions) (*ImageVulnsPage, []byte, error) {
	return GetImageVulnsFunc(digest, opts)
}

// GetVulns returns one page of the cluster CVE summary, plus the raw body.
func GetVulns(opts VulnsListOptions) (*CvePage, []byte, error) { return GetVulnsFunc(opts) }

// GetExposure returns where a CVE runs and its observed exposure. 0 =
// broker default window.
func GetExposure(id string, windowHours int) (*Exposure, []byte, error) {
	return GetExposureFunc(id, windowHours)
}

// GetSbom returns one page of an image's SBOM components.
func GetSbom(digest, source string, limit int, after int64) (*SbomPage, []byte, error) {
	return GetSbomFunc(digest, source, limit, after)
}

// GetSbomCycloneDX returns the broker's CycloneDX export for an image.
func GetSbomCycloneDX(digest, source string) ([]byte, error) {
	return GetSbomCycloneDXFunc(digest, source)
}

func boolQuery(q url.Values, key string, v *bool) {
	if v != nil {
		q.Set(key, strconv.FormatBool(*v))
	}
}

func withQuery(path string, q url.Values) string {
	if enc := q.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

func decodeInto[T any](op string, body []byte) (*T, []byte, error) {
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("%s: decoding response: %w", op, err)
	}
	return &out, body, nil
}

func getRealImageVulns(digest string, o ImageVulnsOptions) (*ImageVulnsPage, []byte, error) {
	q := url.Values{}
	if o.Severity != "" {
		q.Set("severity", o.Severity)
	}
	boolQuery(q, "fixable", o.Fixable)
	if o.Source != "" {
		q.Set("source", o.Source)
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.After != "" {
		q.Set("after", o.After)
	}
	body, err := brokerGetBody("GetImageVulns", withQuery("/images/"+url.PathEscape(digest)+"/vulnerabilities", q))
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[ImageVulnsPage]("GetImageVulns", body)
}

func getRealVulns(o VulnsListOptions) (*CvePage, []byte, error) {
	q := url.Values{}
	if o.Namespace != "" {
		q.Set("namespace", o.Namespace)
	}
	if o.Severity != "" {
		q.Set("severity", o.Severity)
	}
	boolQuery(q, "fixable", o.Fixable)
	if o.Running {
		q.Set("running", "true")
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.After != "" {
		q.Set("after", o.After)
	}
	body, err := brokerGetBody("GetVulns", withQuery("/vulnerabilities", q))
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[CvePage]("GetVulns", body)
}

func getRealExposure(id string, windowHours int) (*Exposure, []byte, error) {
	q := url.Values{}
	if windowHours > 0 {
		q.Set("window_hours", strconv.Itoa(windowHours))
	}
	body, err := brokerGetBody("GetExposure", withQuery("/vulnerabilities/"+url.PathEscape(id)+"/exposure", q))
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[Exposure]("GetExposure", body)
}

func getRealSbom(digest, source string, limit int, after int64) (*SbomPage, []byte, error) {
	q := url.Values{}
	if source != "" {
		q.Set("source", source)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if after > 0 {
		q.Set("after", strconv.FormatInt(after, 10))
	}
	body, err := brokerGetBody("GetSbom", withQuery("/images/"+url.PathEscape(digest)+"/sbom", q))
	if err != nil {
		return nil, nil, err
	}
	return decodeInto[SbomPage]("GetSbom", body)
}

func getRealSbomCycloneDX(digest, source string) ([]byte, error) {
	q := url.Values{}
	if source != "" {
		q.Set("source", source)
	}
	resp, err := brokerGet(withQuery("/images/"+url.PathEscape(digest)+"/sbom/cyclonedx", q))
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetSbomCycloneDX: Error closing response body")
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCycloneDXBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GetSbomCycloneDX: reading response body: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if len(body) > maxCycloneDXBytes {
			return nil, fmt.Errorf("GetSbomCycloneDX: document larger than %d MiB; page it with 'images sbom' instead", maxCycloneDXBytes>>20)
		}
		return body, nil
	case http.StatusNotFound:
		return nil, &NotFoundError{Message: string(body)}
	default:
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("GetSbomCycloneDX: broker returned HTTP %d: %s", resp.StatusCode, msg)
	}
}
