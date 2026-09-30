// Package protocol is the Controller-worker scan protocol (PROTOCOL.md):
// the JSON messages, their framing, and passing the root fd with
// SCM_RIGHTS. PROTOCOL.md is the contract; this package is its reference
// implementation.
package protocol

import (
	"fmt"
	"path"
	"regexp"
	"unicode/utf8"
)

// Version is the protocol version this worker speaks.
const Version = 1

// Ops.
const (
	OpScan = "scan"
	OpPing = "ping"
)

// Profiles.
const (
	ProfileFull   = "full"
	ProfileOSOnly = "os_only"
)

// Status values.
const (
	StatusOK     = "ok"
	StatusFailed = "failed"
)

// Completeness values.
const (
	CompletenessFull    = "full"
	CompletenessPartial = "partial"
	CompletenessOSOnly  = "os_only"
)

// Failure reasons (PROTOCOL.md §4.4).
const (
	ReasonTimeout             = "timeout"
	ReasonOOM                 = "oom"
	ReasonTooManyComponents   = "too_many_components"
	ReasonNoPackagesFound     = "no_packages_found"
	ReasonLSMDenied           = "lsm_denied"
	ReasonKernelUnsupported   = "kernel_unsupported"
	ReasonCapsUnavailable     = "caps_unavailable"
	ReasonError               = "error"
	ReasonBusy                = "busy"
	ReasonBadRequest          = "bad_request"
	ReasonUnsupportedProtocol = "unsupported_protocol"
	ReasonOutputTooLarge      = "output_too_large"
	// ReasonWorkerUnavailable: the worker started but its environment
	// does not let it scan (it answers pings with this and refuses scans).
	ReasonWorkerUnavailable = "worker_unavailable"

	// ReasonTooManyFiles is only ever a retry_reason: the os_only retry
	// indexes up to the budget instead of failing.
	ReasonTooManyFiles = "too_many_files"
)

// Partial reasons (PROTOCOL.md §4.2).
const (
	PartialEACCES            = "eacces"
	PartialNoDACReadSearch   = "no_dac_read_search"
	PartialCtimeDropped      = "ctime_dropped"
	PartialDepthLimited      = "depth_limited"
	PartialFilesTruncated    = "files_truncated"
	PartialResponseTrimmed   = "response_trimmed"
	PartialComponentsDropped = "components_dropped"
	PartialFileBudget        = "file_budget"
)

// Limits. The component and OS limits are the broker's (its LEN_* and
// MAX_* constants in broker/src/supplychain.rs; contract_test.go keeps
// them equal): the worker drops what does not fit rather than letting the
// broker cut it silently.
const (
	MaxRequestBytes       = 64 * 1024
	MaxResponseCeiling    = 64 * 1024 * 1024
	MaxSubmounts          = 1024
	MaxSubmountLen        = 4096
	MaxScanIDLen          = 128
	MaxMessageLen         = 1024
	MaxNameLen            = 256
	MaxVersionLen         = 128
	MaxPathLen            = 1024
	MaxLicenses           = 8
	MaxLicenseLen         = 128 // broker LEN_VERSION, as clean_list applies it
	MaxShortLen           = 64  // broker LEN_SHORT: type, class, scanner fields
	MaxOSLen              = 64  // broker LEN_SHORT: os family and name
	MaxPURLLen            = 1024
	MaxPathsPerPkgCeiling = 4096
)

// Budget defaults and ceilings (PROTOCOL.md §3.2).
var (
	DefaultBudgets = Budgets{
		MaxFiles:           2_000_000,
		MaxComponents:      50_000,
		MaxDepth:           4096,
		ScanTimeoutMS:      600_000,
		MaxPathsPerPackage: 4096,
		// The Controller normally sends its own value (16 MiB by default);
		// this applies only when it does not.
		MaxResponseBytes: 16 * 1024 * 1024,
	}
	CeilingBudgets = Budgets{
		MaxFiles:           10_000_000,
		MaxComponents:      50_000,
		MaxDepth:           4096,
		ScanTimeoutMS:      1_800_000,
		MaxPathsPerPackage: MaxPathsPerPkgCeiling,
		MaxResponseBytes:   MaxResponseCeiling,
	}
)

// Budgets bound one scan. Zero means the default.
type Budgets struct {
	MaxFiles           int64 `json:"max_files,omitempty"`
	MaxComponents      int64 `json:"max_components,omitempty"`
	MaxDepth           int64 `json:"max_depth,omitempty"`
	ScanTimeoutMS      int64 `json:"scan_timeout_ms,omitempty"`
	MaxPathsPerPackage int64 `json:"max_paths_per_package,omitempty"`
	MaxResponseBytes   int64 `json:"max_response_bytes,omitempty"`
}

func clamp(v, def, ceil int64) int64 {
	if v <= 0 {
		return def
	}
	return min(v, ceil)
}

// Effective fills defaults and clamps to the ceilings.
func (b Budgets) Effective() Budgets {
	d, c := DefaultBudgets, CeilingBudgets
	return Budgets{
		MaxFiles:           clamp(b.MaxFiles, d.MaxFiles, c.MaxFiles),
		MaxComponents:      clamp(b.MaxComponents, d.MaxComponents, c.MaxComponents),
		MaxDepth:           clamp(b.MaxDepth, d.MaxDepth, c.MaxDepth),
		ScanTimeoutMS:      clamp(b.ScanTimeoutMS, d.ScanTimeoutMS, c.ScanTimeoutMS),
		MaxPathsPerPackage: clamp(b.MaxPathsPerPackage, d.MaxPathsPerPackage, c.MaxPathsPerPackage),
		MaxResponseBytes:   clamp(b.MaxResponseBytes, d.MaxResponseBytes, c.MaxResponseBytes),
	}
}

// Request is the Controller's message.
type Request struct {
	ProtocolVersion         int      `json:"protocol_version"`
	Op                      string   `json:"op"`
	ScanID                  string   `json:"scan_id"`
	Epoch                   int64    `json:"epoch"`
	ContainerStartUnixNanos int64    `json:"container_start_unix_nanos"`
	Submounts               []string `json:"submounts,omitempty"`
	Profile                 string   `json:"profile,omitempty"`
	Budgets                 Budgets  `json:"budgets"`
}

var scanIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// RequestError is a request that fails validation; Reason is the
// response reason.
type RequestError struct {
	Reason string
	Msg    string
}

func (e *RequestError) Error() string { return e.Reason + ": " + e.Msg }

func badRequest(format string, a ...any) error {
	return &RequestError{Reason: ReasonBadRequest, Msg: fmt.Sprintf(format, a...)}
}

// Validate checks a decoded request.
func (r *Request) Validate() error {
	if r.ProtocolVersion != Version {
		return &RequestError{Reason: ReasonUnsupportedProtocol, Msg: fmt.Sprintf("protocol_version %d, this worker speaks %d", r.ProtocolVersion, Version)}
	}
	if !scanIDRe.MatchString(r.ScanID) {
		return badRequest("scan_id must be 1..128 of [A-Za-z0-9._:-]")
	}
	switch r.Op {
	case OpPing:
		return nil
	case OpScan:
	default:
		return badRequest("unknown op %q", r.Op)
	}
	switch r.Profile {
	case "", ProfileFull, ProfileOSOnly:
	default:
		return badRequest("unknown profile %q", r.Profile)
	}
	if r.ContainerStartUnixNanos < 0 {
		return badRequest("container_start_unix_nanos is negative")
	}
	if len(r.Submounts) > MaxSubmounts {
		return badRequest("more than %d submounts", MaxSubmounts)
	}
	for _, s := range r.Submounts {
		if len(s) == 0 || len(s) > MaxSubmountLen || s[0] != '/' || path.Clean(s) != s || !utf8.ValidString(s) {
			return badRequest("submount %q is not an absolute clean path", truncate(s, 64))
		}
	}
	b := r.Budgets
	for _, v := range []int64{b.MaxFiles, b.MaxComponents, b.MaxDepth, b.ScanTimeoutMS, b.MaxPathsPerPackage, b.MaxResponseBytes} {
		if v < 0 {
			return badRequest("negative budget")
		}
	}
	return nil
}

// Scanner identifies the producer (ImageSBOM.scanner).
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// OS is os-release ID and VERSION_ID (broker WireOs).
type OS struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// Stats describe the scan (also on failure).
type Stats struct {
	Files             int64   `json:"files"`
	Dirs              int64   `json:"dirs"`
	Components        int64   `json:"components"`
	DurationMS        int64   `json:"duration_ms"`
	SyftVersion       string  `json:"syft_version"`
	WorkerVersion     string  `json:"worker_version"`
	EACCES            int64   `json:"eacces"`
	CtimeDropped      int64   `json:"ctime_dropped"`
	MountSkipped      int64   `json:"mount_skipped"`
	DepthLimited      int64   `json:"depth_limited"`
	ComponentsDropped int64   `json:"components_dropped"`
	Attempts          int     `json:"attempts"`
	CapsModel         string  `json:"caps_model"`
	MaxRSSBytes       int64   `json:"max_rss_bytes,omitempty"`
	Budgets           Budgets `json:"budgets"`
}

// Component maps 1:1 onto the broker's ImageSBOM v1 WireComponent plus
// the two per-package flags.
type Component struct {
	Name               string   `json:"name"`
	Version            string   `json:"version,omitempty"`
	PURL               string   `json:"purl,omitempty"`
	Type               string   `json:"type,omitempty"`
	Class              string   `json:"class,omitempty"`
	SrcName            string   `json:"src_name,omitempty"`
	SrcVersion         string   `json:"src_version,omitempty"`
	Licenses           []string `json:"licenses,omitempty"`
	FilePaths          []string `json:"file_paths,omitempty"`
	FilesTruncated     bool     `json:"files_truncated,omitempty"`
	InterpretedContent bool     `json:"interpreted_content,omitempty"`
}

// Response is the worker's message.
type Response struct {
	ProtocolVersion int         `json:"protocol_version"`
	ScanID          string      `json:"scan_id"`
	Epoch           int64       `json:"epoch"`
	Status          string      `json:"status"`
	Reason          string      `json:"reason"`
	Message         string      `json:"message"`
	Completeness    string      `json:"completeness"`
	PartialReasons  []string    `json:"partial_reasons"`
	RetryReason     string      `json:"retry_reason"`
	Scanner         Scanner     `json:"scanner"`
	OS              *OS         `json:"os,omitempty"`
	Stats           Stats       `json:"stats"`
	Components      []Component `json:"components"`
}

// Failed builds a failure response.
func Failed(req *Request, reason, msg string) *Response {
	r := &Response{ProtocolVersion: Version, Status: StatusFailed, Reason: reason, Message: truncate(msg, MaxMessageLen),
		PartialReasons: []string{}, Components: []Component{}}
	if req != nil {
		r.ScanID, r.Epoch = req.ScanID, req.Epoch
	}
	return r
}

// AddPartial records a partial reason once.
func (r *Response) AddPartial(reason string) {
	for _, p := range r.PartialReasons {
		if p == reason {
			return
		}
	}
	r.PartialReasons = append(r.PartialReasons, reason)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// HasControl reports ASCII control characters (and DEL), which no path,
// name or version the broker stores may contain.
func HasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// ValidPath is a file path as the Controller and broker accept it:
// absolute, clean, at most MaxPathLen bytes, valid UTF-8, no control
// characters.
func ValidPath(p string) bool {
	return len(p) > 0 && len(p) <= MaxPathLen && p[0] == '/' && path.Clean(p) == p &&
		utf8.ValidString(p) && !HasControl(p)
}

// Truncate cuts s to at most n bytes on a rune boundary.
func Truncate(s string, n int) string { return truncate(s, n) }
