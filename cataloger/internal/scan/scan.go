package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/rootfs"
)

// Options for one scan attempt.
type Options struct {
	Profile             string
	Budgets             protocol.Budgets // effective
	ContainerStartNanos int64
	Submounts           []string
	CapsModel           string // "i" or "ii"
	Version             string
}

// osReleasePaths are read by Syft's distro detection; an LSM refusing them
// must surface as lsm_denied, never as a silently distro-less SBOM.
var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// Run scans the root open at fd (which it takes ownership of) and returns
// the response (status, components, stats; the parent fills scan_id,
// epoch, attempts and duration).
func Run(ctx context.Context, fd int, o Options) *protocol.Response {
	start := time.Now()
	resp := protocol.Failed(nil, "", "")
	resp.Stats.SyftVersion = SyftVersion()
	resp.Stats.WorkerVersion = o.Version
	resp.Stats.CapsModel = o.CapsModel
	resp.Stats.Budgets = o.Budgets
	fail := func(reason, msg string) *protocol.Response {
		resp.Status, resp.Reason, resp.Message = protocol.StatusFailed, reason, protocol.Truncate(msg, protocol.MaxMessageLen)
		resp.Components = []protocol.Component{}
		resp.Completeness = ""
		resp.Stats.DurationMS = time.Since(start).Milliseconds()
		return resp
	}

	osOnly := o.Profile == protocol.ProfileOSOnly
	root, err := rootfs.Open(fd, RootOptions(o.Profile, o.Budgets, o.Submounts, o.ContainerStartNanos))
	if err != nil {
		_ = unix.Close(fd)
		switch {
		case errors.Is(err, rootfs.ErrKernelUnsupported):
			return fail(protocol.ReasonKernelUnsupported, err.Error())
		case errors.Is(err, rootfs.ErrLSMDenied):
			return fail(protocol.ReasonLSMDenied, err.Error())
		}
		return fail(protocol.ReasonBadRequest, err.Error())
	}
	defer func() { _ = root.Close() }()
	defer func() {
		fillStats(resp, root)
		driftSafetyNet(resp)
	}()

	for _, p := range osReleasePaths {
		if _, err := root.StatPath(p); err != nil {
			if isAccess(err) {
				return fail(protocol.ReasonLSMDenied, "stat "+p+": "+err.Error())
			}
			continue
		}
		f, err := root.OpenFile(p)
		if err != nil {
			if isAccess(err) {
				return fail(protocol.ReasonLSMDenied, "open "+p+": "+err.Error())
			}
			continue
		}
		_ = f.Close()
	}

	src := rootfs.NewSource(root)
	s, err := syft.CreateSBOM(ctx, src, SyftConfig(o.Profile, o.Version))
	switch {
	case err == nil:
	case errors.Is(err, rootfs.ErrLSMDenied):
		return fail(protocol.ReasonLSMDenied, err.Error())
	case errors.Is(err, rootfs.ErrTooManyFiles):
		return fail(protocol.ReasonTooManyFiles, fmt.Sprintf("more than %d files", o.Budgets.MaxFiles))
	case errors.Is(err, rootfs.ErrKernelUnsupported):
		return fail(protocol.ReasonKernelUnsupported, err.Error())
	case IsNoSpace(err) || NoSpaceSeen.Load():
		return fail(protocol.ReasonOOM, "temp space exhausted: "+err.Error())
	case ctx.Err() != nil:
		return fail(protocol.ReasonTimeout, ctx.Err().Error())
	default:
		// Syft reports per-cataloger problems as a joined error beside a
		// usable SBOM; only a missing SBOM is fatal.
		if s == nil {
			return fail(protocol.ReasonError, err.Error())
		}
		resp.Message = protocol.Truncate("cataloger errors: "+err.Error(), protocol.MaxMessageLen)
	}
	if NoSpaceSeen.Load() {
		return fail(protocol.ReasonOOM, "temp space exhausted during cataloging")
	}

	res := src.Resolver()
	classifyDrift(resp, res)
	fr := resolverAdapter{res: res, root: root}
	comps, dropped := Components(s, fr, int(o.Budgets.MaxPathsPerPackage))
	resp.Stats.ComponentsDropped = int64(dropped)

	pkgs := 0
	for _, c := range comps {
		if c.Type != "operating-system" {
			pkgs++
		}
	}
	if int64(len(comps)) > o.Budgets.MaxComponents {
		return fail(protocol.ReasonTooManyComponents, fmt.Sprintf("%d components, budget %d", len(comps), o.Budgets.MaxComponents))
	}
	if d := s.Artifacts.LinuxDistribution; d != nil && d.ID != "" {
		name := d.VersionID
		if name == "" {
			name = d.PrettyName
		}
		// The broker keeps os family/name up to LEN_SHORT: send nothing
		// rather than something it would cut.
		if validField(d.ID, protocol.MaxOSLen) && validField(name, protocol.MaxOSLen) {
			resp.OS = &protocol.OS{Family: d.ID, Name: name}
		}
	}
	if pkgs == 0 {
		fillStats(resp, root)
		// With CAP_DAC_READ_SEARCH (model (i)) only an LSM can refuse a
		// read, so unreadable entries mean lsm_denied. Without it (model
		// (ii)) they are ordinary DAC refusals: the scan is merely
		// incomplete, reported below as a partial no_packages_found, which
		// the Controller retries.
		if resp.Stats.EACCES > 0 && o.CapsModel == "i" {
			return fail(protocol.ReasonLSMDenied, fmt.Sprintf("no packages found and %d entries unreadable", resp.Stats.EACCES))
		}
		// Terminal only for a genuinely clean scan: the Controller treats
		// no_packages_found as terminal only with completeness "full" (or
		// empty) and no partial reasons (PROTOCOL.md §4.4). Anything that
		// could have hidden a package says so here.
		r := fail(protocol.ReasonNoPackagesFound, "the root was readable but contained no packages")
		r.Completeness = protocol.CompletenessFull
		if resp.Stats.EACCES > 0 {
			r.AddPartial(protocol.PartialEACCES)
			r.AddPartial(protocol.PartialNoDACReadSearch)
		}
		if resp.Stats.DepthLimited > 0 {
			r.AddPartial(protocol.PartialDepthLimited)
		}
		if resp.Stats.CtimeDroppedEvidence > 0 {
			r.AddPartial(protocol.PartialCtimeDropped)
		}
		if dropped > 0 {
			r.AddPartial(protocol.PartialComponentsDropped)
		}
		if root.Stats.FileBudget.Load() {
			r.AddPartial(protocol.PartialFileBudget)
		}
		switch {
		case osOnly:
			// Language catalogers did not run: zero packages proves nothing.
			r.Completeness = protocol.CompletenessOSOnly
		case len(r.PartialReasons) > 0:
			r.Completeness = protocol.CompletenessPartial
		}
		if r.Completeness != protocol.CompletenessFull {
			r.Message = "no packages found, but the scan was not complete"
		}
		return r
	}

	resp.Status, resp.Reason = protocol.StatusOK, ""
	resp.Components = comps
	resp.Stats.Components = int64(len(comps))
	fillStats(resp, root)
	resp.Completeness = protocol.CompletenessFull
	if osOnly {
		resp.Completeness = protocol.CompletenessOSOnly
	}
	if resp.Stats.EACCES > 0 {
		resp.AddPartial(protocol.PartialEACCES)
	}
	if o.CapsModel == "ii" {
		resp.AddPartial(protocol.PartialNoDACReadSearch)
	}
	if resp.Stats.CtimeDroppedEvidence > 0 {
		resp.AddPartial(protocol.PartialCtimeDropped)
	}
	if resp.Stats.DepthLimited > 0 {
		resp.AddPartial(protocol.PartialDepthLimited)
	}
	if dropped > 0 {
		resp.AddPartial(protocol.PartialComponentsDropped)
	}
	if root.Stats.FileBudget.Load() {
		resp.AddPartial(protocol.PartialFileBudget)
	}
	for _, c := range comps {
		if c.FilesTruncated {
			resp.AddPartial(protocol.PartialFilesTruncated)
			break
		}
	}
	if !osOnly && len(resp.PartialReasons) > 0 {
		resp.Completeness = protocol.CompletenessPartial
	}
	resp.Stats.DurationMS = time.Since(start).Milliseconds()
	if err := Fit(resp, int(o.Budgets.MaxResponseBytes)); err != nil {
		return fail(protocol.ReasonOutputTooLarge, err.Error())
	}
	return resp
}

func fillStats(resp *protocol.Response, root *rootfs.Root) {
	st := &root.Stats
	resp.Stats.Files = st.Files.Load()
	resp.Stats.Dirs = st.Dirs.Load()
	resp.Stats.EACCES = st.EACCES.Load()
	resp.Stats.CtimeDropped = st.CtimeDropped.Load()
	resp.Stats.MountSkipped = st.MountSkipped.Load()
	resp.Stats.DepthLimited = st.DepthLimited.Load()
	resp.Stats.Reclaims = st.Reclaims.Load()
	resp.Stats.ReclaimMS = st.ReclaimNanos.Load() / 1e6
}

// driftSafetyNet: an entry dropped after classification (none is today:
// nothing reads a file then) was never judged, so it counts as evidence.
// Only responses that carry a completeness are touched.
func driftSafetyNet(resp *protocol.Response) {
	st := &resp.Stats
	if resp.Completeness == "" || st.CtimeDropped <= st.CtimeDroppedEvidence+st.CtimeDroppedData {
		return
	}
	resp.AddPartial(protocol.PartialCtimeDropped)
	if resp.Completeness == protocol.CompletenessFull {
		resp.Completeness = protocol.CompletenessPartial
	}
}

// classifyDrift splits the runtime-drift entries (ctime after container
// start, left out of the index) into possible package evidence, which
// makes the SBOM partial (ctime_dropped), and plain runtime data (logs,
// caches, bytecode caches, pid and lock files, temp files), which does
// not: a package that owns a dropped file is flagged files_truncated
// either way (PackageFiles). A bounded sample of the paths goes in the
// stats. It runs after cataloging, when the resolver knows every query
// the catalogers made.
func classifyDrift(resp *protocol.Response, res *rootfs.Resolver) {
	if res == nil {
		return
	}
	// More candidates than fit: a path SamplePath cannot make valid is
	// left out and the next one taken.
	d := res.ClassifyDropped(4 * protocol.MaxDriftSample)
	resp.Stats.CtimeDroppedEvidence, resp.Stats.CtimeDroppedData = d.Evidence, d.Data
	resp.Stats.CtimeDroppedUnclassified = d.Unclassified
	resp.Stats.CtimeDroppedSample = nil
	for _, p := range d.Sample {
		if len(resp.Stats.CtimeDroppedSample) == protocol.MaxDriftSample {
			break
		}
		if sp, ok := SamplePath(p); ok {
			resp.Stats.CtimeDroppedSample = append(resp.Stats.CtimeDroppedSample, sp)
		}
	}
}

// SamplePath bounds a path for the drift sample so that the Controller
// keeps it (its valid_path: absolute, no Unicode control character, no
// empty, "." or ".." segment): valid UTF-8, every control character
// (C0, DEL, C1) replaced by '?', cut to MaxDriftSamplePathLen bytes on a
// rune boundary, then a trailing "/", "/." or "/.." left by the cut
// trimmed. ok is false when the result is still not a valid path.
func SamplePath(p string) (string, bool) {
	p = strings.ToValidUTF8(p, "?")
	p = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return '?'
		}
		return c
	}, p)
	p = protocol.Truncate(p, protocol.MaxDriftSamplePathLen)
	for {
		t := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(p, "/.."), "/."), "/")
		if t == p {
			break
		}
		p = t
	}
	return p, protocol.ValidSamplePath(p)
}

func isAccess(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

// IsNoSpace: the temp directory is full or a temp file hit RLIMIT_FSIZE.
// A write that crosses the limit is cut short without an error, and
// io.Copy then reports io.ErrShortWrite; the child writes only temp
// files, so a short write means the budget was hit.
func IsNoSpace(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EFBIG) || errors.Is(err, unix.EDQUOT) || errors.Is(err, io.ErrShortWrite) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "no space left on device") || strings.Contains(s, "file too large") ||
		strings.Contains(s, "disk quota exceeded") || strings.Contains(s, io.ErrShortWrite.Error())
}

// RootOptions is how a profile opens the root: shared by production scans
// and the differential test, so the test exercises exactly what runs.
func RootOptions(profile string, b protocol.Budgets, submounts []string, containerStartNanos int64) rootfs.Options {
	osOnly := profile == protocol.ProfileOSOnly
	return rootfs.Options{
		Submounts:            submounts,
		CtimeCutoffNanos:     containerStartNanos,
		MaxFiles:             int(b.MaxFiles),
		MaxDepth:             int(b.MaxDepth),
		StopAtBudget:         osOnly,
		SystemFirst:          osOnly,
		SniffExecutablesOnly: osOnly,
	}
}

// Components maps the SBOM (sorted, OS entry first) and counts packages
// dropped for failing validation.
func Components(s *sbom.SBOM, fr FileResolution, maxPaths int) ([]protocol.Component, int) {
	var out []protocol.Component
	if d := s.Artifacts.LinuxDistribution; d != nil && d.ID != "" && validField(d.ID, protocol.MaxNameLen) && validField(d.VersionID, protocol.MaxVersionLen) {
		out = append(out, protocol.Component{Name: d.ID, Version: d.VersionID, Type: "operating-system"})
	}
	dropped := 0
	for _, p := range s.Artifacts.Packages.Sorted() {
		c, ok := Component(p, fr, maxPaths)
		if !ok {
			dropped++
			continue
		}
		out = append(out, c)
	}
	return out, dropped
}

// Fit makes the encoded response at most max bytes by removing file paths
// from the components with the most paths first.
func Fit(resp *protocol.Response, max int) error {
	size := func() int {
		b, _ := json.Marshal(resp)
		return len(b)
	}
	if max <= 0 || size() <= max {
		return nil
	}
	idx := make([]int, len(resp.Components))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return len(resp.Components[idx[a]].FilePaths) > len(resp.Components[idx[b]].FilePaths)
	})
	resp.AddPartial(protocol.PartialResponseTrimmed)
	resp.AddPartial(protocol.PartialFilesTruncated)
	if resp.Completeness == protocol.CompletenessFull {
		resp.Completeness = protocol.CompletenessPartial
	}
	// Drop in growing batches so a huge response is not re-encoded once
	// per component.
	batch := 1
	for i := 0; i < len(idx); {
		for j := 0; j < batch && i < len(idx); j, i = j+1, i+1 {
			c := &resp.Components[idx[i]]
			if len(c.FilePaths) == 0 {
				continue
			}
			c.FilePaths, c.FilesTruncated = nil, true
		}
		if size() <= max {
			return nil
		}
		batch *= 2
	}
	return fmt.Errorf("response is %d bytes without file paths, limit %d", size(), max)
}

// Stderr is where the child logs (the parent reads and bounds it).
var Stderr = os.Stderr
