package rootfs

import (
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"golang.org/x/sys/unix"
)

// queries records what Syft's catalogers asked the resolver for: every
// glob, path, MIME type, and whether anything listed every file. It is
// the exact set of files the configured catalogers could have selected,
// taken from the pinned Syft at run time rather than from a hand-kept
// list.
type queries struct {
	mu    sync.Mutex
	globs map[string]struct{}
	paths map[string]struct{}
	mimes map[string]struct{}
	all   bool
}

func newQueries() *queries {
	return &queries{globs: map[string]struct{}{}, paths: map[string]struct{}{}, mimes: map[string]struct{}{}}
}

func (q *queries) add(m map[string]struct{}, vals ...string) {
	q.mu.Lock()
	for _, v := range vals {
		m[v] = struct{}{}
	}
	q.mu.Unlock()
}

// nixCataloger is the one package cataloger at the pinned Syft that lists
// every file (the file catalogers, which also do, are off). It keeps only
// paths in a Nix store, so its listing is recorded as the store globs; a
// listing by anything else counts every dropped entry as evidence.
const nixCataloger = "github.com/anchore/syft/syft/pkg/cataloger/nix."

var nixStoreGlobs = []string{"**/nix/store/*", "**/nix/store/*/**"}

// listedAll records an AllLocations call by its caller: the first frame
// outside this package and Syft's resolver wrappers.
func (q *queries) listedAll() {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		fn := f.Function
		switch {
		case strings.HasPrefix(fn, "github.com/kguardian-dev/kguardian/cataloger/internal/rootfs."),
			strings.HasPrefix(fn, "github.com/anchore/syft/syft/internal/fileresolver."):
		case strings.HasPrefix(fn, nixCataloger):
			q.add(q.globs, nixStoreGlobs...)
			return
		default:
			q.mu.Lock()
			q.all = true
			q.mu.Unlock()
			return
		}
		if !more {
			break
		}
	}
	q.mu.Lock()
	q.all = true
	q.mu.Unlock()
}

// DriftSummary splits the entries left out as runtime drift (ctime after
// container start) into those that could have been package evidence and
// plain data.
type DriftSummary struct {
	Evidence int64
	Data     int64
	// Sample: up to the requested number of dropped paths (as walked,
	// unbounded in length), evidence first, each group sorted.
	Sample []string
}

// ClassifyDropped decides, for every entry left out as drift, whether a
// configured cataloger could have derived a package from it, so that the
// SBOM may now be missing that package. Evidence is any of:
//
//   - a file a cataloger went to read (it was dropped at read time);
//   - executable-looking (an execute bit or a *.so* name), unless it is
//     empty or sniffs as text: a runtime-written script or a 0-byte lock
//     file with a stray execute bit is no binary any cataloger reads;
//   - a MIME type a cataloger asked for (ELF, Mach-O, PE, ...), or a file
//     that should have been sniffed but could not be read while one did;
//   - a path a cataloger asked for, directly or through a symlinked
//     directory;
//   - a match for a glob a cataloger asked for (package databases,
//     *.jar, dist-info/METADATA, package.json, ...), matched by the same
//     stereoscope search the resolver uses;
//   - anything, if a cataloger listed every file.
//
// Everything else (logs, caches, bytecode caches, pid and lock files,
// temp files, generated config) is data. Call it after cataloging.
func (r *Resolver) ClassifyDropped(sampleMax int) DriftSummary {
	r.root.mu.Lock()
	dropped := make(map[string]droppedFile, len(r.root.dropped))
	for p, d := range r.root.dropped {
		dropped[p] = d
	}
	r.root.mu.Unlock()
	if len(dropped) == 0 {
		return DriftSummary{}
	}
	q := r.q
	q.mu.Lock()
	defer q.mu.Unlock()

	evidence := map[string]bool{}
	for p, d := range dropped {
		if q.all || d.atRead || executableEvidence(p, d) || mimeEvidence(q.mimes, d) {
			evidence[p] = true
		}
	}
	r.pathEvidence(q.paths, dropped, evidence)
	globEvidence(q.globs, dropped, evidence)

	var s DriftSummary
	var ev, data []string
	for p := range dropped {
		if evidence[p] {
			s.Evidence++
			ev = append(ev, p)
		} else {
			s.Data++
			data = append(data, p)
		}
	}
	sort.Strings(ev)
	sort.Strings(data)
	for _, p := range append(ev, data...) {
		if len(s.Sample) >= sampleMax {
			break
		}
		s.Sample = append(s.Sample, p)
	}
	return s
}

func executableEvidence(p string, d droppedFile) bool {
	switch d.mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return IsSharedObjectName(p)
	case unix.S_IFREG:
		if !looksExecutable(path.Base(p), d.mode) {
			return false
		}
		if d.unsniffed {
			return true
		}
		return d.size > 0 && !strings.HasPrefix(d.mime, "text/")
	}
	return false
}

func mimeEvidence(mimes map[string]struct{}, d droppedFile) bool {
	if len(mimes) == 0 {
		return false
	}
	if d.unsniffed {
		return true
	}
	_, ok := mimes[d.mime]
	return d.mime != "" && ok
}

// pathEvidence marks dropped entries a cataloger asked for by path: the
// path itself, or the path with its directory resolved through the index
// (a query for /lib/apk/db/installed finds a dropped
// /usr/lib/apk/db/installed when /lib links to usr/lib).
func (r *Resolver) pathEvidence(paths map[string]struct{}, dropped map[string]droppedFile, evidence map[string]bool) {
	byBase := map[string]bool{}
	for p := range dropped {
		byBase[path.Base(p)] = true
	}
	for qp := range paths {
		if _, ok := dropped[qp]; ok {
			evidence[qp] = true
			continue
		}
		if !byBase[path.Base(qp)] {
			continue
		}
		dir, _, ok := r.Lookup(path.Dir(qp))
		if !ok {
			continue
		}
		if p := path.Join(dir, path.Base(qp)); p != qp {
			if _, ok := dropped[p]; ok {
				evidence[p] = true
			}
		}
	}
}

// globEvidence runs every recorded glob over a tree of just the dropped
// entries, with the stereoscope search the resolver itself uses, so a
// dropped path matches exactly when it would have been found.
func globEvidence(globs map[string]struct{}, dropped map[string]droppedFile, evidence map[string]bool) {
	if len(globs) == 0 {
		return
	}
	tree := filetree.New()
	index := filetree.NewIndex()
	for p, d := range dropped {
		if evidence[p] {
			continue
		}
		// Every entry as a regular file: only its name has to match, and
		// a symlink's target is not in this tree to follow.
		ref, err := tree.AddFile(stereofile.Path(p))
		if err != nil || ref == nil {
			evidence[p] = true // cannot test it: count it
			continue
		}
		index.Add(*ref, stereofile.Metadata{Path: p, Type: stereofile.TypeRegular, MIMEType: d.mime})
	}
	search := filetree.NewSearchContext(tree, index)
	for g := range globs {
		res, err := search.SearchByGlob(g)
		if err != nil {
			continue
		}
		for _, rv := range res {
			evidence[string(rv.RealPath)] = true
		}
	}
}

// Queries returns what the catalogers asked for so far (sorted): globs,
// paths, MIME types, and whether any listed every file.
func (r *Resolver) Queries() (globs, paths, mimes []string, all bool) {
	q := r.q
	q.mu.Lock()
	defer q.mu.Unlock()
	keys := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return keys(q.globs), keys(q.paths), keys(q.mimes), q.all
}
