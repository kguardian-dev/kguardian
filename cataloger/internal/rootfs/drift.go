package rootfs

import (
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/bmatcuk/doublestar/v4"
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
	// mimeCallers: every MIME query as "caller: type,type" (sorted types).
	mimeCallers map[string]struct{}
}

func newQueries() *queries {
	return &queries{globs: map[string]struct{}{}, paths: map[string]struct{}{}, mimes: map[string]struct{}{},
		mimeCallers: map[string]struct{}{}}
}

func (q *queries) mimeCall(caller string, types []string) {
	t := slices.Clone(types)
	sort.Strings(t)
	q.add(q.mimeCallers, caller+": "+strings.Join(t, ","))
}

func (q *queries) add(m map[string]struct{}, vals ...string) {
	q.mu.Lock()
	for _, v := range vals {
		m[v] = struct{}{}
	}
	q.mu.Unlock()
}

// listedAll records an AllLocations call by its caller.
func (q *queries) listedAll() {
	if strings.HasPrefix(catalogerCaller(), nixCataloger) {
		q.add(q.globs, nixStoreGlobs...)
		return
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
	// names: each path a query could have found, and the dropped entries
	// it stands for. A dropped entry stands for its own path; a dropped
	// symlink also for its resolved target.
	names := map[string][]string{}
	for p, d := range dropped {
		if q.all || d.atRead || executableEvidence(p, d) || mimeEvidence(q.mimes, d) {
			evidence[p] = true
			continue
		}
		names[p] = append(names[p], p)
		if d.mode&unix.S_IFMT != unix.S_IFLNK || d.link == "" {
			continue
		}
		// A symlink created after start that leads to a directory can
		// reroute a package database or any tree a cataloger walks
		// (lib/apk -> ../data/apk): evidence. One to a file counts when
		// the file's path was asked for; a dangling one is data.
		real, md, ok := r.Lookup(d.link)
		if !ok {
			continue
		}
		if md.IsDir() {
			evidence[p] = true
			continue
		}
		if real != p {
			names[real] = append(names[real], p)
		}
	}
	r.pathEvidence(q.paths, names, evidence)
	globEvidence(q.globs, names, evidence)

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
func (r *Resolver) pathEvidence(paths map[string]struct{}, names map[string][]string, evidence map[string]bool) {
	byBase := map[string]bool{}
	for n := range names {
		byBase[path.Base(n)] = true
	}
	mark := func(n string) {
		for _, p := range names[n] {
			evidence[p] = true
		}
	}
	for qp := range paths {
		if !byBase[path.Base(qp)] {
			continue
		}
		mark(qp)
		if dir, _, ok := r.Lookup(path.Dir(qp)); ok {
			if n := path.Join(dir, path.Base(qp)); n != qp {
				mark(n)
			}
		}
	}
}

// globEvidence runs every recorded glob over a tree of just the candidate
// names (and their ancestor directories, which stereoscope's
// subdirectory search looks up in the index), with the search the
// resolver itself uses, so a name matches exactly when it would have been
// found. A glob ending in "/*" is also matched directly with doublestar,
// as a second line.
func globEvidence(globs map[string]struct{}, names map[string][]string, evidence map[string]bool) {
	if len(globs) == 0 || len(names) == 0 {
		return
	}
	mark := func(n string) {
		for _, p := range names[n] {
			evidence[p] = true
		}
	}
	tree := filetree.New()
	index := filetree.NewIndex()
	dirs := map[string]bool{"/": true}
	for n := range names {
		for d := path.Dir(n); !dirs[d]; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	sorted := make([]string, 0, len(dirs))
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		if ref, err := tree.AddDir(stereofile.Path(d)); err == nil && ref != nil {
			index.Add(*ref, stereofile.Metadata{Path: d, Type: stereofile.TypeDirectory})
		}
	}
	for n := range names {
		// Every name as a regular file: only the name has to match, and a
		// symlink's target is not in this tree to follow.
		ref, err := tree.AddFile(stereofile.Path(n))
		if err != nil || ref == nil {
			mark(n) // cannot test it: count it
			continue
		}
		index.Add(*ref, stereofile.Metadata{Path: n, Type: stereofile.TypeRegular})
	}
	search := filetree.NewSearchContext(tree, index)
	for g := range globs {
		if res, err := search.SearchByGlob(g); err == nil {
			for _, rv := range res {
				mark(string(rv.RealPath))
			}
		}
		if path.Base(g) == "*" {
			for n := range names {
				if ok, _ := doublestar.Match(g, n); ok {
					mark(n)
				}
			}
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

// MIMEQueries returns every MIME query so far as "caller: type,type".
func (r *Resolver) MIMEQueries() []string {
	q := r.q
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, 0, len(q.mimeCallers))
	for k := range q.mimeCallers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
