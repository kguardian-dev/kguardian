package rootfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

var _ file.Resolver = (*Resolver)(nil)

// Resolver implements Syft's file.Resolver over an indexed Root.
//
// Path, glob, MIME and symlink semantics come from stereoscope's filetree
// search context, exactly as in Syft's own directory resolver
// (syft/internal/fileresolver.FiletreeResolver, whose methods these
// mirror), so catalogers see the same Locations: RealPath is the
// symlink-resolved in-root path and AccessPath the path that was asked
// for. The differences are where the bytes come from: the index was built
// by a kernel-confined walk (Root.Index), and every read re-opens the
// file through the root fd (Root.OpenFile), never by a host path.
type Resolver struct {
	root   *Root
	tree   filetree.Reader
	index  filetree.IndexReader
	search filetree.Searcher
}

// NewResolver indexes root and returns a resolver over it.
func NewResolver(root *Root) (*Resolver, error) {
	tree, index, err := root.Index()
	if err != nil {
		return nil, err
	}
	return &Resolver{root: root, tree: tree, index: index, search: filetree.NewSearchContext(tree, index)}, nil
}

func requestPath(p string) string {
	return path.Clean("/" + p)
}

// requestGlob anchors a glob at the root the way Syft's chroot context
// does: a pattern starting with "*" is left alone, any other prefix before
// the first "*" is cleaned as an absolute path.
func requestGlob(pattern string) string {
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 || parts[0] == "" {
		return pattern
	}
	if len(parts) == 1 {
		return requestPath(pattern)
	}
	prefix := requestPath(parts[0])
	if strings.HasSuffix(parts[0], "/") && prefix != "/" {
		prefix += "/"
	}
	parts[0] = prefix
	return strings.Join(parts, "*")
}

// HasPath reports whether p exists (following links).
func (r *Resolver) HasPath(p string) bool {
	return r.tree.HasPath(stereofile.Path(requestPath(p)))
}

// FilesByPath returns the non-directory files at the given paths, with
// symlinks resolved in-tree.
func (r *Resolver) FilesByPath(paths ...string) ([]file.Location, error) {
	refs := make([]file.Location, 0)
	for _, p := range paths {
		req := requestPath(p)
		ref, err := r.search.SearchByPath(req, filetree.FollowBasenameLinks)
		if err != nil || ref == nil || !ref.HasReference() {
			continue
		}
		entry, err := r.index.Get(*ref.Reference)
		if err != nil || entry.IsDir() {
			continue
		}
		refs = append(refs, file.NewVirtualLocationFromDirectory(string(ref.RealPath), req, *ref.Reference))
	}
	return refs, nil
}

// FilesByGlob returns the non-directory files matching any pattern, one
// Location per real file.
func (r *Resolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	seen := stereofile.NewFileReferenceSet()
	out := make([]file.Location, 0)
	for _, pattern := range patterns {
		refVias, err := r.search.SearchByGlob(requestGlob(pattern), filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, rv := range refVias {
			if !rv.HasReference() || seen.Contains(*rv.Reference) {
				continue
			}
			entry, err := r.index.Get(*rv.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for reference %s: %w", rv.RealPath, err)
			}
			if entry.IsDir() {
				continue
			}
			seen.Add(*rv.Reference)
			out = append(out, file.NewVirtualLocationFromDirectory(string(rv.RealPath), string(rv.RequestPath), *rv.Reference))
		}
	}
	return out, nil
}

// FilesByMIMEType returns the files whose sniffed MIME type is one of types.
func (r *Resolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	seen := stereofile.NewFileReferenceSet()
	out := make([]file.Location, 0)
	refVias, err := r.search.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	for _, rv := range refVias {
		if !rv.HasReference() || seen.Contains(*rv.Reference) {
			continue
		}
		seen.Add(*rv.Reference)
		out = append(out, file.NewVirtualLocationFromDirectory(string(rv.RealPath), string(rv.RequestPath), *rv.Reference))
	}
	return out, nil
}

// RelativeFileByPath: a directory has one layer, so this is FilesByPath's
// first result.
func (r *Resolver) RelativeFileByPath(_ file.Location, p string) *file.Location {
	locs, err := r.FilesByPath(p)
	if err != nil || len(locs) == 0 {
		return nil
	}
	return &locs[0]
}

// FileContentsByLocation opens the file through the root fd.
func (r *Resolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	if loc.RealPath == "" {
		return nil, errors.New("empty path given")
	}
	entry, err := r.index.Get(loc.Reference())
	if err != nil {
		return nil, err
	}
	if entry.Type == stereofile.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", loc.RealPath)
	}
	return r.root.OpenFile(loc.RealPath)
}

// AllLocations streams every indexed entry, unresolved.
func (r *Resolver) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for _, ref := range r.tree.AllFiles(stereofile.AllTypes()...) {
			select {
			case <-ctx.Done():
				return
			case out <- file.NewLocationFromDirectory(string(ref.RealPath), "", ref):
			}
		}
	}()
	return out
}

// FileMetadataByLocation returns the indexed metadata.
func (r *Resolver) FileMetadataByLocation(loc file.Location) (file.Metadata, error) {
	entry, err := r.index.Get(loc.Reference())
	if err != nil {
		return file.Metadata{}, fmt.Errorf("location: %+v : %w", loc, os.ErrNotExist)
	}
	return entry.Metadata, nil
}

// Lookup resolves p (following in-root links) to its real path and
// metadata; ok is false when p is not in the index.
func (r *Resolver) Lookup(p string) (realPath string, md file.Metadata, ok bool) {
	ref, err := r.search.SearchByPath(requestPath(p), filetree.FollowBasenameLinks)
	if err != nil || ref == nil || !ref.HasReference() {
		return "", file.Metadata{}, false
	}
	entry, err := r.index.Get(*ref.Reference)
	if err != nil {
		return "", file.Metadata{}, false
	}
	return string(ref.RealPath), entry.Metadata, true
}

// Source is a Syft source over a Root.
type Source struct {
	root *Root
	once sync.Once
	res  *Resolver
	err  error
}

var _ source.Source = (*Source)(nil)

// NewSource wraps root. The index is built on the first FileResolver call.
func NewSource(root *Root) *Source { return &Source{root: root} }

// ID is constant: the source is anonymous (the Controller knows the digest).
func (s *Source) ID() artifact.ID { return artifact.ID("kguardian-container-root") }

// Describe reports a directory source rooted at "/".
func (s *Source) Describe() source.Description {
	return source.Description{
		ID:       string(s.ID()),
		Name:     "container-root",
		Metadata: source.DirectoryMetadata{Path: "/"},
	}
}

// FileResolver indexes the root once and returns the resolver.
func (s *Source) FileResolver(source.Scope) (file.Resolver, error) {
	s.once.Do(func() { s.res, s.err = NewResolver(s.root) })
	return s.res, s.err
}

// Resolver returns the resolver built by FileResolver (nil before).
func (s *Source) Resolver() *Resolver { return s.res }

// Close is a no-op: the caller owns the Root.
func (s *Source) Close() error { return nil }
