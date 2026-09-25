// Package registry classifies an image digest as an index (multi-arch
// list) or a single-platform manifest, and lists an index's platform
// manifests, by asking the image's registry.
//
// It only ever uses anonymous access. It never reads imagePullSecrets or
// any other credential (#1533 decision D3): a private image simply stays
// DigestKindUnknown. Results are cached per digest (digests are immutable);
// failures are cached for FailureTTL so an unreachable registry is not
// hammered.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// Result is what is known about one digest.
type Result struct {
	Kind              string
	PlatformManifests map[string]string
}

// Inspector looks digests up anonymously, with a bounded cache.
type Inspector struct {
	// Timeout bounds one registry lookup. Default 10s.
	Timeout time.Duration
	// FailureTTL is how long an unknown result is cached. Default 1h.
	FailureTTL time.Duration
	// MaxEntries bounds the cache; when full it is cleared. Default 10000.
	MaxEntries int
	// Insecure allows plain-HTTP registries (tests only).
	Insecure bool
	// Transport overrides the HTTP transport (tests).
	Transport http.RoundTripper

	mu    sync.Mutex
	cache map[string]entry
	now   func() time.Time
}

type entry struct {
	res     Result
	expires time.Time // zero = never (a definitive answer)
}

// New returns an Inspector with defaults.
func New() *Inspector {
	return &Inspector{Timeout: 10 * time.Second, FailureTTL: time.Hour, MaxEntries: 10000}
}

// Inspect classifies digest in repository (e.g. "index.docker.io",
// "library/nginx"). It never returns an error: anything it cannot
// determine is DigestKindUnknown.
func (i *Inspector) Inspect(ctx context.Context, registry, repository, digest string) Result {
	unknown := Result{Kind: types.DigestKindUnknown}
	if repository == "" || digest == "" {
		return unknown
	}
	repo := repository
	if registry != "" {
		repo = registry + "/" + repository
	}
	key := repo + "@" + digest
	if r, ok := i.cached(key); ok {
		return r
	}
	res, definitive := i.lookup(ctx, key)
	i.store(key, res, definitive)
	return res
}

func (i *Inspector) lookup(ctx context.Context, ref string) (Result, bool) {
	unknown := Result{Kind: types.DigestKindUnknown}
	var opts []name.Option
	if i.Insecure {
		opts = append(opts, name.Insecure)
	}
	d, err := name.NewDigest(ref, opts...)
	if err != nil {
		return unknown, true // malformed will not get better
	}
	timeout := i.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ropts := []remote.Option{remote.WithAuth(authn.Anonymous), remote.WithContext(ctx)}
	if i.Transport != nil {
		ropts = append(ropts, remote.WithTransport(i.Transport))
	}
	desc, err := remote.Get(d, ropts...)
	if err != nil {
		return unknown, false
	}
	switch {
	case desc.MediaType.IsIndex():
		idx, err := desc.ImageIndex()
		if err != nil {
			return unknown, false
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return unknown, false
		}
		return Result{Kind: types.DigestKindIndex, PlatformManifests: platforms(im)}, true
	case desc.MediaType.IsImage():
		return Result{Kind: types.DigestKindManifest}, true
	}
	return unknown, true
}

// platforms maps "os/arch[/variant]" to manifest digest, skipping
// attestation entries ("unknown/unknown") and nested indexes.
func platforms(im *v1.IndexManifest) map[string]string {
	out := map[string]string{}
	for _, m := range im.Manifests {
		if m.Platform == nil || !m.MediaType.IsImage() || m.Platform.OS == "unknown" || m.Platform.OS == "" {
			continue
		}
		p := m.Platform.OS + "/" + m.Platform.Architecture
		if m.Platform.Variant != "" {
			p += "/" + m.Platform.Variant
		}
		out[p] = m.Digest.String()
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (i *Inspector) cached(key string) (Result, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	e, ok := i.cache[key]
	if !ok {
		return Result{}, false
	}
	if !e.expires.IsZero() && i.clock().After(e.expires) {
		delete(i.cache, key)
		return Result{}, false
	}
	return e.res, true
}

func (i *Inspector) store(key string, r Result, definitive bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	max := i.MaxEntries
	if max <= 0 {
		max = 10000
	}
	if i.cache == nil || len(i.cache) >= max {
		i.cache = map[string]entry{}
	}
	e := entry{res: r}
	if !definitive {
		ttl := i.FailureTTL
		if ttl <= 0 {
			ttl = time.Hour
		}
		e.expires = i.clock().Add(ttl)
	}
	i.cache[key] = e
}

func (i *Inspector) clock() time.Time {
	if i.now != nil {
		return i.now()
	}
	return time.Now()
}

// Enrich sets DigestKind and PlatformManifests on img.
func (i *Inspector) Enrich(ctx context.Context, img *types.ImageRef) {
	r := i.Inspect(ctx, normaliseRegistry(img.Registry), img.Repository, img.Digest)
	img.DigestKind = r.Kind
	img.PlatformManifests = r.PlatformManifests
}

// normaliseRegistry maps Trivy's Docker Hub spellings onto one
// go-containerregistry accepts.
func normaliseRegistry(r string) string {
	switch strings.ToLower(r) {
	case "docker.io", "registry-1.docker.io":
		return "index.docker.io"
	}
	return r
}

// String is for logs.
func (r Result) String() string {
	return fmt.Sprintf("%s (%d platforms)", r.Kind, len(r.PlatformManifests))
}
