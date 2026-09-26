package attest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
)

// Size limits for what is read from a registry. A signature or bundle is
// a few KiB; an SBOM attestation can be several MiB.
const (
	maxSigPayloadBytes   = 64 << 10 // simplesigning payload
	maxBundleBytes       = 1 << 20  // one Sigstore bundle (signature)
	maxAttestationBytes  = 16 << 20 // one DSSE envelope / attestation bundle, SBOMs included
	maxLayersPerTag      = 32       // layers read from one .sig / .att manifest
	maxReferrers         = 64       // referrers considered per digest
	maxIndexTagsResolved = 3        // tags tried when looking for a signed index
)

const (
	bundleArtifactPrefix = "application/vnd.dev.sigstore.bundle"
	emptyConfigMediaType = "application/vnd.oci.empty.v1+json"
)

// errNotBundle marks a referrer that turned out not to be a Sigstore
// bundle (a candidate kept only because its artifact type was unknown).
var errNotBundle = errors.New("referrer is not a Sigstore bundle")

// fetchError is a registry failure classified into a Reason.
type fetchError struct {
	reason string
	err    error
}

func (e *fetchError) Error() string { return e.reason + ": " + e.err.Error() }
func (e *fetchError) Unwrap() error { return e.err }

// classify turns a registry error into a fetchError with a Reason. It
// never returns a not-found: callers check isNotFound first.
func classify(err error) *fetchError {
	var fe *fetchError
	if errors.As(err, &fe) {
		return fe
	}
	var be *registry.BlockedError
	if errors.As(err, &be) {
		return &fetchError{reason: be.Reason, err: err}
	}
	if strings.Contains(err.Error(), "invalid realm") {
		return &fetchError{reason: registry.ReasonBlockedRealm, err: err}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &fetchError{reason: ReasonTimeout, err: err}
	}
	var te *transport.Error
	if errors.As(err, &te) {
		switch te.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return &fetchError{reason: ReasonRegistryAuth, err: err}
		case http.StatusTooManyRequests:
			return &fetchError{reason: ReasonRateLimited, err: err}
		}
		return &fetchError{reason: ReasonRegistryError, err: err}
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return &fetchError{reason: ReasonTimeout, err: err}
		}
		return &fetchError{reason: ReasonNetwork, err: err}
	}
	return &fetchError{reason: ReasonNetwork, err: err}
}

// isNotFound reports a definitive "does not exist" from the registry.
func isNotFound(err error) bool {
	var te *transport.Error
	if !errors.As(err, &te) {
		return false
	}
	if te.StatusCode == http.StatusNotFound {
		return true
	}
	for _, d := range te.Errors {
		if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}

// fetcher reads signature artifacts anonymously through the guard.
type fetcher struct {
	rt       http.RoundTripper
	insecure bool // plain HTTP registries, tests only
}

func (f *fetcher) opts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithContext(ctx),
		remote.WithTransport(f.rt),
		// One quick retry for transient server errors. Not 429: a
		// rate-limited registry is left alone until the next pass.
		remote.WithRetryStatusCodes(http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout),
		remote.WithRetryBackoff(remote.Backoff{Duration: 500 * time.Millisecond, Factor: 2, Steps: 2}),
	}
}

func (f *fetcher) nameOpts() []name.Option {
	if f.insecure {
		return []name.Option{name.Insecure}
	}
	return nil
}

func (f *fetcher) repo(repository string) (name.Repository, error) {
	return name.NewRepository(repository, f.nameOpts()...)
}

// tagFor returns the cosign tag for digest: "sha256-<hex>.<suffix>", or
// "sha256-<hex>" (the referrers fallback tag) for an empty suffix.
func tagFor(repo name.Repository, digest, suffix string) name.Tag {
	t := strings.Replace(digest, ":", "-", 1)
	if suffix != "" {
		t += "." + suffix
	}
	return repo.Tag(t)
}

// manifestAt fetches an image manifest by tag. found=false with a nil
// error is a definitive "no such tag".
func (f *fetcher) manifestAt(ctx context.Context, ref name.Reference) (*v1.Manifest, bool, error) {
	desc, err := remote.Get(ref, f.opts(ctx)...)
	if err != nil {
		if isNotFound(err) {
			return nil, false, nil
		}
		return nil, false, classify(err)
	}
	if !desc.MediaType.IsImage() {
		return nil, true, &fetchError{reason: ReasonUnsupportedFormat, err: fmt.Errorf("%s is %s, not an image manifest", ref, desc.MediaType)}
	}
	m, err := v1.ParseManifest(strings.NewReader(string(desc.Manifest)))
	if err != nil {
		return nil, true, &fetchError{reason: ReasonMalformed, err: err}
	}
	return m, true, nil
}

// blob reads one blob, refusing anything over max. go-containerregistry
// checks the content against its digest as it is read.
func (f *fetcher) blob(ctx context.Context, repo name.Repository, desc v1.Descriptor, max int64) ([]byte, error) {
	if desc.Size > max {
		return nil, &fetchError{reason: ReasonTooLarge, err: fmt.Errorf("blob %s is %d bytes (limit %d)", desc.Digest, desc.Size, max)}
	}
	l, err := remote.Layer(repo.Digest(desc.Digest.String()), f.opts(ctx)...)
	if err != nil {
		return nil, classify(err)
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, classify(err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, classify(err)
	}
	if int64(len(b)) > max {
		return nil, &fetchError{reason: ReasonTooLarge, err: fmt.Errorf("blob %s exceeds %d bytes", desc.Digest, max)}
	}
	return b, nil
}

// referrers lists the Sigstore bundles attached to digest, through the
// referrers API or its tag fallback (go-containerregistry tries the API
// first and falls back on 404/400/406 or a non-index answer). No
// referrers is an empty list and a nil error.
func (f *fetcher) referrers(ctx context.Context, repo name.Repository, digest string) ([]v1.Descriptor, error) {
	idx, err := remote.Referrers(repo.Digest(digest), f.opts(ctx)...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, classify(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, classify(err)
	}
	var out []v1.Descriptor
	for _, d := range im.Manifests {
		at := d.ArtifactType
		if at == "" && d.Annotations != nil {
			at = d.Annotations["org.opencontainers.image.artifactType"]
		}
		// Some registries (go-containerregistry's own, for one) report the
		// config media type instead of the manifest's artifactType. Keep
		// those as candidates; bundleBlob decides from the layers.
		if !strings.HasPrefix(at, bundleArtifactPrefix) && at != "" && at != emptyConfigMediaType {
			continue
		}
		out = append(out, d)
		if len(out) == maxReferrers {
			break
		}
	}
	return out, nil
}

// bundleBlob fetches the bundle layer of one referrer manifest.
func (f *fetcher) bundleBlob(ctx context.Context, repo name.Repository, ref v1.Descriptor, max int64) ([]byte, error) {
	m, found, err := f.manifestAt(ctx, repo.Digest(ref.Digest.String()))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, &fetchError{reason: ReasonRegistryError, err: fmt.Errorf("referrer %s listed but not found", ref.Digest)}
	}
	for _, l := range m.Layers {
		if strings.HasPrefix(string(l.MediaType), bundleArtifactPrefix) {
			return f.blob(ctx, repo, l, max)
		}
	}
	return nil, errNotBundle
}

// indexListing resolves tag and, if it names an index, returns the index
// digest and whether it lists digest. Any failure is reported as not
// listed: this is a best-effort route to a signature, never evidence of
// its absence.
func (f *fetcher) indexListing(ctx context.Context, repo name.Repository, tag, digest string) (string, bool) {
	desc, err := remote.Get(repo.Tag(tag), f.opts(ctx)...)
	if err != nil || !desc.MediaType.IsIndex() {
		return "", false
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", false
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return "", false
	}
	for _, m := range im.Manifests {
		if m.Digest.String() == digest {
			return desc.Digest.String(), true
		}
	}
	return "", false
}
