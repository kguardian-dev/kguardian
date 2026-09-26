package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tuffetcher "github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"golang.org/x/time/rate"
)

// TrustRoot supplies the Sigstore trusted material (Fulcio CAs, Rekor
// and CT log keys, TSAs) signatures are verified against.
type TrustRoot interface {
	// Material returns the current trusted material and a label for it
	// ("public-good" or "custom:<sha256 prefix>").
	Material(ctx context.Context) (root.TrustedMaterial, string, error)
}

// FileTrustRoot reads a trusted_root.json (Sigstore protobuf-specs
// TrustedRoot, JSON). For a private Sigstore or an air-gapped cluster:
// nothing is fetched, ever. The file is re-read when it changes (a
// mounted ConfigMap is updated in place).
type FileTrustRoot struct {
	Path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	tm      root.TrustedMaterial
	label   string
}

// Material implements TrustRoot.
func (f *FileTrustRoot) Material(context.Context) (root.TrustedMaterial, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, err := os.Stat(f.Path)
	if err != nil {
		if f.tm != nil {
			return f.tm, f.label, nil
		}
		return nil, "", fmt.Errorf("trusted root %s: %w", f.Path, err)
	}
	if f.tm != nil && st.ModTime().Equal(f.modTime) && st.Size() == f.size {
		return f.tm, f.label, nil
	}
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		if f.tm != nil {
			return f.tm, f.label, nil
		}
		return nil, "", fmt.Errorf("trusted root %s: %w", f.Path, err)
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		if f.tm != nil {
			return f.tm, f.label, nil // keep the last good root over a bad edit
		}
		return nil, "", fmt.Errorf("trusted root %s: %w", f.Path, err)
	}
	sum := sha256.Sum256(raw)
	f.tm, f.label = tr, trustRootCustomLabel+hex.EncodeToString(sum[:])[:12]
	f.modTime, f.size = st.ModTime(), st.Size()
	return f.tm, f.label, nil
}

// TUFTrustRoot fetches trusted_root.json through Sigstore's TUF
// repository (the public-good instance by default) and refreshes it
// periodically. Every request goes through Transport (the SSRF guard) and
// a rate limiter; a failed refresh keeps the last good root.
type TUFTrustRoot struct {
	// Transport carries every TUF request. Required.
	Transport http.RoundTripper
	// MirrorURL overrides the TUF repository (default
	// https://tuf-repo-cdn.sigstore.dev). It must serve the public-good
	// root: the embedded TUF root is the trust anchor.
	MirrorURL string
	// RefreshEvery is how often a good root is refreshed. Default 24h.
	RefreshEvery time.Duration
	// RetryEvery is the minimum gap between attempts after a failure.
	// Default 15m.
	RetryEvery time.Duration

	mu          sync.Mutex
	tm          root.TrustedMaterial
	fetchedAt   time.Time
	lastAttempt time.Time
	lastErr     error
	load        func(ctx context.Context) (root.TrustedMaterial, error) // tests
}

// Material implements TrustRoot.
func (t *TUFTrustRoot) Material(ctx context.Context) (root.TrustedMaterial, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	refresh := t.RefreshEvery
	if refresh <= 0 {
		refresh = 24 * time.Hour
	}
	retry := t.RetryEvery
	if retry <= 0 {
		retry = 15 * time.Minute
	}
	n := time.Now()
	due := t.tm == nil || n.Sub(t.fetchedAt) >= refresh
	if due && (t.lastAttempt.IsZero() || n.Sub(t.lastAttempt) >= retry) {
		t.lastAttempt = n
		load := t.load
		if load == nil {
			load = t.fetch
		}
		tm, err := load(ctx)
		if err == nil {
			t.tm, t.fetchedAt, t.lastErr = tm, n, nil
		} else {
			t.lastErr = err
		}
	}
	if t.tm == nil {
		err := t.lastErr
		if err == nil {
			err = errors.New("trusted root not fetched yet")
		}
		return nil, "", err
	}
	return t.tm, TrustRootPublicGood, nil
}

func (t *TUFTrustRoot) fetch(ctx context.Context) (root.TrustedMaterial, error) {
	raw, err := t.fetchRaw(ctx)
	if err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("sigstore TUF: trusted_root.json: %w", err)
	}
	return tr, nil
}

// fetchRaw returns trusted_root.json from the TUF repository, verified by
// the TUF client against the embedded root.
func (t *TUFTrustRoot) fetchRaw(ctx context.Context) ([]byte, error) {
	if t.Transport == nil {
		return nil, errors.New("TUFTrustRoot: no transport")
	}
	opts := tuf.DefaultOptions()
	// Read-only root filesystem; the root is held in memory.
	opts.DisableLocalCache = true
	opts.CachePath = ""
	if t.MirrorURL != "" {
		opts.RepositoryBaseURL = t.MirrorURL
	}
	// Not NewFetcherWithRoundTripper: in go-tuf v2.4.2 it sets the
	// transport on the shared http.DefaultClient and drops the retry
	// limit, so a failing request is retried for up to 15 minutes.
	f := tuffetcher.NewDefaultFetcher()
	f.SetHTTPClient(&http.Client{Transport: t.Transport, Timeout: 30 * time.Second})
	f.SetRetry(time.Second, 2)
	opts.Fetcher = f
	opts = opts.WithContext(ctx)
	c, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("sigstore TUF: %w", err)
	}
	raw, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("sigstore TUF: %w", err)
	}
	return raw, nil
}

// rateLimited wraps a RoundTripper with a token bucket, so no burst of
// work can hammer a registry or the Sigstore infrastructure.
type rateLimited struct {
	base http.RoundTripper
	lim  *rate.Limiter
}

// RateLimit returns base limited to rps requests per second with the
// given burst.
func RateLimit(base http.RoundTripper, rps float64, burst int) http.RoundTripper {
	return &rateLimited{base: base, lim: rate.NewLimiter(rate.Limit(rps), burst)}
}

func (r *rateLimited) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := r.lim.Wait(req.Context()); err != nil {
		return nil, err
	}
	return r.base.RoundTrip(req)
}
