// Package broker is the supplychain component's outbound interface to the
// kguardian broker. Sources never talk to the broker directly: they hand
// normalised payloads to a Client.
//
// Two implementations:
//   - LoggingClient (the default): logs a one-line summary per payload and
//     sends nothing. Used until the broker's supply-chain ingest routes
//     exist (#1533 P1-3).
//   - HTTPClient: POSTs gzip-compressed JSON to the broker with the scoped
//     bearer token from BROKER_AUTH_TOKEN, splitting large SBOMs into pages
//     so no request body exceeds MaxRequestBytes compressed. Its route
//     paths are provisional; P1-3 owns them.
package broker

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

// Client submits normalised payloads to the broker. Each call replaces the
// stored set for (digest, source); implementations must be safe for
// concurrent use.
type Client interface {
	SubmitVulnerabilities(ctx context.Context, p *types.ImageVulnerabilities) error
	SubmitSBOM(ctx context.Context, p *types.ImageSBOM) error
}

// StatusError is a non-2xx broker response.
type StatusError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("POST %s: broker returned %d %s: %s",
		e.Path, e.StatusCode, http.StatusText(e.StatusCode), e.Body)
}

// ErrPayloadTooLarge is returned, without contacting the broker, when a
// payload cannot be brought under MaxRequestBytes (a single vulnerability
// set, or one SBOM component, that is itself too large).
var ErrPayloadTooLarge = errors.New("payload exceeds the request size limit")

// Retryable reports whether a failed submission may succeed if repeated
// unchanged: network errors, 5xx, 408 and 429 are; any other 4xx, an
// oversized payload or an encoding error is not, and retrying it would
// only block the queue.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrPayloadTooLarge) || errors.Is(err, errEncoding) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.StatusCode == http.StatusRequestTimeout, se.StatusCode == http.StatusTooManyRequests:
			return true
		case se.StatusCode >= 400 && se.StatusCode < 500:
			return false
		}
		return true
	}
	return true
}

// Reason is a short, low-cardinality label for err, for metrics.
func Reason(err error) string {
	var se *StatusError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrPayloadTooLarge):
		return "too_large"
	case errors.Is(err, errEncoding):
		return "encoding"
	case errors.As(err, &se):
		return fmt.Sprintf("http_%d", se.StatusCode)
	default:
		return "network"
	}
}

var errEncoding = errors.New("encoding payload")

// LoggingClient logs payload summaries instead of sending them.
type LoggingClient struct {
	Log *logrus.Logger
}

// SubmitVulnerabilities logs a summary of p.
func (c LoggingClient) SubmitVulnerabilities(_ context.Context, p *types.ImageVulnerabilities) error {
	counts := map[string]int{}
	for _, v := range p.Vulnerabilities {
		counts[v.Severity]++
	}
	c.Log.WithFields(logrus.Fields{
		"kind":        "vulnerabilities",
		"digest":      p.Image.Digest,
		"digest_kind": p.Image.DigestKind,
		"ref":         p.Image.Ref,
		"source":      p.Source,
		"scanned_at":  p.ScannedAt,
		"total":       len(p.Vulnerabilities),
		"critical":    counts["CRITICAL"],
		"high":        counts["HIGH"],
		"observed_in": len(p.ObservedIn),
	}).Info("payload ready (broker ingest not enabled; not sent)")
	return nil
}

// SubmitSBOM logs a summary of p.
func (c LoggingClient) SubmitSBOM(_ context.Context, p *types.ImageSBOM) error {
	c.Log.WithFields(logrus.Fields{
		"kind":        "sbom",
		"digest":      p.Image.Digest,
		"digest_kind": p.Image.DigestKind,
		"ref":         p.Image.Ref,
		"source":      p.Source,
		"scanned_at":  p.ScannedAt,
		"components":  len(p.Components),
		"observed_in": len(p.ObservedIn),
	}).Info("payload ready (broker ingest not enabled; not sent)")
	return nil
}

// Provisional ingest routes (#1533 P1-3 owns the final shape). %s is the
// URL-escaped digest.
const (
	vulnerabilitiesPath = "/images/%s/vulnerabilities"
	sbomPath            = "/images/%s/sbom"
)

const (
	// MaxRequestBytes is the ceiling for one compressed request body. The
	// broker's ingest JsonConfig limit (P1-3) is set to match.
	MaxRequestBytes = 1 << 20
	// DefaultSBOMPageComponents is the starting page size for SBOM
	// splitting; pages that still compress above MaxRequestBytes are
	// halved until they fit.
	DefaultSBOMPageComponents = 2000
	// maxErrorBody caps how much of an error response is kept.
	maxErrorBody = 4 << 10
)

// HTTPClient posts payloads to the broker.
type HTTPClient struct {
	baseURL string
	token   string
	http    *http.Client

	// MaxBytes and PageComponents default to MaxRequestBytes and
	// DefaultSBOMPageComponents; tests lower them.
	MaxBytes       int
	PageComponents int
}

// NewHTTPClient returns a client for the broker at baseURL. token is the
// scoped broker token (BROKER_AUTH_TOKEN); empty sends no Authorization
// header, which a broker with auth enabled will reject.
func NewHTTPClient(baseURL, token string) (*HTTPClient, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid broker URL %q", baseURL)
	}
	return &HTTPClient{
		baseURL:        strings.TrimRight(u.String(), "/"),
		token:          strings.TrimSpace(token),
		http:           &http.Client{Timeout: 30 * time.Second},
		MaxBytes:       MaxRequestBytes,
		PageComponents: DefaultSBOMPageComponents,
	}, nil
}

// SubmitVulnerabilities posts p as one request. A vulnerability set comes
// from one Kubernetes object (bounded by etcd's object size), so it is not
// paged; one that still compresses above the limit is rejected locally.
func (c *HTTPClient) SubmitVulnerabilities(ctx context.Context, p *types.ImageVulnerabilities) error {
	body, err := gzipJSON(p)
	if err != nil {
		return err
	}
	if len(body) > c.MaxBytes {
		return fmt.Errorf("vulnerabilities for %s: %d bytes compressed: %w", p.Image.Digest, len(body), ErrPayloadTooLarge)
	}
	return c.post(ctx, fmt.Sprintf(vulnerabilitiesPath, url.PathEscape(p.Image.Digest)), body)
}

// SubmitSBOM posts p, split into pages when it does not fit one request.
// Pages are sent in order; if one fails the whole set is retried later
// under a new call (same SetID, since it is derived from the content), and
// the broker discards incomplete sets.
func (c *HTTPClient) SubmitSBOM(ctx context.Context, p *types.ImageSBOM) error {
	pages, err := c.PageSBOM(p)
	if err != nil {
		return err
	}
	path := fmt.Sprintf(sbomPath, url.PathEscape(p.Image.Digest))
	for _, body := range pages {
		if err := c.post(ctx, path, body); err != nil {
			return err
		}
	}
	return nil
}

// PageSBOM encodes p as one or more gzip bodies, each at most MaxBytes.
// A single-body SBOM carries no Page field.
func (c *HTTPClient) PageSBOM(p *types.ImageSBOM) ([][]byte, error) {
	whole, err := gzipJSON(p)
	if err != nil {
		return nil, err
	}
	if len(whole) <= c.MaxBytes {
		return [][]byte{whole}, nil
	}

	// Chunk by component count, halving any chunk that is still too big.
	size := c.PageComponents
	if size <= 0 {
		size = DefaultSBOMPageComponents
	}
	var chunks [][]types.Component
	for i := 0; i < len(p.Components); i += size {
		end := min(i+size, len(p.Components))
		chunks = append(chunks, p.Components[i:end])
	}
	setID := sbomSetID(p)
	encode := func(comps []types.Component, idx, total int) ([]byte, error) {
		page := *p
		page.Components = comps
		page.Page = &types.Page{SetID: setID, Index: idx, Total: total}
		return gzipJSON(&page)
	}
	for {
		split := false
		var next [][]types.Component
		for _, ch := range chunks {
			// Encode with a worst-case index/total so the size check
			// holds after the real values are filled in.
			b, err := encode(ch, 1<<30, 1<<30)
			if err != nil {
				return nil, err
			}
			if len(b) <= c.MaxBytes {
				next = append(next, ch)
				continue
			}
			if len(ch) == 1 {
				return nil, fmt.Errorf("sbom for %s: one component is %d bytes compressed: %w", p.Image.Digest, len(b), ErrPayloadTooLarge)
			}
			half := len(ch) / 2
			next = append(next, ch[:half], ch[half:])
			split = true
		}
		chunks = next
		if !split {
			break
		}
	}
	out := make([][]byte, 0, len(chunks))
	for i, ch := range chunks {
		b, err := encode(ch, i, len(chunks))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// sbomSetID is a content hash, so a retry of the same SBOM reuses the id
// and the broker can recognise and deduplicate the pages.
func sbomSetID(p *types.ImageSBOM) string {
	cp := *p
	cp.ObservedIn = nil
	cp.Page = nil
	b, _ := json.Marshal(&cp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func gzipJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %v", errEncoding, err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("%w: %v", errEncoding, err)
	}
	return buf.Bytes(), nil
}

func (c *HTTPClient) post(ctx context.Context, path string, gz []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(gz))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return &StatusError{Path: path, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
