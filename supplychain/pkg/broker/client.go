// Package broker is the supplychain component's outbound interface to the
// kguardian broker. Sources never talk to the broker directly: they hand
// normalised payloads to a Client.
//
// Two implementations:
//   - LoggingClient (the default): logs a one-line summary per payload and
//     sends nothing. Used until the broker's supply-chain ingest routes
//     exist (#1533 P1-3).
//   - HTTPClient: POSTs JSON to the broker with the scoped bearer token from
//     BROKER_AUTH_TOKEN. Its route paths are provisional; P1-3 owns them.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
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

// maxErrorBody caps how much of an error response is read into the error.
const maxErrorBody = 4 << 10

// HTTPClient posts payloads to the broker.
type HTTPClient struct {
	baseURL string
	token   string
	http    *http.Client
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
		baseURL: strings.TrimRight(u.String(), "/"),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SubmitVulnerabilities posts p to the broker.
func (c *HTTPClient) SubmitVulnerabilities(ctx context.Context, p *types.ImageVulnerabilities) error {
	return c.post(ctx, fmt.Sprintf(vulnerabilitiesPath, url.PathEscape(p.Image.Digest)), p)
}

// SubmitSBOM posts p to the broker.
func (c *HTTPClient) SubmitSBOM(ctx context.Context, p *types.ImageSBOM) error {
	return c.post(ctx, fmt.Sprintf(sbomPath, url.PathEscape(p.Image.Digest)), p)
}

func (c *HTTPClient) post(ctx context.Context, path string, body interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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
		return fmt.Errorf("POST %s: broker returned %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
