package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Broker bounds.
const (
	inventoryPageSize = 500 // GET /images max
	maxInventoryPages = 40  // 20000 digests per pass
	maxInventoryBody  = 4 << 20
	// MaxPostBytes is the broker's body limit for
	// POST /images/{digest}/attestation.
	MaxPostBytes   = 256 << 10
	maxSignatures  = 32
	maxAttestation = 64
)

// BrokerClient reads the image inventory and posts results. It holds the
// supplychain-scoped token, which includes read.
type BrokerClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewBrokerClient returns a client with a 30s request timeout.
func NewBrokerClient(baseURL, token string) (*BrokerClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("broker URL %q is not an absolute URL", baseURL)
	}
	return &BrokerClient{BaseURL: u.String(), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// InventoryImage is one row of GET /images.
type InventoryImage struct {
	Digest            string   `json:"digest"`
	Repository        *string  `json:"repository"`
	Tags              []string `json:"tags"`
	DigestKind        string   `json:"digestKind"`
	RunningContainers int64    `json:"runningContainers"`
}

type inventoryPage struct {
	Items     []InventoryImage `json:"items"`
	NextAfter *string          `json:"nextAfter"`
}

// StatusError is a non-2xx broker answer.
type StatusError struct {
	Method, Path string
	Code         int
	Body         string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: broker returned %d: %s", e.Method, e.Path, e.Code, e.Body)
}

func (b *BrokerClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token)
	}
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxInventoryBody+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		msg := string(data)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, &StatusError{Method: method, Path: path, Code: resp.StatusCode, Body: msg}
	}
	if len(data) > maxInventoryBody {
		return nil, fmt.Errorf("%s %s: response over %d bytes", method, path, maxInventoryBody)
	}
	return data, nil
}

// RunningImages pages through GET /images and returns the digests some
// workload container is running now.
func (b *BrokerClient) RunningImages(ctx context.Context) ([]Target, error) {
	var out []Target
	after := ""
	for page := 0; page < maxInventoryPages; page++ {
		q := url.Values{"limit": {fmt.Sprint(inventoryPageSize)}}
		if after != "" {
			q.Set("after", after)
		}
		data, err := b.do(ctx, http.MethodGet, "/images?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var p inventoryPage
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("GET /images: %w", err)
		}
		for _, it := range p.Items {
			if it.RunningContainers <= 0 {
				continue
			}
			t := Target{Digest: it.Digest, DigestKind: it.DigestKind, Tags: it.Tags}
			if it.Repository != nil {
				t.Repository = *it.Repository
			}
			out = append(out, t)
		}
		if p.NextAfter == nil || *p.NextAfter == "" {
			return out, nil
		}
		after = *p.NextAfter
	}
	return out, errInventoryTruncated
}

var errInventoryTruncated = errors.New("GET /images: more than the per-pass page limit; the rest is checked next pass")

// Post sends one result to POST /images/{digest}/attestation.
func (b *BrokerClient) Post(ctx context.Context, r Result) error {
	body, err := encodeBounded(r)
	if err != nil {
		return err
	}
	_, err = b.do(ctx, http.MethodPost, "/images/"+url.PathEscape(r.Digest)+"/attestation", body)
	return err
}

// encodeBounded serialises r within MaxPostBytes: the lists are capped
// first, then details dropped, then attestations trimmed.
func encodeBounded(r Result) ([]byte, error) {
	if len(r.Signatures) > maxSignatures {
		r.Signatures = r.Signatures[:maxSignatures]
	}
	if len(r.Attestations) > maxAttestation {
		r.Attestations = r.Attestations[:maxAttestation]
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) <= MaxPostBytes {
		return b, err
	}
	for i := range r.Signatures {
		r.Signatures[i].Detail = ""
	}
	for i := range r.Attestations {
		r.Attestations[i].Detail = ""
	}
	for {
		b, err = json.Marshal(r)
		if err != nil || len(b) <= MaxPostBytes || len(r.Attestations) == 0 {
			break
		}
		r.Attestations = r.Attestations[:len(r.Attestations)/2]
	}
	if len(b) > MaxPostBytes {
		return nil, fmt.Errorf("attestation result for %s exceeds %d bytes", r.Digest, MaxPostBytes)
	}
	return b, err
}

// Retryable reports whether a failed post may succeed unchanged later.
func Retryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500 || se.Code == http.StatusRequestTimeout || se.Code == http.StatusTooManyRequests
	}
	return err != nil
}
